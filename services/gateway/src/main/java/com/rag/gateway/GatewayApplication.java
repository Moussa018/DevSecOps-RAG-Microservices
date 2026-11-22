package com.rag.gateway;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.boot.web.client.ClientHttpRequestFactories;
import org.springframework.boot.web.client.ClientHttpRequestFactorySettings;
import org.springframework.context.annotation.Bean;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.converter.RsaKeyConverters;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientResponseException;

/**
 * Point d'entree unique. Il valide le JWT utilisateur (RS256, emis par uaa-service), applique les roles, puis
 * ECHANGE ce jeton aupres de uaa-service contre un jeton court destine a UN service cible. Les services internes
 * verifient ce jeton (signature, audience, appelant) : ils ne font plus confiance a des en-tetes, et un jeton
 * vole ne sert que pour un service et quelques minutes. Le tout passe en TLS mutuel.
 */
@SpringBootApplication
@RestController
@RequestMapping("/api")
public class GatewayApplication {
    static final String GATEWAY_AUDIENCE = "rag-gateway";
    private final RestClient ingestion;
    private final RestClient rag;
    private final RestClient audit;
    private final RestClient uaa;
    private final String clientId;
    private final String clientSecret;
    private final Map<String, CachedToken> cache = new ConcurrentHashMap<>();

    record CachedToken(String value, Instant expires) {}

    GatewayApplication(@Value("${ingestion.url}") String ingestionUrl, @Value("${rag.url}") String ragUrl,
                       @Value("${audit.url}") String auditUrl, @Value("${uaa.url}") String uaaUrl,
                       @Value("${gateway.client-id}") String clientId,
                       @Value("${gateway.client-secret}") String clientSecret,
                       @Value("${gateway.tls.bundle:}") String bundle, SslBundles sslBundles) {
        var settings = ClientHttpRequestFactorySettings.DEFAULTS
            .withConnectTimeout(Duration.ofSeconds(5)).withReadTimeout(Duration.ofSeconds(60));
        if (!bundle.isEmpty()) {
            settings = settings.withSslBundle(sslBundles.getBundle(bundle));
        }
        var factory = ClientHttpRequestFactories.get(settings);
        this.ingestion = RestClient.builder().baseUrl(ingestionUrl).requestFactory(factory).build();
        this.rag = RestClient.builder().baseUrl(ragUrl).requestFactory(factory).build();
        this.audit = RestClient.builder().baseUrl(auditUrl).requestFactory(factory).build();
        this.uaa = RestClient.builder().baseUrl(uaaUrl).requestFactory(factory).build();
        this.clientId = clientId;
        this.clientSecret = clientSecret;
    }

    public static void main(String[] args) { SpringApplication.run(GatewayApplication.class, args); }

    /** Connexion : relayee a uaa-service (qui exige le TLS mutuel, donc inaccessible directement depuis l'exterieur). */
    @PostMapping("/auth/login")
    ResponseEntity<String> login(@RequestBody Map<String, Object> body) {
        return uaa.post().uri("/auth/login").contentType(MediaType.APPLICATION_JSON).body(body)
            .exchange((req, res) -> {
                int code = res.getStatusCode().value();
                if (code != 200 && code != 401 && code != 429 && code != 422) {
                    return ResponseEntity.status(HttpStatus.BAD_GATEWAY).<String>build();
                }
                return ResponseEntity.status(code).contentType(MediaType.APPLICATION_JSON).body(res.bodyTo(String.class));
            });
    }

    @PostMapping("/documents")  // role INGEST
    Map<?, ?> ingest(@RequestBody Map<String, Object> body, @AuthenticationPrincipal Jwt jwt) {
        return ingestion.post().uri("/documents").header("Authorization", bearer(jwt, "ingestion-service"))
            .body(body).retrieve().body(Map.class);
    }

    @PostMapping("/query")  // role QUERY
    Map<?, ?> query(@RequestBody Map<String, Object> body, @AuthenticationPrincipal Jwt jwt) {
        return rag.post().uri("/query").header("Authorization", bearer(jwt, "rag-service"))
            .body(body).retrieve().body(Map.class);
    }

    @GetMapping("/audit")  // role ADMIN
    Map<?, ?> auditEvents(@RequestParam(defaultValue = "100") int limit, @AuthenticationPrincipal Jwt jwt) {
        return audit.get().uri("/events?limit={l}", Math.max(1, Math.min(limit, 500)))
            .header("Authorization", bearer(jwt, "audit-service")).retrieve().body(Map.class);
    }

    /** Jeton echange pour {@code audience}, mis en cache jusqu'a 30 s avant son expiration. */
    private String bearer(Jwt user, String audience) {
        String key = user.getId() + "|" + audience;
        CachedToken t = cache.get(key);
        if (t == null || t.expires().isBefore(Instant.now().plusSeconds(30))) {
            if (cache.size() > 5000) { cache.clear(); }  // borne la memoire
            Map<?, ?> r = uaa.post().uri("/auth/exchange").contentType(MediaType.APPLICATION_JSON)
                .body(Map.of("client_id", clientId, "client_secret", clientSecret, "audience", audience,
                             "subject_token", user.getTokenValue()))
                .retrieve().body(Map.class);
            int ttl = ((Number) r.get("expires_in")).intValue();
            t = new CachedToken((String) r.get("access_token"), Instant.now().plusSeconds(ttl));
            cache.put(key, t);
        }
        return "Bearer " + t.value();
    }

    /** Relaie un refus 4xx des services internes (ex. 403 ABAC) ; une panne ou un 401 interne devient 502 sans detail. */
    @ExceptionHandler(RestClientResponseException.class)
    ResponseEntity<String> downstream(RestClientResponseException e) {
        if (e.getStatusCode().is4xxClientError() && e.getStatusCode().value() != 401) {
            return ResponseEntity.status(e.getStatusCode()).contentType(MediaType.APPLICATION_JSON)
                .body(e.getResponseBodyAsString());
        }
        // un 401 interne (jeton refuse entre services) est un defaut de configuration, pas une erreur du client
        return ResponseEntity.status(HttpStatus.BAD_GATEWAY).build();
    }

    @ExceptionHandler(ResourceAccessException.class)
    ResponseEntity<Void> unreachable(ResourceAccessException e) {
        return ResponseEntity.status(HttpStatus.BAD_GATEWAY).build();
    }

    @Bean
    SecurityFilterChain chain(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable)
            .authorizeHttpRequests(a -> a
                .requestMatchers("/actuator/health/**").permitAll()
                .requestMatchers("/api/auth/login").permitAll()
                .requestMatchers("/error").permitAll()  // sinon toute erreur interne est masquee en 403
                .requestMatchers("/api/documents").hasAuthority("ROLE_INGEST")
                .requestMatchers("/api/query").hasAuthority("ROLE_QUERY")
                .requestMatchers("/api/audit").hasAuthority("ROLE_ADMIN")
                .anyRequest().denyAll())
            .oauth2ResourceServer(o -> o.jwt(j -> j.jwtAuthenticationConverter(converter())))
            .headers(h -> h.contentTypeOptions(c -> {}).frameOptions(f -> f.deny()));
        return http.build();
    }

    private static JwtAuthenticationConverter converter() {
        var c = new JwtAuthenticationConverter();
        c.setJwtGrantedAuthoritiesConverter(jwt -> {
            List<String> roles = jwt.getClaimAsStringList("roles");
            return roles == null ? List.<GrantedAuthority>of()
                : roles.stream().<GrantedAuthority>map(r -> new SimpleGrantedAuthority("ROLE_" + r)).toList();
        });
        return c;
    }

    /** Cle PUBLIQUE de uaa-service (ConfigMap) : le gateway ne peut pas fabriquer de jeton. Algorithme : RS256. */
    @Bean
    JwtDecoder jwtDecoder(@Value("${jwt.public-key-location}") Resource key) throws Exception {
        try (var in = key.getInputStream()) {
            var decoder = NimbusJwtDecoder.withPublicKey(RsaKeyConverters.x509().convert(in)).build();
            OAuth2TokenValidator<Jwt> audience = jwt -> jwt.getAudience() != null
                && jwt.getAudience().contains(GATEWAY_AUDIENCE) && "user".equals(jwt.getClaimAsString("typ"))
                ? OAuth2TokenValidatorResult.success()
                : OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token", "audience ou type refuse", null));
            decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                JwtValidators.createDefaultWithIssuer("uaa-service"), audience));
            return decoder;
        }
    }
}
