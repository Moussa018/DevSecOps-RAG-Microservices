package com.rag.gateway;

import com.rag.common.JwtSupport;
import com.rag.common.MtlsClients;
import java.time.Duration;
import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientResponseException;

/**
 * API gateway, the only entry point. Verifies the user JWT (signature, issuer, audience, expiry) and the role
 * required by the route, then forwards the request over mutual TLS with the same token.
 */
@SpringBootApplication(scanBasePackages = {"com.rag.common", "com.rag.gateway"})
@RestController
@RequestMapping("/api")
public class GatewayApplication {
    private final RestClient ingestion;
    private final RestClient rag;
    private final RestClient uaa;

    GatewayApplication(@Value("${ingestion.url}") String ingestionUrl, @Value("${rag.url}") String ragUrl,
                       @Value("${uaa.url}") String uaaUrl, @Value("${app.tls.bundle:}") String bundle, SslBundles sslBundles) {
        this.ingestion = MtlsClients.create(ingestionUrl, bundle, sslBundles, Duration.ofSeconds(60));
        this.rag = MtlsClients.create(ragUrl, bundle, sslBundles, Duration.ofSeconds(60));
        this.uaa = MtlsClients.create(uaaUrl, bundle, sslBundles, Duration.ofSeconds(10));
    }

    public static void main(String[] args) {
        SpringApplication.run(GatewayApplication.class, args);
    }

    @PostMapping("/auth/login")
    ResponseEntity<String> login(@RequestBody Map<String, Object> body) {
        return uaa.post().uri("/auth/login").contentType(MediaType.APPLICATION_JSON).body(body)
            .exchange((req, res) -> {
                int code = res.getStatusCode().value();
                if (code != 200 && code != 400 && code != 401 && code != 429) {
                    return ResponseEntity.status(HttpStatus.BAD_GATEWAY).<String>build();
                }
                return ResponseEntity.status(code).contentType(MediaType.APPLICATION_JSON).body(res.bodyTo(String.class));
            });
    }

    @PostMapping("/documents")
    Map<?, ?> ingest(@RequestBody Map<String, Object> body, @AuthenticationPrincipal Jwt jwt) {
        return ingestion.post().uri("/documents").header("Authorization", bearer(jwt)).body(body).retrieve().body(Map.class);
    }

    @PostMapping("/query")
    Map<?, ?> query(@RequestBody Map<String, Object> body, @AuthenticationPrincipal Jwt jwt) {
        return rag.post().uri("/query").header("Authorization", bearer(jwt)).body(body).retrieve().body(Map.class);
    }

    /** The user's signed token is forwarded as is: each service verifies it again with the public key. */
    private static String bearer(Jwt user) {
        return "Bearer " + user.getTokenValue();
    }

    /** A refusal from a service (400, 403, 413) is relayed; anything else becomes a generic 502. */
    @ExceptionHandler(RestClientResponseException.class)
    ResponseEntity<String> downstream(RestClientResponseException e) {
        if (e.getStatusCode().is4xxClientError() && e.getStatusCode().value() != 401) {
            return ResponseEntity.status(e.getStatusCode()).contentType(MediaType.APPLICATION_JSON).body(e.getResponseBodyAsString());
        }
        return ResponseEntity.status(HttpStatus.BAD_GATEWAY).build();
    }

    @ExceptionHandler(ResourceAccessException.class)
    ResponseEntity<Void> unreachable(ResourceAccessException e) {
        return ResponseEntity.status(HttpStatus.BAD_GATEWAY).build();
    }

    /** RBAC at the entry point: whatever is not explicitly allowed is denied. */
    @Bean
    SecurityFilterChain chain(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable)
            .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(a -> a
                .requestMatchers("/actuator/health/**").permitAll()
                .requestMatchers(HttpMethod.GET, "/", "/index.html", "/app.css", "/app.js").permitAll()
                .requestMatchers("/api/auth/login").permitAll()
                .requestMatchers("/error").permitAll()
                .requestMatchers("/api/documents").hasAuthority("ROLE_INGEST")
                .requestMatchers("/api/query").hasAuthority("ROLE_QUERY")
                .anyRequest().denyAll())
            .oauth2ResourceServer(o -> o.jwt(j -> j.jwtAuthenticationConverter(JwtSupport.rolesConverter())))
            .headers(h -> h.contentTypeOptions(c -> {}).frameOptions(f -> f.deny())
                // The web UI loads only its own files: no inline script, no third-party origin (XSS mitigation).
                .contentSecurityPolicy(c -> c.policyDirectives(
                    "default-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; "
                    + "form-action 'self'; frame-ancestors 'none'")));
        return http.build();
    }
}
