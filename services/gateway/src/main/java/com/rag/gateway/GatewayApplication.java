package com.rag.gateway;

import java.util.List;
import java.util.Map;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestClient;

/**
 * Point d'entree unique : valide le JWT, applique les roles, puis transmet l'identite aux services
 * internes via des en-tetes. Les services internes ne font confiance qu'a ce gateway (AuthorizationPolicy Istio).
 */
@SpringBootApplication
@RestController
@RequestMapping("/api")
public class GatewayApplication {
    private final RestClient ingestion;
    private final RestClient rag;

    GatewayApplication(@Value("${ingestion.url}") String ingestionUrl, @Value("${rag.url}") String ragUrl) {
        this.ingestion = RestClient.builder().baseUrl(ingestionUrl).build();
        this.rag = RestClient.builder().baseUrl(ragUrl).build();
    }

    public static void main(String[] args) { SpringApplication.run(GatewayApplication.class, args); }

    @PostMapping("/documents")  // role INGEST
    Map<?, ?> ingest(@RequestBody Map<String, Object> body, Jwt jwt) {
        return ingestion.post().uri("/documents")
            .header("X-User", jwt.getSubject())
            .header("X-Groups", String.join(",", groups(jwt)))
            .body(body).retrieve().body(Map.class);
    }

    @PostMapping("/query")  // role QUERY
    Map<?, ?> query(@RequestBody Map<String, Object> body, Jwt jwt) {
        return rag.post().uri("/query")
            .header("X-User", jwt.getSubject())
            .header("X-Groups", String.join(",", groups(jwt)))
            .body(body).retrieve().body(Map.class);
    }

    private static List<String> groups(Jwt jwt) {
        List<String> g = jwt.getClaimAsStringList("groups");
        return g == null ? List.of() : g;
    }

    @Bean
    SecurityFilterChain chain(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable)
            .authorizeHttpRequests(a -> a
                .requestMatchers("/actuator/health/**").permitAll()
                .requestMatchers("/api/documents").hasAuthority("ROLE_INGEST")
                .requestMatchers("/api/query").hasAuthority("ROLE_QUERY")
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

    /** Secret injecte depuis un Secret Kubernetes (>= 32 octets). En prod : IdP + RS256/JWKS. */
    @Bean
    JwtDecoder jwtDecoder(@Value("${JWT_SECRET}") String secret) {
        return NimbusJwtDecoder.withSecretKey(new SecretKeySpec(secret.getBytes(), "HmacSHA256"))
            .macAlgorithm(MacAlgorithm.HS256).build();
    }
}
