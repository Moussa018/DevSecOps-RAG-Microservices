package com.rag.common;

import java.util.List;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.security.converter.RsaKeyConverters;
import org.springframework.security.core.GrantedAuthority;
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

/**
 * JWT verification shared by every microservice: RS256 signature checked with the public key of uaa-service,
 * issuer, audience and expiry. The algorithm is fixed by the RSA key, so "alg=none" and HS256 tokens are rejected.
 */
@Configuration
public class JwtSupport {
    public static final String ISSUER = "uaa-service";
    public static final String AUDIENCE = "rag-api";

    @Bean
    JwtDecoder jwtDecoder(@Value("${jwt.public-key-location}") Resource key) throws Exception {
        try (var in = key.getInputStream()) {
            var decoder = NimbusJwtDecoder.withPublicKey(RsaKeyConverters.x509().convert(in)).build();
            OAuth2TokenValidator<Jwt> audience = jwt -> jwt.getAudience() != null && jwt.getAudience().contains(AUDIENCE)
                ? OAuth2TokenValidatorResult.success()
                : OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token", "audience refusee", null));
            decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(JwtValidators.createDefaultWithIssuer(ISSUER), audience));
            return decoder;
        }
    }

    /** RBAC: every value of the signed "roles" claim becomes the authority ROLE_value. */
    public static JwtAuthenticationConverter rolesConverter() {
        var c = new JwtAuthenticationConverter();
        c.setJwtGrantedAuthoritiesConverter(jwt -> {
            List<String> roles = jwt.getClaimAsStringList("roles");
            return roles == null ? List.<GrantedAuthority>of()
                : roles.stream().<GrantedAuthority>map(r -> new SimpleGrantedAuthority("ROLE_" + r)).toList();
        });
        return c;
    }

    /** ABAC attribute: the groups carried by the signed token (never by the request body). */
    public static List<String> groups(Jwt jwt) {
        List<String> g = jwt.getClaimAsStringList("groups");
        return g == null ? List.of() : g;
    }
}
