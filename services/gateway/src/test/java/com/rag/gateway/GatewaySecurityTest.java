package com.rag.gateway;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/** Authentication (401) and authorization (403) rules of the gateway, without any downstream service. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class GatewaySecurityTest {
    static final KeyPair KEYS = rsa();
    static final KeyPair OTHER_KEYS = rsa();

    @LocalServerPort
    int port;

    private final HttpClient http = HttpClient.newHttpClient();

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) throws Exception {
        Path pem = Files.createTempFile("jwt-public", ".pem");
        String body = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(KEYS.getPublic().getEncoded());
        Files.writeString(pem, "-----BEGIN PUBLIC KEY-----\n" + body + "\n-----END PUBLIC KEY-----\n");
        registry.add("jwt.public-key-location", () -> "file:" + pem);
        registry.add("app.tls.bundle", () -> "");
    }

    static KeyPair rsa() {
        try {
            KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
            g.initialize(2048);
            return g.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    static String token(KeyPair keys, List<String> roles, String audience, Instant expires) throws Exception {
        var claims = new JWTClaimsSet.Builder()
            .issuer("uaa-service").audience(audience).subject("alice")
            .issueTime(new Date()).expirationTime(Date.from(expires))
            .claim("roles", roles).claim("groups", List.of("finance")).build();
        var jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claims);
        jwt.sign(new RSASSASigner((RSAPrivateKey) keys.getPrivate()));
        return jwt.serialize();
    }

    static String valid(String... roles) throws Exception {
        return token(KEYS, List.of(roles), "rag-api", Instant.now().plusSeconds(300));
    }

    int status(String method, String path, String token) throws Exception {
        var b = HttpRequest.newBuilder(URI.create("http://localhost:" + port + path))
            .header("Content-Type", "application/json")
            .method(method, method.equals("GET") ? HttpRequest.BodyPublishers.noBody()
                                                 : HttpRequest.BodyPublishers.ofString("{}"));
        if (token != null) {
            b.header("Authorization", "Bearer " + token);
        }
        return http.send(b.build(), HttpResponse.BodyHandlers.discarding()).statusCode();
    }

    @Test
    void healthIsPublic() throws Exception {
        assertEquals(200, status("GET", "/actuator/health", null));
    }

    @Test
    void webUiIsPublicAndServedWithContentSecurityPolicy() throws Exception {
        for (String path : List.of("/", "/app.js", "/app.css")) {
            var res = http.send(HttpRequest.newBuilder(URI.create("http://localhost:" + port + path)).build(),
                HttpResponse.BodyHandlers.ofString());
            assertEquals(200, res.statusCode(), path);
            String csp = res.headers().firstValue("Content-Security-Policy").orElse("");
            org.junit.jupiter.api.Assertions.assertTrue(csp.contains("default-src 'self'"), csp);
        }
    }

    @Test
    void requestWithoutTokenIs401() throws Exception {
        assertEquals(401, status("POST", "/api/query", null));
    }

    @Test
    void forgedExpiredOrWrongAudienceTokenIs401() throws Exception {
        Instant later = Instant.now().plusSeconds(300);
        assertEquals(401, status("POST", "/api/query", token(OTHER_KEYS, List.of("QUERY"), "rag-api", later)));
        assertEquals(401, status("POST", "/api/query", token(KEYS, List.of("QUERY"), "rag-api", Instant.now().minusSeconds(120))));
        assertEquals(401, status("POST", "/api/query", token(KEYS, List.of("QUERY"), "other-app", later)));
    }

    @Test
    void missingRoleIs403() throws Exception {
        assertEquals(403, status("POST", "/api/documents", valid("QUERY")));
        assertEquals(403, status("POST", "/api/query", valid("INGEST")));
        assertEquals(403, status("GET", "/api/audit", valid("INGEST", "QUERY")));   // route removed: denied
    }

    @Test
    void undeclaredRouteIs403() throws Exception {
        assertEquals(403, status("GET", "/api/other", valid("INGEST", "QUERY")));
    }
}
