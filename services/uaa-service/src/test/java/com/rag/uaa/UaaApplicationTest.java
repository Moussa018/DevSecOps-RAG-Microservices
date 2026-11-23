package com.rag.uaa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class UaaApplicationTest {
    static final KeyPair KEYS = rsa();
    static final JsonMapper JSON = JsonMapper.builder().build();

    @LocalServerPort
    int port;

    private final HttpClient http = HttpClient.newHttpClient();

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) throws Exception {
        Path dir = Files.createTempDirectory("uaa-test");
        String pem = "-----BEGIN PRIVATE KEY-----\n"
            + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(KEYS.getPrivate().getEncoded())
            + "\n-----END PRIVATE KEY-----\n";
        Files.writeString(dir.resolve("private.pem"), pem);
        Files.writeString(dir.resolve("users.json"), "{\"alice\":{\"password\":\"" + pbkdf2("pw-alice")
            + "\",\"roles\":[\"INGEST\",\"QUERY\"],\"groups\":[\"finance\"]}}");
        registry.add("uaa.private-key-location", () -> dir.resolve("private.pem").toString());
        registry.add("uaa.users-file", () -> dir.resolve("users.json").toString());
    }

    static KeyPair rsa() {
        try {
            var g = KeyPairGenerator.getInstance("RSA");
            g.initialize(2048);
            return g.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    static String pbkdf2(String password) throws Exception {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        var spec = new PBEKeySpec(password.toCharArray(), salt, 1000, 256);
        byte[] hash = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
        return "pbkdf2_sha256$1000$" + HexFormat.of().formatHex(salt) + "$" + HexFormat.of().formatHex(hash);
    }

    HttpResponse<String> login(String user, String password) throws Exception {
        String body = "{\"username\":\"" + user + "\",\"password\":\"" + password + "\"}";
        var req = HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/auth/login"))
            .header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString(body)).build();
        return http.send(req, HttpResponse.BodyHandlers.ofString());
    }

    @Test
    void goodPasswordIsAcceptedOthersAreRefused() throws Exception {
        assertEquals(200, login("alice", "pw-alice").statusCode());
        assertEquals(401, login("alice", "wrong").statusCode());
        assertEquals(401, login("ghost", "pw-alice").statusCode());
        assertEquals(400, login("", "x").statusCode());
    }

    @Test
    void repeatedFailuresAreRateLimited() throws Exception {
        List<Integer> codes = new ArrayList<>();
        for (int i = 0; i < 7; i++) {
            codes.add(login("brute", "bad").statusCode());
        }
        assertEquals(List.of(401, 401, 401, 401, 401, 429, 429), codes);
    }

    @Test
    void tokenIsSignedWithRs256AndCarriesRolesAndGroups() throws Exception {
        JsonNode body = JSON.readTree(login("alice", "pw-alice").body());
        SignedJWT jwt = SignedJWT.parse(body.get("access_token").asString());
        assertEquals(JWSAlgorithm.RS256, jwt.getHeader().getAlgorithm());
        assertTrue(jwt.verify(new RSASSAVerifier((RSAPublicKey) KEYS.getPublic())));
        var c = jwt.getJWTClaimsSet();
        assertEquals("uaa-service", c.getIssuer());
        assertEquals(List.of("rag-api"), c.getAudience());
        assertEquals("alice", c.getSubject());
        assertEquals(List.of("INGEST", "QUERY"), c.getStringListClaim("roles"));
        assertEquals(List.of("finance"), c.getStringListClaim("groups"));
        assertEquals(900, (c.getExpirationTime().getTime() - c.getIssueTime().getTime()) / 1000);
    }
}
