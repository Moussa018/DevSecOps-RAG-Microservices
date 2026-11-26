package com.rag.uaa;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Base64;
import java.util.Date;
import java.util.Deque;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.json.JsonMapper;

/**
 * Identity service (UAA). Verifies the password (salted PBKDF2-SHA256, constant time), limits repeated failures,
 * then signs a JWT with the private RSA key. No other service holds this key: the others can verify, never sign.
 */
@SpringBootApplication
@RestController
public class UaaApplication {
    static final String ISSUER = "uaa-service";
    static final String AUDIENCE = "rag-api";
    static final long USER_TTL_SECONDS = 900;
    static final int MAX_FAILURES = 5;
    private static final String DUMMY = "pbkdf2_sha256$600000$00$" + "0".repeat(64);
    private static final Logger AUDIT = LoggerFactory.getLogger("AUDIT");
    private static final JsonMapper JSON = JsonMapper.builder().build();

    record User(String password, List<String> roles, List<String> groups) {}

    record Login(@NotBlank @Size(max = 64) String username, @NotBlank @Size(max = 128) String password) {}

    private final RSASSASigner signer;
    private final Map<String, User> users;
    private final Map<String, Deque<Long>> failures = new ConcurrentHashMap<>();

    UaaApplication(@Value("${uaa.private-key-location}") String privateKey, @Value("${uaa.users-file}") String usersFile)
            throws Exception {
        this.signer = new RSASSASigner(readPrivateKey(Path.of(privateKey)));
        this.users = JSON.readValue(new File(usersFile), new TypeReference<Map<String, User>>() {});
    }

    public static void main(String[] args) {
        SpringApplication.run(UaaApplication.class, args);
    }

    @PostMapping("/auth/login")
    ResponseEntity<Map<String, Object>> login(@Valid @RequestBody Login body) throws Exception {
        long now = System.currentTimeMillis();
        if (failures.size() > 10_000) {
            failures.clear();
        }
        Deque<Long> recent = failures.computeIfAbsent(body.username(), k -> new ArrayDeque<>());
        synchronized (recent) {
            while (!recent.isEmpty() && recent.peekFirst() < now - 60_000) {
                recent.pollFirst();
            }
            if (recent.size() >= MAX_FAILURES) {
                return ResponseEntity.status(429).body(Map.of("detail", "trop de tentatives"));
            }
        }
        User user = users.get(body.username());
        // Same PBKDF2 cost for an unknown user: response time does not reveal which accounts exist.
        boolean ok = checkPassword(user == null ? DUMMY : user.password(), body.password()) && user != null;
        if (!ok) {
            synchronized (recent) {
                recent.addLast(now);
            }
            audit("login_failed", body.username());
            return ResponseEntity.status(401).body(Map.of("detail", "identifiants invalides"));
        }
        audit("login_ok", body.username());
        Instant issued = Instant.now();
        var claims = new JWTClaimsSet.Builder()
            .issuer(ISSUER).audience(AUDIENCE).subject(body.username())
            .issueTime(Date.from(issued)).expirationTime(Date.from(issued.plusSeconds(USER_TTL_SECONDS)))
            .jwtID(UUID.randomUUID().toString())
            .claim("roles", user.roles()).claim("groups", user.groups())
            .build();
        var jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).type(JOSEObjectType.JWT).build(), claims);
        jwt.sign(signer);
        return ResponseEntity.ok(Map.of("access_token", jwt.serialize(), "token_type", "Bearer", "expires_in", USER_TTL_SECONDS));
    }

    @ExceptionHandler({MethodArgumentNotValidException.class, HttpMessageNotReadableException.class})
    ResponseEntity<Map<String, String>> invalid(Exception e) {
        return ResponseEntity.badRequest().body(Map.of("detail", "champs invalides"));
    }

    /** Format "pbkdf2_sha256$iterations$salt_hex$hash_hex", produced by scripts/gen-secrets.sh (openssl kdf PBKDF2). */
    static boolean checkPassword(String stored, String password) {
        try {
            String[] p = stored.split("\\$");
            byte[] salt = HexFormat.of().parseHex(p[2]);
            byte[] expected = HexFormat.of().parseHex(p[3]);
            var spec = new PBEKeySpec(password.toCharArray(), salt, Integer.parseInt(p[1]), expected.length * 8);
            byte[] actual = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
            return MessageDigest.isEqual(actual, expected);
        } catch (Exception e) {
            return false;
        }
    }

    static RSAPrivateKey readPrivateKey(Path pem) throws Exception {
        String b64 = Files.readString(pem, StandardCharsets.US_ASCII).replaceAll("-----[A-Z ]+-----", "").replaceAll("\\s", "");
        return (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(b64)));
    }

    private static void audit(String event, String user) {
        var rec = new LinkedHashMap<String, Object>();
        rec.put("ts", Instant.now().toString());
        rec.put("service", ISSUER);
        rec.put("user", user.length() > 64 ? user.substring(0, 64) : user);
        rec.put("event", event);
        rec.put("detail", Map.of());
        AUDIT.info("AUDIT {}", JSON.writeValueAsString(rec));
    }
}
