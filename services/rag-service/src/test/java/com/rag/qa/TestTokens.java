package com.rag.qa;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;

/** Test key pair and signed tokens, as uaa-service would issue them. */
final class TestTokens {
    static final KeyPair KEYS = rsa();
    static final Path PUBLIC_PEM = writePublicKey();

    private TestTokens() {}

    static KeyPair rsa() {
        try {
            var g = KeyPairGenerator.getInstance("RSA");
            g.initialize(2048);
            return g.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    static Path writePublicKey() {
        try {
            Path pem = Files.createTempFile("jwt-public", ".pem");
            Files.writeString(pem, "-----BEGIN PUBLIC KEY-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(KEYS.getPublic().getEncoded())
                + "\n-----END PUBLIC KEY-----\n");
            return pem;
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    static String token(String user, List<String> roles, List<String> groups) {
        try {
            var claims = new JWTClaimsSet.Builder().issuer("uaa-service").audience("rag-api").subject(user)
                .issueTime(new Date()).expirationTime(Date.from(Instant.now().plusSeconds(300)))
                .claim("roles", roles).claim("groups", groups).build();
            var jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claims);
            jwt.sign(new RSASSASigner(KEYS.getPrivate()));
            return jwt.serialize();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
