package com.rag.ingestion;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

/** ingestion-service verifies the token itself, applies RBAC and ABAC, validates and masks before indexing. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class IngestionSecurityTest {
    @LocalServerPort
    int port;

    @MockitoBean
    VectorStore store;

    private final HttpClient http = HttpClient.newHttpClient();
    private final String alice = TestTokens.token("alice", List.of("INGEST", "QUERY"), List.of("finance"));

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        registry.add("jwt.public-key-location", () -> "file:" + TestTokens.PUBLIC_PEM);
    }

    int post(String json, String token) throws Exception {
        var b = HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/documents"))
            .header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString(json));
        if (token != null) {
            b.header("Authorization", "Bearer " + token);
        }
        return http.send(b.build(), HttpResponse.BodyHandlers.discarding()).statusCode();
    }

    static String doc(String text, String group) {
        return "{\"title\":\"Budget\",\"text\":\"" + text + "\",\"allowed_groups\":[\"" + group + "\"]}";
    }

    @Test
    void withoutTokenIs401() throws Exception {
        assertEquals(401, post(doc("x", "finance"), null));
    }

    @Test
    void withoutIngestRoleIs403() throws Exception {
        assertEquals(403, post(doc("x", "finance"), TestTokens.token("bob", List.of("QUERY"), List.of("finance"))));
    }

    @Test
    void sharingWithAForeignGroupIs403AndNothingIsIndexed() throws Exception {
        assertEquals(403, post(doc("x", "rh"), alice));
        verify(store, never()).upsert(any());
    }

    @Test
    void controlCharactersOversizedTextOrTooManyChunksAreRefused() throws Exception {
        assertEquals(400, post(doc("binaire \\u0000\\u0001", "finance"), alice));
        assertEquals(400, post(doc("a".repeat(200_001), "finance"), alice));
        assertEquals(413, post(doc("mot ".repeat(20_000), "finance"), alice));
        verify(store, never()).upsert(any());
    }

    @Test
    @SuppressWarnings("unchecked")
    void secretsAreMaskedBeforeIndexingAndGroupsComeFromTheRequestCheckedAgainstTheToken() throws Exception {
        assertEquals(200, post(doc("Budget 2M. password=hunter2 contact jean@exemple.ma", "finance"), alice));
        ArgumentCaptor<List<Map<String, Object>>> points = ArgumentCaptor.forClass(List.class);
        verify(store).upsert(points.capture());
        var payload = (Map<String, Object>) points.getValue().get(0).get("payload");
        String text = (String) payload.get("text");
        assertFalse(text.contains("hunter2"));
        assertFalse(text.contains("jean@exemple.ma"));
        assertTrue(text.contains("password=[REDACTED]") && text.contains("[EMAIL]"));
        assertEquals(List.of("finance"), payload.get("groups"));
        assertEquals("alice", payload.get("owner"));
    }

    @Test
    void redactorCoversKeysCardsAndPrivateKeys() {
        var r = Redactor.redact("AKIAIOSFODNN7EXAMPLE 4111 1111 1111 1111 -----BEGIN PRIVATE KEY-----abc-----END PRIVATE KEY-----");
        assertEquals("[AWS_KEY] [CARD] [PRIVATE_KEY]", r.text());
        assertEquals(3, r.count());
    }
}
