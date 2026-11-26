package com.rag.ingestion;

import com.rag.common.Embeddings;
import com.rag.common.MtlsClients;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

/** Qdrant over mutual TLS: ingestion presents its certificate, Qdrant verifies it with the private CA. */
@Component
class VectorStore {
    static final String COLLECTION = "docs";
    private final RestClient qdrant;

    VectorStore(@Value("${qdrant.url}") String url, @Value("${app.tls.bundle:}") String bundle, SslBundles sslBundles) {
        this.qdrant = MtlsClients.create(url, bundle, sslBundles, Duration.ofSeconds(60));
    }

    void upsert(List<Map<String, Object>> points) {
        // Create the collection if needed (409 when it already exists: ignored).
        qdrant.put().uri("/collections/{c}", COLLECTION).contentType(MediaType.APPLICATION_JSON)
            .body(Map.of("vectors", Map.of("size", Embeddings.DIM, "distance", "Cosine")))
            .exchange((req, res) -> null);
        qdrant.put().uri("/collections/{c}/points?wait=true", COLLECTION).contentType(MediaType.APPLICATION_JSON)
            .body(Map.of("points", points)).retrieve().toBodilessEntity();
    }
}
