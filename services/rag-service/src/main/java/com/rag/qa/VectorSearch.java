package com.rag.qa;

import com.rag.common.MtlsClients;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

/** Qdrant search over mutual TLS. The ABAC filter is applied by Qdrant itself, on the server side. */
@Component
class VectorSearch {
    record Hit(String title, String text, double score) {}

    private final RestClient qdrant;

    VectorSearch(@Value("${qdrant.url}") String url, @Value("${app.tls.bundle:}") String bundle, SslBundles sslBundles) {
        this.qdrant = MtlsClients.create(url, bundle, sslBundles, Duration.ofSeconds(60));
    }

    @SuppressWarnings("unchecked")
    List<Hit> search(float[] vector, List<String> groups, int limit) {
        Map<String, Object> body = Map.of("vector", vector, "limit", limit, "with_payload", true,
            "filter", Map.of("must", List.of(Map.of("key", "groups", "match", Map.of("any", groups)))));
        Map<String, Object> res = qdrant.post().uri("/collections/docs/points/search").contentType(MediaType.APPLICATION_JSON)
            .body(body).exchange((req, r) -> r.getStatusCode().value() == 404 ? Map.of("result", List.of())
                : r.bodyTo(new ParameterizedTypeReference<Map<String, Object>>() {}));
        if (res == null || !(res.get("result") instanceof List<?> hits)) {
            throw new IllegalStateException("reponse Qdrant inattendue");
        }
        return hits.stream().map(h -> (Map<String, Object>) h).map(h -> {
            var p = (Map<String, Object>) h.get("payload");
            return new Hit((String) p.get("title"), (String) p.get("text"), ((Number) h.get("score")).doubleValue());
        }).toList();
    }
}
