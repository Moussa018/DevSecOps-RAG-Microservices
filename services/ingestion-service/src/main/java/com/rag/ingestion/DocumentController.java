package com.rag.ingestion;

import com.rag.common.Audit;
import com.rag.common.Embeddings;
import com.rag.common.JwtSupport;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Pattern;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
class DocumentController {
    static final int CHUNK = 800;
    static final int OVERLAP = 100;
    static final int MAX_CHUNKS = 100;
    private static final Pattern CONTROL = Pattern.compile("[\\x00-\\x08\\x0b\\x0c\\x0e-\\x1f]");

    record Doc(@NotBlank @Size(max = 200) String title,
               @NotNull @Size(min = 1, max = 200_000) String text,
               @NotNull @Size(min = 1, max = 20) List<@NotBlank @Size(max = 64) String> allowed_groups) {}

    private final VectorStore store;
    private final Audit audit;

    DocumentController(VectorStore store, Audit audit) {
        this.store = store;
        this.audit = audit;
    }

    @PostMapping("/documents")
    Map<String, Object> ingest(@Valid @RequestBody Doc doc, @AuthenticationPrincipal Jwt jwt) {
        String user = jwt.getSubject();
        // ABAC: a user may only share a document with groups he belongs to (groups from the signed token).
        if (!new HashSet<>(JwtSupport.groups(jwt)).containsAll(doc.allowed_groups())) {
            audit.event("ingest.denied", user, Map.of("reason", "group_not_allowed"));
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "groupe non autorise");
        }
        if (CONTROL.matcher(doc.text()).find()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "contenu binaire refuse");
        }
        Redactor.Result clean = Redactor.redact(doc.text());
        List<String> parts = chunk(clean.text());
        if (parts.size() > MAX_CHUNKS) {
            throw new ResponseStatusException(HttpStatus.PAYLOAD_TOO_LARGE, "document trop volumineux");
        }
        String docId = UUID.randomUUID().toString();
        List<Map<String, Object>> points = new ArrayList<>();
        for (int i = 0; i < parts.size(); i++) {
            points.add(Map.of(
                "id", UUID.randomUUID().toString(),
                "vector", Embeddings.embed(parts.get(i)),
                "payload", Map.of("doc_id", docId, "title", doc.title(), "chunk", i, "text", parts.get(i),
                                  "groups", doc.allowed_groups(), "owner", user)));
        }
        store.upsert(points);
        audit.event("ingest.ok", user, Map.of("doc_id", docId, "chunks", points.size(), "redactions", clean.count()));
        return Map.of("doc_id", docId, "chunks", points.size(), "redactions", clean.count());
    }

    static List<String> chunk(String text) {
        List<String> parts = new ArrayList<>();
        for (int i = 0; i < text.length(); i += CHUNK - OVERLAP) {
            parts.add(text.substring(i, Math.min(text.length(), i + CHUNK)));
        }
        return parts;
    }
}
