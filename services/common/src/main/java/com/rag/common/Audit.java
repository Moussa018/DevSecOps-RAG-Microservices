package com.rag.common;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import tools.jackson.databind.json.JsonMapper;

/**
 * Security events (traceability). One JSON line per event on the "AUDIT" logger, read with
 * {@code kubectl -n rag logs deploy/<service> | grep AUDIT}. The user always comes from the verified token.
 */
@Component
public class Audit {
    private static final Logger LOG = LoggerFactory.getLogger("AUDIT");
    private static final JsonMapper JSON = JsonMapper.builder().build();
    private final String service;

    public Audit(@Value("${spring.application.name}") String service) {
        this.service = service;
    }

    public void event(String event, String user, Map<String, ?> detail) {
        var rec = new LinkedHashMap<String, Object>();
        rec.put("ts", Instant.now().toString());
        rec.put("service", service);
        rec.put("user", user);
        rec.put("event", event);
        rec.put("detail", detail);
        LOG.info("AUDIT {}", JSON.writeValueAsString(rec));
    }
}
