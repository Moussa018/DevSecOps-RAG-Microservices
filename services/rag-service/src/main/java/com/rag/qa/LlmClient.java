package com.rag.qa;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.http.client.ClientHttpRequestFactoryBuilder;
import org.springframework.boot.http.client.HttpClientSettings;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;


@Component
class LlmClient {
    private final String backend;
    private final String model;
    private final String apiKey;
    private final int maxTokens;
    private final RestClient groq;

    LlmClient(@Value("${llm.backend}") String backend, @Value("${llm.model}") String model,
              @Value("${llm.api-key:}") String apiKey, @Value("${llm.max-tokens}") int maxTokens,
              @Value("${llm.url}") String url) {
        this.backend = backend;
        this.model = model;
        this.apiKey = apiKey;
        this.maxTokens = maxTokens;
        var settings = HttpClientSettings.defaults().withConnectTimeout(Duration.ofSeconds(5)).withReadTimeout(Duration.ofSeconds(60));
        this.groq = RestClient.builder().baseUrl(url)
            .requestFactory(ClientHttpRequestFactoryBuilder.httpComponents().build(settings)).build();
    }

    @SuppressWarnings("unchecked")
    String generate(String system, String prompt) {
        if (!"groq".equals(backend)) {
            return "[mode test, sans LLM] Extraits les plus proches : " + prompt.substring(0, Math.min(400, prompt.length()));
        }
        Map<String, Object> body = Map.of("model", model, "max_tokens", maxTokens, "temperature", 0.2,
            "messages", List.of(Map.of("role", "system", "content", system), Map.of("role", "user", "content", prompt)));
        Map<String, Object> res = groq.post().uri("/chat/completions").contentType(MediaType.APPLICATION_JSON)
            .header("Authorization", "Bearer " + apiKey).body(body)
            .retrieve().body(new ParameterizedTypeReference<Map<String, Object>>() {});
        var choice = (Map<String, Object>) ((List<Object>) res.get("choices")).get(0);
        Object content = ((Map<String, Object>) choice.get("message")).get("content");
        return content == null ? "" : content.toString();
    }
}
