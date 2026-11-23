package com.rag.common;

import java.time.Duration;
import org.springframework.boot.http.client.ClientHttpRequestFactoryBuilder;
import org.springframework.boot.http.client.HttpClientSettings;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.web.client.RestClient;

/**
 * HTTP clients for calls between microservices. With an SSL bundle the client presents its own certificate
 * and verifies the server with the private CA (mutual TLS). Without one (unit tests) it uses plain HTTP.
 */
public final class MtlsClients {
    private MtlsClients() {}

    public static RestClient create(String baseUrl, String bundle, SslBundles sslBundles, Duration readTimeout) {
        var settings = HttpClientSettings.defaults()
            .withConnectTimeout(Duration.ofSeconds(5)).withReadTimeout(readTimeout);
        if (bundle != null && !bundle.isEmpty()) {
            settings = settings.withSslBundle(sslBundles.getBundle(bundle));
        }
        var factory = ClientHttpRequestFactoryBuilder.httpComponents().build(settings);
        return RestClient.builder().baseUrl(baseUrl).requestFactory(factory).build();
    }
}
