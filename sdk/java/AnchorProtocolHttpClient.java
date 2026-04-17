package com.bennettschwartz.anchor.sdk;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

public final class AnchorProtocolHttpClient {
    private final String baseUrl;
    private final HttpClient httpClient;

    public AnchorProtocolHttpClient(String baseUrl, HttpClient httpClient) {
        if (baseUrl == null || baseUrl.trim().isEmpty()) {
            throw new IllegalArgumentException("baseUrl is required");
        }
        if (httpClient == null) {
            throw new IllegalArgumentException("httpClient is required");
        }
        this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        this.httpClient = httpClient;
    }

    public static AnchorProtocolHttpClient withDefaultHttpClient(String baseUrl) {
        HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(30)).build();
        return new AnchorProtocolHttpClient(baseUrl, client);
    }

    public String postJson(String path, String payloadJson, int expectedStatus) throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(baseUrl + path))
            .timeout(Duration.ofSeconds(30))
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(payloadJson))
            .build();
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != expectedStatus) {
            throw new IOException("Unexpected status (" + response.statusCode() + "): " + response.body());
        }
        return response.body();
    }
}
