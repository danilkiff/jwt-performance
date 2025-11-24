package com.github.danilkiff.jwt.perf;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.test.web.reactive.server.WebTestClient;

@WebFluxTest(PingController.class)
class PingControllerTest {

    @Autowired
    WebTestClient webTestClient;

    @Test
    void ping_ShouldReturnPongResponse() {
        webTestClient.get().uri("/api/ping")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.message").isEqualTo("pong")
                .jsonPath("$.timestamp").exists()
                .jsonPath("$.timestamp").isNotEmpty();
    }
}