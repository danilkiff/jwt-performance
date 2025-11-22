package com.github.danilkiff.jwt.perf;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDateTime;

@SpringBootApplication
public class BackendApplication {
    public static void main(String[] args) {
        SpringApplication.run(BackendApplication.class, args);
    }
}

@RestController()
class PingController {

    record PingResponse(LocalDateTime timestamp, String message) { }

    @GetMapping("/api/ping")
    PingResponse ping() {
        return new PingResponse(LocalDateTime.now(), "pong");
    }
}
