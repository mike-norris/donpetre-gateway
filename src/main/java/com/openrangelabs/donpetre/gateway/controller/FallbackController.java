package com.openrangelabs.donpetre.gateway.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;
import java.util.Map;

@RestController
public class FallbackController {

    @GetMapping("/fallback")
    public Mono<ResponseEntity<Map<String, Object>>> fallback() {
        Map<String, Object> response = Map.of(
                "message", "Service temporarily unavailable. Please try again later.",
                "timestamp", LocalDateTime.now(),
                "status", HttpStatus.SERVICE_UNAVAILABLE.value()
        );

        return Mono.just(ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(response));
    }

    @GetMapping("/health")
    public Mono<ResponseEntity<Map<String, Object>>> health() {
        Map<String, Object> response = Map.of(
                "status", "UP",
                "timestamp", LocalDateTime.now(),
                "service", "api-gateway"
        );

        return Mono.just(ResponseEntity.ok(response));
    }
}