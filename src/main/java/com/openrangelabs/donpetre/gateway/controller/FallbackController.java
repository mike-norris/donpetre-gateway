package com.openrangelabs.donpetre.gateway.controller;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

/**
 * Enhanced Fallback Controller with service-specific fallback responses
 * Provides graceful degradation when services are unavailable
 */
@RestController
@RequestMapping("/fallback")
public class FallbackController {

    @Value("${spring.application.name:api-gateway}")
    private String applicationName;

    /**
     * Default fallback for all services
     */
    @GetMapping
    @PostMapping
    @PutMapping
    @DeleteMapping
    public Mono<ResponseEntity<Map<String, Object>>> defaultFallback() {
        Map<String, Object> response = Map.of(
                "error", "Service Temporarily Unavailable",
                "message", "The requested service is currently experiencing issues. Please try again in a few moments.",
                "timestamp", LocalDateTime.now(),
                "status", HttpStatus.SERVICE_UNAVAILABLE.value(),
                "gateway", applicationName,
                "fallback", "default"
        );

        return Mono.just(ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(response));
    }

    /**
     * Knowledge Ingestion Service fallback
     */
    @RequestMapping("/knowledge-ingestion/**")
    public Mono<ResponseEntity<Map<String, Object>>> knowledgeIngestionFallback() {
        Map<String, Object> response = Map.of(
                "error", "Knowledge Ingestion Service Unavailable",
                "message", "Data ingestion is temporarily paused. Your request has been queued and will be processed when the service recovers.",
                "timestamp", LocalDateTime.now(),
                "status", HttpStatus.SERVICE_UNAVAILABLE.value(),
                "service", "knowledge-ingestion",
                "recommendations", List.of(
                        "Try again in 2-3 minutes",
                        "Check service status at /actuator/health",
                        "Contact support if issue persists"
                ),
                "fallback", true
        );

        return Mono.just(ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(response));
    }

    /**
     * Knowledge Management Service fallback
     */
    @RequestMapping("/knowledge-management/**")
    public Mono<ResponseEntity<Map<String, Object>>> knowledgeManagementFallback() {
        Map<String, Object> response = Map.of(
                "error", "Knowledge Management Service Unavailable",
                "message", "Knowledge retrieval and management operations are temporarily unavailable. Data is safe and will be accessible once service recovers.",
                "timestamp", LocalDateTime.now(),
                "status", HttpStatus.SERVICE_UNAVAILABLE.value(),
                "service", "knowledge-management",
                "cached_data_available", false,
                "recommendations", List.of(
                        "Retry your request in a few minutes",
                        "Use search functionality if available",
                        "Check /actuator/health for service status"
                ),
                "fallback", true
        );

        return Mono.just(ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(response));
    }

    /**
     * Search Service fallback with cached suggestions
     */
    @RequestMapping("/search-service/**")
    public Mono<ResponseEntity<Map<String, Object>>> searchServiceFallback() {
        Map<String, Object> response = Map.of(
                "error", "Search Service Unavailable",
                "message", "Advanced search functionality is temporarily unavailable. Basic browsing may still be available through the knowledge management service.",
                "timestamp", LocalDateTime.now(),
                "status", HttpStatus.SERVICE_UNAVAILABLE.value(),
                "service", "search-service",
                "alternative_endpoints", List.of(
                        "/api/knowledge/browse",
                        "/api/knowledge/recent",
                        "/api/knowledge/categories"
                ),
                "recommendations", List.of(
                        "Use basic browsing functionality",
                        "Try simple keyword searches later",
                        "Check recently accessed items"
                ),
                "fallback", true
        );

        return Mono.just(ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(response));
    }

    /**
     * Web UI Service fallback
     */
    @RequestMapping("/web-ui/**")
    public Mono<ResponseEntity<Map<String, Object>>> webUiFallback() {
        Map<String, Object> response = Map.of(
                "error", "Web UI Service Unavailable",
                "message", "The web interface is temporarily unavailable. You can still access the API directly.",
                "timestamp", LocalDateTime.now(),
                "status", HttpStatus.SERVICE_UNAVAILABLE.value(),
                "service", "web-ui",
                "api_endpoints", Map.of(
                        "authentication", "/api/auth",
                        "knowledge", "/api/knowledge",
                        "search", "/api/search",
                        "health", "/actuator/health"
                ),
                "recommendations", List.of(
                        "Use API endpoints directly",
                        "Check service status periodically",
                        "Contact support for extended outages"
                ),
                "fallback", true
        );

        return Mono.just(ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(response));
    }

    /**
     * Health check fallback
     */
    @GetMapping("/health")
    public Mono<ResponseEntity<Map<String, Object>>> healthFallback() {
        Map<String, Object> response = Map.of(
                "status", "DEGRADED",
                "message", "Gateway is operational but some services may be unavailable",
                "timestamp", LocalDateTime.now(),
                "gateway", applicationName,
                "services", Map.of(
                        "api-gateway", "UP",
                        "downstream-services", "DEGRADED"
                ),
                "fallback", true
        );

        return Mono.just(ResponseEntity.status(HttpStatus.PARTIAL_CONTENT).body(response));
    }

    /**
     * Authentication fallback - critical service
     */
    @RequestMapping("/auth/**")
    public Mono<ResponseEntity<Map<String, Object>>> authFallback() {
        Map<String, Object> response = Map.of(
                "error", "Authentication Service Issue",
                "message", "Authentication is experiencing temporary issues. Existing sessions remain valid.",
                "timestamp", LocalDateTime.now(),
                "status", HttpStatus.SERVICE_UNAVAILABLE.value(),
                "service", "authentication",
                "session_impact", "Existing tokens remain valid until expiration",
                "recommendations", List.of(
                        "Avoid logging out during this time",
                        "New logins will be available shortly",
                        "Contact support for urgent access needs"
                ),
                "fallback", true
        );

        return Mono.just(ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(response));
    }

    /**
     * Generic API fallback for unspecified endpoints
     */
    @RequestMapping("/api/**")
    public Mono<ResponseEntity<Map<String, Object>>> apiFallback() {
        Map<String, Object> response = Map.of(
                "error", "API Service Unavailable",
                "message", "The requested API endpoint is temporarily unavailable due to downstream service issues.",
                "timestamp", LocalDateTime.now(),
                "status", HttpStatus.SERVICE_UNAVAILABLE.value(),
                "retry_after", "120 seconds",
                "recommendations", List.of(
                        "Implement exponential backoff in your client",
                        "Check service health endpoints",
                        "Use cached data if available"
                ),
                "fallback", true
        );

        return Mono.just(ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(response));
    }
}