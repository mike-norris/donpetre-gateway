package com.openrangelabs.donpetre.gateway.config;

import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import io.github.resilience4j.circuitbreaker.CircuitBreakerConfig;
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry;
import io.github.resilience4j.timelimiter.TimeLimiterConfig;
import org.springframework.cloud.circuitbreaker.resilience4j.ReactiveResilience4JCircuitBreakerFactory;
import org.springframework.cloud.circuitbreaker.resilience4j.Resilience4JConfigBuilder;
import org.springframework.cloud.client.circuitbreaker.Customizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Duration;

/**
 * Circuit Breaker Configuration for Spring Cloud 2024.0.0
 * Uses only Customizer beans - Spring creates the factory automatically
 */
@Configuration
public class CircuitBreakerConfiguration {

    /**
     * Circuit Breaker Registry bean for monitoring and management
     */
    @Bean
    public CircuitBreakerRegistry circuitBreakerRegistry() {
        return CircuitBreakerRegistry.ofDefaults();
    }

    /**
     * Default circuit breaker configuration for all services
     */
    @Bean
    public Customizer<ReactiveResilience4JCircuitBreakerFactory> defaultCircuitBreakerCustomizer() {
        return factory -> factory.configureDefault(id -> new Resilience4JConfigBuilder(id)
                .circuitBreakerConfig(CircuitBreakerConfig.custom()
                        .failureRateThreshold(50.0f)
                        .slowCallRateThreshold(50.0f)
                        .slowCallDurationThreshold(Duration.ofSeconds(10))
                        .permittedNumberOfCallsInHalfOpenState(10)
                        .slidingWindowSize(100)
                        .minimumNumberOfCalls(20)
                        .waitDurationInOpenState(Duration.ofSeconds(60))
                        .enableAutomaticTransitionFromOpenToHalfOpen()
                        .build())
                .timeLimiterConfig(TimeLimiterConfig.custom()
                        .timeoutDuration(Duration.ofSeconds(30))
                        .cancelRunningFuture(true)
                        .build())
                .build());
    }

    /**
     * Knowledge Ingestion Service circuit breaker
     */
    @Bean
    public Customizer<ReactiveResilience4JCircuitBreakerFactory> knowledgeIngestionCircuitBreakerCustomizer() {
        return factory -> factory.configure(builder -> builder
                .circuitBreakerConfig(CircuitBreakerConfig.custom()
                        .failureRateThreshold(60.0f)
                        .slowCallRateThreshold(60.0f)
                        .slowCallDurationThreshold(Duration.ofSeconds(15))
                        .permittedNumberOfCallsInHalfOpenState(5)
                        .slidingWindowSize(50)
                        .minimumNumberOfCalls(10)
                        .waitDurationInOpenState(Duration.ofSeconds(30))
                        .enableAutomaticTransitionFromOpenToHalfOpen()
                        .build())
                .timeLimiterConfig(TimeLimiterConfig.custom()
                        .timeoutDuration(Duration.ofSeconds(15))
                        .cancelRunningFuture(true)
                        .build())
                .build(), "knowledge-ingestion");
    }

    /**
     * Knowledge Management Service circuit breaker
     */
    @Bean
    public Customizer<ReactiveResilience4JCircuitBreakerFactory> knowledgeManagementCircuitBreakerCustomizer() {
        return factory -> factory.configure(builder -> builder
                .circuitBreakerConfig(CircuitBreakerConfig.custom()
                        .failureRateThreshold(45.0f)
                        .slowCallRateThreshold(45.0f)
                        .slowCallDurationThreshold(Duration.ofSeconds(8))
                        .permittedNumberOfCallsInHalfOpenState(8)
                        .slidingWindowSize(80)
                        .minimumNumberOfCalls(15)
                        .waitDurationInOpenState(Duration.ofSeconds(45))
                        .enableAutomaticTransitionFromOpenToHalfOpen()
                        .build())
                .timeLimiterConfig(TimeLimiterConfig.custom()
                        .timeoutDuration(Duration.ofSeconds(10))
                        .cancelRunningFuture(true)
                        .build())
                .build(), "knowledge-management");
    }

    /**
     * Search Service circuit breaker - higher tolerance for complex queries
     */
    @Bean
    public Customizer<ReactiveResilience4JCircuitBreakerFactory> searchServiceCircuitBreakerCustomizer() {
        return factory -> factory.configure(builder -> builder
                .circuitBreakerConfig(CircuitBreakerConfig.custom()
                        .failureRateThreshold(40.0f)
                        .slowCallRateThreshold(40.0f)
                        .slowCallDurationThreshold(Duration.ofSeconds(20))
                        .permittedNumberOfCallsInHalfOpenState(12)
                        .slidingWindowSize(200)
                        .minimumNumberOfCalls(25)
                        .waitDurationInOpenState(Duration.ofSeconds(90))
                        .enableAutomaticTransitionFromOpenToHalfOpen()
                        .build())
                .timeLimiterConfig(TimeLimiterConfig.custom()
                        .timeoutDuration(Duration.ofSeconds(25))
                        .cancelRunningFuture(true)
                        .build())
                .build(), "search-service");
    }

    /**
     * Web UI Service circuit breaker - fast response expected
     */
    @Bean
    public Customizer<ReactiveResilience4JCircuitBreakerFactory> webUiCircuitBreakerCustomizer() {
        return factory -> factory.configure(builder -> builder
                .circuitBreakerConfig(CircuitBreakerConfig.custom()
                        .failureRateThreshold(30.0f)
                        .slowCallRateThreshold(30.0f)
                        .slowCallDurationThreshold(Duration.ofSeconds(3))
                        .permittedNumberOfCallsInHalfOpenState(15)
                        .slidingWindowSize(150)
                        .minimumNumberOfCalls(20)
                        .waitDurationInOpenState(Duration.ofSeconds(20))
                        .enableAutomaticTransitionFromOpenToHalfOpen()
                        .build())
                .timeLimiterConfig(TimeLimiterConfig.custom()
                        .timeoutDuration(Duration.ofSeconds(5))
                        .cancelRunningFuture(true)
                        .build())
                .build(), "web-ui");
    }

    /**
     * Create individual circuit breaker beans for monitoring
     * These will be registered with the CircuitBreakerRegistry
     */
    @Bean
    public CircuitBreaker knowledgeIngestionCircuitBreaker(CircuitBreakerRegistry registry) {
        return registry.circuitBreaker("knowledge-ingestion");
    }

    @Bean
    public CircuitBreaker knowledgeManagementCircuitBreaker(CircuitBreakerRegistry registry) {
        return registry.circuitBreaker("knowledge-management");
    }

    @Bean
    public CircuitBreaker searchServiceCircuitBreaker(CircuitBreakerRegistry registry) {
        return registry.circuitBreaker("search-service");
    }

    @Bean
    public CircuitBreaker webUiCircuitBreaker(CircuitBreakerRegistry registry) {
        return registry.circuitBreaker("web-ui");
    }
}