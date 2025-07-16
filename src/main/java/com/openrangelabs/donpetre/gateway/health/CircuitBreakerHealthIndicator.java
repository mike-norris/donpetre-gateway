package com.openrangelabs.donpetre.gateway.health;

import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

/**
 * Health indicator for monitoring circuit breaker states
 * Provides visibility into circuit breaker status via actuator endpoints
 */
@Component
public class CircuitBreakerHealthIndicator implements HealthIndicator {

    private final CircuitBreakerRegistry circuitBreakerRegistry;

    @Autowired
    public CircuitBreakerHealthIndicator(CircuitBreakerRegistry circuitBreakerRegistry) {
        this.circuitBreakerRegistry = circuitBreakerRegistry;
    }

    @Override
    public Health health() {
        Map<String, Object> details = new HashMap<>();
        boolean allHealthy = true;

        // Check all registered circuit breakers
        for (CircuitBreaker circuitBreaker : circuitBreakerRegistry.getAllCircuitBreakers()) {
            String name = circuitBreaker.getName();
            CircuitBreaker.State state = circuitBreaker.getState();

            Map<String, Object> circuitBreakerInfo = new HashMap<>();
            circuitBreakerInfo.put("state", state.toString());
            circuitBreakerInfo.put("failureRate", circuitBreaker.getMetrics().getFailureRate());
            circuitBreakerInfo.put("slowCallRate", circuitBreaker.getMetrics().getSlowCallRate());
            circuitBreakerInfo.put("numberOfBufferedCalls", circuitBreaker.getMetrics().getNumberOfBufferedCalls());
            circuitBreakerInfo.put("numberOfFailedCalls", circuitBreaker.getMetrics().getNumberOfFailedCalls());
            circuitBreakerInfo.put("numberOfSlowCalls", circuitBreaker.getMetrics().getNumberOfSlowCalls());
            circuitBreakerInfo.put("numberOfSuccessfulCalls", circuitBreaker.getMetrics().getNumberOfSuccessfulCalls());

            details.put(name, circuitBreakerInfo);

            // Circuit breaker is unhealthy if it's OPEN or FORCED_OPEN
            if (state == CircuitBreaker.State.OPEN || state == CircuitBreaker.State.FORCED_OPEN) {
                allHealthy = false;
            }
        }

        // Overall health assessment
        details.put("circuitBreakersCount", circuitBreakerRegistry.getAllCircuitBreakers().size());
        details.put("allCircuitBreakersHealthy", allHealthy);

        if (allHealthy) {
            return Health.up()
                    .withDetail("circuitBreakers", details)
                    .withDetail("status", "All circuit breakers are closed or half-open")
                    .build();
        } else {
            return Health.down()
                    .withDetail("circuitBreakers", details)
                    .withDetail("status", "One or more circuit breakers are open")
                    .build();
        }
    }
}