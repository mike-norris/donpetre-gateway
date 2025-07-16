package com.openrangelabs.donpetre.gateway.security;

import org.springframework.cloud.circuitbreaker.resilience4j.ReactiveResilience4JCircuitBreakerFactory;
import org.springframework.cloud.circuitbreaker.resilience4j.Resilience4JConfigBuilder;
import org.springframework.cloud.client.circuitbreaker.ReactiveCircuitBreakerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SecurityConfig {

    @Bean
    public ReactiveCircuitBreakerFactory reactiveCircuitBreakerFactory() {
        io.github.resilience4j.circuitbreaker.CircuitBreakerConfig circuitBreakerConfig =
                io.github.resilience4j.circuitbreaker.CircuitBreakerConfig.ofDefaults();

        ReactiveCircuitBreakerFactory factory = new ReactiveResilience4JCircuitBreakerFactory();
        factory.configureDefault(id -> new Resilience4JConfigBuilder(id)
                .circuitBreakerConfig(circuitBreakerConfig)
                .build());

        return factory;
    }
}