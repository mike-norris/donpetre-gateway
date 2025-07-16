package com.openrangelabs.donpetre.gateway.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsWebFilter;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import java.time.Duration;
import java.util.Arrays;
import java.util.List;

/**
 * CORS configuration for the API Gateway
 * Configures Cross-Origin Resource Sharing for web clients
 */
@Configuration
public class CorsConfig {

    @Value("${open-range-labs.donpetre.security.cors.allowed-origins}")
    private String allowedOrigins;

    @Value("${open-range-labs.donpetre.security.cors.allowed-methods}")
    private String allowedMethods;

    @Value("${open-range-labs.donpetre.security.cors.allowed-headers}")
    private String allowedHeaders;

    @Value("${open-range-labs.donpetre.security.cors.allow-credentials}")
    private boolean allowCredentials;

    @Value("${open-range-labs.donpetre.security.cors.max-age}")
    private long maxAge;

    /**
     * Configure CORS for reactive web applications
     */
    @Bean
    public CorsWebFilter corsWebFilter() {
        CorsConfiguration corsConfig = new CorsConfiguration();

        // Parse allowed origins
        List<String> origins = Arrays.asList(allowedOrigins.split(","));
        corsConfig.setAllowedOriginPatterns(origins);

        // Parse allowed methods
        List<String> methods = Arrays.asList(allowedMethods.split(","));
        corsConfig.setAllowedMethods(methods);

        // Parse allowed headers
        if ("*".equals(allowedHeaders.trim())) {
            corsConfig.addAllowedHeader("*");
        } else {
            List<String> headers = Arrays.asList(allowedHeaders.split(","));
            corsConfig.setAllowedHeaders(headers);
        }

        // Configure credentials and max age
        corsConfig.setAllowCredentials(allowCredentials);
        corsConfig.setMaxAge(Duration.ofSeconds(maxAge));

        // Expose common headers
        corsConfig.setExposedHeaders(Arrays.asList(
                "Authorization",
                "Content-Type",
                "X-Requested-With",
                "X-Total-Count",
                "X-Rate-Limit-Remaining",
                "X-Rate-Limit-Reset"
        ));

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", corsConfig);

        return new CorsWebFilter(source);
    }

    /**
     * Development-friendly CORS configuration
     * Only use in development environment
     */
    @Bean("developmentCorsConfig")
    public CorsConfiguration developmentCorsConfiguration() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowCredentials(true);
        configuration.addAllowedOriginPattern("*");
        configuration.addAllowedHeader("*");
        configuration.addAllowedMethod("*");
        configuration.setMaxAge(Duration.ofHours(1));
        return configuration;
    }
}