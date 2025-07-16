package com.openrangelabs.donpetre.gateway.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UserDetailsRepositoryReactiveAuthenticationManager;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.web.cors.reactive.CorsWebFilter;

/**
 * Simplified Security Configuration for API Gateway
 * Uses custom JWT authentication without OAuth2 resource server complexity
 */
@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    private final CorsWebFilter corsWebFilter;
    private final ReactiveUserDetailsService userDetailsService;
    private final JwtAuthenticationWebFilter jwtAuthenticationWebFilter;

    @Autowired
    public SecurityConfig(
            CorsWebFilter corsWebFilter,
            ReactiveUserDetailsService userDetailsService,
            JwtAuthenticationWebFilter jwtAuthenticationWebFilter) {
        this.corsWebFilter = corsWebFilter;
        this.userDetailsService = userDetailsService;
        this.jwtAuthenticationWebFilter = jwtAuthenticationWebFilter;
    }

    /**
     * Main security filter chain configuration
     */
    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        return http
                .csrf(csrf -> csrf.disable())
                .cors(cors -> cors.configurationSource(exchange -> null)) // Use CorsWebFilter
                .authorizeExchange(exchanges -> exchanges
                        // Public endpoints
                        .pathMatchers(HttpMethod.POST, "/api/auth/register", "/api/auth/authenticate").permitAll()
                        .pathMatchers(HttpMethod.GET, "/actuator/health", "/health", "/fallback").permitAll()
                        .pathMatchers(HttpMethod.OPTIONS, "/**").permitAll()

                        // Protected endpoints
                        .pathMatchers("/api/auth/refresh-token", "/api/auth/logout", "/api/auth/validate", "/api/auth/me").authenticated()
                        .pathMatchers("/api/knowledge/**", "/api/ingestion/**", "/api/search/**").authenticated()
                        .pathMatchers("/actuator/**").hasRole("ADMIN")

                        // Admin endpoints
                        .pathMatchers("/admin/**").hasRole("ADMIN")

                        // Default - require authentication
                        .anyExchange().authenticated()
                )
                .httpBasic(httpBasic -> httpBasic.disable())
                .formLogin(formLogin -> formLogin.disable())
                .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
                .addFilterBefore(corsWebFilter, SecurityWebFiltersOrder.CORS)
                .addFilterAfter(jwtAuthenticationWebFilter, SecurityWebFiltersOrder.AUTHENTICATION)
                .build();
    }

    /**
     * Password encoder for user authentication
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }

    /**
     * Reactive authentication manager for username/password authentication
     */
    @Bean
    public ReactiveAuthenticationManager reactiveAuthenticationManager() {
        UserDetailsRepositoryReactiveAuthenticationManager authManager =
                new UserDetailsRepositoryReactiveAuthenticationManager(userDetailsService);
        authManager.setPasswordEncoder(passwordEncoder());
        return authManager;
    }
}