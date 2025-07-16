package com.openrangelabs.donpetre.gateway.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

/**
 * Custom JWT Authentication Web Filter
 * Validates JWT tokens and sets authentication context
 */
@Component
public class JwtAuthenticationWebFilter implements WebFilter {

    private final JwtService jwtService;
    private final ReactiveUserDetailsService userDetailsService;

    @Autowired
    public JwtAuthenticationWebFilter(JwtService jwtService, ReactiveUserDetailsService userDetailsService) {
        this.jwtService = jwtService;
        this.userDetailsService = userDetailsService;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String path = exchange.getRequest().getPath().value();

        // Skip JWT validation for public endpoints
        if (isPublicPath(path)) {
            return chain.filter(exchange);
        }

        return extractToken(exchange)
                .flatMap(this::authenticateToken)
                .flatMap(authentication -> chain.filter(exchange)
                        .contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication)))
                .onErrorResume(throwable -> chain.filter(exchange));
    }

    /**
     * Extract JWT token from Authorization header
     */
    private Mono<String> extractToken(ServerWebExchange exchange) {
        String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return Mono.just(authHeader.substring(7));
        }

        return Mono.empty();
    }

    /**
     * Authenticate JWT token and create Authentication object
     */
    private Mono<Authentication> authenticateToken(String token) {
        try {
            String username = jwtService.extractUsername(token);

            return userDetailsService.findByUsername(username)
                    .filter(userDetails -> jwtService.isTokenValid(token, userDetails))
                    .map(userDetails -> new UsernamePasswordAuthenticationToken(
                            userDetails,
                            null,
                            userDetails.getAuthorities()
                    ));
        } catch (Exception e) {
            return Mono.empty();
        }
    }

    /**
     * Check if the path is public and doesn't require authentication
     */
    private boolean isPublicPath(String path) {
        return path.equals("/api/auth/register") ||
                path.equals("/api/auth/authenticate") ||
                path.equals("/actuator/health") ||
                path.equals("/health") ||
                path.equals("/fallback") ||
                path.startsWith("/actuator/");
    }
}