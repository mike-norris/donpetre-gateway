package com.openrangelabs.donpetre.gateway.security;

import com.openrangelabs.donpetre.gateway.security.JwtService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.ratelimit.KeyResolver;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Rate limiting key resolver that extracts user information from JWT tokens
 * Falls back to IP-based rate limiting for unauthenticated users
 */
@Component("userKeyResolver")
public class UserKeyResolver implements KeyResolver {

    private final JwtService jwtService;

    @Autowired
    public UserKeyResolver(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @Override
    public Mono<String> resolve(ServerWebExchange exchange) {
        // Try to extract user from JWT token first
        return extractUserFromJwt(exchange)
                .switchIfEmpty(getClientIpKey(exchange))
                .onErrorResume(throwable -> getClientIpKey(exchange));
    }

    /**
     * Extract username from JWT token in Authorization header
     */
    private Mono<String> extractUserFromJwt(ServerWebExchange exchange) {
        String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);
            try {
                String username = jwtService.extractUsername(token);
                if (username != null && !username.trim().isEmpty()) {
                    return Mono.just("user:" + username);
                }
            } catch (Exception e) {
                // Token is invalid, fall back to IP-based rate limiting
                return Mono.empty();
            }
        }

        // Try to get from Spring Security context if available
        return exchange.getPrincipal()
                .cast(Authentication.class)
                .filter(auth -> auth instanceof UsernamePasswordAuthenticationToken)
                .filter(Authentication::isAuthenticated)
                .map(Authentication::getName)
                .filter(name -> name != null && !name.trim().isEmpty())
                .map(username -> "user:" + username);
    }

    /**
     * Fallback to IP-based rate limiting for anonymous users
     */
    private Mono<String> getClientIpKey(ServerWebExchange exchange) {
        // Check for forwarded headers first (proxy/load balancer)
        String xForwardedFor = exchange.getRequest().getHeaders().getFirst("X-Forwarded-For");
        String xRealIp = exchange.getRequest().getHeaders().getFirst("X-Real-IP");
        String cfConnectingIp = exchange.getRequest().getHeaders().getFirst("CF-Connecting-IP"); // Cloudflare

        String clientIp;

        if (xForwardedFor != null && !xForwardedFor.trim().isEmpty()) {
            // X-Forwarded-For can contain multiple IPs, take the first one
            clientIp = xForwardedFor.split(",")[0].trim();
        } else if (xRealIp != null && !xRealIp.trim().isEmpty()) {
            clientIp = xRealIp.trim();
        } else if (cfConnectingIp != null && !cfConnectingIp.trim().isEmpty()) {
            clientIp = cfConnectingIp.trim();
        } else {
            // Fall back to remote address
            clientIp = exchange.getRequest().getRemoteAddress() != null ?
                    exchange.getRequest().getRemoteAddress().getAddress().getHostAddress() : "unknown";
        }

        return Mono.just("ip:" + clientIp);
    }

    /**
     * Alternative resolver for admin users (higher rate limits)
     */
    public Mono<String> resolveForAdminUsers(ServerWebExchange exchange) {
        return extractUserFromJwt(exchange)
                .flatMap(userKey -> {
                    // Extract username and check if admin
                    String username = userKey.replace("user:", "");
                    return checkIfAdmin(exchange, username)
                            .map(isAdmin -> isAdmin ? "admin:" + username : userKey);
                })
                .switchIfEmpty(getClientIpKey(exchange));
    }

    /**
     * Check if user has admin role (you can implement this based on your needs)
     */
    private Mono<Boolean> checkIfAdmin(ServerWebExchange exchange, String username) {
        return exchange.getPrincipal()
                .cast(Authentication.class)
                .map(auth -> auth.getAuthorities().stream()
                        .anyMatch(authority -> authority.getAuthority().equals("ROLE_ADMIN")))
                .defaultIfEmpty(false);
    }

    /**
     * Get rate limiting key for API endpoints (different limits per endpoint type)
     */
    public Mono<String> resolveForApiEndpoint(ServerWebExchange exchange, String endpointType) {
        return extractUserFromJwt(exchange)
                .map(userKey -> userKey + ":" + endpointType)
                .switchIfEmpty(getClientIpKey(exchange)
                        .map(ipKey -> ipKey + ":" + endpointType));
    }

    /**
     * Special resolver for authentication endpoints (stricter limits)
     */
    public Mono<String> resolveForAuthEndpoints(ServerWebExchange exchange) {
        return getClientIpKey(exchange)
                .map(ipKey -> ipKey + ":auth");
    }
}