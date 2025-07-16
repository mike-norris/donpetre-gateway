package com.openrangelabs.donpetre.gateway.security;

import org.springframework.cloud.gateway.filter.ratelimit.KeyResolver;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Rate limiting configuration that resolves user keys for rate limiting
 * Falls back to IP-based rate limiting for unauthenticated users
 */
@Component
public class UserKeyResolver implements KeyResolver {

    @Override
    public Mono<String> resolve(ServerWebExchange exchange) {
        return exchange.getPrincipal()
                .cast(Authentication.class)
                .filter(auth -> auth instanceof UsernamePasswordAuthenticationToken)
                .cast(UsernamePasswordAuthenticationToken.class)
                .filter(auth -> auth.getCredentials() instanceof Jwt)
                .map(auth -> (Jwt) auth.getCredentials())
                .map(jwt -> jwt.getClaimAsString("sub"))
                .map(userId -> "user:" + userId)
                .switchIfEmpty(getClientIpKey(exchange))
                .onErrorResume(throwable -> getClientIpKey(exchange));
    }

    /**
     * Fallback to IP-based rate limiting for anonymous users
     */
    private Mono<String> getClientIpKey(ServerWebExchange exchange) {
        String xForwardedFor = exchange.getRequest().getHeaders().getFirst("X-Forwarded-For");
        String xRealIp = exchange.getRequest().getHeaders().getFirst("X-Real-IP");
        String remoteAddress = exchange.getRequest().getRemoteAddress() != null ?
                exchange.getRequest().getRemoteAddress().getAddress().getHostAddress() : "unknown";

        String clientIp = xForwardedFor != null ? xForwardedFor.split(",")[0].trim() :
                xRealIp != null ? xRealIp :
                        remoteAddress;

        return Mono.just("ip:" + clientIp);
    }
}