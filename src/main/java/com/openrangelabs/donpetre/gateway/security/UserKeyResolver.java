package com.openrangelabs.donpetre.gateway.security;

import org.springframework.cloud.gateway.filter.ratelimit.KeyResolver;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

// Rate limiting configuration
@Component
public class UserKeyResolver implements KeyResolver {

    @Override
    public Mono<String> resolve(ServerWebExchange exchange) {
        return exchange.getPrincipal()
                .cast(UsernamePasswordAuthenticationToken.class)
                .map(auth -> auth.getCredentials())
                .cast(Jwt.class)
                .map(jwt -> jwt.getClaimAsString("sub"))
                .switchIfEmpty(Mono.just("anonymous"))
                .map(userId -> "user:" + userId);
    }
}
