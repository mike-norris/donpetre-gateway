package com.openrangelabs.donpetre.gateway.security;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.Collection;
import java.util.Collections;
import java.util.stream.Collectors;

@Component("simpleJwtConverter")
public class SimpleReactiveJwtAuthenticationConverter implements Converter<Jwt, Mono<AbstractAuthenticationToken>> {

    @Override
    public Mono<AbstractAuthenticationToken> convert(Jwt jwt) {
        return Mono.fromCallable(() -> {
            Collection<GrantedAuthority> authorities = extractAuthorities(jwt);
            String username = jwt.getSubject();

            // Create a UsernamePasswordAuthenticationToken with JWT as credentials
            UsernamePasswordAuthenticationToken authToken =
                    new UsernamePasswordAuthenticationToken(username, jwt, authorities);

            return authToken;
        });
    }

    private Collection<GrantedAuthority> extractAuthorities(Jwt jwt) {
        // Try to extract authorities from multiple possible claim names
        Collection<String> authorities = null;

        // First try 'authorities' claim
        authorities = jwt.getClaimAsStringList("authorities");

        if (authorities == null || authorities.isEmpty()) {
            // Try 'roles' claim
            Collection<String> roles = jwt.getClaimAsStringList("roles");
            if (roles != null && !roles.isEmpty()) {
                authorities = roles.stream()
                        .map(role -> role.startsWith("ROLE_") ? role : "ROLE_" + role.toUpperCase())
                        .collect(Collectors.toList());
            }
        }

        if (authorities == null || authorities.isEmpty()) {
            // Try 'scope' claim (common in OAuth2)
            String scope = jwt.getClaimAsString("scope");
            if (scope != null && !scope.trim().isEmpty()) {
                authorities = java.util.Arrays.asList(scope.split("\\s+"));
            }
        }

        if (authorities == null) {
            authorities = Collections.emptyList();
        }

        return authorities.stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }
}
