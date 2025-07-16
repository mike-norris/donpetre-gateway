package com.openrangelabs.donpetre.gateway.security;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Simple JWT claims to authorities converter
 * Extracts user roles and authorities from JWT token claims
 */
@Component("customJwtConverter")
public class JwtAuthenticationConverter {

    /**
     * Convert JWT claims to Spring Security authorities
     */
    public UsernamePasswordAuthenticationToken convert(String username, Map<String, Object> claims) {
        Collection<GrantedAuthority> authorities = extractAuthorities(claims);

        return new UsernamePasswordAuthenticationToken(
                username,
                null,
                authorities
        );
    }

    /**
     * Extract authorities from JWT claims
     */
    private Collection<GrantedAuthority> extractAuthorities(Map<String, Object> claims) {
        // Try to extract authorities from multiple possible claim names
        Collection<String> authorities = null;

        // First try 'authorities' claim
        Object authoritiesClaim = claims.get("authorities");
        if (authoritiesClaim instanceof List) {
            authorities = (List<String>) authoritiesClaim;
        }

        if (authorities == null || authorities.isEmpty()) {
            // Try 'roles' claim
            Object rolesClaim = claims.get("roles");
            if (rolesClaim instanceof List) {
                List<String> roles = (List<String>) rolesClaim;
                authorities = roles.stream()
                        .map(role -> role.startsWith("ROLE_") ? role : "ROLE_" + role.toUpperCase())
                        .collect(Collectors.toList());
            }
        }

        if (authorities == null || authorities.isEmpty()) {
            // Try 'scope' claim (common in OAuth2)
            Object scopeClaim = claims.get("scope");
            if (scopeClaim instanceof String) {
                String scope = (String) scopeClaim;
                if (!scope.trim().isEmpty()) {
                    authorities = List.of(scope.split("\\s+"));
                }
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