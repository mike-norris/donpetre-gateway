package com.openrangelabs.donpetre.gateway.service;

import com.openrangelabs.donpetre.gateway.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

/**
 * Reactive implementation of UserDetailsService for Spring Security
 * Loads user details for authentication and authorization using R2DBC
 */
@Slf4j
@Component
public class CustomReactiveUserDetailsService implements ReactiveUserDetailsService {

    private final UserRepository userRepository;
    private final UserRoleService userRoleService;

    @Autowired
    public CustomReactiveUserDetailsService(UserRepository userRepository, UserRoleService userRoleService) {
        this.userRepository = userRepository;
        this.userRoleService = userRoleService;
    }

    /**
     * Load user by username for authentication - fully reactive
     * Loads user with all roles populated
     */
    @Override
    public Mono<UserDetails> findByUsername(String username) {
        log.debug("CustomReactiveUserDetailsService.findByUsername called for user: {}", username);
        return userRoleService.loadUserWithRolesByUsername(username)
                .doOnNext(user -> {
                    log.debug("User found: {}, roles: {}, isActive: {}, isEnabled: {}", 
                        user.getUsername(), user.getRoles().size(), user.getIsActive(), user.isEnabled());
                    log.debug("User authorities: {}", user.getAuthorities());
                })
                .doOnError(error -> log.error("Error loading user {}: {}", username, error.getMessage()))
                .switchIfEmpty(Mono.defer(() -> {
                    log.warn("User not found in database: {}", username);
                    return Mono.error(new UsernameNotFoundException("User not found: " + username));
                }))
                .cast(UserDetails.class)
                .doOnNext(userDetails -> log.debug("Returning UserDetails for: {}", userDetails.getUsername()));
    }

    /**
     * Load user by email (additional method for flexibility) - fully reactive
     */
    public Mono<UserDetails> findByEmail(String email) {
        log.debug("CustomReactiveUserDetailsService.findByEmail called for email: {}", email);
        return userRepository.findActiveByEmail(email)
                .doOnNext(user -> log.debug("Active user found by email: {}", user.getUsername()))
                .flatMap(user -> userRoleService.loadUserWithRoles(user.getId()))
                .switchIfEmpty(Mono.defer(() -> {
                    log.warn("User not found with email: {}", email);
                    return Mono.error(new UsernameNotFoundException("User not found with email: " + email));
                }))
                .cast(UserDetails.class);
    }

    /**
     * Load active user by username (additional method)
     */
    public Mono<UserDetails> findActiveByUsername(String username) {
        log.debug("CustomReactiveUserDetailsService.findActiveByUsername called for user: {}", username);
        return userRepository.findActiveByUsername(username)
                .doOnNext(user -> log.debug("Active user found: {}", user.getUsername()))
                .flatMap(user -> userRoleService.loadUserWithRoles(user.getId()))
                .switchIfEmpty(Mono.defer(() -> {
                    log.warn("Active user not found: {}", username);
                    return Mono.error(new UsernameNotFoundException("Active user not found: " + username));
                }))
                .cast(UserDetails.class);
    }
}