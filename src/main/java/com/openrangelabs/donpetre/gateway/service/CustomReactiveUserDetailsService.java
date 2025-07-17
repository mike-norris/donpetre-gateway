package com.openrangelabs.donpetre.gateway.service;

import com.openrangelabs.donpetre.gateway.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

/**
 * Reactive implementation of UserDetailsService for Spring Security
 * Loads user details for authentication and authorization using R2DBC
 */
@Service
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
        return userRoleService.loadUserWithRolesByUsername(username)
                .switchIfEmpty(Mono.error(new UsernameNotFoundException("User not found: " + username)))
                .cast(UserDetails.class);
    }

    /**
     * Load user by email (additional method for flexibility) - fully reactive
     */
    public Mono<UserDetails> findByEmail(String email) {
        return userRepository.findActiveByEmail(email)
                .flatMap(user -> userRoleService.loadUserWithRoles(user.getId()))
                .switchIfEmpty(Mono.error(new UsernameNotFoundException("User not found with email: " + email)))
                .cast(UserDetails.class);
    }

    /**
     * Load active user by username (additional method)
     */
    public Mono<UserDetails> findActiveByUsername(String username) {
        return userRepository.findActiveByUsername(username)
                .flatMap(user -> userRoleService.loadUserWithRoles(user.getId()))
                .switchIfEmpty(Mono.error(new UsernameNotFoundException("Active user not found: " + username)))
                .cast(UserDetails.class);
    }
}