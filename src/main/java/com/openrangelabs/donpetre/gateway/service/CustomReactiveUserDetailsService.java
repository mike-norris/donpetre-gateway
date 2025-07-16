package com.openrangelabs.donpetre.gateway.service;

import com.openrangelabs.donpetre.gateway.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

/**
 * Reactive implementation of UserDetailsService for Spring Security
 * Loads user details for authentication and authorization
 */
@Service
public class CustomReactiveUserDetailsService implements ReactiveUserDetailsService {

    private final UserRepository userRepository;

    @Autowired
    public CustomReactiveUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    /**
     * Load user by username for authentication
     * Converts blocking JPA calls to reactive streams
     */
    @Override
    public Mono<UserDetails> findByUsername(String username) {
        return Mono.fromCallable(() -> userRepository.findActiveByUsername(username))
                .subscribeOn(Schedulers.boundedElastic())
                .map(optionalUser -> optionalUser.orElseThrow(() ->
                        new UsernameNotFoundException("User not found: " + username)))
                .cast(UserDetails.class);
    }

    /**
     * Load user by email (additional method for flexibility)
     */
    public Mono<UserDetails> findByEmail(String email) {
        return Mono.fromCallable(() -> userRepository.findActiveByEmail(email))
                .subscribeOn(Schedulers.boundedElastic())
                .map(optionalUser -> optionalUser.orElseThrow(() ->
                        new UsernameNotFoundException("User not found with email: " + email)))
                .cast(UserDetails.class);
    }
}