package com.openrangelabs.donpetre.gateway.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

/**
 * Custom Reactive Authentication Manager that implements ReactiveAuthenticationManager
 * Contains custom authentication logic using our ReactiveUserDetailsService
 */
@Slf4j
@Component
public class CustomReactiveAuthenticationManager implements ReactiveAuthenticationManager {

    private final ReactiveUserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public CustomReactiveAuthenticationManager(
            ReactiveUserDetailsService userDetailsService,
            PasswordEncoder passwordEncoder) {
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
        log.debug("CustomReactiveAuthenticationManager created with userDetailsService: {}", 
            userDetailsService.getClass().getSimpleName());
    }

    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {
        log.debug("CustomReactiveAuthenticationManager.authenticate called for: {}", 
            authentication.getName());
        
        if (!(authentication instanceof UsernamePasswordAuthenticationToken)) {
            log.debug("Authentication type not supported: {}", authentication.getClass());
            return Mono.empty();
        }

        String username = authentication.getName();
        String password = (String) authentication.getCredentials();
        
        log.debug("Authenticating user: {} with password length: {}", 
            username, password != null ? password.length() : 0);

        return userDetailsService.findByUsername(username)
                .doOnNext(userDetails -> log.debug("UserDetails found for {}: enabled={}, authorities={}", 
                    username, userDetails.isEnabled(), userDetails.getAuthorities().size()))
                .cast(UserDetails.class)
                .flatMap(userDetails -> {
                    if (!userDetails.isEnabled()) {
                        log.warn("User account disabled: {}", username);
                        return Mono.error(new BadCredentialsException("User account is disabled"));
                    }
                    
                    if (!userDetails.isAccountNonLocked()) {
                        log.warn("User account locked: {}", username);
                        return Mono.error(new BadCredentialsException("User account is locked"));
                    }
                    
                    if (!userDetails.isAccountNonExpired()) {
                        log.warn("User account expired: {}", username);
                        return Mono.error(new BadCredentialsException("User account has expired"));
                    }
                    
                    if (!userDetails.isCredentialsNonExpired()) {
                        log.warn("User credentials expired: {}", username);
                        return Mono.error(new BadCredentialsException("User credentials have expired"));
                    }
                    
                    // Verify password
                    log.debug("Verifying password for user: {}", username);
                    log.debug("Stored password hash: {}", userDetails.getPassword());
                    
                    boolean passwordMatches = passwordEncoder.matches(password, userDetails.getPassword());
                    log.debug("Password matches for {}: {}", username, passwordMatches);
                    
                    if (!passwordMatches) {
                        log.warn("Invalid password for user: {}", username);
                        return Mono.error(new BadCredentialsException("Invalid credentials"));
                    }
                    
                    // Create successful authentication
                    UsernamePasswordAuthenticationToken successAuth = 
                            new UsernamePasswordAuthenticationToken(
                                    userDetails, 
                                    null, // Clear the credentials
                                    userDetails.getAuthorities()
                            );
                    
                    log.debug("Authentication successful for user: {} with authorities: {}", 
                        username, userDetails.getAuthorities());
                    
                    return Mono.just((Authentication) successAuth);
                })
                .doOnError(error -> log.error("Authentication failed for user {}: {}", 
                    username, error.getMessage()));
    }
}