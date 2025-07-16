package com.openrangelabs.donpetre.gateway.controller;

import com.openrangelabs.donpetre.gateway.dto.AuthenticationRequest;
import com.openrangelabs.donpetre.gateway.dto.AuthenticationResponse;
import com.openrangelabs.donpetre.gateway.dto.RegisterRequest;
import com.openrangelabs.donpetre.gateway.service.AuthenticationService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;
import java.util.Map;

/**
 * REST controller for authentication operations
 * Handles user registration, login, token refresh, logout, and token validation
 */
@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = "${open-range-labs.donpetre.security.cors.allowed-origins}")
public class AuthenticationController {

    private final AuthenticationService authenticationService;

    @Autowired
    public AuthenticationController(AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    /**
     * Register a new user account
     */
    @PostMapping("/register")
    public Mono<ResponseEntity<AuthenticationResponse>> register(
            @Valid @RequestBody RegisterRequest request) {
        return authenticationService.register(request)
                .map(ResponseEntity::ok)
                .onErrorResume(RuntimeException.class, e -> {
                    Map<String, Object> errorResponse = Map.of(
                            "message", e.getMessage(),
                            "timestamp", LocalDateTime.now(),
                            "status", HttpStatus.BAD_REQUEST.value()
                    );
                    return Mono.just(ResponseEntity.badRequest().body(null));
                });
    }

    /**
     * Authenticate existing user and return JWT tokens
     */
    @PostMapping("/authenticate")
    public Mono<ResponseEntity<AuthenticationResponse>> authenticate(
            @Valid @RequestBody AuthenticationRequest request) {
        return authenticationService.authenticate(request)
                .map(ResponseEntity::ok)
                .onErrorResume(RuntimeException.class, e -> {
                    Map<String, Object> errorResponse = Map.of(
                            "message", "Invalid username or password",
                            "timestamp", LocalDateTime.now(),
                            "status", HttpStatus.UNAUTHORIZED.value()
                    );
                    return Mono.just(ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(null));
                });
    }

    /**
     * Refresh JWT access token using refresh token
     */
    @PostMapping("/refresh-token")
    public Mono<ResponseEntity<AuthenticationResponse>> refreshToken(
            @RequestHeader("Authorization") String authHeader) {
        return authenticationService.refreshToken(authHeader)
                .map(ResponseEntity::ok)
                .onErrorResume(RuntimeException.class, e -> {
                    Map<String, Object> errorResponse = Map.of(
                            "message", "Invalid or expired refresh token",
                            "timestamp", LocalDateTime.now(),
                            "status", HttpStatus.UNAUTHORIZED.value()
                    );
                    return Mono.just(ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(null));
                });
    }

    /**
     * Logout user by invalidating refresh token
     */
    @PostMapping("/logout")
    public Mono<ResponseEntity<Map<String, Object>>> logout(
            @RequestHeader("Authorization") String authHeader) {
        return authenticationService.logout(authHeader)
                .then(Mono.fromCallable(() -> {
                    Map<String, Object> response = Map.of(
                            "message", "Successfully logged out",
                            "timestamp", LocalDateTime.now()
                    );
                    return ResponseEntity.ok(response);
                }))
                .onErrorResume(RuntimeException.class, e -> {
                    Map<String, Object> errorResponse = Map.of(
                            "message", "Logout failed",
                            "timestamp", LocalDateTime.now(),
                            "status", HttpStatus.BAD_REQUEST.value()
                    );
                    return Mono.just(ResponseEntity.badRequest().body(errorResponse));
                });
    }

    /**
     * Validate JWT access token
     */
    @GetMapping("/validate")
    public Mono<ResponseEntity<Map<String, Object>>> validateToken(
            @RequestHeader("Authorization") String authHeader) {
        return authenticationService.validateToken(authHeader)
                .map(isValid -> {
                    Map<String, Object> response = Map.of(
                            "valid", isValid,
                            "timestamp", LocalDateTime.now()
                    );
                    return ResponseEntity.ok(response);
                })
                .onErrorReturn(ResponseEntity.badRequest().body(Map.of(
                        "valid", false,
                        "message", "Token validation failed",
                        "timestamp", LocalDateTime.now()
                )));
    }

    /**
     * Get current user information from JWT token
     */
    @GetMapping("/me")
    public Mono<ResponseEntity<Map<String, Object>>> getCurrentUser(
            @RequestHeader("Authorization") String authHeader) {
        return authenticationService.getCurrentUser(authHeader)
                .map(userInfo -> ResponseEntity.ok(userInfo))
                .onErrorResume(RuntimeException.class, e -> {
                    Map<String, Object> errorResponse = Map.of(
                            "message", "Unable to retrieve user information",
                            "timestamp", LocalDateTime.now(),
                            "status", HttpStatus.UNAUTHORIZED.value()
                    );
                    return Mono.just(ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse));
                });
    }
}