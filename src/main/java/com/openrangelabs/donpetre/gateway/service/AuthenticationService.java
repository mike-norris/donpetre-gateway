package com.openrangelabs.donpetre.gateway.service;

import com.openrangelabs.donpetre.gateway.dto.AuthenticationRequest;
import com.openrangelabs.donpetre.gateway.dto.AuthenticationResponse;
import com.openrangelabs.donpetre.gateway.dto.RegisterRequest;
import com.openrangelabs.donpetre.gateway.entity.RefreshToken;
import com.openrangelabs.donpetre.gateway.entity.Role;
import com.openrangelabs.donpetre.gateway.entity.User;
import com.openrangelabs.donpetre.gateway.repository.RefreshTokenRepository;
import com.openrangelabs.donpetre.gateway.repository.RoleRepository;
import com.openrangelabs.donpetre.gateway.repository.UserRepository;
import com.openrangelabs.donpetre.gateway.security.JwtService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Authentication service handling user registration, login, and token management
 * Bridges blocking repository calls with reactive controller layer
 */
@Service
public class AuthenticationService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final ReactiveAuthenticationManager authenticationManager;
    private final ReactiveUserDetailsService userDetailsService;

    @Autowired
    public AuthenticationService(
            UserRepository userRepository,
            RoleRepository roleRepository,
            RefreshTokenRepository refreshTokenRepository,
            PasswordEncoder passwordEncoder,
            JwtService jwtService,
            ReactiveAuthenticationManager authenticationManager,
            ReactiveUserDetailsService userDetailsService) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.authenticationManager = authenticationManager;
        this.userDetailsService = userDetailsService;
    }

    /**
     * Register a new user with default USER role
     */
    public Mono<AuthenticationResponse> register(RegisterRequest request) {
        return Mono.fromCallable(() -> {
                    // Check if username already exists
                    if (userRepository.existsByUsername(request.getUsername())) {
                        throw new RuntimeException("Username already exists");
                    }

                    // Check if email already exists
                    if (userRepository.existsByEmail(request.getEmail())) {
                        throw new RuntimeException("Email already exists");
                    }

                    return createUser(request);
                })
                .subscribeOn(Schedulers.boundedElastic())
                .flatMap(this::generateAuthResponse);
    }

    /**
     * Authenticate existing user and return JWT tokens
     */
    public Mono<AuthenticationResponse> authenticate(AuthenticationRequest request) {
        return authenticationManager
                .authenticate(new UsernamePasswordAuthenticationToken(
                        request.getUsername(),
                        request.getPassword()))
                .then(Mono.fromCallable(() -> {
                    Optional<User> userOpt = userRepository.findByUsername(request.getUsername());
                    if (userOpt.isEmpty()) {
                        throw new RuntimeException("User not found");
                    }

                    User user = userOpt.get();
                    user.setLastLogin(LocalDateTime.now());
                    return userRepository.save(user);
                }))
                .subscribeOn(Schedulers.boundedElastic())
                .flatMap(this::generateAuthResponse);
    }

    /**
     * Refresh JWT access token using refresh token
     */
    public Mono<AuthenticationResponse> refreshToken(String authHeader) {
        return extractTokenFromHeader(authHeader)
                .flatMap(token -> Mono.fromCallable(() -> {
                    Optional<RefreshToken> refreshTokenOpt = refreshTokenRepository.findByToken(token);
                    if (refreshTokenOpt.isEmpty() || refreshTokenOpt.get().isExpired()) {
                        throw new RuntimeException("Invalid or expired refresh token");
                    }

                    RefreshToken refreshToken = refreshTokenOpt.get();
                    User user = refreshToken.getUser();

                    // Delete old refresh token
                    refreshTokenRepository.delete(refreshToken);

                    return user;
                }))
                .subscribeOn(Schedulers.boundedElastic())
                .flatMap(this::generateAuthResponse);
    }

    /**
     * Logout user by invalidating refresh token
     */
    public Mono<Void> logout(String authHeader) {
        return extractTokenFromHeader(authHeader)
                .flatMap(token -> Mono.fromCallable(() -> {
                    Optional<RefreshToken> refreshTokenOpt = refreshTokenRepository.findByToken(token);
                    refreshTokenOpt.ifPresent(refreshTokenRepository::delete);
                    return null;
                }))
                .subscribeOn(Schedulers.boundedElastic())
                .then();
    }

    /**
     * Validate JWT access token
     */
    public Mono<Boolean> validateToken(String authHeader) {
        return extractTokenFromHeader(authHeader)
                .flatMap(token -> {
                    try {
                        String username = jwtService.extractUsername(token);
                        return userDetailsService.findByUsername(username)
                                .map(userDetails -> jwtService.isTokenValid(token, userDetails));
                    } catch (Exception e) {
                        return Mono.just(false);
                    }
                })
                .onErrorReturn(false);
    }

    /**
     * Get current user information from JWT token
     */
    public Mono<Map<String, Object>> getCurrentUser(String authHeader) {
        return extractTokenFromHeader(authHeader)
                .flatMap(token -> {
                    try {
                        String username = jwtService.extractUsername(token);
                        return Mono.fromCallable(() -> {
                            Optional<User> userOpt = userRepository.findByUsername(username);
                            if (userOpt.isEmpty()) {
                                throw new RuntimeException("User not found");
                            }

                            User user = userOpt.get();
                            return Map.of(
                                    "id", user.getId().toString(),
                                    "username", user.getUsername(),
                                    "email", user.getEmail(),
                                    "roles", user.getRoles().stream()
                                            .map(Role::getName)
                                            .collect(Collectors.toSet()),
                                    "lastLogin", user.getLastLogin() != null ? user.getLastLogin().toString() : null,
                                    "isActive", user.getIsActive()
                            );
                        }).subscribeOn(Schedulers.boundedElastic());
                    } catch (Exception e) {
                        return Mono.error(new RuntimeException("Invalid token"));
                    }
                });
    }

    /**
     * Create new user with default USER role
     */
    private User createUser(RegisterRequest request) {
        User user = new User(
                request.getUsername(),
                request.getEmail(),
                passwordEncoder.encode(request.getPassword())
        );

        // Get or create USER role
        Optional<Role> roleOpt = roleRepository.findByName("USER");
        Role userRole;
        if (roleOpt.isEmpty()) {
            userRole = new Role("USER", "Default user role");
            userRole = roleRepository.save(userRole);
        } else {
            userRole = roleOpt.get();
        }

        user.addRole(userRole);
        return userRepository.save(user);
    }

    /**
     * Generate JWT access and refresh tokens for authenticated user
     */
    private Mono<AuthenticationResponse> generateAuthResponse(User user) {
        return Mono.fromCallable(() -> {
            String accessToken = jwtService.generateToken(user);
            String refreshToken = jwtService.generateRefreshToken(user);

            RefreshToken refreshTokenEntity = new RefreshToken(
                    refreshToken,
                    LocalDateTime.now().plusDays(7),
                    user
            );

            refreshTokenRepository.save(refreshTokenEntity);

            return new AuthenticationResponse(
                    accessToken,
                    refreshToken,
                    86400000L, // 24 hours in milliseconds
                    user.getUsername(),
                    user.getEmail(),
                    user.getRoles().stream()
                            .map(Role::getName)
                            .collect(Collectors.toSet())
            );
        }).subscribeOn(Schedulers.boundedElastic());
    }

    /**
     * Extract Bearer token from Authorization header
     */
    private Mono<String> extractTokenFromHeader(String authHeader) {
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return Mono.just(authHeader.substring(7));
        }
        return Mono.error(new RuntimeException("Invalid authorization header"));
    }
}