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

import java.time.LocalDateTime;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

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
        return userRepository.existsByUsername(request.getUsername())
                .flatMap(exists -> {
                    if (exists) {
                        return Mono.error(new RuntimeException("Username already exists"));
                    }
                    return userRepository.existsByEmail(request.getEmail());
                })
                .flatMap(exists -> {
                    if (exists) {
                        return Mono.error(new RuntimeException("Email already exists"));
                    }
                    return createUser(request);
                })
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
                .then(userRepository.findByUsername(request.getUsername()))
                .flatMap(user -> {
                    user.setLastLogin(LocalDateTime.now());
                    return userRepository.save(user);
                })
                .flatMap(this::generateAuthResponse);
    }

    /**
     * Refresh JWT access token using refresh token
     */
    public Mono<AuthenticationResponse> refreshToken(String authHeader) {
        return extractTokenFromHeader(authHeader)
                .flatMap(token -> refreshTokenRepository.findByToken(token))
                .filter(refreshToken -> !refreshToken.isExpired())
                .flatMap(refreshToken -> {
                    User user = refreshToken.getUser();
                    // Delete old refresh token and create new one
                    return refreshTokenRepository.delete(refreshToken)
                            .then(generateAuthResponse(user));
                })
                .switchIfEmpty(Mono.error(new RuntimeException("Invalid or expired refresh token")));
    }

    /**
     * Logout user by invalidating refresh token
     */
    public Mono<Void> logout(String authHeader) {
        return extractTokenFromHeader(authHeader)
                .flatMap(token -> refreshTokenRepository.findByToken(token))
                .flatMap(refreshToken -> refreshTokenRepository.delete(refreshToken))
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
     * Create new user with default USER role
     */
    private Mono<User> createUser(RegisterRequest request) {
        User user = new User(
                request.getUsername(),
                request.getEmail(),
                passwordEncoder.encode(request.getPassword())
        );

        return roleRepository.findByName("USER")
                .switchIfEmpty(createDefaultRole())
                .flatMap(role -> {
                    user.addRole(role);
                    return userRepository.save(user);
                });
    }

    /**
     * Create default USER role if it doesn't exist
     */
    private Mono<Role> createDefaultRole() {
        Role userRole = new Role("USER", "Default user role");
        return roleRepository.save(userRole);
    }

    /**
     * Generate JWT access and refresh tokens for authenticated user
     */
    private Mono<AuthenticationResponse> generateAuthResponse(User user) {
        String accessToken = jwtService.generateToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);

        RefreshToken refreshTokenEntity = new RefreshToken(
                refreshToken,
                LocalDateTime.now().plusDays(7),
                user
        );

        return refreshTokenRepository.save(refreshTokenEntity)
                .then(Mono.just(new AuthenticationResponse(
                        accessToken,
                        refreshToken,
                        86400000L, // 24 hours in milliseconds
                        user.getUsername(),
                        user.getEmail(),
                        user.getRoles().stream()
                                .map(Role::getName)
                                .collect(Collectors.toSet())
                )));
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