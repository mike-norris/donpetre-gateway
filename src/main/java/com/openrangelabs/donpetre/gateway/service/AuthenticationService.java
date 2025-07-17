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
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Reactive Authentication service handling user registration, login, and token management
 * Fully reactive implementation using R2DBC repositories
 */
@Service
public class AuthenticationService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRoleService userRoleService;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final ReactiveAuthenticationManager authenticationManager;
    private final ReactiveUserDetailsService userDetailsService;

    @Autowired
    public AuthenticationService(
            UserRepository userRepository,
            RoleRepository roleRepository,
            RefreshTokenRepository refreshTokenRepository,
            UserRoleService userRoleService,
            PasswordEncoder passwordEncoder,
            JwtService jwtService,
            ReactiveAuthenticationManager authenticationManager,
            ReactiveUserDetailsService userDetailsService) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.userRoleService = userRoleService;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.authenticationManager = authenticationManager;
        this.userDetailsService = userDetailsService;
    }

    /**
     * Register a new user with default USER role - fully reactive
     */
    public Mono<AuthenticationResponse> register(RegisterRequest request) {
        // Check if username already exists
        return userRepository.existsByUsername(request.getUsername())
                .flatMap(usernameExists -> {
                    if (usernameExists) {
                        return Mono.error(new RuntimeException("Username already exists"));
                    }
                    // Check if email already exists
                    return userRepository.existsByEmail(request.getEmail());
                })
                .flatMap(emailExists -> {
                    if (emailExists) {
                        return Mono.error(new RuntimeException("Email already exists"));
                    }
                    // Create the user
                    return createUserReactive(request);
                })
                .flatMap(this::generateAuthResponse);
    }

    /**
     * Authenticate existing user and return JWT tokens - fully reactive
     */
    public Mono<AuthenticationResponse> authenticate(AuthenticationRequest request) {
        return authenticationManager
                .authenticate(new UsernamePasswordAuthenticationToken(
                        request.getUsername(),
                        request.getPassword()))
                .then(userRoleService.loadUserWithRolesByUsername(request.getUsername()))
                .switchIfEmpty(Mono.error(new RuntimeException("User not found")))
                .flatMap(user -> {
                    // Update last login time
                    user.setLastLogin(LocalDateTime.now());
                    return userRepository.save(user);
                })
                .flatMap(this::generateAuthResponse);
    }

    /**
     * Refresh JWT access token using refresh token - fully reactive
     */
    public Mono<AuthenticationResponse> refreshToken(String authHeader) {
        return extractTokenFromHeader(authHeader)
                .flatMap(token ->
                        refreshTokenRepository.findByToken(token)
                                .switchIfEmpty(Mono.error(new RuntimeException("Invalid refresh token")))
                                .flatMap(refreshToken -> {
                                    if (refreshToken.isExpired()) {
                                        return Mono.error(new RuntimeException("Refresh token expired"));
                                    }

                                    // Delete old refresh token and load user with roles
                                    return refreshTokenRepository.deleteById(refreshToken.getId())
                                            .then(userRoleService.loadUserWithRoles(refreshToken.getUserId()));
                                })
                )
                .flatMap(this::generateAuthResponse);
    }

    /**
     * Logout user by invalidating refresh token - fully reactive
     */
    public Mono<Void> logout(String authHeader) {
        return extractTokenFromHeader(authHeader)
                .flatMap(token ->
                        refreshTokenRepository.findByToken(token)
                                .flatMap(refreshToken -> refreshTokenRepository.deleteById(refreshToken.getId()))
                                .then()
                );
    }

    /**
     * Validate JWT access token - fully reactive
     */
    public Mono<Boolean> validateToken(String authHeader) {
        return extractTokenFromHeader(authHeader)
                .flatMap(token -> {
                    try {
                        String username = jwtService.extractUsername(token);
                        return userDetailsService.findByUsername(username)
                                .map(userDetails -> jwtService.isTokenValid(token, userDetails))
                                .onErrorReturn(false);
                    } catch (Exception e) {
                        return Mono.just(false);
                    }
                })
                .onErrorReturn(false);
    }

    /**
     * Get current user information from JWT token - fully reactive
     */
    public Mono<Map<String, Object>> getCurrentUser(String authHeader) {
        return extractTokenFromHeader(authHeader)
                .flatMap(token -> {
                    try {
                        String username = jwtService.extractUsername(token);
                        return userRoleService.loadUserWithRolesByUsername(username)
                                .switchIfEmpty(Mono.error(new RuntimeException("User not found")))
                                .map(user -> Map.of(
                                        "id", user.getId().toString(),
                                        "username", user.getUsername(),
                                        "email", user.getEmail(),
                                        "roles", user.getRoles().stream()
                                                .map(Role::getName)
                                                .collect(Collectors.toSet()),
                                        "lastLogin", user.getLastLogin() != null ? user.getLastLogin().toString() : null,
                                        "isActive", user.getIsActive()
                                ));
                    } catch (Exception e) {
                        return Mono.error(new RuntimeException("Invalid token"));
                    }
                });
    }

    /**
     * Create new user with default USER role - reactive implementation
     */
    private Mono<User> createUserReactive(RegisterRequest request) {
        User user = new User(
                request.getUsername(),
                request.getEmail(),
                passwordEncoder.encode(request.getPassword())
        );

        // Save user first, then assign role
        return userRepository.save(user)
                .flatMap(savedUser ->
                        // Get or create USER role
                        roleRepository.findByName("USER")
                                .switchIfEmpty(createDefaultUserRole())
                                .flatMap(userRole ->
                                        // Assign role to user
                                        userRoleService.assignRoleToUser(savedUser.getId(), userRole.getId())
                                                .thenReturn(savedUser.withRoles(Set.of(userRole)))
                                )
                );
    }

    /**
     * Create default USER role if it doesn't exist
     */
    private Mono<Role> createDefaultUserRole() {
        Role defaultRole = new Role("USER", "Default user role");
        return roleRepository.save(defaultRole);
    }

    /**
     * Generate JWT access and refresh tokens for authenticated user - reactive
     */
    private Mono<AuthenticationResponse> generateAuthResponse(User user) {
        String accessToken = jwtService.generateToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);

        RefreshToken refreshTokenEntity = new RefreshToken(
                refreshToken,
                LocalDateTime.now().plusDays(7),
                user.getId()
        );

        return refreshTokenRepository.save(refreshTokenEntity)
                .map(savedToken -> new AuthenticationResponse(
                        accessToken,
                        refreshToken,
                        86400000L, // 24 hours in milliseconds
                        user.getUsername(),
                        user.getEmail(),
                        user.getRoles().stream()
                                .map(Role::getName)
                                .collect(Collectors.toSet())
                ));
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

    /**
     * Check if user exists by username
     */
    public Mono<Boolean> userExists(String username) {
        return userRepository.existsByUsername(username);
    }

    /**
     * Check if email is already registered
     */
    public Mono<Boolean> emailExists(String email) {
        return userRepository.existsByEmail(email);
    }

    /**
     * Get user by username with roles
     */
    public Mono<User> getUserByUsername(String username) {
        return userRoleService.loadUserWithRolesByUsername(username);
    }

    /**
     * Update user's last login time
     */
    public Mono<User> updateLastLogin(String username) {
        return userRepository.findByUsername(username)
                .flatMap(user -> {
                    user.setLastLogin(LocalDateTime.now());
                    return userRepository.save(user);
                });
    }

    /**
     * Deactivate user account
     */
    public Mono<Void> deactivateUser(String username) {
        return userRepository.findByUsername(username)
                .flatMap(user -> {
                    user.setIsActive(false);
                    return userRepository.save(user);
                })
                .then();
    }

    /**
     * Clean up expired refresh tokens
     */
    public Mono<Long> cleanupExpiredTokens() {
        return refreshTokenRepository.deleteExpiredTokens(LocalDateTime.now())
                .map(Integer::longValue);
    }
}