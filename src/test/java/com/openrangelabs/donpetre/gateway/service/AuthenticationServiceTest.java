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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("AuthenticationService Unit Tests")
class AuthenticationServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private RoleRepository roleRepository;

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    @Mock
    private UserRoleService userRoleService;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private JwtService jwtService;

    @Mock
    private ReactiveAuthenticationManager authenticationManager;

    @Mock
    private ReactiveUserDetailsService userDetailsService;

    private AuthenticationService authenticationService;

    private User testUser;
    private Role testRole;
    private RegisterRequest registerRequest;
    private AuthenticationRequest authRequest;

    @BeforeEach
    void setUp() {
        authenticationService = new AuthenticationService(
                userRepository,
                roleRepository,
                refreshTokenRepository,
                userRoleService,
                passwordEncoder,
                jwtService,
                authenticationManager,
                userDetailsService
        );

        testRole = new Role("USER", "Default user role");
        testRole.setId(UUID.randomUUID());

        testUser = new User("testuser", "test@example.com", "encoded_password");
        testUser.setId(UUID.randomUUID());
        testUser.setRoles(Set.of(testRole));
        testUser.setIsActive(true);

        registerRequest = new RegisterRequest();
        registerRequest.setUsername("newuser");
        registerRequest.setEmail("newuser@example.com");
        registerRequest.setPassword("password123");

        authRequest = new AuthenticationRequest();
        authRequest.setUsername("testuser");
        authRequest.setPassword("password123");
    }

    @Nested
    @DisplayName("User Registration Tests")
    class RegistrationTests {

        @Test
        @DisplayName("Should register new user successfully")
        void shouldRegisterNewUserSuccessfully() {
            // Arrange
            when(userRepository.existsByUsername(registerRequest.getUsername())).thenReturn(Mono.just(false));
            when(userRepository.existsByEmail(registerRequest.getEmail())).thenReturn(Mono.just(false));
            when(passwordEncoder.encode(registerRequest.getPassword())).thenReturn("encoded_password");
            when(userRepository.save(any(User.class))).thenReturn(Mono.just(testUser));
            when(roleRepository.findByName("USER")).thenReturn(Mono.just(testRole));
            when(userRoleService.assignRoleToUser(any(UUID.class), any(UUID.class))).thenReturn(Mono.empty());
            
            // Mock withRoles method
            User userWithRoles = new User("testuser", "test@example.com", "encoded_password");
            userWithRoles.setId(testUser.getId());
            userWithRoles.setRoles(Set.of(testRole));
            when(jwtService.generateToken(any(User.class))).thenReturn("access_token");
            when(jwtService.generateRefreshToken(any(User.class))).thenReturn("refresh_token");
            when(refreshTokenRepository.save(any(RefreshToken.class))).thenReturn(Mono.just(new RefreshToken()));

            // Act & Assert
            StepVerifier.create(authenticationService.register(registerRequest))
                    .assertNext(response -> {
                        assertThat(response).isNotNull();
                        assertThat(response.getAccessToken()).isEqualTo("access_token");
                        assertThat(response.getRefreshToken()).isEqualTo("refresh_token");
                        assertThat(response.getUsername()).isEqualTo(testUser.getUsername());
                        assertThat(response.getEmail()).isEqualTo(testUser.getEmail());
                    })
                    .verifyComplete();

            verify(userRepository).save(any(User.class));
            verify(refreshTokenRepository).save(any(RefreshToken.class));
        }

        @Test
        @DisplayName("Should reject registration with existing username")
        void shouldRejectRegistrationWithExistingUsername() {
            // Arrange
            when(userRepository.existsByUsername(registerRequest.getUsername())).thenReturn(Mono.just(true));

            // Act & Assert
            StepVerifier.create(authenticationService.register(registerRequest))
                    .expectErrorMatches(throwable -> throwable instanceof RuntimeException &&
                            "Username already exists".equals(throwable.getMessage()))
                    .verify();

            verify(userRepository, never()).save(any(User.class));
        }

        @Test
        @DisplayName("Should reject registration with existing email")
        void shouldRejectRegistrationWithExistingEmail() {
            // Arrange
            when(userRepository.existsByUsername(registerRequest.getUsername())).thenReturn(Mono.just(false));
            when(userRepository.existsByEmail(registerRequest.getEmail())).thenReturn(Mono.just(true));

            // Act & Assert
            StepVerifier.create(authenticationService.register(registerRequest))
                    .expectErrorMatches(throwable -> throwable instanceof RuntimeException &&
                            "Email already exists".equals(throwable.getMessage()))
                    .verify();

            verify(userRepository, never()).save(any(User.class));
        }

        @Test
        @DisplayName("Should create USER role if it doesn't exist during registration")
        void shouldCreateUserRoleIfNotExists() {
            // Arrange
            when(userRepository.existsByUsername(registerRequest.getUsername())).thenReturn(Mono.just(false));
            when(userRepository.existsByEmail(registerRequest.getEmail())).thenReturn(Mono.just(false));
            when(passwordEncoder.encode(registerRequest.getPassword())).thenReturn("encoded_password");
            when(userRepository.save(any(User.class))).thenReturn(Mono.just(testUser));
            when(roleRepository.findByName("USER")).thenReturn(Mono.empty());
            when(roleRepository.save(any(Role.class))).thenReturn(Mono.just(testRole));
            when(userRoleService.assignRoleToUser(any(UUID.class), any(UUID.class))).thenReturn(Mono.empty());
            when(jwtService.generateToken(any(User.class))).thenReturn("access_token");
            when(jwtService.generateRefreshToken(any(User.class))).thenReturn("refresh_token");
            when(refreshTokenRepository.save(any(RefreshToken.class))).thenReturn(Mono.just(new RefreshToken()));

            // Act
            StepVerifier.create(authenticationService.register(registerRequest))
                    .expectNextCount(1)
                    .verifyComplete();

            // Assert
            verify(roleRepository).save(any(Role.class));
        }
    }

    @Nested
    @DisplayName("User Authentication Tests")
    class AuthenticationTests {

        @Test
        @DisplayName("Should authenticate user successfully")
        void shouldAuthenticateUserSuccessfully() {
            // Arrange
            Authentication mockAuth = mock(Authentication.class);
            when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                    .thenReturn(Mono.just(mockAuth));
            when(userRoleService.loadUserWithRolesByUsername(authRequest.getUsername()))
                    .thenReturn(Mono.just(testUser));
            when(userRepository.save(any(User.class))).thenReturn(Mono.just(testUser));
            when(jwtService.generateToken(any(User.class))).thenReturn("access_token");
            when(jwtService.generateRefreshToken(any(User.class))).thenReturn("refresh_token");
            when(refreshTokenRepository.save(any(RefreshToken.class))).thenReturn(Mono.just(new RefreshToken()));

            // Act & Assert
            StepVerifier.create(authenticationService.authenticate(authRequest))
                    .assertNext(response -> {
                        assertThat(response).isNotNull();
                        assertThat(response.getAccessToken()).isEqualTo("access_token");
                        assertThat(response.getUsername()).isEqualTo(testUser.getUsername());
                    })
                    .verifyComplete();

            verify(userRepository).save(argThat(user -> user.getLastLogin() != null));
        }

        @Test
        @DisplayName("Should reject authentication for non-existent user")
        void shouldRejectAuthenticationForNonExistentUser() {
            // Arrange
            Authentication mockAuth = mock(Authentication.class);
            when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                    .thenReturn(Mono.just(mockAuth));
            when(userRoleService.loadUserWithRolesByUsername(authRequest.getUsername()))
                    .thenReturn(Mono.empty());

            // Act & Assert
            StepVerifier.create(authenticationService.authenticate(authRequest))
                    .expectErrorMatches(throwable -> throwable instanceof RuntimeException &&
                            "User not found".equals(throwable.getMessage()))
                    .verify();
        }
    }

    @Nested
    @DisplayName("Token Management Tests")
    class TokenManagementTests {

        @Test
        @DisplayName("Should refresh token successfully")
        void shouldRefreshTokenSuccessfully() {
            // Arrange
            String authHeader = "Bearer refresh_token_123";
            RefreshToken refreshToken = new RefreshToken("refresh_token_123", 
                    LocalDateTime.now().plusDays(7), testUser.getId());
            refreshToken.setId(UUID.randomUUID());

            when(refreshTokenRepository.findByToken("refresh_token_123"))
                    .thenReturn(Mono.just(refreshToken));
            when(refreshTokenRepository.deleteById(refreshToken.getId())).thenReturn(Mono.empty());
            when(userRoleService.loadUserWithRoles(testUser.getId())).thenReturn(Mono.just(testUser));
            when(jwtService.generateToken(any(User.class))).thenReturn("new_access_token");
            when(jwtService.generateRefreshToken(any(User.class))).thenReturn("new_refresh_token");
            when(refreshTokenRepository.save(any(RefreshToken.class))).thenReturn(Mono.just(new RefreshToken()));

            // Act & Assert
            StepVerifier.create(authenticationService.refreshToken(authHeader))
                    .assertNext(response -> {
                        assertThat(response).isNotNull();
                        assertThat(response.getAccessToken()).isEqualTo("new_access_token");
                        assertThat(response.getRefreshToken()).isEqualTo("new_refresh_token");
                    })
                    .verifyComplete();
        }

        @Test
        @DisplayName("Should reject refresh with invalid token")
        void shouldRejectRefreshWithInvalidToken() {
            // Arrange
            String authHeader = "Bearer invalid_token";
            when(refreshTokenRepository.findByToken("invalid_token")).thenReturn(Mono.empty());

            // Act & Assert
            StepVerifier.create(authenticationService.refreshToken(authHeader))
                    .expectErrorMatches(throwable -> throwable instanceof RuntimeException &&
                            "Invalid refresh token".equals(throwable.getMessage()))
                    .verify();
        }

        @Test
        @DisplayName("Should reject refresh with expired token")
        void shouldRejectRefreshWithExpiredToken() {
            // Arrange
            String authHeader = "Bearer expired_token";
            RefreshToken expiredToken = new RefreshToken("expired_token", 
                    LocalDateTime.now().minusDays(1), testUser.getId());

            when(refreshTokenRepository.findByToken("expired_token")).thenReturn(Mono.just(expiredToken));

            // Act & Assert
            StepVerifier.create(authenticationService.refreshToken(authHeader))
                    .expectErrorMatches(throwable -> throwable instanceof RuntimeException &&
                            "Refresh token expired".equals(throwable.getMessage()))
                    .verify();
        }

        @Test
        @DisplayName("Should validate token successfully")
        void shouldValidateTokenSuccessfully() {
            // Arrange
            String authHeader = "Bearer valid_token";
            UserDetails mockUserDetails = mock(UserDetails.class);
            
            when(jwtService.extractUsername("valid_token")).thenReturn("testuser");
            when(userDetailsService.findByUsername("testuser")).thenReturn(Mono.just(mockUserDetails));
            when(jwtService.isTokenValid("valid_token", mockUserDetails)).thenReturn(true);

            // Act & Assert
            StepVerifier.create(authenticationService.validateToken(authHeader))
                    .expectNext(true)
                    .verifyComplete();
        }

        @Test
        @DisplayName("Should reject invalid token")
        void shouldRejectInvalidToken() {
            // Arrange
            String authHeader = "Bearer invalid_token";
            
            when(jwtService.extractUsername("invalid_token")).thenThrow(new RuntimeException("Invalid token"));

            // Act & Assert
            StepVerifier.create(authenticationService.validateToken(authHeader))
                    .expectNext(false)
                    .verifyComplete();
        }

        @Test
        @DisplayName("Should logout successfully")
        void shouldLogoutSuccessfully() {
            // Arrange
            String authHeader = "Bearer refresh_token_123";
            RefreshToken refreshToken = new RefreshToken();
            refreshToken.setId(UUID.randomUUID());

            when(refreshTokenRepository.findByToken("refresh_token_123")).thenReturn(Mono.just(refreshToken));
            when(refreshTokenRepository.deleteById(refreshToken.getId())).thenReturn(Mono.empty());

            // Act & Assert
            StepVerifier.create(authenticationService.logout(authHeader))
                    .verifyComplete();

            verify(refreshTokenRepository).deleteById(refreshToken.getId());
        }
    }

    @Nested
    @DisplayName("User Information Tests")
    class UserInformationTests {

        @Test
        @DisplayName("Should get current user information")
        void shouldGetCurrentUserInformation() {
            // Arrange
            String authHeader = "Bearer valid_token";
            testUser.setLastLogin(LocalDateTime.now());

            when(jwtService.extractUsername("valid_token")).thenReturn("testuser");
            when(userRoleService.loadUserWithRolesByUsername("testuser")).thenReturn(Mono.just(testUser));

            // Act & Assert
            StepVerifier.create(authenticationService.getCurrentUser(authHeader))
                    .assertNext(userInfo -> {
                        assertThat(userInfo).containsKeys("id", "username", "email", "roles", "lastLogin", "isActive");
                        assertThat(userInfo.get("username")).isEqualTo("testuser");
                        assertThat(userInfo.get("email")).isEqualTo("test@example.com");
                        assertThat(userInfo.get("isActive")).isEqualTo(true);
                    })
                    .verifyComplete();
        }

        @Test
        @DisplayName("Should check if user exists")
        void shouldCheckIfUserExists() {
            // Arrange
            when(userRepository.existsByUsername("testuser")).thenReturn(Mono.just(true));

            // Act & Assert
            StepVerifier.create(authenticationService.userExists("testuser"))
                    .expectNext(true)
                    .verifyComplete();
        }

        @Test
        @DisplayName("Should check if email exists")
        void shouldCheckIfEmailExists() {
            // Arrange
            when(userRepository.existsByEmail("test@example.com")).thenReturn(Mono.just(true));

            // Act & Assert
            StepVerifier.create(authenticationService.emailExists("test@example.com"))
                    .expectNext(true)
                    .verifyComplete();
        }
    }

    @Nested
    @DisplayName("User Management Tests")
    class UserManagementTests {

        @Test
        @DisplayName("Should update last login time")
        void shouldUpdateLastLoginTime() {
            // Arrange
            when(userRepository.findByUsername("testuser")).thenReturn(Mono.just(testUser));
            when(userRepository.save(any(User.class))).thenReturn(Mono.just(testUser));

            // Act & Assert
            StepVerifier.create(authenticationService.updateLastLogin("testuser"))
                    .assertNext(user -> assertThat(user.getLastLogin()).isNotNull())
                    .verifyComplete();
        }

        @Test
        @DisplayName("Should deactivate user account")
        void shouldDeactivateUserAccount() {
            // Arrange
            when(userRepository.findByUsername("testuser")).thenReturn(Mono.just(testUser));
            when(userRepository.save(any(User.class))).thenReturn(Mono.just(testUser));

            // Act & Assert
            StepVerifier.create(authenticationService.deactivateUser("testuser"))
                    .verifyComplete();

            verify(userRepository).save(argThat(user -> !user.getIsActive()));
        }

        @Test
        @DisplayName("Should cleanup expired tokens")
        void shouldCleanupExpiredTokens() {
            // Arrange
            when(refreshTokenRepository.deleteExpiredTokens(any(LocalDateTime.class))).thenReturn(Mono.just(5));

            // Act & Assert
            StepVerifier.create(authenticationService.cleanupExpiredTokens())
                    .expectNext(5L)
                    .verifyComplete();
        }
    }

    @Nested
    @DisplayName("Error Handling Tests")
    class ErrorHandlingTests {

        @Test
        @DisplayName("Should handle invalid authorization header format")
        void shouldHandleInvalidAuthHeaderFormat() {
            // Arrange
            String invalidHeader = "InvalidHeader";

            // Act & Assert
            StepVerifier.create(authenticationService.validateToken(invalidHeader))
                    .expectNext(false)
                    .verifyComplete();
        }

        @Test
        @DisplayName("Should handle null authorization header")
        void shouldHandleNullAuthHeader() {
            // Act & Assert
            StepVerifier.create(authenticationService.validateToken(null))
                    .expectNext(false)
                    .verifyComplete();
        }

        @Test
        @DisplayName("Should handle repository errors gracefully")
        void shouldHandleRepositoryErrorsGracefully() {
            // Arrange
            when(userRepository.existsByUsername(anyString()))
                    .thenReturn(Mono.error(new RuntimeException("Database error")));

            // Act & Assert
            StepVerifier.create(authenticationService.register(registerRequest))
                    .expectError(RuntimeException.class)
                    .verify();
        }
    }
}