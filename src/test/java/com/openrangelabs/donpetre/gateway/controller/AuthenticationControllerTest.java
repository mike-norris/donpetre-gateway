package com.openrangelabs.donpetre.gateway.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.openrangelabs.donpetre.gateway.dto.AuthenticationRequest;
import com.openrangelabs.donpetre.gateway.dto.AuthenticationResponse;
import com.openrangelabs.donpetre.gateway.dto.RegisterRequest;
import com.openrangelabs.donpetre.gateway.service.AuthenticationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Pure unit tests for AuthenticationController without Spring context
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("AuthenticationController Unit Tests")
class AuthenticationControllerTest {

    @Mock
    private AuthenticationService authenticationService;

    @InjectMocks
    private AuthenticationController authenticationController;

    private ObjectMapper objectMapper = new ObjectMapper();
    private RegisterRequest registerRequest;
    private AuthenticationRequest authRequest;
    private AuthenticationResponse authResponse;

    @BeforeEach
    void setUp() {
        registerRequest = new RegisterRequest();
        registerRequest.setUsername("testuser");
        registerRequest.setEmail("test@example.com");
        registerRequest.setPassword("password123");

        authRequest = new AuthenticationRequest();
        authRequest.setUsername("testuser");
        authRequest.setPassword("password123");

        authResponse = new AuthenticationResponse(
                "access_token",
                "refresh_token",
                86400000L,
                "testuser",
                "test@example.com",
                Set.of("USER")
        );
    }

    @Nested
    @DisplayName("Registration Tests")
    class RegistrationTests {

        @Test
        @DisplayName("Should handle successful registration")
        void shouldHandleSuccessfulRegistration() {
            // Arrange
            when(authenticationService.register(any(RegisterRequest.class)))
                    .thenReturn(Mono.just(authResponse));

            // Act & Assert
            StepVerifier.create(authenticationController.register(registerRequest))
                    .assertNext(response -> {
                        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
                        assertThat(response.getBody()).isNotNull();
                        assertThat(response.getBody().getAccessToken()).isEqualTo("access_token");
                        assertThat(response.getBody().getUsername()).isEqualTo("testuser");
                    })
                    .verifyComplete();

            verify(authenticationService).register(registerRequest);
        }

        @Test
        @DisplayName("Should handle registration failure")
        void shouldHandleRegistrationFailure() {
            // Arrange
            when(authenticationService.register(any(RegisterRequest.class)))
                    .thenReturn(Mono.error(new RuntimeException("Username already exists")));

            // Act & Assert
            StepVerifier.create(authenticationController.register(registerRequest))
                    .assertNext(response -> {
                        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
                        assertThat(response.getBody()).isNull();
                    })
                    .verifyComplete();

            verify(authenticationService).register(registerRequest);
        }
    }

    @Nested
    @DisplayName("Authentication Tests")
    class AuthenticationTests {

        @Test
        @DisplayName("Should handle successful authentication")
        void shouldHandleSuccessfulAuthentication() {
            // Arrange
            when(authenticationService.authenticate(any(AuthenticationRequest.class)))
                    .thenReturn(Mono.just(authResponse));

            // Act & Assert
            StepVerifier.create(authenticationController.authenticate(authRequest))
                    .assertNext(response -> {
                        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
                        assertThat(response.getBody()).isNotNull();
                        assertThat(response.getBody().getAccessToken()).isEqualTo("access_token");
                    })
                    .verifyComplete();

            verify(authenticationService).authenticate(authRequest);
        }

        @Test
        @DisplayName("Should handle authentication failure")
        void shouldHandleAuthenticationFailure() {
            // Arrange
            when(authenticationService.authenticate(any(AuthenticationRequest.class)))
                    .thenReturn(Mono.error(new RuntimeException("Invalid credentials")));

            // Act & Assert
            StepVerifier.create(authenticationController.authenticate(authRequest))
                    .assertNext(response -> {
                        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
                        assertThat(response.getBody()).isNull();
                    })
                    .verifyComplete();

            verify(authenticationService).authenticate(authRequest);
        }
    }

    @Nested
    @DisplayName("Token Management Tests")
    class TokenManagementTests {

        @Test
        @DisplayName("Should handle successful token refresh")
        void shouldHandleSuccessfulTokenRefresh() {
            // Arrange
            String authHeader = "Bearer refresh_token";
            when(authenticationService.refreshToken(authHeader))
                    .thenReturn(Mono.just(authResponse));

            // Act & Assert
            StepVerifier.create(authenticationController.refreshToken(authHeader))
                    .assertNext(response -> {
                        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
                        assertThat(response.getBody()).isNotNull();
                        assertThat(response.getBody().getAccessToken()).isEqualTo("access_token");
                    })
                    .verifyComplete();

            verify(authenticationService).refreshToken(authHeader);
        }

        @Test
        @DisplayName("Should handle token validation")
        void shouldHandleTokenValidation() {
            // Arrange
            String authHeader = "Bearer valid_token";
            when(authenticationService.validateToken(authHeader))
                    .thenReturn(Mono.just(true));

            // Act & Assert
            StepVerifier.create(authenticationController.validateToken(authHeader))
                    .assertNext(response -> {
                        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
                        assertThat(response.getBody()).isNotNull();
                        assertThat(response.getBody().get("valid")).isEqualTo(true);
                    })
                    .verifyComplete();

            verify(authenticationService).validateToken(authHeader);
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
            Map<String, Object> userInfo = Map.of(
                    "id", "123e4567-e89b-12d3-a456-426614174000",
                    "username", "testuser",
                    "email", "test@example.com",
                    "roles", Set.of("USER"),
                    "isActive", true
            );

            when(authenticationService.getCurrentUser(authHeader))
                    .thenReturn(Mono.just(userInfo));

            // Act & Assert
            StepVerifier.create(authenticationController.getCurrentUser(authHeader))
                    .assertNext(response -> {
                        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
                        assertThat(response.getBody()).isNotNull();
                        assertThat(response.getBody()).containsEntry("username", "testuser");
                    })
                    .verifyComplete();

            verify(authenticationService).getCurrentUser(authHeader);
        }
    }

    @Nested
    @DisplayName("Logout Tests")
    class LogoutTests {

        @Test
        @DisplayName("Should handle successful logout")
        void shouldHandleSuccessfulLogout() {
            // Arrange
            String authHeader = "Bearer refresh_token";
            when(authenticationService.logout(authHeader))
                    .thenReturn(Mono.empty());

            // Act & Assert
            StepVerifier.create(authenticationController.logout(authHeader))
                    .assertNext(response -> {
                        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
                        assertThat(response.getBody()).isNotNull();
                        assertThat(response.getBody()).containsEntry("message", "Successfully logged out");
                    })
                    .verifyComplete();

            verify(authenticationService).logout(authHeader);
        }

        @Test
        @DisplayName("Should handle logout failure")
        void shouldHandleLogoutFailure() {
            // Arrange
            String authHeader = "Bearer invalid_token";
            when(authenticationService.logout(authHeader))
                    .thenReturn(Mono.error(new RuntimeException("Logout failed")));

            // Act & Assert
            StepVerifier.create(authenticationController.logout(authHeader))
                    .assertNext(response -> {
                        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
                        assertThat(response.getBody()).isNotNull();
                        assertThat(response.getBody()).containsEntry("message", "Logout failed");
                    })
                    .verifyComplete();

            verify(authenticationService).logout(authHeader);
        }
    }
}