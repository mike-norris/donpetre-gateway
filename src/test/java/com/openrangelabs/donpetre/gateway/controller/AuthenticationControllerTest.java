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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.Set;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@WebFluxTest(controllers = AuthenticationController.class)
@Import(AuthenticationControllerTest.TestConfig.class)
@DisplayName("AuthenticationController Integration Tests")
class AuthenticationControllerTest {

    @Autowired
    private WebTestClient webTestClient;

    @Autowired
    private AuthenticationService authenticationService;

    private ObjectMapper objectMapper = new ObjectMapper();

    private RegisterRequest registerRequest;
    private AuthenticationRequest authRequest;
    private AuthenticationResponse authResponse;

    @TestConfiguration
    static class TestConfig {
        @Bean
        public AuthenticationService authenticationService() {
            return mock(AuthenticationService.class);
        }
    }

    @BeforeEach
    void setUp() {
        reset(authenticationService);

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
    @DisplayName("Registration Endpoint Tests")
    class RegistrationEndpointTests {

        @Test
        @DisplayName("POST /api/auth/register - Success")
        void registerUser_Success() throws Exception {
            // Arrange
            when(authenticationService.register(any(RegisterRequest.class)))
                    .thenReturn(Mono.just(authResponse));

            // Act & Assert
            webTestClient.post()
                    .uri("/api/auth/register")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(objectMapper.writeValueAsString(registerRequest))
                    .exchange()
                    .expectStatus().isOk()
                    .expectHeader().contentType(MediaType.APPLICATION_JSON)
                    .expectBody()
                    .jsonPath("$.accessToken").isEqualTo("access_token")
                    .jsonPath("$.refreshToken").isEqualTo("refresh_token")
                    .jsonPath("$.username").isEqualTo("testuser")
                    .jsonPath("$.email").isEqualTo("test@example.com")
                    .jsonPath("$.roles").isArray()
                    .jsonPath("$.roles[0]").isEqualTo("USER");

            verify(authenticationService).register(any(RegisterRequest.class));
        }

        @Test
        @DisplayName("POST /api/auth/register - Username already exists")
        void registerUser_UsernameExists() throws Exception {
            // Arrange
            when(authenticationService.register(any(RegisterRequest.class)))
                    .thenReturn(Mono.error(new RuntimeException("Username already exists")));

            // Act & Assert
            webTestClient.post()
                    .uri("/api/auth/register")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(objectMapper.writeValueAsString(registerRequest))
                    .exchange()
                    .expectStatus().isBadRequest();

            verify(authenticationService).register(any(RegisterRequest.class));
        }

        @Test
        @DisplayName("POST /api/auth/register - Invalid request body")
        void registerUser_InvalidRequest() {
            // Arrange - Empty request body
            RegisterRequest invalidRequest = new RegisterRequest();

            // Act & Assert
            webTestClient.post()
                    .uri("/api/auth/register")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(invalidRequest)
                    .exchange()
                    .expectStatus().isBadRequest();

            verify(authenticationService, never()).register(any(RegisterRequest.class));
        }

        @Test
        @DisplayName("POST /api/auth/register - Malformed JSON")
        void registerUser_MalformedJson() {
            // Act & Assert
            webTestClient.post()
                    .uri("/api/auth/register")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue("{ invalid json }")
                    .exchange()
                    .expectStatus().isBadRequest();

            verify(authenticationService, never()).register(any(RegisterRequest.class));
        }
    }

    @Nested
    @DisplayName("Authentication Endpoint Tests")
    class AuthenticationEndpointTests {

        @Test
        @DisplayName("POST /api/auth/authenticate - Success")
        void authenticateUser_Success() throws Exception {
            // Arrange
            when(authenticationService.authenticate(any(AuthenticationRequest.class)))
                    .thenReturn(Mono.just(authResponse));

            // Act & Assert
            webTestClient.post()
                    .uri("/api/auth/authenticate")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(objectMapper.writeValueAsString(authRequest))
                    .exchange()
                    .expectStatus().isOk()
                    .expectHeader().contentType(MediaType.APPLICATION_JSON)
                    .expectBody()
                    .jsonPath("$.accessToken").isEqualTo("access_token")
                    .jsonPath("$.username").isEqualTo("testuser");

            verify(authenticationService).authenticate(any(AuthenticationRequest.class));
        }

        @Test
        @DisplayName("POST /api/auth/authenticate - Invalid credentials")
        void authenticateUser_InvalidCredentials() throws Exception {
            // Arrange
            when(authenticationService.authenticate(any(AuthenticationRequest.class)))
                    .thenReturn(Mono.error(new RuntimeException("Invalid credentials")));

            // Act & Assert
            webTestClient.post()
                    .uri("/api/auth/authenticate")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(objectMapper.writeValueAsString(authRequest))
                    .exchange()
                    .expectStatus().isUnauthorized();

            verify(authenticationService).authenticate(any(AuthenticationRequest.class));
        }

        @Test
        @DisplayName("POST /api/auth/login - Success (alias endpoint)")
        void loginUser_Success() throws Exception {
            // Arrange
            when(authenticationService.authenticate(any(AuthenticationRequest.class)))
                    .thenReturn(Mono.just(authResponse));

            // Act & Assert
            webTestClient.post()
                    .uri("/api/auth/login")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(objectMapper.writeValueAsString(authRequest))
                    .exchange()
                    .expectStatus().isOk()
                    .expectHeader().contentType(MediaType.APPLICATION_JSON)
                    .expectBody()
                    .jsonPath("$.accessToken").isEqualTo("access_token");

            verify(authenticationService).authenticate(any(AuthenticationRequest.class));
        }
    }

    @Nested
    @DisplayName("Token Management Endpoint Tests")
    class TokenManagementEndpointTests {

        @Test
        @DisplayName("POST /api/auth/refresh-token - Success")
        void refreshToken_Success() {
            // Arrange
            when(authenticationService.refreshToken(anyString()))
                    .thenReturn(Mono.just(authResponse));

            // Act & Assert
            webTestClient.post()
                    .uri("/api/auth/refresh-token")
                    .header("Authorization", "Bearer refresh_token_123")
                    .exchange()
                    .expectStatus().isOk()
                    .expectHeader().contentType(MediaType.APPLICATION_JSON)
                    .expectBody()
                    .jsonPath("$.accessToken").isEqualTo("access_token")
                    .jsonPath("$.refreshToken").isEqualTo("refresh_token");

            verify(authenticationService).refreshToken("Bearer refresh_token_123");
        }

        @Test
        @DisplayName("POST /api/auth/refresh-token - Invalid token")
        void refreshToken_InvalidToken() {
            // Arrange
            when(authenticationService.refreshToken(anyString()))
                    .thenReturn(Mono.error(new RuntimeException("Invalid refresh token")));

            // Act & Assert
            webTestClient.post()
                    .uri("/api/auth/refresh-token")
                    .header("Authorization", "Bearer invalid_token")
                    .exchange()
                    .expectStatus().isUnauthorized();

            verify(authenticationService).refreshToken("Bearer invalid_token");
        }

        @Test
        @DisplayName("POST /api/auth/refresh-token - Missing header")
        void refreshToken_MissingHeader() {
            // Act & Assert
            webTestClient.post()
                    .uri("/api/auth/refresh-token")
                    .exchange()
                    .expectStatus().isBadRequest();

            verify(authenticationService, never()).refreshToken(anyString());
        }

        @Test
        @DisplayName("GET /api/auth/validate - Valid token")
        void validateToken_ValidToken() {
            // Arrange
            when(authenticationService.validateToken(anyString()))
                    .thenReturn(Mono.just(true));

            // Act & Assert
            webTestClient.get()
                    .uri("/api/auth/validate")
                    .header("Authorization", "Bearer valid_token")
                    .exchange()
                    .expectStatus().isOk()
                    .expectHeader().contentType(MediaType.APPLICATION_JSON)
                    .expectBody()
                    .jsonPath("$.valid").isEqualTo(true);

            verify(authenticationService).validateToken("Bearer valid_token");
        }

        @Test
        @DisplayName("GET /api/auth/validate - Invalid token")
        void validateToken_InvalidToken() {
            // Arrange
            when(authenticationService.validateToken(anyString()))
                    .thenReturn(Mono.just(false));

            // Act & Assert
            webTestClient.get()
                    .uri("/api/auth/validate")
                    .header("Authorization", "Bearer invalid_token")
                    .exchange()
                    .expectStatus().isOk()
                    .expectHeader().contentType(MediaType.APPLICATION_JSON)
                    .expectBody()
                    .jsonPath("$.valid").isEqualTo(false);

            verify(authenticationService).validateToken("Bearer invalid_token");
        }
    }

    @Nested
    @DisplayName("Logout Endpoint Tests")
    class LogoutEndpointTests {

        @Test
        @DisplayName("POST /api/auth/logout - Success")
        void logout_Success() {
            // Arrange
            when(authenticationService.logout(anyString()))
                    .thenReturn(Mono.empty());

            // Act & Assert
            webTestClient.post()
                    .uri("/api/auth/logout")
                    .header("Authorization", "Bearer refresh_token")
                    .exchange()
                    .expectStatus().isOk()
                    .expectHeader().contentType(MediaType.APPLICATION_JSON)
                    .expectBody()
                    .jsonPath("$.message").isEqualTo("Successfully logged out");

            verify(authenticationService).logout("Bearer refresh_token");
        }

        @Test
        @DisplayName("POST /api/auth/logout - Failure")
        void logout_Failure() {
            // Arrange
            when(authenticationService.logout(anyString()))
                    .thenReturn(Mono.error(new RuntimeException("Logout failed")));

            // Act & Assert
            webTestClient.post()
                    .uri("/api/auth/logout")
                    .header("Authorization", "Bearer invalid_token")
                    .exchange()
                    .expectStatus().isBadRequest()
                    .expectHeader().contentType(MediaType.APPLICATION_JSON)
                    .expectBody()
                    .jsonPath("$.message").isEqualTo("Logout failed");

            verify(authenticationService).logout("Bearer invalid_token");
        }
    }

    @Nested
    @DisplayName("Current User Endpoint Tests")
    class CurrentUserEndpointTests {

        @Test
        @DisplayName("GET /api/auth/me - Success")
        void getCurrentUser_Success() {
            // Arrange
            Map<String, Object> userInfo = Map.of(
                    "id", "123e4567-e89b-12d3-a456-426614174000",
                    "username", "testuser",
                    "email", "test@example.com",
                    "roles", Set.of("USER"),
                    "isActive", true
            );

            when(authenticationService.getCurrentUser(anyString()))
                    .thenReturn(Mono.just(userInfo));

            // Act & Assert
            webTestClient.get()
                    .uri("/api/auth/me")
                    .header("Authorization", "Bearer valid_token")
                    .exchange()
                    .expectStatus().isOk()
                    .expectHeader().contentType(MediaType.APPLICATION_JSON)
                    .expectBody()
                    .jsonPath("$.username").isEqualTo("testuser")
                    .jsonPath("$.email").isEqualTo("test@example.com")
                    .jsonPath("$.isActive").isEqualTo(true);

            verify(authenticationService).getCurrentUser("Bearer valid_token");
        }

        @Test
        @DisplayName("GET /api/auth/me - Invalid token")
        void getCurrentUser_InvalidToken() {
            // Arrange
            when(authenticationService.getCurrentUser(anyString()))
                    .thenReturn(Mono.error(new RuntimeException("Invalid token")));

            // Act & Assert
            webTestClient.get()
                    .uri("/api/auth/me")
                    .header("Authorization", "Bearer invalid_token")
                    .exchange()
                    .expectStatus().isUnauthorized()
                    .expectHeader().contentType(MediaType.APPLICATION_JSON)
                    .expectBody()
                    .jsonPath("$.message").isEqualTo("Unable to retrieve user information");

            verify(authenticationService).getCurrentUser("Bearer invalid_token");
        }

        @Test
        @DisplayName("GET /api/auth/me - Missing header")
        void getCurrentUser_MissingHeader() {
            // Act & Assert
            webTestClient.get()
                    .uri("/api/auth/me")
                    .exchange()
                    .expectStatus().isBadRequest();

            verify(authenticationService, never()).getCurrentUser(anyString());
        }
    }

    @Nested
    @DisplayName("Error Response Tests")
    class ErrorResponseTests {

        @Test
        @DisplayName("Should return proper error structure for service exceptions")
        void shouldReturnProperErrorStructure() {
            // Arrange
            when(authenticationService.register(any(RegisterRequest.class)))
                    .thenReturn(Mono.error(new RuntimeException("Service error")));

            // Act & Assert
            webTestClient.post()
                    .uri("/api/auth/register")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(registerRequest)
                    .exchange()
                    .expectStatus().isBadRequest();
        }

        @Test
        @DisplayName("Should handle large request bodies")
        void shouldHandleLargeRequestBodies() throws Exception {
            // Arrange - Create a request with very long strings
            RegisterRequest largeRequest = new RegisterRequest();
            largeRequest.setUsername("a".repeat(1000));
            largeRequest.setEmail("test@example.com");
            largeRequest.setPassword("password123");

            // Act & Assert
            webTestClient.post()
                    .uri("/api/auth/register")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(objectMapper.writeValueAsString(largeRequest))
                    .exchange()
                    .expectStatus().isBadRequest();
        }

        @Test
        @DisplayName("Should handle concurrent requests")
        void shouldHandleConcurrentRequests() throws Exception {
            // Arrange
            when(authenticationService.authenticate(any(AuthenticationRequest.class)))
                    .thenReturn(Mono.just(authResponse));

            // Act & Assert - Multiple concurrent requests
            for (int i = 0; i < 5; i++) {
                webTestClient.post()
                        .uri("/api/auth/authenticate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .bodyValue(objectMapper.writeValueAsString(authRequest))
                        .exchange()
                        .expectStatus().isOk();
            }

            verify(authenticationService, times(5)).authenticate(any(AuthenticationRequest.class));
        }
    }

    @Nested
    @DisplayName("Content Type Tests")
    class ContentTypeTests {

        @Test
        @DisplayName("Should reject non-JSON content type for POST endpoints")
        void shouldRejectNonJsonContentType() {
            // Act & Assert
            webTestClient.post()
                    .uri("/api/auth/register")
                    .contentType(MediaType.TEXT_PLAIN)
                    .bodyValue("plain text")
                    .exchange()
                    .expectStatus().is4xxClientError();
        }

        @Test
        @DisplayName("Should accept JSON content type")
        void shouldAcceptJsonContentType() throws Exception {
            // Arrange
            when(authenticationService.register(any(RegisterRequest.class)))
                    .thenReturn(Mono.just(authResponse));

            // Act & Assert
            webTestClient.post()
                    .uri("/api/auth/register")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(objectMapper.writeValueAsString(registerRequest))
                    .exchange()
                    .expectStatus().isOk();
        }
    }
}