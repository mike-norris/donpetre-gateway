package com.openrangelabs.donpetre.gateway.handler;

import com.openrangelabs.donpetre.gateway.dto.AuthenticationRequest;
import com.openrangelabs.donpetre.gateway.dto.AuthenticationResponse;
import com.openrangelabs.donpetre.gateway.dto.RegisterRequest;
import com.openrangelabs.donpetre.gateway.service.AuthenticationService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;
import java.util.Map;

@Slf4j
@Component
public class AuthHandler {

    private final AuthenticationService authenticationService;

    @Autowired
    public AuthHandler(AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    public Mono<ServerResponse> login(ServerRequest request) {
        return authenticate(request);
    }

    public Mono<ServerResponse> authenticate(ServerRequest request) {
        log.info("AuthHandler.authenticate called");
        
        return request.bodyToMono(AuthenticationRequest.class)
                .doOnNext(req -> log.info("Authentication request for user: " + req.getUsername()))
                .flatMap(authRequest -> authenticationService.authenticate(authRequest)
                        .doOnNext(response -> log.info("Authentication successful, access token length: " +
                                (response.getAccessToken() != null ? response.getAccessToken().length() : 0)))
                        .flatMap(authResponse -> 
                                ServerResponse.ok()
                                        .contentType(MediaType.APPLICATION_JSON)
                                        .body(BodyInserters.fromValue(authResponse))
                        )
                        .onErrorResume(RuntimeException.class, e -> {
                            log.error("Authentication failed: " + e.getMessage());
                            e.printStackTrace();
                            Map<String, Object> errorResponse = Map.of(
                                    "message", "Invalid username or password",
                                    "timestamp", LocalDateTime.now(),
                                    "status", 401
                            );
                            return ServerResponse.badRequest()
                                    .contentType(MediaType.APPLICATION_JSON)
                                    .body(BodyInserters.fromValue(errorResponse));
                        })
                );
    }

    public Mono<ServerResponse> register(ServerRequest request) {
        return request.bodyToMono(RegisterRequest.class)
                .flatMap(registerRequest -> authenticationService.register(registerRequest)
                        .flatMap(authResponse -> 
                                ServerResponse.ok()
                                        .contentType(MediaType.APPLICATION_JSON)
                                        .body(BodyInserters.fromValue(authResponse))
                        )
                        .onErrorResume(RuntimeException.class, e -> {
                            Map<String, Object> errorResponse = Map.of(
                                    "message", e.getMessage(),
                                    "timestamp", LocalDateTime.now(),
                                    "status", 400
                            );
                            return ServerResponse.badRequest()
                                    .contentType(MediaType.APPLICATION_JSON)
                                    .body(BodyInserters.fromValue(errorResponse));
                        })
                );
    }

    public Mono<ServerResponse> refreshToken(ServerRequest request) {
        return request.headers().header("Authorization").stream()
                .findFirst()
                .map(authHeader -> authenticationService.refreshToken(authHeader)
                        .flatMap(authResponse -> 
                                ServerResponse.ok()
                                        .contentType(MediaType.APPLICATION_JSON)
                                        .body(BodyInserters.fromValue(authResponse))
                        )
                        .onErrorResume(RuntimeException.class, e -> {
                            Map<String, Object> errorResponse = Map.of(
                                    "message", "Invalid or expired refresh token",
                                    "timestamp", LocalDateTime.now(),
                                    "status", 401
                            );
                            return ServerResponse.status(401)
                                    .contentType(MediaType.APPLICATION_JSON)
                                    .body(BodyInserters.fromValue(errorResponse));
                        })
                )
                .orElse(ServerResponse.badRequest()
                        .contentType(MediaType.APPLICATION_JSON)
                        .body(BodyInserters.fromValue(Map.of(
                                "message", "Authorization header required",
                                "timestamp", LocalDateTime.now(),
                                "status", 400
                        )))
                );
    }

    public Mono<ServerResponse> logout(ServerRequest request) {
        return request.headers().header("Authorization").stream()
                .findFirst()
                .map(authHeader -> authenticationService.logout(authHeader)
                        .then(ServerResponse.ok()
                                .contentType(MediaType.APPLICATION_JSON)
                                .body(BodyInserters.fromValue(Map.of(
                                        "message", "Successfully logged out",
                                        "timestamp", LocalDateTime.now()
                                )))
                        )
                        .onErrorResume(RuntimeException.class, e -> {
                            Map<String, Object> errorResponse = Map.of(
                                    "message", "Logout failed",
                                    "timestamp", LocalDateTime.now(),
                                    "status", 400
                            );
                            return ServerResponse.badRequest()
                                    .contentType(MediaType.APPLICATION_JSON)
                                    .body(BodyInserters.fromValue(errorResponse));
                        })
                )
                .orElse(ServerResponse.badRequest()
                        .contentType(MediaType.APPLICATION_JSON)
                        .body(BodyInserters.fromValue(Map.of(
                                "message", "Authorization header required",
                                "timestamp", LocalDateTime.now(),
                                "status", 400
                        )))
                );
    }

    public Mono<ServerResponse> validate(ServerRequest request) {
        return request.headers().header("Authorization").stream()
                .findFirst()
                .map(authHeader -> authenticationService.validateToken(authHeader)
                        .flatMap(isValid -> {
                            Map<String, Object> response = Map.of(
                                    "valid", isValid,
                                    "timestamp", LocalDateTime.now()
                            );
                            return ServerResponse.ok()
                                    .contentType(MediaType.APPLICATION_JSON)
                                    .body(BodyInserters.fromValue(response));
                        })
                        .onErrorResume(e -> {
                            Map<String, Object> errorResponse = Map.of(
                                    "valid", false,
                                    "message", "Token validation failed",
                                    "timestamp", LocalDateTime.now()
                            );
                            return ServerResponse.ok()
                                    .contentType(MediaType.APPLICATION_JSON)
                                    .body(BodyInserters.fromValue(errorResponse));
                        })
                )
                .orElse(ServerResponse.badRequest()
                        .contentType(MediaType.APPLICATION_JSON)
                        .body(BodyInserters.fromValue(Map.of(
                                "message", "Authorization header required",
                                "timestamp", LocalDateTime.now(),
                                "status", 400
                        )))
                );
    }

    public Mono<ServerResponse> getCurrentUser(ServerRequest request) {
        return request.headers().header("Authorization").stream()
                .findFirst()
                .map(authHeader -> authenticationService.getCurrentUser(authHeader)
                        .flatMap(userInfo -> ServerResponse.ok()
                                .contentType(MediaType.APPLICATION_JSON)
                                .body(BodyInserters.fromValue(userInfo))
                        )
                        .onErrorResume(RuntimeException.class, e -> {
                            Map<String, Object> errorResponse = Map.of(
                                    "message", "Unable to retrieve user information",
                                    "timestamp", LocalDateTime.now(),
                                    "status", 401
                            );
                            return ServerResponse.status(401)
                                    .contentType(MediaType.APPLICATION_JSON)
                                    .body(BodyInserters.fromValue(errorResponse));
                        })
                )
                .orElse(ServerResponse.badRequest()
                        .contentType(MediaType.APPLICATION_JSON)
                        .body(BodyInserters.fromValue(Map.of(
                                "message", "Authorization header required",
                                "timestamp", LocalDateTime.now(),
                                "status", 400
                        )))
                );
    }
}