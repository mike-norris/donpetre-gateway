package com.openrangelabs.donpetre.gateway.controller;

import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/api/auth")
public class AuthenticationController {

    private final AuthenticationService authenticationService;

    @Autowired
    public AuthenticationController(AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    @PostMapping("/register")
    public Mono<ResponseEntity<AuthenticationResponse>> register(
            @Valid @RequestBody RegisterRequest request) {
        return authenticationService.register(request)
                .map(response -> ResponseEntity.ok(response))
                .onErrorResume(Exception.class, e ->
                        Mono.just(ResponseEntity.badRequest().build()));
    }

    @PostMapping("/authenticate")
    public Mono<ResponseEntity<AuthenticationResponse>> authenticate(
            @Valid @RequestBody AuthenticationRequest request) {
        return authenticationService.authenticate(request)
                .map(response -> ResponseEntity.ok(response))
                .onErrorResume(Exception.class, e ->
                        Mono.just(ResponseEntity.badRequest().build()));
    }

    @PostMapping("/refresh-token")
    public Mono<ResponseEntity<AuthenticationResponse>> refreshToken(
            @RequestHeader("Authorization") String authHeader) {
        return authenticationService.refreshToken(authHeader)
                .map(response -> ResponseEntity.ok(response))
                .onErrorResume(Exception.class, e ->
                        Mono.just(ResponseEntity.badRequest().build()));
    }

    @PostMapping("/logout")
    public Mono<ResponseEntity<Void>> logout(
            @RequestHeader("Authorization") String authHeader) {
        return authenticationService.logout(authHeader)
                .then(Mono.just(ResponseEntity.ok().<Void>build()))
                .onErrorResume(Exception.class, e ->
                        Mono.just(ResponseEntity.badRequest().build()));
    }

    @GetMapping("/validate")
    public Mono<ResponseEntity<Boolean>> validateToken(
            @RequestHeader("Authorization") String authHeader) {
        return authenticationService.validateToken(authHeader)
                .map(isValid -> ResponseEntity.ok(isValid))
                .onErrorReturn(ResponseEntity.badRequest().body(false));
    }
}
