package com.openrangelabs.donpetre.gateway.config;

import com.openrangelabs.donpetre.gateway.handler.AuthHandler;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.server.RequestPredicates;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.RouterFunctions;
import org.springframework.web.reactive.function.server.ServerResponse;

@Configuration
public class AuthRouterConfig {

    @Bean
    public RouterFunction<ServerResponse> authRoutes(AuthHandler authHandler) {
        return RouterFunctions.route()
                .POST("/api/auth/login", RequestPredicates.accept(MediaType.APPLICATION_JSON), authHandler::login)
                .POST("/api/auth/authenticate", RequestPredicates.accept(MediaType.APPLICATION_JSON), authHandler::authenticate)
                .POST("/api/auth/register", RequestPredicates.accept(MediaType.APPLICATION_JSON), authHandler::register)
                .POST("/api/auth/refresh-token", RequestPredicates.accept(MediaType.APPLICATION_JSON), authHandler::refreshToken)
                .POST("/api/auth/logout", RequestPredicates.accept(MediaType.APPLICATION_JSON), authHandler::logout)
                .GET("/api/auth/validate", authHandler::validate)
                .GET("/api/auth/me", authHandler::getCurrentUser)
                .build();
    }
}