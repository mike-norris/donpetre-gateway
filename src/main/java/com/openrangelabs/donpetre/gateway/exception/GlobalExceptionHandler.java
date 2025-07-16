package com.openrangelabs.donpetre.gateway.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.bind.support.WebExchangeBindException;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.stream.Collectors;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(WebExchangeBindException.class)
    public Mono<ResponseEntity<Map<String, Object>>> handleValidationErrors(
            WebExchangeBindException ex) {

        String errors = ex.getBindingResult()
                .getFieldErrors()
                .stream()
                .map(error -> error.getField() + ": " + error.getDefaultMessage())
                .collect(Collectors.joining(", "));

        Map<String, Object> response = Map.of(
                "message", "Validation failed",
                "errors", errors,
                "timestamp", LocalDateTime.now(),
                "status", HttpStatus.BAD_REQUEST.value()
        );

        return Mono.just(ResponseEntity.badRequest().body(response));
    }

    @ExceptionHandler(RuntimeException.class)
    public Mono<ResponseEntity<Map<String, Object>>> handleRuntimeException(
            RuntimeException ex) {

        Map<String, Object> response = Map.of(
                "message", ex.getMessage(),
                "timestamp", LocalDateTime.now(),
                "status", HttpStatus.BAD_REQUEST.value()
        );

        return Mono.just(ResponseEntity.badRequest().body(response));
    }

    @ExceptionHandler(Exception.class)
    public Mono<ResponseEntity<Map<String, Object>>> handleGenericException(
            Exception ex) {

        Map<String, Object> response = Map.of(
                "message", "An unexpected error occurred",
                "timestamp", LocalDateTime.now(),
                "status", HttpStatus.INTERNAL_SERVER_ERROR.value()
        );

        return Mono.just(ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response));
    }
}