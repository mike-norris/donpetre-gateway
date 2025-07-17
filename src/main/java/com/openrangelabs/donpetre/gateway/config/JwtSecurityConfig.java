// src/main/java/com/openrangelabs/donpetre/gateway/config/JwtSecurityConfig.java
package com.openrangelabs.donpetre.gateway.config;

import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.util.StringUtils;

import javax.crypto.SecretKey;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * JWT Security Configuration with proper secret management
 * Handles secret generation, validation, and rotation
 */
@Configuration
public class JwtSecurityConfig {

    private final Environment environment;
    private final JwtSecurityProperties jwtProperties;

    @Autowired
    public JwtSecurityConfig(Environment environment, JwtSecurityProperties jwtProperties) {
        this.environment = environment;
        this.jwtProperties = jwtProperties;
    }

    /**
     * Primary JWT signing key - handles secret resolution with fallback strategy
     */
    @Bean(name = "jwtSigningKey")
    public SecretKey jwtSigningKey() {
        String resolvedSecret = resolveJwtSecret();

        // Validate secret strength
        validateSecretStrength(resolvedSecret);

        byte[] keyBytes = Decoders.BASE64.decode(resolvedSecret);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    /**
     * Backup JWT signing key for key rotation scenarios
     */
    @Bean(name = "jwtBackupSigningKey")
    public SecretKey jwtBackupSigningKey() {
        String backupSecret = environment.getProperty("open-range-labs.donpetre.security.jwt.backup-secret");

        if (StringUtils.hasText(backupSecret)) {
            validateSecretStrength(backupSecret);
            byte[] keyBytes = Decoders.BASE64.decode(backupSecret);
            return Keys.hmacShaKeyFor(keyBytes);
        }

        return null; // No backup key configured
    }

    /**
     * Resolve JWT secret with multiple fallback strategies
     */
    private String resolveJwtSecret() {
        // 1. Try environment variable first (highest priority)
        String envSecret = System.getenv("JWT_SECRET_KEY");
        if (StringUtils.hasText(envSecret)) {
            return envSecret;
        }

        // 2. Try Spring Boot encrypted properties
        String encryptedSecret = jwtProperties.getEncryptedSecret();
        if (StringUtils.hasText(encryptedSecret)) {
            return decryptSecret(encryptedSecret);
        }

        // 3. Try external secret store (if available)
        String externalSecret = loadFromExternalStore();
        if (StringUtils.hasText(externalSecret)) {
            return externalSecret;
        }

        // 4. Try configured secret property
        if (StringUtils.hasText(jwtProperties.getSecret())) {
            return jwtProperties.getSecret();
        }

        // 5. Generate new secret if auto-generation is enabled (development only)
        if (jwtProperties.isAutoGenerateSecret() && isDevelopmentEnvironment()) {
            String generatedSecret = generateSecureSecret();
            System.err.println("WARNING: Generated JWT secret for development. Use proper secret management in production!");
            System.err.println("Generated secret: " + generatedSecret);
            return generatedSecret;
        }

        throw new IllegalStateException(
                "No JWT secret found. Configure JWT_SECRET_KEY environment variable, " +
                        "encrypted-secret property, or external secret store."
        );
    }

    /**
     * Generate a cryptographically secure secret
     */
    private String generateSecureSecret() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] secretBytes = new byte[jwtProperties.getKeyLength()];
        secureRandom.nextBytes(secretBytes);
        return Base64.getEncoder().encodeToString(secretBytes);
    }

    /**
     * Validate secret meets security requirements
     */
    private void validateSecretStrength(String secret) {
        if (!StringUtils.hasText(secret)) {
            throw new IllegalArgumentException("JWT secret cannot be null or empty");
        }

        try {
            byte[] decoded = Decoders.BASE64.decode(secret);

            // Minimum 256 bits (32 bytes) for HS256, 512 bits (64 bytes) for HS512
            int minKeyLength = jwtProperties.getAlgorithm().equals("HS512") ? 64 : 32;

            if (decoded.length < minKeyLength) {
                throw new IllegalArgumentException(
                        String.format("JWT secret must be at least %d bytes for %s algorithm. Current: %d bytes",
                                minKeyLength, jwtProperties.getAlgorithm(), decoded.length)
                );
            }

            // Check for weak patterns (all zeros, repeating patterns, etc.)
            if (isWeakSecret(decoded)) {
                throw new IllegalArgumentException("JWT secret appears to be weak or predictable");
            }

        } catch (IllegalArgumentException e) {
            if (e.getMessage().contains("JWT secret must be") || e.getMessage().contains("weak")) {
                throw e;
            }
            throw new IllegalArgumentException("JWT secret must be a valid Base64 encoded string", e);
        }
    }

    /**
     * Check for weak secret patterns
     */
    private boolean isWeakSecret(byte[] secretBytes) {
        // Check for all zeros
        boolean allZeros = true;
        for (byte b : secretBytes) {
            if (b != 0) {
                allZeros = false;
                break;
            }
        }
        if (allZeros) return true;

        // Check for repeating patterns
        if (secretBytes.length >= 8) {
            boolean isRepeating = true;
            for (int i = 4; i < secretBytes.length; i++) {
                if (secretBytes[i] != secretBytes[i % 4]) {
                    isRepeating = false;
                    break;
                }
            }
            if (isRepeating) return true;
        }

        return false;
    }

    /**
     * Decrypt secret from encrypted property (implement based on your encryption strategy)
     */
    private String decryptSecret(String encryptedSecret) {
        // TODO: Implement decryption logic based on your encryption strategy
        // This could use Spring Cloud Config encryption, Jasypt, or custom encryption

        // Example with Spring Cloud Config:
        // return environment.getProperty("open-range-labs.donpetre.security.jwt.secret");

        // For now, return as-is (implement actual decryption)
        return encryptedSecret;
    }

    /**
     * Load secret from external secret store (AWS Secrets Manager, Azure Key Vault, etc.)
     */
    private String loadFromExternalStore() {
        // TODO: Implement external secret store integration
        // Examples:
        // - AWS Secrets Manager
        // - Azure Key Vault
        // - HashiCorp Vault
        // - Kubernetes Secrets

        String secretStoreName = jwtProperties.getSecretStore() != null ?
                jwtProperties.getSecretStore().getName() : null;
        if (StringUtils.hasText(secretStoreName)) {
            // Implement secret store client here
            // return secretStoreClient.getSecret(secretStoreName);
        }

        return null;
    }

    /**
     * Check if running in development environment
     */
    private boolean isDevelopmentEnvironment() {
        String[] activeProfiles = environment.getActiveProfiles();
        for (String profile : activeProfiles) {
            if ("dev".equals(profile) || "development".equals(profile) || "local".equals(profile)) {
                return true;
            }
        }
        return false;
    }
}