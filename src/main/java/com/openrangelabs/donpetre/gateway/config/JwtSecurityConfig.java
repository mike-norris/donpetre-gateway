// src/main/java/com/openrangelabs/donpetre/gateway/config/JwtSecurityConfig.java
package com.openrangelabs.donpetre.gateway.config;

import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
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
@Slf4j
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

        // Handle both hex and base64 encoded secrets
        byte[] keyBytes;
        try {
            // Try hex decoding first (if it's a hex string)
            if (resolvedSecret.matches("^[0-9a-fA-F]+$")) {
                keyBytes = hexStringToByteArray(resolvedSecret);
            } else {
                // Fall back to base64 decoding
                keyBytes = Decoders.BASE64.decode(resolvedSecret);
            }
        } catch (Exception e) {
            // If both fail, treat as raw bytes
            keyBytes = resolvedSecret.getBytes();
        }

        return Keys.hmacShaKeyFor(keyBytes);
    }

    /**
     * Backup JWT signing key for key rotation scenarios
     * FIXED: Always returns a valid SecretKey, never null
     */
    @Bean(name = "jwtBackupSigningKey")
    public SecretKey jwtBackupSigningKey() {
        String backupSecret = environment.getProperty("open-range-labs.donpetre.security.jwt.backup-secret");

        if (StringUtils.hasText(backupSecret)) {
            try {
                validateSecretStrength(backupSecret);
                byte[] keyBytes;
                // Handle both hex and base64 encoded secrets
                if (backupSecret.matches("^[0-9a-fA-F]+$")) {
                    keyBytes = hexStringToByteArray(backupSecret);
                } else {
                    keyBytes = Decoders.BASE64.decode(backupSecret);
                }
                return Keys.hmacShaKeyFor(keyBytes);
            } catch (Exception e) {
                log.info("Backup secret validation failed, using primary secret as backup: " + e.getMessage());
            }
        }

        // CRITICAL: This is the missing part that prevents the null return!
        // FIXED: Return the primary key as backup if no separate backup key is configured
        // This prevents the bean creation failure while maintaining functionality
        log.info("No backup JWT secret configured, using primary secret as backup");
        return jwtSigningKey();
    }

    /**
     * Convert hex string to byte array
     */
    private byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
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
            log.error("WARNING: Generated JWT secret for development. Use proper secret management in production!");
            log.error("Generated secret: " + generatedSecret);
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
            byte[] decoded;

            // Handle both hex and base64 encoded secrets
            if (secret.matches("^[0-9a-fA-F]+$")) {
                // Hex string
                decoded = hexStringToByteArray(secret);
            } else {
                // Base64 string
                decoded = Decoders.BASE64.decode(secret);
            }

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
            // If decoding fails, treat as raw string and check minimum length
            if (secret.length() < 64) {
                throw new IllegalArgumentException("JWT secret must be at least 64 characters long");
            }
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
            if ("dev".equals(profile) || "development".equals(profile) || "local".equals(profile) || "test".equals(profile)) {
                return true;
            }
        }
        return false;
    }
}