// src/main/java/com/openrangelabs/donpetre/gateway/security/JwtService.java
package com.openrangelabs.donpetre.gateway.security;

import com.openrangelabs.donpetre.gateway.config.JwtSecurityProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.SignatureException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

/**
 * Enhanced JWT utility service with improved security and key management
 * Supports key rotation and multiple signing keys
 */
@Service
public class JwtService {

    private static final Logger logger = LoggerFactory.getLogger(JwtService.class);

    private final SecretKey primarySigningKey;
    private final SecretKey backupSigningKey;
    private final JwtSecurityProperties jwtProperties;

    @Autowired
    public JwtService(
            @Qualifier("jwtSigningKey") SecretKey primarySigningKey,
            @Qualifier("jwtBackupSigningKey") SecretKey backupSigningKey,
            JwtSecurityProperties jwtProperties) {
        this.primarySigningKey = primarySigningKey;
        this.backupSigningKey = backupSigningKey;
        this.jwtProperties = jwtProperties;
    }

    /**
     * Generate JWT access token for authenticated user
     */
    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    /**
     * Generate JWT access token with additional claims
     */
    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        // Add security-related claims
        Map<String, Object> securityClaims = new HashMap<>(extraClaims);
        securityClaims.put("token_type", "access");
        securityClaims.put("key_id", getCurrentKeyId());

        return buildToken(securityClaims, userDetails, jwtProperties.getExpiration());
    }

    /**
     * Generate JWT refresh token for token refresh workflow
     */
    public String generateRefreshToken(UserDetails userDetails) {
        Map<String, Object> refreshClaims = new HashMap<>();
        refreshClaims.put("token_type", "refresh");
        refreshClaims.put("key_id", getCurrentKeyId());

        return buildToken(refreshClaims, userDetails, jwtProperties.getRefreshExpiration());
    }

    /**
     * Build JWT token with specified claims and expiration
     */
    private String buildToken(Map<String, Object> extraClaims, UserDetails userDetails, long expiration) {
        try {
            long currentTime = System.currentTimeMillis();

            return Jwts.builder()
                    .setClaims(extraClaims)
                    .setSubject(userDetails.getUsername())
                    .setIssuedAt(new Date(currentTime))
                    .setExpiration(new Date(currentTime + expiration))
                    .setIssuer("donpetre-api-gateway")
                    .setId(generateJwtId())
                    .signWith(primarySigningKey, getSignatureAlgorithm())
                    .compact();
        } catch (Exception e) {
            logger.error("Failed to generate JWT token for user: {}", userDetails.getUsername(), e);
            throw new RuntimeException("Token generation failed", e);
        }
    }

    /**
     * Validate JWT token against user details with enhanced security checks
     */
    public boolean isTokenValid(String token, UserDetails userDetails) {
        try {
            final String username = extractUsername(token);

            // Basic validation
            if (!username.equals(userDetails.getUsername()) || isTokenExpired(token)) {
                return false;
            }

            // Additional security validations
            String tokenType = extractClaim(token, claims -> claims.get("token_type", String.class));
            if (!"access".equals(tokenType)) {
                logger.warn("Invalid token type for access token validation: {}", tokenType);
                return false;
            }

            // Validate issuer
            String issuer = extractClaim(token, Claims::getIssuer);
            if (!"donpetre-api-gateway".equals(issuer)) {
                logger.warn("Invalid token issuer: {}", issuer);
                return false;
            }

            return true;
        } catch (Exception e) {
            logger.warn("Token validation failed for user: {}", userDetails.getUsername(), e);
            return false;
        }
    }

    /**
     * Validate refresh token with specific refresh token checks
     */
    public boolean isRefreshTokenValid(String token, UserDetails userDetails) {
        try {
            final String username = extractUsername(token);

            if (!username.equals(userDetails.getUsername()) || isTokenExpired(token)) {
                return false;
            }

            // Validate token type
            String tokenType = extractClaim(token, claims -> claims.get("token_type", String.class));
            if (!"refresh".equals(tokenType)) {
                logger.warn("Invalid token type for refresh token validation: {}", tokenType);
                return false;
            }

            return true;
        } catch (Exception e) {
            logger.warn("Refresh token validation failed for user: {}", userDetails.getUsername(), e);
            return false;
        }
    }

    /**
     * Extract username from JWT token with key rotation support
     */
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    /**
     * Extract JWT ID for token tracking
     */
    public String extractJwtId(String token) {
        return extractClaim(token, Claims::getId);
    }

    /**
     * Extract specific claim from JWT token with key rotation support
     */
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    /**
     * Extract all claims from JWT token with automatic key rotation handling
     */
    private Claims extractAllClaims(String token) {
        // Try primary key first
        try {
            return Jwts.parser()
                    .verifyWith(primarySigningKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (SignatureException e) {
            // If primary key fails and backup key exists, try backup key
            if (backupSigningKey != null) {
                try {
                    logger.debug("Primary key failed, trying backup key for token validation");
                    return Jwts.parser()
                            .verifyWith(backupSigningKey)
                            .build()
                            .parseSignedClaims(token)
                            .getPayload();
                } catch (SignatureException backupException) {
                    logger.error("Both primary and backup keys failed for token validation");
                    throw new RuntimeException("Token signature validation failed", backupException);
                }
            }
            throw new RuntimeException("Token signature validation failed", e);
        }
    }

    /**
     * Check if JWT token is expired
     */
    private boolean isTokenExpired(String token) {
        try {
            Date expiration = extractClaim(token, Claims::getExpiration);
            return expiration.before(new Date());
        } catch (Exception e) {
            logger.warn("Failed to check token expiration", e);
            return true; // Treat as expired if we can't determine
        }
    }

    /**
     * Generate unique JWT ID for token tracking
     */
    private String generateJwtId() {
        return java.util.UUID.randomUUID().toString();
    }

    /**
     * Get current key identifier for token metadata
     */
    private String getCurrentKeyId() {
        // Generate a simple identifier based on key hash
        // In production, use a proper key versioning system
        return "key-" + Math.abs(primarySigningKey.hashCode() % 1000);
    }

    /**
     * Get signature algorithm based on configuration
     */
    private SignatureAlgorithm getSignatureAlgorithm() {
        return "HS512".equals(jwtProperties.getAlgorithm()) ?
                SignatureAlgorithm.HS512 :
                SignatureAlgorithm.HS256;
    }

    /**
     * Utility method to check if a token can be refreshed
     */
    public boolean canTokenBeRefreshed(String token) {
        try {
            Date expiration = extractClaim(token, Claims::getExpiration);
            Date now = new Date();

            // Allow refresh if token expired within the last hour
            long oneHour = 3600000L;
            return expiration.after(new Date(now.getTime() - oneHour));
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Extract token expiration for monitoring purposes
     */
    public Date getTokenExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    /**
     * Get remaining token lifetime in milliseconds
     */
    public long getRemainingTokenLifetime(String token) {
        try {
            Date expiration = getTokenExpiration(token);
            return Math.max(0, expiration.getTime() - System.currentTimeMillis());
        } catch (Exception e) {
            return 0;
        }
    }
}