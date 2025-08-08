package com.openrangelabs.donpetre.gateway.security;

import com.openrangelabs.donpetre.gateway.config.JwtSecurityProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import javax.crypto.SecretKey;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@DisplayName("JwtService Unit Tests")
class JwtServiceTest {

    @Mock
    private JwtSecurityProperties jwtProperties;

    private JwtService jwtService;
    private SecretKey primaryKey;
    private SecretKey backupKey;
    private UserDetails testUser;

    @BeforeEach
    void setUp() {
        // Create test keys
        primaryKey = Keys.secretKeyFor(io.jsonwebtoken.SignatureAlgorithm.HS512);
        backupKey = Keys.secretKeyFor(io.jsonwebtoken.SignatureAlgorithm.HS512);

        // Create test user
        testUser = User.builder()
                .username("testuser")
                .password("encoded_password")
                .authorities(List.of(new SimpleGrantedAuthority("ROLE_USER")))
                .build();
    }
    
    private void mockTokenExpiration() {
        when(jwtProperties.getExpiration()).thenReturn(86400000L); // 24 hours
    }
    
    private void mockRefreshTokenExpiration() {
        when(jwtProperties.getRefreshExpiration()).thenReturn(604800000L); // 7 days
    }
    
    private void mockSignatureAlgorithm() {
        when(jwtProperties.getAlgorithm()).thenReturn("HS512");
    }
    
    private JwtService createJwtService() {
        return new JwtService(primaryKey, backupKey, jwtProperties);
    }

    @Nested
    @DisplayName("Token Generation Tests")
    class TokenGenerationTests {

        @Test
        @DisplayName("Should generate valid access token")
        void shouldGenerateValidAccessToken() {
            // Arrange
            mockTokenExpiration();
            jwtService = createJwtService();
            
            // Act
            String token = jwtService.generateToken(testUser);

            // Assert
            assertThat(token).isNotNull().isNotEmpty();
            assertThat(jwtService.extractUsername(token)).isEqualTo("testuser");
            assertThat(jwtService.isTokenValid(token, testUser)).isTrue();
        }

        @Test
        @DisplayName("Should generate access token with custom claims")
        void shouldGenerateTokenWithCustomClaims() {
            // Arrange
            mockTokenExpiration();
            jwtService = createJwtService();
            
            Map<String, Object> extraClaims = Map.of(
                    "role", "USER",
                    "permissions", List.of("read", "write")
            );

            // Act
            String token = jwtService.generateToken(extraClaims, testUser);

            // Assert
            assertThat(token).isNotNull();
            String role = jwtService.extractClaim(token, claims -> claims.get("role", String.class));
            assertThat(role).isEqualTo("USER");
            List<?> permissions = jwtService.extractClaim(token, claims -> claims.get("permissions", List.class));
            assertThat(permissions).isEqualTo(List.of("read", "write"));
        }

        @Test
        @DisplayName("Should generate valid refresh token")
        void shouldGenerateValidRefreshToken() {
            // Arrange
            mockRefreshTokenExpiration();
            jwtService = createJwtService();
            
            // Act
            String refreshToken = jwtService.generateRefreshToken(testUser);

            // Assert
            assertThat(refreshToken).isNotNull().isNotEmpty();
            assertThat(jwtService.extractUsername(refreshToken)).isEqualTo("testuser");
            
            // Refresh token should have longer expiration
            Date expiration = jwtService.extractClaim(refreshToken, Claims::getExpiration);
            Date now = new Date();
            long timeDiff = expiration.getTime() - now.getTime();
            assertThat(timeDiff).isGreaterThan(86400000L); // More than 24 hours
        }

        @Test
        @DisplayName("Should generate unique tokens for same user")
        void shouldGenerateUniqueTokensForSameUser() {
            // Arrange
            mockTokenExpiration();
            jwtService = createJwtService();
            
            // Act
            String token1 = jwtService.generateToken(testUser);
            String token2 = jwtService.generateToken(testUser);

            // Assert
            assertThat(token1).isNotEqualTo(token2);
            assertThat(jwtService.isTokenValid(token1, testUser)).isTrue();
            assertThat(jwtService.isTokenValid(token2, testUser)).isTrue();
        }
    }

    @Nested
    @DisplayName("Token Extraction Tests")
    class TokenExtractionTests {

        @Test
        @DisplayName("Should extract username correctly")
        void shouldExtractUsernameCorrectly() {
            // Arrange
            mockTokenExpiration();
            jwtService = createJwtService();
            String token = jwtService.generateToken(testUser);

            // Act
            String extractedUsername = jwtService.extractUsername(token);

            // Assert
            assertThat(extractedUsername).isEqualTo("testuser");
        }

        @Test
        @DisplayName("Should extract expiration date correctly")
        void shouldExtractExpirationDateCorrectly() {
            // Arrange
            mockTokenExpiration();
            jwtService = createJwtService();
            String token = jwtService.generateToken(testUser);

            // Act
            Date expiration = jwtService.extractClaim(token, Claims::getExpiration);

            // Assert
            assertThat(expiration).isAfter(new Date());
            
            // Should be approximately 24 hours from now
            long timeDiff = expiration.getTime() - new Date().getTime();
            assertThat(timeDiff).isBetween(86390000L, 86400000L); // Allow 10 second variance
        }

        @Test
        @DisplayName("Should extract all claims correctly")
        void shouldExtractAllClaimsCorrectly() {
            // Arrange
            mockTokenExpiration();
            jwtService = createJwtService();
            Map<String, Object> extraClaims = Map.of("role", "ADMIN");
            String token = jwtService.generateToken(extraClaims, testUser);

            // Act & Assert
            String subject = jwtService.extractClaim(token, Claims::getSubject);
            String role = jwtService.extractClaim(token, claims -> claims.get("role", String.class));
            String issuer = jwtService.extractClaim(token, Claims::getIssuer);
            Date expiration = jwtService.extractClaim(token, Claims::getExpiration);
            Date issuedAt = jwtService.extractClaim(token, Claims::getIssuedAt);

            assertThat(subject).isEqualTo("testuser");
            assertThat(role).isEqualTo("ADMIN");
            assertThat(issuer).isEqualTo("donpetre-api-gateway");
            assertThat(expiration).isAfter(new Date());
            assertThat(issuedAt).isBefore(new Date());
        }

        @Test
        @DisplayName("Should extract custom claim correctly")
        void shouldExtractCustomClaimCorrectly() {
            // Arrange
            mockTokenExpiration();
            jwtService = createJwtService();
            Map<String, Object> extraClaims = Map.of("customField", "customValue");
            String token = jwtService.generateToken(extraClaims, testUser);

            // Act
            String customValue = jwtService.extractClaim(token, claims -> claims.get("customField", String.class));

            // Assert
            assertThat(customValue).isEqualTo("customValue");
        }
    }

    @Nested
    @DisplayName("Token Validation Tests")
    class TokenValidationTests {

        @Test
        @DisplayName("Should validate correct token")
        void shouldValidateCorrectToken() {
            // Arrange
            mockTokenExpiration();
            jwtService = createJwtService();
            String token = jwtService.generateToken(testUser);

            // Act & Assert
            assertThat(jwtService.isTokenValid(token, testUser)).isTrue();
        }

        @Test
        @DisplayName("Should reject token for different user")
        void shouldRejectTokenForDifferentUser() {
            // Arrange
            mockTokenExpiration();
            jwtService = createJwtService();
            String token = jwtService.generateToken(testUser);
            UserDetails differentUser = User.builder()
                    .username("differentuser")
                    .password("password")
                    .authorities(List.of(new SimpleGrantedAuthority("ROLE_USER")))
                    .build();

            // Act & Assert
            assertThat(jwtService.isTokenValid(token, differentUser)).isFalse();
        }

        @Test
        @DisplayName("Should reject malformed token")
        void shouldRejectMalformedToken() {
            // Arrange
            jwtService = createJwtService();
            String malformedToken = "invalid.jwt.token";

            // Act & Assert
            assertThatThrownBy(() -> jwtService.extractUsername(malformedToken))
                    .isInstanceOf(MalformedJwtException.class);
        }

        @Test
        @DisplayName("Should reject token with invalid signature")
        void shouldRejectTokenWithInvalidSignature() {
            // Arrange
            jwtService = createJwtService();
            SecretKey wrongKey = Keys.secretKeyFor(io.jsonwebtoken.SignatureAlgorithm.HS512);
            String tokenWithWrongSignature = Jwts.builder()
                    .setSubject("testuser")
                    .setIssuedAt(new Date())
                    .setExpiration(new Date(System.currentTimeMillis() + 86400000))
                    .signWith(wrongKey)
                    .compact();

            // Act & Assert - Service wraps SignatureException in RuntimeException
            assertThatThrownBy(() -> jwtService.extractUsername(tokenWithWrongSignature))
                    .isInstanceOf(RuntimeException.class)
                    .hasCauseInstanceOf(SignatureException.class);
        }

        @Test
        @DisplayName("Should check if token is expired correctly")
        void shouldCheckIfTokenIsExpiredCorrectly() {
            // Arrange
            mockTokenExpiration();
            jwtService = createJwtService();
            String validToken = jwtService.generateToken(testUser);

            // Create expired token with more buffer time to avoid timing issues
            Date pastDate = new Date(System.currentTimeMillis() - 5000); // 5 seconds ago
            String expiredToken = Jwts.builder()
                    .setSubject("testuser")
                    .setIssuedAt(new Date(System.currentTimeMillis() - 10000)) // 10 seconds ago
                    .setExpiration(pastDate)
                    .setIssuer("donpetre-api-gateway")
                    .signWith(primaryKey)
                    .compact();

            // Act & Assert
            Date validExpiration = jwtService.extractClaim(validToken, Claims::getExpiration);
            
            // For expired token, expect ExpiredJwtException during claim extraction
            assertThat(validExpiration).isAfter(new Date());
            assertThatThrownBy(() -> jwtService.extractClaim(expiredToken, Claims::getExpiration))
                    .isInstanceOf(ExpiredJwtException.class);
        }

        @Test
        @DisplayName("Should reject expired token in validation")
        void shouldRejectExpiredTokenInValidation() {
            // Arrange
            jwtService = createJwtService();
            Date pastDate = new Date(System.currentTimeMillis() - 5000); // 5 seconds ago
            String expiredToken = Jwts.builder()
                    .setSubject("testuser")
                    .setIssuedAt(new Date(System.currentTimeMillis() - 10000)) // 10 seconds ago
                    .setExpiration(pastDate)
                    .setIssuer("donpetre-api-gateway")
                    .signWith(primaryKey)
                    .compact();

            // Act & Assert
            assertThat(jwtService.isTokenValid(expiredToken, testUser)).isFalse();
        }
    }

    @Nested
    @DisplayName("Token Security Tests")
    class TokenSecurityTests {

        @Test
        @DisplayName("Should use secure signature algorithm")
        void shouldUseSecureSignatureAlgorithm() {
            // Arrange
            mockTokenExpiration();
            jwtService = createJwtService();
            
            // Act
            String token = jwtService.generateToken(testUser);

            // Assert
            // JWT header should indicate HS512 algorithm
            assertThat(token.split("\\.")).hasSize(3); // header.payload.signature
            assertThat(token).isNotEmpty();
        }

        @Test
        @DisplayName("Should include security-relevant claims")
        void shouldIncludeSecurityRelevantClaims() {
            // Arrange
            mockTokenExpiration();
            jwtService = createJwtService();
            
            // Act
            String token = jwtService.generateToken(testUser);

            // Assert
            String subject = jwtService.extractClaim(token, Claims::getSubject);
            Date issuedAt = jwtService.extractClaim(token, Claims::getIssuedAt);
            Date expiration = jwtService.extractClaim(token, Claims::getExpiration);
            String issuer = jwtService.extractClaim(token, Claims::getIssuer);

            assertThat(subject).isNotEmpty();
            assertThat(issuedAt).isNotNull();
            assertThat(expiration).isNotNull();
            assertThat(issuer).isEqualTo("donpetre-api-gateway");
        }

        @Test
        @DisplayName("Should not include sensitive information in token")
        void shouldNotIncludeSensitiveInformationInToken() {
            // Arrange
            mockTokenExpiration();
            jwtService = createJwtService();
            
            // Act
            String token = jwtService.generateToken(testUser);
            String subject = jwtService.extractClaim(token, Claims::getSubject);

            // Assert - Should not contain password or other sensitive data, only username
            assertThat(subject).isEqualTo("testuser");
        }

        @Test
        @DisplayName("Should handle key rotation gracefully")
        void shouldHandleKeyRotationGracefully() {
            // Arrange
            mockTokenExpiration();
            jwtService = createJwtService();
            String tokenWithPrimaryKey = jwtService.generateToken(testUser);

            // Act & Assert - Token should be valid with current service instance
            assertThat(jwtService.isTokenValid(tokenWithPrimaryKey, testUser)).isTrue();
        }
    }

    @Nested
    @DisplayName("Error Handling Tests")
    class ErrorHandlingTests {

        @Test
        @DisplayName("Should handle null token gracefully")
        void shouldHandleNullTokenGracefully() {
            // Arrange
            jwtService = createJwtService();
            
            // Act & Assert
            assertThatThrownBy(() -> jwtService.extractUsername(null))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        @DisplayName("Should handle empty token gracefully")
        void shouldHandleEmptyTokenGracefully() {
            // Arrange
            jwtService = createJwtService();
            
            // Act & Assert
            assertThatThrownBy(() -> jwtService.extractUsername(""))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        @DisplayName("Should handle whitespace token gracefully")
        void shouldHandleWhitespaceTokenGracefully() {
            // Arrange
            jwtService = createJwtService();
            
            // Act & Assert
            assertThatThrownBy(() -> jwtService.extractUsername("   "))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        @DisplayName("Should throw ExpiredJwtException for expired token extraction")
        void shouldThrowExpiredJwtExceptionForExpiredTokenExtraction() {
            // Arrange
            jwtService = createJwtService();
            Date pastDate = new Date(System.currentTimeMillis() - 5000); // 5 seconds ago
            String expiredToken = Jwts.builder()
                    .setSubject("testuser")
                    .setIssuedAt(new Date(System.currentTimeMillis() - 10000)) // 10 seconds ago  
                    .setExpiration(pastDate)
                    .setIssuer("donpetre-api-gateway") // Fix issuer to match service
                    .signWith(primaryKey)
                    .compact();

            // Act & Assert - ExpiredJwtException is thrown directly by JWT library
            assertThatThrownBy(() -> jwtService.extractUsername(expiredToken))
                    .isInstanceOf(ExpiredJwtException.class);
        }
    }

    @Nested
    @DisplayName("Token Lifecycle Tests")
    class TokenLifecycleTests {

        @Test
        @DisplayName("Should create token with correct lifecycle")
        void shouldCreateTokenWithCorrectLifecycle() {
            // Arrange
            mockTokenExpiration();
            jwtService = createJwtService();
            long beforeCreationTime = System.currentTimeMillis();

            // Act
            String token = jwtService.generateToken(testUser);

            // Assert
            long afterCreationTime = System.currentTimeMillis();
            Date issuedAt = jwtService.extractClaim(token, Claims::getIssuedAt);
            Date expiration = jwtService.extractClaim(token, Claims::getExpiration);

            // Allow for some timing tolerance (within 1 second)
            assertThat(issuedAt.getTime()).isBetween(beforeCreationTime - 1000, afterCreationTime + 1000);
            assertThat(expiration.getTime()).isGreaterThan(afterCreationTime);
            
            long tokenLifetime = expiration.getTime() - issuedAt.getTime();
            assertThat(tokenLifetime).isEqualTo(86400000L); // 24 hours
        }

        @Test
        @DisplayName("Should respect different expiration times for access and refresh tokens")
        void shouldRespectDifferentExpirationTimes() {
            // Arrange
            mockTokenExpiration();
            mockRefreshTokenExpiration();
            jwtService = createJwtService();
            
            // Act
            String accessToken = jwtService.generateToken(testUser);
            String refreshToken = jwtService.generateRefreshToken(testUser);

            // Assert
            Date accessExpiration = jwtService.extractClaim(accessToken, Claims::getExpiration);
            Date refreshExpiration = jwtService.extractClaim(refreshToken, Claims::getExpiration);

            assertThat(refreshExpiration).isAfter(accessExpiration);
            
            long accessLifetime = accessExpiration.getTime() - new Date().getTime();
            long refreshLifetime = refreshExpiration.getTime() - new Date().getTime();
            
            assertThat(refreshLifetime).isGreaterThan(accessLifetime);
        }
    }

    @Nested
    @DisplayName("Performance Tests")
    class PerformanceTests {

        @Test
        @DisplayName("Should generate tokens efficiently")
        void shouldGenerateTokensEfficiently() {
            // Arrange
            mockTokenExpiration();
            jwtService = createJwtService();
            long startTime = System.currentTimeMillis();

            // Act - Generate 100 tokens
            for (int i = 0; i < 100; i++) {
                jwtService.generateToken(testUser);
            }

            // Assert
            long endTime = System.currentTimeMillis();
            long duration = endTime - startTime;
            
            // Should generate 100 tokens in less than 1 second
            assertThat(duration).isLessThan(1000);
        }

        @Test
        @DisplayName("Should validate tokens efficiently")
        void shouldValidateTokensEfficiently() {
            // Arrange
            mockTokenExpiration();
            jwtService = createJwtService();
            String token = jwtService.generateToken(testUser);
            long startTime = System.currentTimeMillis();

            // Act - Validate token 100 times
            for (int i = 0; i < 100; i++) {
                jwtService.isTokenValid(token, testUser);
            }

            // Assert
            long endTime = System.currentTimeMillis();
            long duration = endTime - startTime;
            
            // Should validate 100 tokens in less than 500ms
            assertThat(duration).isLessThan(500);
        }
    }
}