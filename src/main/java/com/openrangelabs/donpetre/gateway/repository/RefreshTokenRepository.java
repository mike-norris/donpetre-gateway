package com.openrangelabs.donpetre.gateway.repository;

import com.openrangelabs.donpetre.gateway.entity.RefreshToken;
import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.r2dbc.repository.R2dbcRepository;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Reactive RefreshTokenRepository using R2DBC for non-blocking database operations
 */
@Repository
public interface RefreshTokenRepository extends R2dbcRepository<RefreshToken, UUID> {

    /**
     * Find refresh token by token string
     */
    Mono<RefreshToken> findByToken(String token);

    /**
     * Find refresh token by user ID
     */
    Mono<RefreshToken> findByUserId(UUID userId);

    /**
     * Find all refresh tokens for a user (if multiple sessions allowed)
     */
    Flux<RefreshToken> findAllByUserId(UUID userId);

    /**
     * Check if token exists
     */
    Mono<Boolean> existsByToken(String token);

    /**
     * Delete refresh token by user ID
     */
    @Modifying
    @Query("DELETE FROM refresh_tokens WHERE user_id = :userId")
    Mono<Integer> deleteByUserId(@Param("userId") UUID userId);

    /**
     * Delete expired tokens (cleanup job)
     */
    @Modifying
    @Query("DELETE FROM refresh_tokens WHERE expiry_date < :currentTime")
    Mono<Integer> deleteExpiredTokens(@Param("currentTime") LocalDateTime currentTime);

    /**
     * Find expired tokens (for monitoring before cleanup)
     */
    @Query("SELECT * FROM refresh_tokens WHERE expiry_date < :currentTime")
    Flux<RefreshToken> findExpiredTokens(@Param("currentTime") LocalDateTime currentTime);

    /**
     * Count refresh tokens for a user
     */
    @Query("SELECT COUNT(*) FROM refresh_tokens WHERE user_id = :userId")
    Mono<Long> countByUserId(@Param("userId") UUID userId);

    /**
     * Find tokens expiring soon (for proactive refresh notifications)
     */
    @Query("SELECT * FROM refresh_tokens WHERE expiry_date BETWEEN :now AND :threshold")
    Flux<RefreshToken> findTokensExpiringSoon(
            @Param("now") LocalDateTime now,
            @Param("threshold") LocalDateTime threshold
    );

    /**
     * Update last used timestamp
     */
    @Modifying
    @Query("UPDATE refresh_tokens SET last_used = :lastUsed WHERE token = :token")
    Mono<Integer> updateLastUsed(@Param("token") String token, @Param("lastUsed") LocalDateTime lastUsed);

    /**
     * Find tokens by device info (for device-specific logout)
     */
    Flux<RefreshToken> findByDeviceInfoContainingIgnoreCase(String deviceInfo);

    /**
     * Find recently used tokens
     */
    @Query("SELECT * FROM refresh_tokens WHERE last_used > :threshold")
    Flux<RefreshToken> findRecentlyUsedTokens(@Param("threshold") LocalDateTime threshold);

    /**
     * Delete tokens for user except the current one
     */
    @Modifying
    @Query("DELETE FROM refresh_tokens WHERE user_id = :userId AND token != :currentToken")
    Mono<Integer> deleteOtherUserTokens(@Param("userId") UUID userId, @Param("currentToken") String currentToken);

    /**
     * Get token statistics for monitoring
     */
    @Query("""
        SELECT 
            COUNT(*) as total_tokens,
            COUNT(CASE WHEN expiry_date > NOW() THEN 1 END) as active_tokens,
            COUNT(CASE WHEN last_used > :recentThreshold THEN 1 END) as recently_used_tokens
        FROM refresh_tokens
        """)
    Mono<TokenStats> getTokenStatistics(@Param("recentThreshold") LocalDateTime recentThreshold);

    /**
     * Custom result interface for token statistics
     */
    interface TokenStats {
        Long getTotalTokens();
        Long getActiveTokens();
        Long getRecentlyUsedTokens();
    }
}