package com.openrangelabs.donpetre.gateway.repository;

import com.openrangelabs.donpetre.gateway.entity.User;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.r2dbc.repository.R2dbcRepository;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Reactive UserRepository using R2DBC for non-blocking database operations
 * Replaces the blocking JPA implementation for better performance in reactive context
 * Uses R2dbcRepository for R2DBC-specific features and optimizations
 */
@Repository
public interface UserRepository extends R2dbcRepository<User, UUID> {

    /**
     * Find user by username (reactive)
     */
    Mono<User> findByUsername(String username);

    /**
     * Find user by email (reactive)
     */
    Mono<User> findByEmail(String email);

    /**
     * Check if username exists (reactive)
     */
    Mono<Boolean> existsByUsername(String username);

    /**
     * Check if email exists (reactive)
     */
    Mono<Boolean> existsByEmail(String email);

    /**
     * Find active user by username
     * Custom query needed because R2DBC doesn't support method name queries with boolean properties as elegantly
     */
    @Query("SELECT u.* FROM users u WHERE u.username = :username AND u.is_active = true")
    Mono<User> findActiveByUsername(@Param("username") String username);

    /**
     * Find active user by email
     */
    @Query("SELECT u.* FROM users u WHERE u.email = :email AND u.is_active = true")
    Mono<User> findActiveByEmail(@Param("email") String email);

    /**
     * Find users inactive after a certain date
     */
    @Query("SELECT u.* FROM users u WHERE u.last_login < :cutoffDate")
    Flux<User> findUsersInactiveAfter(@Param("cutoffDate") LocalDateTime cutoffDate);

    /**
     * Find users by role name (requires join with user_roles and roles tables)
     */
    @Query("""
        SELECT DISTINCT u.* FROM users u 
        INNER JOIN user_roles ur ON u.id = ur.user_id 
        INNER JOIN roles r ON ur.role_id = r.id 
        WHERE r.name = :roleName AND u.is_active = true
        """)
    Flux<User> findActiveUsersByRoleName(@Param("roleName") String roleName);

    /**
     * Count total active users
     */
    @Query("SELECT COUNT(*) FROM users WHERE is_active = true")
    Mono<Long> countActiveUsers();

    /**
     * Update user's last login time
     * R2DBC doesn't support @Modifying queries as elegantly, so this returns the updated count
     */
    @Query("UPDATE users SET last_login = :lastLogin WHERE id = :userId")
    Mono<Integer> updateLastLogin(@Param("userId") UUID userId, @Param("lastLogin") LocalDateTime lastLogin);

    /**
     * Deactivate user account
     */
    @Query("UPDATE users SET is_active = false WHERE id = :userId")
    Mono<Integer> deactivateUser(@Param("userId") UUID userId);

    /**
     * Reactivate user account
     */
    @Query("UPDATE users SET is_active = true WHERE id = :userId")
    Mono<Integer> reactivateUser(@Param("userId") UUID userId);

    /**
     * Find users created within a date range
     */
    @Query("SELECT u.* FROM users u WHERE u.created_at BETWEEN :startDate AND :endDate ORDER BY u.created_at DESC")
    Flux<User> findUsersCreatedBetween(@Param("startDate") LocalDateTime startDate, @Param("endDate") LocalDateTime endDate);

    /**
     * Search users by username pattern (case-insensitive)
     */
    @Query("SELECT u.* FROM users u WHERE LOWER(u.username) LIKE LOWER(CONCAT('%', :pattern, '%')) AND u.is_active = true")
    Flux<User> searchUsersByUsernamePattern(@Param("pattern") String pattern);

    /**
     * Find users with specific email domain
     */
    @Query("SELECT u.* FROM users u WHERE u.email LIKE CONCAT('%@', :domain) AND u.is_active = true")
    Flux<User> findUsersByEmailDomain(@Param("domain") String domain);

    /**
     * Get user statistics for admin dashboard
     */
    @Query("""
        SELECT 
            COUNT(*) as total_users,
            COUNT(CASE WHEN is_active = true THEN 1 END) as active_users,
            COUNT(CASE WHEN last_login > :recentThreshold THEN 1 END) as recent_users
        FROM users
        """)
    Mono<UserStats> getUserStatistics(@Param("recentThreshold") LocalDateTime recentThreshold);

    /**
     * Custom result class for user statistics
     * Note: In a real implementation, you might want to create a separate record/class for this
     */
    interface UserStats {
        Long getTotalUsers();
        Long getActiveUsers();
        Long getRecentUsers();
    }
}