package com.openrangelabs.donpetre.gateway.service;

import com.openrangelabs.donpetre.gateway.entity.Role;
import com.openrangelabs.donpetre.gateway.entity.User;
import com.openrangelabs.donpetre.gateway.repository.RoleRepository;
import com.openrangelabs.donpetre.gateway.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.r2dbc.core.R2dbcEntityTemplate;
import org.springframework.data.relational.core.query.Criteria;
import org.springframework.data.relational.core.query.Query;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.Set;
import java.util.UUID;

/**
 * Service to handle User-Role relationships in R2DBC
 * Since R2DBC doesn't support @ManyToMany, we manage the junction table manually
 */
@Slf4j
@Service
public class UserRoleService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final DatabaseClient databaseClient;
    private final R2dbcEntityTemplate r2dbcTemplate;

    @Autowired
    public UserRoleService(
            UserRepository userRepository,
            RoleRepository roleRepository,
            DatabaseClient databaseClient,
            R2dbcEntityTemplate r2dbcTemplate) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.databaseClient = databaseClient;
        this.r2dbcTemplate = r2dbcTemplate;
    }

    /**
     * Load user with all their roles populated
     */
    public Mono<User> loadUserWithRoles(UUID userId) {
        log.debug("UserRoleService.loadUserWithRoles called for userId: {}", userId);
        return userRepository.findById(userId)
                .doOnNext(user -> log.debug("User found by ID: {}, isActive: {}", user.getUsername(), user.getIsActive()))
                .doOnError(error -> log.error("Error finding user by ID {}: {}", userId, error.getMessage()))
                .flatMap(user -> {
                    log.debug("Loading roles for user: {}", user.getUsername());
                    return roleRepository.findRolesByUserId(userId)
                            .doOnNext(role -> log.debug("Role found for user {}: {}", user.getUsername(), role.getName()))
                            .collect(java.util.stream.Collectors.toSet())
                            .doOnNext(roles -> log.debug("Total roles loaded for user {}: {}", user.getUsername(), roles.size()))
                            .map(user::withRoles)
                            .doOnNext(userWithRoles -> log.debug("User with roles created: {}, roles: {}", 
                                userWithRoles.getUsername(), userWithRoles.getRoles().size()));
                })
                .doOnError(error -> log.error("Error loading user with roles for userId {}: {}", userId, error.getMessage()));
    }

    /**
     * Load user with roles by username
     */
    public Mono<User> loadUserWithRolesByUsername(String username) {
        log.debug("UserRoleService.loadUserWithRolesByUsername called for username: {}", username);
        return userRepository.findByUsername(username)
                .doOnNext(user -> log.debug("User found by username: {}, ID: {}, isActive: {}", 
                    user.getUsername(), user.getId(), user.getIsActive()))
                .doOnError(error -> log.error("Error finding user by username {}: {}", username, error.getMessage()))
                .switchIfEmpty(Mono.defer(() -> {
                    log.warn("User not found by username: {}", username);
                    return Mono.empty();
                }))
                .flatMap(user -> {
                    log.debug("Loading roles for user: {} (ID: {})", user.getUsername(), user.getId());
                    return roleRepository.findRolesByUserId(user.getId())
                            .doOnNext(role -> log.debug("Role found for user {}: {} (ID: {})", 
                                user.getUsername(), role.getName(), role.getId()))
                            .collect(java.util.stream.Collectors.toSet())
                            .doOnNext(roles -> log.debug("Total roles loaded for user {}: {}", user.getUsername(), roles.size()))
                            .map(user::withRoles)
                            .doOnNext(userWithRoles -> {
                                log.debug("User with roles created: {}, roles: {}, authorities: {}", 
                                    userWithRoles.getUsername(), 
                                    userWithRoles.getRoles().size(),
                                    userWithRoles.getAuthorities().size());
                                userWithRoles.getRoles().forEach(role -> 
                                    log.debug("  - Role: {}", role.getName()));
                            });
                })
                .doOnError(error -> log.error("Error loading user with roles for username {}: {}", username, error.getMessage()));
    }

    /**
     * Load role with all users who have this role
     */
    public Mono<Role> loadRoleWithUsers(UUID roleId) {
        return roleRepository.findById(roleId)
                .flatMap(role ->
                        userRepository.findActiveUsersByRoleName(role.getName())
                                .collect(java.util.stream.Collectors.toSet())
                                .map(role::withUsers)
                );
    }

    /**
     * Assign role to user
     */
    public Mono<Void> assignRoleToUser(UUID userId, UUID roleId) {
        return databaseClient.sql("""
                INSERT INTO user_roles (user_id, role_id) 
                VALUES (:userId, :roleId) 
                ON CONFLICT (user_id, role_id) DO NOTHING
                """)
                .bind("userId", userId)
                .bind("roleId", roleId)
                .then();
    }

    /**
     * Assign role to user by names
     */
    public Mono<Void> assignRoleToUser(String username, String roleName) {
        return userRepository.findByUsername(username)
                .zipWith(roleRepository.findByName(roleName))
                .flatMap(tuple -> assignRoleToUser(tuple.getT1().getId(), tuple.getT2().getId()));
    }

    /**
     * Remove role from user
     */
    public Mono<Void> removeRoleFromUser(UUID userId, UUID roleId) {
        return databaseClient.sql("DELETE FROM user_roles WHERE user_id = :userId AND role_id = :roleId")
                .bind("userId", userId)
                .bind("roleId", roleId)
                .then();
    }

    /**
     * Remove role from user by names
     */
    public Mono<Void> removeRoleFromUser(String username, String roleName) {
        return userRepository.findByUsername(username)
                .zipWith(roleRepository.findByName(roleName))
                .flatMap(tuple -> removeRoleFromUser(tuple.getT1().getId(), tuple.getT2().getId()));
    }

    /**
     * Remove all roles from user
     */
    public Mono<Void> removeAllRolesFromUser(UUID userId) {
        return databaseClient.sql("DELETE FROM user_roles WHERE user_id = :userId")
                .bind("userId", userId)
                .then();
    }

    /**
     * Set user roles (replaces all existing roles)
     */
    public Mono<Void> setUserRoles(UUID userId, Set<UUID> roleIds) {
        return removeAllRolesFromUser(userId)
                .then(Flux.fromIterable(roleIds)
                        .flatMap(roleId -> assignRoleToUser(userId, roleId))
                        .then());
    }

    /**
     * Check if user has specific role
     */
    public Mono<Boolean> userHasRole(UUID userId, String roleName) {
        return databaseClient.sql("""
                SELECT EXISTS(
                    SELECT 1 FROM user_roles ur 
                    INNER JOIN roles r ON ur.role_id = r.id 
                    WHERE ur.user_id = :userId AND r.name = :roleName
                )
                """)
                .bind("userId", userId)
                .bind("roleName", roleName)
                .map(row -> (Boolean) row.get(0))
                .one();
    }

    /**
     * Get all users with a specific role
     */
    public Flux<User> getUsersWithRole(String roleName) {
        return userRepository.findActiveUsersByRoleName(roleName);
    }

    /**
     * Get role statistics
     */
    public Mono<RoleStats> getRoleStatistics() {
        return databaseClient.sql("""
                SELECT 
                    r.name,
                    r.description,
                    COUNT(ur.user_id) as user_count
                FROM roles r 
                LEFT JOIN user_roles ur ON r.id = ur.role_id 
                GROUP BY r.id, r.name, r.description
                ORDER BY user_count DESC
                """)
                .map(row -> new RoleStats(
                        (String) row.get("name"),
                        (String) row.get("description"),
                        ((Number) row.get("user_count")).longValue()
                ))
                .all()
                .collectList()
                .map(list -> new RoleStats("summary", "Total roles: " + list.size(),
                        list.stream().mapToLong(RoleStats::userCount).sum()));
    }

    /**
     * Create user with default role
     */
    public Mono<User> createUserWithDefaultRole(User user) {
        return userRepository.save(user)
                .flatMap(savedUser ->
                        roleRepository.findByName("USER")
                                .switchIfEmpty(createDefaultUserRole())
                                .flatMap(role -> assignRoleToUser(savedUser.getId(), role.getId())
                                        .thenReturn(savedUser.withRoles(Set.of(role))))
                );
    }

    /**
     * Create default USER role if it doesn't exist
     */
    private Mono<Role> createDefaultUserRole() {
        Role defaultRole = new Role("USER", "Default user role");
        return roleRepository.save(defaultRole);
    }

    /**
     * Simple record for role statistics
     */
    public record RoleStats(String roleName, String description, Long userCount) {}
}