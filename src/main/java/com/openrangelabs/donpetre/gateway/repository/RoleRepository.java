package com.openrangelabs.donpetre.gateway.repository;

import com.openrangelabs.donpetre.gateway.entity.Role;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.r2dbc.repository.R2dbcRepository;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.Set;
import java.util.UUID;

/**
 * Reactive RoleRepository using R2DBC for non-blocking database operations
 */
@Repository
public interface RoleRepository extends R2dbcRepository<Role, UUID> {

    /**
     * Find role by name
     */
    Mono<Role> findByName(String name);

    /**
     * Check if role exists by name
     */
    Mono<Boolean> existsByName(String name);

    /**
     * Find roles by name list (for bulk operations)
     */
    @Query("SELECT * FROM roles WHERE name = ANY(:roleNames)")
    Flux<Role> findByNameIn(@Param("roleNames") String[] roleNames);

    /**
     * Find all roles ordered by name
     */
    @Query("SELECT * FROM roles ORDER BY name")
    Flux<Role> findAllOrderByName();

    /**
     * Find roles assigned to a specific user
     */
    @Query("""
        SELECT r.* FROM roles r 
        INNER JOIN user_roles ur ON r.id = ur.role_id 
        WHERE ur.user_id = :userId
        """)
    Flux<Role> findRolesByUserId(@Param("userId") UUID userId);

    /**
     * Count users with a specific role
     */
    @Query("""
        SELECT COUNT(ur.user_id) FROM user_roles ur 
        INNER JOIN roles r ON ur.role_id = r.id 
        WHERE r.name = :roleName
        """)
    Mono<Long> countUsersByRoleName(@Param("roleName") String roleName);

    /**
     * Find roles that have no users assigned
     */
    @Query("""
        SELECT r.* FROM roles r 
        LEFT JOIN user_roles ur ON r.id = ur.role_id 
        WHERE ur.role_id IS NULL
        """)
    Flux<Role> findUnassignedRoles();

    /**
     * Search roles by name pattern (case-insensitive)
     */
    @Query("SELECT * FROM roles WHERE LOWER(name) LIKE LOWER(CONCAT('%', :pattern, '%'))")
    Flux<Role> searchRolesByNamePattern(@Param("pattern") String pattern);

    /**
     * Find roles with description containing keyword
     */
    @Query("SELECT * FROM roles WHERE LOWER(description) LIKE LOWER(CONCAT('%', :keyword, '%'))")
    Flux<Role> findRolesByDescriptionKeyword(@Param("keyword") String keyword);
}