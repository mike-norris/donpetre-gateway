package com.openrangelabs.donpetre.gateway.repository;

import com.openrangelabs.donpetre.gateway.entity.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.Set;
import java.util.UUID;

@Repository
public interface RoleRepository extends JpaRepository<Role, UUID> {

    Optional<Role> findByName(String name);

    boolean existsByName(String name);

    @Query("SELECT r FROM Role r WHERE r.name IN :roleNames")
    Set<Role> findByNameIn(Set<String> roleNames);

    @Query("SELECT r FROM Role r ORDER BY r.name")
    Set<Role> findAllOrderByName();
}