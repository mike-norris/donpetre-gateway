package com.openrangelabs.donpetre.gateway.entity;

import lombok.extern.slf4j.Slf4j;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.Transient;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

/**
 * User entity for R2DBC (reactive database operations)
 * Implements Spring Security UserDetails interface
 * Note: R2DBC doesn't support complex relationships like JPA, so roles are handled separately
 */
@Slf4j
@Table("users")
public class User implements UserDetails {

    @Id
    private UUID id;

    @Column("username")
    private String username;

    @Column("email")
    private String email;

    @Column("password")
    private String password;

    @Column("is_active")
    private Boolean isActive = true;

    @Column("created_at")
    private LocalDateTime createdAt = LocalDateTime.now();

    @Column("last_login")
    private LocalDateTime lastLogin;

    // R2DBC doesn't support @ManyToMany relationships
    // Roles will be loaded separately and set via service layer
    @Transient
    private Set<Role> roles = new HashSet<>();

    // Constructors
    public User() {}

    public User(String username, String email, String password) {
        this.username = username;
        this.email = email;
        this.password = password;
    }

    // UserDetails interface implementation
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return roles.stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role.getName().toUpperCase()))
                .collect(Collectors.toList());
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return isActive != null && isActive;
    }

    // Getters and Setters
    public UUID getId() { return id; }
    public void setId(UUID id) { this.id = id; }

    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }

    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }

    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }

    public Boolean getIsActive() { return isActive; }
    public void setIsActive(Boolean isActive) { this.isActive = isActive; }

    public LocalDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }

    public LocalDateTime getLastLogin() { return lastLogin; }
    public void setLastLogin(LocalDateTime lastLogin) { this.lastLogin = lastLogin; }

    public Set<Role> getRoles() { return roles; }
    public void setRoles(Set<Role> roles) { this.roles = roles != null ? roles : new HashSet<>(); }

    // Helper methods for role management (these work with the transient roles set)
    public void addRole(Role role) {
        if (role != null) {
            this.roles.add(role);
            // Note: R2DBC relationship management is done at service layer
        }
    }

    public void removeRole(Role role) {
        if (role != null) {
            this.roles.remove(role);
            // Note: R2DBC relationship management is done at service layer
        }
    }

    public boolean hasRole(String roleName) {
        return roles.stream()
                .anyMatch(role -> role.getName().equalsIgnoreCase(roleName));
    }

    public Set<String> getRoleNames() {
        return roles.stream()
                .map(Role::getName)
                .collect(Collectors.toSet());
    }

    // For reactive contexts, create a copy with roles populated
    public User withRoles(Set<Role> newRoles) {
        User userWithRoles = new User();
        userWithRoles.id = this.id;
        userWithRoles.username = this.username;
        userWithRoles.email = this.email;
        userWithRoles.password = this.password;
        userWithRoles.isActive = this.isActive;
        userWithRoles.createdAt = this.createdAt;
        userWithRoles.lastLogin = this.lastLogin;
        userWithRoles.roles = newRoles != null ? new HashSet<>(newRoles) : new HashSet<>();
        return userWithRoles;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        User user = (User) o;
        return Objects.equals(id, user.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }

    @Override
    public String toString() {
        return "User{" +
                "id=" + id +
                ", username='" + username + '\'' +
                ", email='" + email + '\'' +
                ", isActive=" + isActive +
                ", createdAt=" + createdAt +
                ", rolesCount=" + (roles != null ? roles.size() : 0) +
                '}';
    }
}