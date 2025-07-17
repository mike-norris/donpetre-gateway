package com.openrangelabs.donpetre.gateway.entity;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.Transient;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.util.*;

/**
 * Role entity for R2DBC (reactive database operations)
 * R2DBC doesn't support complex relationships, so user associations are handled separately
 */
@Table("roles")
public class Role {

    @Id
    private UUID id;

    @Column("name")
    private String name;

    @Column("description")
    private String description;

    // R2DBC doesn't support @ManyToMany relationships
    // Users will be loaded separately and set via service layer
    @Transient
    private Set<User> users = new HashSet<>();

    // Constructors
    public Role() {}

    public Role(String name, String description) {
        this.name = name;
        this.description = description;
    }

    public Role(String name) {
        this.name = name;
    }

    // Getters and Setters
    public UUID getId() { return id; }
    public void setId(UUID id) { this.id = id; }

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }

    public Set<User> getUsers() { return users; }
    public void setUsers(Set<User> users) { this.users = users != null ? users : new HashSet<>(); }

    // Helper methods for user management (work with transient users set)
    public void addUser(User user) {
        if (user != null) {
            this.users.add(user);
        }
    }

    public void removeUser(User user) {
        if (user != null) {
            this.users.remove(user);
        }
    }

    public boolean hasUser(UUID userId) {
        return users.stream()
                .anyMatch(user -> Objects.equals(user.getId(), userId));
    }

    public int getUserCount() {
        return users.size();
    }

    // For reactive contexts, create a copy with users populated
    public Role withUsers(Set<User> newUsers) {
        Role roleWithUsers = new Role();
        roleWithUsers.id = this.id;
        roleWithUsers.name = this.name;
        roleWithUsers.description = this.description;
        roleWithUsers.users = newUsers != null ? new HashSet<>(newUsers) : new HashSet<>();
        return roleWithUsers;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Role role = (Role) o;
        return Objects.equals(name, role.name);
    }

    @Override
    public int hashCode() {
        return Objects.hash(name);
    }

    @Override
    public String toString() {
        return "Role{" +
                "id=" + id +
                ", name='" + name + '\'' +
                ", description='" + description + '\'' +
                ", userCount=" + (users != null ? users.size() : 0) +
                '}';
    }
}