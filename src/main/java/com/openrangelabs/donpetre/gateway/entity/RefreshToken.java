package com.openrangelabs.donpetre.gateway.entity;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.Transient;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.LocalDateTime;
import java.util.*;

/**
 * RefreshToken entity for R2DBC (reactive database operations)
 * R2DBC uses foreign key columns instead of object references
 */
@Table("refresh_tokens")
public class RefreshToken {

    @Id
    private UUID id;

    @Column("token")
    private String token;

    @Column("expiry_date")
    private LocalDateTime expiryDate;

    @Column("user_id")
    private UUID userId;

    @Column("created_at")
    private LocalDateTime createdAt = LocalDateTime.now();

    @Column("last_used")
    private LocalDateTime lastUsed;

    @Column("device_info")
    private String deviceInfo; // Optional: store device/browser info

    // R2DBC doesn't support @OneToOne relationships
    // User will be loaded separately if needed
    @Transient
    private User user;

    // Constructors
    public RefreshToken() {}

    public RefreshToken(String token, LocalDateTime expiryDate, UUID userId) {
        this.token = token;
        this.expiryDate = expiryDate;
        this.userId = userId;
    }

    public RefreshToken(String token, LocalDateTime expiryDate, User user) {
        this.token = token;
        this.expiryDate = expiryDate;
        this.userId = user != null ? user.getId() : null;
        this.user = user;
    }

    public RefreshToken(String token, LocalDateTime expiryDate, UUID userId, String deviceInfo) {
        this.token = token;
        this.expiryDate = expiryDate;
        this.userId = userId;
        this.deviceInfo = deviceInfo;
    }

    public RefreshToken(String token, LocalDateTime expiryDate, User user, String deviceInfo) {
        this.token = token;
        this.expiryDate = expiryDate;
        this.userId = user != null ? user.getId() : null;
        this.user = user;
        this.deviceInfo = deviceInfo;
    }

    // Business logic methods
    public boolean isExpired() {
        return LocalDateTime.now().isAfter(expiryDate);
    }

    public void markAsUsed() {
        this.lastUsed = LocalDateTime.now();
    }

    public boolean isRecentlyUsed(int minutesThreshold) {
        if (lastUsed == null) return false;
        return lastUsed.isAfter(LocalDateTime.now().minusMinutes(minutesThreshold));
    }

    public boolean isExpiringSoon(int minutesThreshold) {
        return expiryDate.isBefore(LocalDateTime.now().plusMinutes(minutesThreshold));
    }

    public long getMinutesUntilExpiry() {
        return java.time.Duration.between(LocalDateTime.now(), expiryDate).toMinutes();
    }

    // Getters and Setters
    public UUID getId() { return id; }
    public void setId(UUID id) { this.id = id; }

    public String getToken() { return token; }
    public void setToken(String token) { this.token = token; }

    public LocalDateTime getExpiryDate() { return expiryDate; }
    public void setExpiryDate(LocalDateTime expiryDate) { this.expiryDate = expiryDate; }

    public UUID getUserId() { return userId; }
    public void setUserId(UUID userId) { this.userId = userId; }

    public LocalDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }

    public LocalDateTime getLastUsed() { return lastUsed; }
    public void setLastUsed(LocalDateTime lastUsed) { this.lastUsed = lastUsed; }

    public String getDeviceInfo() { return deviceInfo; }
    public void setDeviceInfo(String deviceInfo) { this.deviceInfo = deviceInfo; }

    // Transient user property (loaded separately)
    public User getUser() { return user; }
    public void setUser(User user) {
        this.user = user;
        if (user != null) {
            this.userId = user.getId();
        }
    }

    // For reactive contexts, create a copy with user populated
    public RefreshToken withUser(User newUser) {
        RefreshToken tokenWithUser = new RefreshToken();
        tokenWithUser.id = this.id;
        tokenWithUser.token = this.token;
        tokenWithUser.expiryDate = this.expiryDate;
        tokenWithUser.userId = this.userId;
        tokenWithUser.createdAt = this.createdAt;
        tokenWithUser.lastUsed = this.lastUsed;
        tokenWithUser.deviceInfo = this.deviceInfo;
        tokenWithUser.user = newUser;
        return tokenWithUser;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        RefreshToken that = (RefreshToken) o;
        return Objects.equals(token, that.token);
    }

    @Override
    public int hashCode() {
        return Objects.hash(token);
    }

    @Override
    public String toString() {
        return "RefreshToken{" +
                "id=" + id +
                ", userId=" + userId +
                ", expiryDate=" + expiryDate +
                ", createdAt=" + createdAt +
                ", lastUsed=" + lastUsed +
                ", deviceInfo='" + deviceInfo + '\'' +
                ", expired=" + isExpired() +
                '}';
    }
}