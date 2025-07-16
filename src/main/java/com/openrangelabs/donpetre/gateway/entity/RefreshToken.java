package com.openrangelabs.donpetre.gateway.entity;

import jakarta.persistence.*;

import java.time.LocalDateTime;
import java.util.*;

@Entity
@Table(name = "refresh_tokens")
public class RefreshToken {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(unique = true, nullable = false, length = 512)
    private String token;

    @Column(name = "expiry_date", nullable = false)
    private LocalDateTime expiryDate;

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", referencedColumnName = "id")
    private User user;

    @Column(name = "created_at")
    private LocalDateTime createdAt = LocalDateTime.now();

    @Column(name = "last_used")
    private LocalDateTime lastUsed;

    @Column(name = "device_info")
    private String deviceInfo; // Optional: store device/browser info

    // Constructors
    public RefreshToken() {}

    public RefreshToken(String token, LocalDateTime expiryDate, User user) {
        this.token = token;
        this.expiryDate = expiryDate;
        this.user = user;
    }

    public RefreshToken(String token, LocalDateTime expiryDate, User user, String deviceInfo) {
        this.token = token;
        this.expiryDate = expiryDate;
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

    // Getters and Setters
    public UUID getId() { return id; }
    public void setId(UUID id) { this.id = id; }

    public String getToken() { return token; }
    public void setToken(String token) { this.token = token; }

    public LocalDateTime getExpiryDate() { return expiryDate; }
    public void setExpiryDate(LocalDateTime expiryDate) { this.expiryDate = expiryDate; }

    public User getUser() { return user; }
    public void setUser(User user) { this.user = user; }

    public LocalDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }

    public LocalDateTime getLastUsed() { return lastUsed; }
    public void setLastUsed(LocalDateTime lastUsed) { this.lastUsed = lastUsed; }

    public String getDeviceInfo() { return deviceInfo; }
    public void setDeviceInfo(String deviceInfo) { this.deviceInfo = deviceInfo; }

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
                ", expiryDate=" + expiryDate +
                ", createdAt=" + createdAt +
                ", lastUsed=" + lastUsed +
                ", deviceInfo='" + deviceInfo + '\'' +
                '}';
    }
}
