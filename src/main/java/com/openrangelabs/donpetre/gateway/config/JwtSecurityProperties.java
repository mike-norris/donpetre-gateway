// src/main/java/com/openrangelabs/donpetre/gateway/config/JwtSecurityProperties.java
package com.openrangelabs.donpetre.gateway.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration properties for JWT security settings
 * Uses @ConfigurationProperties for property binding
 */
@ConfigurationProperties(prefix = "open-range-labs.donpetre.security.jwt")
public class JwtSecurityProperties {

    private String secret;
    private long expiration = 86400000L; // 24 hours default
    private long refreshExpiration = 604800000L; // 7 days default
    private int keyLength = 64; // 512 bits default
    private boolean autoGenerateSecret = false;
    private String algorithm = "HS512";
    private String encryptedSecret;
    private String backupSecret;
    private SecretStore secretStore;

    // Getters and setters
    public String getSecret() { return secret; }
    public void setSecret(String secret) { this.secret = secret; }

    public long getExpiration() { return expiration; }
    public void setExpiration(long expiration) { this.expiration = expiration; }

    public long getRefreshExpiration() { return refreshExpiration; }
    public void setRefreshExpiration(long refreshExpiration) { this.refreshExpiration = refreshExpiration; }

    public int getKeyLength() { return keyLength; }
    public void setKeyLength(int keyLength) { this.keyLength = keyLength; }

    public boolean isAutoGenerateSecret() { return autoGenerateSecret; }
    public void setAutoGenerateSecret(boolean autoGenerateSecret) { this.autoGenerateSecret = autoGenerateSecret; }

    public String getAlgorithm() { return algorithm; }
    public void setAlgorithm(String algorithm) { this.algorithm = algorithm; }

    public String getEncryptedSecret() { return encryptedSecret; }
    public void setEncryptedSecret(String encryptedSecret) { this.encryptedSecret = encryptedSecret; }

    public String getBackupSecret() { return backupSecret; }
    public void setBackupSecret(String backupSecret) { this.backupSecret = backupSecret; }

    public SecretStore getSecretStore() { return secretStore; }
    public void setSecretStore(SecretStore secretStore) { this.secretStore = secretStore; }

    /**
     * Nested configuration for external secret store settings
     */
    public static class SecretStore {
        private boolean enabled = false;
        private String name;
        private String provider;

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }

        public String getName() { return name; }
        public void setName(String name) { this.name = name; }

        public String getProvider() { return provider; }
        public void setProvider(String provider) { this.provider = provider; }
    }

    @Override
    public String toString() {
        return "JwtSecurityProperties{" +
                "expiration=" + expiration +
                ", refreshExpiration=" + refreshExpiration +
                ", keyLength=" + keyLength +
                ", autoGenerateSecret=" + autoGenerateSecret +
                ", algorithm='" + algorithm + '\'' +
                ", secretStore=" + secretStore +
                '}';
    }
}