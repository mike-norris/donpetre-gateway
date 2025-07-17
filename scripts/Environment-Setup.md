# Secure JWT Secret Management Setup Guide

## Overview

This guide implements enterprise-grade secret management for JWT tokens in your Spring Boot 3.4 API Gateway, replacing the insecure hardcoded secrets with a multi-layered security approach.

## 🔐 Security Features Implemented

### 1. **Multi-Source Secret Resolution**
- Environment variables (highest priority)
- Docker secrets
- External secret stores (AWS/Azure/Vault)
- Encrypted configuration properties
- Secure fallback generation (dev only)

### 2. **Enhanced JWT Security**
- HS512 algorithm with 512-bit keys
- Secret strength validation
- Key rotation support
- Token type validation
- Issuer validation
- Unique token IDs for tracking

### 3. **Operational Security**
- Automatic secret backup
- Secret validation scripts
- Secure file permissions
- Audit logging

## 🚀 Quick Setup

### Step 1: Generate Secrets
```bash
# Make the script executable
chmod +x scripts/generate-secrets.sh

# Generate all secrets
./scripts/generate-secrets.sh

# Or force regenerate if secrets exist
./scripts/generate-secrets.sh --force
```

### Step 2: Environment Variables Setup

#### Development (.env file)
```bash
# Create .env file for development
cat > .env << EOF
# JWT Configuration
JWT_SECRET_KEY=$(cat secrets/jwt_secret.txt)
JWT_BACKUP_SECRET=$(cat secrets/jwt_backup_secret.txt)
JWT_ALGORITHM=HS512

# Database
DB_PASSWORD=$(cat secrets/db_password.txt)

# Redis
REDIS_PASSWORD=$(cat secrets/redis_password.txt)

# CORS
CORS_ALLOWED_ORIGINS=http://localhost:3000,http://localhost:8080,http://localhost:8084
EOF
```

#### Production Environment Variables
```bash
# Set these in your production environment
export JWT_SECRET_KEY="your-secure-base64-secret"
export JWT_BACKUP_SECRET="your-backup-base64-secret"
export JWT_ALGORITHM="HS512"
export DB_PASSWORD="your-secure-db-password"
export REDIS_PASSWORD="your-secure-redis-password"
```

### Step 3: Docker Deployment
```bash
# Use the secure docker-compose.yml
docker-compose up -d

# Or for production with external secrets
docker-compose -f docker-compose.prod.yml up -d
```

## 🏗️ Architecture Changes

### Original vs. Enhanced Security

| Aspect | Before | After |
|--------|---------|--------|
| Secret Storage | Hardcoded in YAML | Environment variables + Docker secrets |
| Key Algorithm | HS256 | HS512 (configurable) |
| Secret Validation | None | Strength validation + pattern detection |
| Key Rotation | Not supported | Backup key support |
| Token Security | Basic | Enhanced with issuer, type, ID validation |
| Development | Exposed secrets | Auto-generation with warnings |

### JWT Token Structure (Enhanced)
```json
{
  "sub": "username",
  "iss": "donpetre-api-gateway",
  "iat": 1640995200,
  "exp": 1641081600,
  "jti": "unique-token-id",
  "token_type": "access|refresh",
  "key_id": "key-123"
}
```

## 🔧 Configuration Reference

### Application Properties
```yaml
open-range-labs:
  donpetre:
    security:
      jwt:
        # Primary secret sources (in priority order)
        secret: ${JWT_SECRET:}                    # Legacy fallback
        encrypted-secret: ${JWT_ENCRYPTED_SECRET:} # Encrypted property
        
        # Token configuration
        expiration: 86400000                      # 24 hours
        refresh-expiration: 604800000             # 7 days
        algorithm: HS512                          # HS256 or HS512
        key-length: 64                            # 64 bytes for HS512
        
        # Security settings
        auto-generate-secret: false               # Only true in dev
        
        # External secret store
        secret-store:
          enabled: false
          name: "jwt-secrets"
          provider: "aws"                         # aws, azure, vault
        
        # Key rotation
        backup-secret: ${JWT_BACKUP_SECRET:}
```

## 🔒 External Secret Store Integration

### AWS Secrets Manager
```java
// Add to your JwtSecurityConfig.java
private String loadFromAwsSecretsManager() {
    try {
        SecretsManagerClient client = SecretsManagerClient.builder()
                .region(Region.US_EAST_1)
                .build();
        
        GetSecretValueRequest request = GetSecretValueRequest.builder()
                .secretId("jwt-secret-key")
                .build();
        
        GetSecretValueResponse response = client.getSecretValue(request);
        return response.secretString();
    } catch (Exception e) {
        logger.warn("Failed to load secret from AWS Secrets Manager", e);
        return null;
    }
}
```

### Azure Key Vault
```java
// Add Azure Key Vault dependency and configuration
private String loadFromAzureKeyVault() {
    try {
        SecretClient secretClient = new SecretClientBuilder()
                .vaultUrl("https://your-vault.vault.azure.net/")
                .credential(new DefaultAzureCredentialBuilder().build())
                .buildClient();
        
        KeyVaultSecret secret = secretClient.getSecret("jwt-secret-key");
        return secret.getValue();
    } catch (Exception e) {
        logger.warn("Failed to load secret from Azure Key Vault", e);
        return null;
    }
}
```

### HashiCorp Vault
```java
// Add Vault dependency and configuration
private String loadFromHashiCorpVault() {
    try {
        VaultTemplate vaultTemplate = new VaultTemplate(
                VaultEndpoint.create("localhost", 8200),
                new TokenAuthentication("your-token")
        );
        
        VaultResponse response = vaultTemplate.read("secret/jwt");
        return (String) response.getData().get("secret-key");
    } catch (Exception e) {
        logger.warn("Failed to load secret from HashiCorp Vault", e);
        return null;
    }
}
```

## 🛡️ Security Best Practices

### 1. **Secret Rotation Schedule**
```bash
# Rotate secrets monthly
0 0 1 * * /path/to/rotate-secrets.sh

# Backup old secrets before rotation
# Test with backup key before full rotation
# Update all instances simultaneously
```

### 2. **Monitoring and Alerting**
- Monitor failed JWT validations
- Alert on secret access failures
- Track key usage patterns
- Log secret rotation events

### 3. **Access Control**
```bash
# File permissions for secrets
chmod 600 secrets/*.txt
chown app:app secrets/*.txt

# Environment variable access
# Use init containers or secret management operators in K8s
```

## 🧪 Testing the Implementation

### Validate Secret Strength
```bash
# Check existing secrets
./scripts/generate-secrets.sh --validate

# Test with weak secret (should fail)
echo "weak" > secrets/test_weak.txt
```

### Test JWT Generation
```bash
# Start the application
./mvnw spring-boot:run

# Test authentication endpoint
curl -X POST http://localhost:8080/api/auth/authenticate \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"testpass"}'

# Verify JWT structure
echo "JWT_TOKEN" | cut -d. -f2 | base64 -d | jq .
```

### Key Rotation Testing
```bash
# Generate new backup secret
./scripts/generate-secrets.sh --force

# Update JWT_BACKUP_SECRET environment variable
# Test token validation with both keys
```

## 🚨 Migration from Existing Setup

### Step 1: Backup Current State
```bash
# Backup current configuration
cp src/main/resources/application.yml application.yml.backup
cp docker-compose.yml docker-compose.yml.backup
```

### Step 2: Gradual Migration
```bash
# 1. Deploy with backup secret support
# 2. Rotate to new primary secret
# 3. Update backup secret
# 4. Remove old secret references
```

### Step 3: Verify Migration
```bash
# Test existing tokens still work
# Generate new tokens with new secret
# Confirm no service disruption
```

## 🔍 Troubleshooting

### Common Issues

1. **"JWT secret cannot be null or empty"**
    - Check JWT_SECRET_KEY environment variable
    - Verify secret file permissions
    - Ensure secret generation completed successfully

2. **"Token signature validation failed"**
    - Verify secret matches between services
    - Check key rotation timing
    - Validate secret encoding (Base64)

3. **"JWT secret must be at least 64 bytes"**
    - Regenerate secrets with proper length
    - Use HS512 algorithm with 64-byte keys
    - Avoid manual secret creation

### Debug Commands
```bash
# Check secret file contents (be careful with output)
wc -c secrets/jwt_secret.txt

# Verify environment variables (in development only)
echo $JWT_SECRET_KEY | wc -c

# Test JWT parsing
java -jar jwt-cli.jar decode YOUR_JWT_TOKEN
```

## 📚 Additional Resources

- [Spring Boot Security Documentation](https://spring.io/guides/topicals/spring-security-architecture)
- [JWT Best Practices](https://tools.ietf.org/html/rfc8725)
- [OWASP JWT Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [Docker Secrets Management](https://docs.docker.com/engine/swarm/secrets/)

---

## ⚡ Next Steps

1. **Implement Account Security Features**
    - Account lockout after failed attempts
    - Password reset functionality
    - Email verification

2. **Add Token Blacklisting**
    - Redis-based token blacklist
    - Logout token invalidation
    - Security event token revocation

3. **Enhanced Monitoring**
    - JWT validation metrics
    - Secret access logging
    - Suspicious activity detection

This implementation provides enterprise-grade JWT secret management while maintaining compatibility with your existing Spring Boot 3.4 architecture. The multi-layered approach ensures security in development, staging, and production environments.