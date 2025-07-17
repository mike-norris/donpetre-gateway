#!/bin/bash
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

echo '''
export JWT_SECRET_KEY="your-secure-base64-secret"
export JWT_BACKUP_SECRET="your-backup-base64-secret"
export JWT_ALGORITHM="HS512"
export DB_PASSWORD="your-secure-db-password"
export REDIS_PASSWORD="your-secure-redis-password"
'''