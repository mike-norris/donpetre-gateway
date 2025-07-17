#!/bin/bash
# Quick fix for the immediate Docker build issue

echo "🔧 Quick Fix: Building JAR file first..."

# Step 1: Make scripts executable
chmod +x scripts/generate-secrets.sh 2>/dev/null || echo "Script not found, will create secrets manually"

# Step 2: Create secrets directory and basic secrets
mkdir -p secrets
if [ ! -f "secrets/jwt_secret.txt" ]; then
    echo "🔐 Generating basic secrets..."
    openssl rand -base64 88 > secrets/jwt_secret.txt
    openssl rand -base64 88 > secrets/jwt_backup_secret.txt
    openssl rand -base64 32 > secrets/db_password.txt
    openssl rand -base64 32 > secrets/redis_password.txt
    chmod 600 secrets/*.txt
    echo "✓ Secrets generated"
fi

# Step 3: Build the Maven project
echo "🔨 Building Maven project..."
./mvnw clean package -DskipTests

# Check if JAR was built
if [ -f "target/api-gateway-1.0.0-SNAPSHOT.jar" ]; then
    echo "✓ JAR file built successfully: $(ls -lh target/api-gateway-1.0.0-SNAPSHOT.jar)"

    # Step 4: Now start Docker
    echo "🐳 Starting Docker services..."
    docker-compose down --remove-orphans
    docker-compose up -d --build

    echo "⏳ Waiting for services to start..."
    sleep 30

    echo "📊 Checking service status..."
    docker-compose ps

    echo "🧪 Testing health endpoint..."
    curl -f http://localhost:8080/actuator/health 2>/dev/null && echo "✓ API Gateway is healthy!" || echo "⚠️ API Gateway not ready yet, check logs: docker-compose logs api-gateway"

else
    echo "❌ JAR file not found. Build failed."
    echo "Check the Maven build output above for errors."
    exit 1
fi