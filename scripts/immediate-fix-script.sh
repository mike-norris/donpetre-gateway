#!/bin/bash
# Immediate fix for bean conflicts

echo "🚨 IMMEDIATE FIX: Resolving bean name conflicts..."

# Step 1: Remove conflicting classes
echo "1️⃣ Removing conflicting JWT converter classes..."

# Remove the conflicting reactive JWT converters
rm -f "src/main/java/com/openrangelabs/donpetre/gateway/security/CustomReactiveJwtAuthenticationConverter.java"
rm -f "src/main/java/com/openrangelabs/donpetre/gateway/security/SimpleReactiveJwtAuthenticationConverter.java"

echo "✅ Removed conflicting reactive JWT converters"

# Step 2: Update the remaining JwtAuthenticationConverter to remove @Component
echo "2️⃣ Fixing JwtAuthenticationConverter..."

JWT_FILE="src/main/java/com/openrangelabs/donpetre/gateway/security/JwtAuthenticationConverter.java"
if [ -f "$JWT_FILE" ]; then
    # Remove @Component annotations
    sed -i.bak 's/@Component.*//g' "$JWT_FILE"
    sed -i.bak '/^import.*Component;/d' "$JWT_FILE"
    rm "${JWT_FILE}.bak" 2>/dev/null || true
    echo "✅ Removed @Component annotation from JwtAuthenticationConverter"
fi

# Step 3: Quick build test
echo "3️⃣ Testing the fix..."
./mvnw clean compile -q

if [ $? -eq 0 ]; then
    echo "✅ Compilation successful! Bean conflicts resolved."
    echo ""
    echo "🚀 Now you can run:"
    echo "   ./mvnw clean package -DskipTests"
    echo "   docker-compose up -d --build"
else
    echo "❌ Compilation still failing. Check the output above."
    echo ""
    echo "🔧 Manual steps may be needed:"
    echo "1. Check for any remaining @Component('customJwtConverter') annotations"
    echo "2. Ensure no duplicate bean names exist"
    echo "3. Verify import statements are correct"
fi