#!/bin/bash
# scripts/generate-secrets.sh - Script to generate secure secrets

set -euo pipefail

SECRETS_DIR="./secrets"
BACKUP_DIR="./secrets/backup"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Create secrets directory
mkdir -p "$SECRETS_DIR"
mkdir -p "$BACKUP_DIR"

# Set restrictive permissions on secrets directory
chmod 700 "$SECRETS_DIR"

echo -e "${GREEN}🔐 Generating secure secrets for JWT and database...${NC}"

# Function to generate secure JWT secret (hex format - no spaces or special chars)
generate_jwt_secret() {
    local output_file=$1
    local bytes=$2

    # Generate hex secret (guaranteed no spaces or special characters)
    openssl rand -hex "$bytes" > "$output_file"
    chmod 600 "$output_file"
    echo -e "${GREEN}✓ Generated JWT secret: $output_file ($(($bytes * 2)) hex chars)${NC}"
}

# Function to generate secure random string for other secrets
generate_secure_string() {
    local length=$1
    local output_file=$2

    # Generate base64 and clean it up to avoid problematic characters
    openssl rand -base64 $((length * 3 / 4)) | tr -d "=+/\n " | cut -c1-$length > "$output_file"
    chmod 600 "$output_file"
    echo -e "${GREEN}✓ Generated secure string: $output_file (${length} chars)${NC}"
}

# Function to generate database password
generate_db_password() {
    local output_file="$SECRETS_DIR/db_password.txt"

    # Generate a 32-character password with alphanumeric characters only
    openssl rand -base64 32 | tr -d "=+/\n " | cut -c1-32 > "$output_file"
    chmod 600 "$output_file"
    echo -e "${GREEN}✓ Generated database password: $output_file${NC}"
}

# Function to backup existing secrets
backup_existing_secrets() {
    if [ -f "$SECRETS_DIR/jwt_secret.txt" ]; then
        echo -e "${YELLOW}⚠️  Backing up existing secrets...${NC}"
        local timestamp=$(date +%Y%m%d_%H%M%S)
        cp "$SECRETS_DIR"/*.txt "$BACKUP_DIR/" 2>/dev/null || true
        echo -e "${GREEN}✓ Existing secrets backed up to $BACKUP_DIR${NC}"
    fi
}

# Function to validate secret strength
validate_secret() {
    local secret_file=$1
    local min_length=$2

    if [ ! -f "$secret_file" ]; then
        echo -e "${RED}❌ Secret file not found: $secret_file${NC}"
        return 1
    fi

    local secret_length=$(wc -c < "$secret_file" | tr -d ' ')
    if [ "$secret_length" -lt "$min_length" ]; then
        echo -e "${RED}❌ Secret too short: $secret_length chars (minimum: $min_length)${NC}"
        return 1
    fi

    # Check for spaces (which cause Docker issues)
    if grep -q " " "$secret_file"; then
        echo -e "${RED}❌ Secret contains spaces: $secret_file${NC}"
        return 1
    fi

    echo -e "${GREEN}✓ Secret validation passed: $secret_file${NC}"
    return 0
}

# Main secret generation
main() {
    echo -e "${GREEN}🚀 Starting secret generation process...${NC}"

    # Check if running as root (not recommended)
    if [ "$EUID" -eq 0 ]; then
        echo -e "${YELLOW}⚠️  Running as root. Consider using a non-root user for better security.${NC}"
    fi

    # Backup existing secrets
    backup_existing_secrets

    # Generate database password (32 characters, alphanumeric)
    echo -e "${GREEN}📊 Generating database password...${NC}"
    generate_db_password

    # Generate JWT primary secret (64 bytes = 128 hex characters for HS512)
    echo -e "${GREEN}🔑 Generating JWT primary secret (128 hex chars for 64 bytes)...${NC}"
    generate_jwt_secret "$SECRETS_DIR/jwt_secret.txt" 64

    # Generate JWT backup secret for key rotation
    echo -e "${GREEN}🔄 Generating JWT backup secret...${NC}"
    generate_jwt_secret "$SECRETS_DIR/jwt_backup_secret.txt" 64

    # Generate Redis password (32 characters, clean)
    echo -e "${GREEN}🗄️  Generating Redis password...${NC}"
    generate_secure_string 32 "$SECRETS_DIR/redis_password.txt"

    # Validate generated secrets
    echo -e "${GREEN}✅ Validating generated secrets...${NC}"
    validate_secret "$SECRETS_DIR/jwt_secret.txt" 64
    validate_secret "$SECRETS_DIR/jwt_backup_secret.txt" 64
    validate_secret "$SECRETS_DIR/db_password.txt" 16
    validate_secret "$SECRETS_DIR/redis_password.txt" 16

    # Set final permissions
    chmod -R 600 "$SECRETS_DIR"/*.txt

    echo -e "${GREEN}🎉 Secret generation completed successfully!${NC}"
    echo -e "${YELLOW}⚠️  Important Security Notes:${NC}"
    echo -e "   • Store these secrets securely and never commit them to version control"
    echo -e "   • Use environment variables or secret management systems in production"
    echo -e "   • Rotate secrets regularly"
    echo -e "   • Consider using tools like HashiCorp Vault, AWS Secrets Manager, or Azure Key Vault"
    echo ""
    echo -e "${GREEN}📋 Generated files:${NC}"
    ls -la "$SECRETS_DIR"/*.txt
    echo ""
    echo -e "${GREEN}🔧 Next steps:${NC}"
    echo -e "   1. Review the generated secrets"
    echo -e "   2. Update your environment variables or docker-compose.yml"
    echo -e "   3. Test the application with new secrets"
    echo -e "   4. Remove old secrets after successful deployment"
    echo ""
    echo -e "${GREEN}📝 Export commands for immediate use:${NC}"
    echo -e "   export JWT_SECRET_KEY=\"\$(cat $SECRETS_DIR/jwt_secret.txt)\""
    echo -e "   export JWT_BACKUP_SECRET=\"\$(cat $SECRETS_DIR/jwt_backup_secret.txt)\""
    echo -e "   export DB_PASSWORD=\"\$(cat $SECRETS_DIR/db_password.txt)\""
    echo -e "   export REDIS_PASSWORD=\"\$(cat $SECRETS_DIR/redis_password.txt)\""
}

# Help function
show_help() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Generate secure secrets for the Knowledge Platform API Gateway"
    echo ""
    echo "Options:"
    echo "  -h, --help     Show this help message"
    echo "  --force        Force regeneration even if secrets exist"
    echo "  --validate     Only validate existing secrets"
    echo ""
    echo "Examples:"
    echo "  $0                    # Generate secrets interactively"
    echo "  $0 --force           # Force regenerate all secrets"
    echo "  $0 --validate        # Validate existing secrets"
    echo ""
    echo "🔐 JWT Secret Format:"
    echo "  • Primary & Backup: 128 hex characters (64 bytes for HS512)"
    echo "  • Database: 32 alphanumeric characters"
    echo "  • Redis: 32 alphanumeric characters"
    echo "  • All secrets are free of spaces and special characters"
}

# Parse command line arguments
case "${1:-}" in
    -h|--help)
        show_help
        exit 0
        ;;
    --force)
        echo -e "${YELLOW}🔄 Force regenerating secrets...${NC}"
        main
        ;;
    --validate)
        echo -e "${GREEN}🔍 Validating existing secrets...${NC}"
        validate_secret "$SECRETS_DIR/jwt_secret.txt" 64
        validate_secret "$SECRETS_DIR/jwt_backup_secret.txt" 64
        validate_secret "$SECRETS_DIR/db_password.txt" 16
        validate_secret "$SECRETS_DIR/redis_password.txt" 16
        echo -e "${GREEN}✅ Validation completed${NC}"
        ;;
    "")
        # Check if secrets already exist
        if [ -f "$SECRETS_DIR/jwt_secret.txt" ]; then
            echo -e "${YELLOW}⚠️  Secrets already exist. Use --force to regenerate or --validate to check them.${NC}"
            exit 1
        fi
        main
        ;;
    *)
        echo -e "${RED}❌ Unknown option: $1${NC}"
        show_help
        exit 1
        ;;
esac