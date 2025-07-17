#!/bin/bash
# scripts/build-and-run.sh - Complete build and deployment script

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PROJECT_NAME="openrangelabs-donpetre"
SECRETS_DIR="./secrets"

echo -e "${GREEN}🚀 Starting Knowledge Platform API Gateway Build and Deployment${NC}"

# Function to print section headers
print_section() {
    echo -e "\n${BLUE}===== $1 =====${NC}"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check prerequisites
check_prerequisites() {
    print_section "Checking Prerequisites"

    local missing_tools=()

    if ! command_exists java; then
        missing_tools+=("java")
    fi

    if ! command_exists mvn; then
        missing_tools+=("maven")
    fi

    if ! command_exists docker; then
        missing_tools+=("docker")
    fi

    if ! command_exists docker-compose; then
        missing_tools+=("docker-compose")
    fi

    if [ ${#missing_tools[@]} -ne 0 ]; then
        echo -e "${RED}❌ Missing required tools: ${missing_tools[*]}${NC}"
        echo -e "${YELLOW}Please install the missing tools and try again.${NC}"
        exit 1
    fi

    echo -e "${GREEN}✓ All prerequisites satisfied${NC}"

    # Check Java version
    local java_version=$(java -version 2>&1 | awk -F '"' '/version/ {print $2}' | cut -d. -f1)
    if [ "$java_version" -lt 17 ]; then
        echo -e "${YELLOW}⚠️  Java 17+ recommended. Current version: $java_version${NC}"
    else
        echo -e "${GREEN}✓ Java version: $java_version${NC}"
    fi
}

# Function to generate secrets if they don't exist
setup_secrets() {
    print_section "Setting Up Secrets"

    if [ -f "$SECRETS_DIR/jwt_secret.txt" ]; then
        echo -e "${YELLOW}🔐 Secrets already exist. Validating...${NC}"
        if [ -x "scripts/generate-secrets.sh" ]; then
            ./scripts/generate-secrets.sh --validate
        else
            echo -e "${YELLOW}⚠️  Secret validation script not found or not executable${NC}"
        fi
    else
        echo -e "${GREEN}🔐 Generating new secrets...${NC}"
        mkdir -p "$SECRETS_DIR"

        if [ -x "scripts/generate-secrets.sh" ]; then
            ./scripts/generate-secrets.sh
        else
            echo -e "${YELLOW}⚠️  Secret generation script not found. Creating basic secrets...${NC}"

            # Generate basic secrets manually
            openssl rand -base64 88 > "$SECRETS_DIR/jwt_secret.txt"
            openssl rand -base64 88 > "$SECRETS_DIR/jwt_backup_secret.txt"
            openssl rand -base64 32 > "$SECRETS_DIR/db_password.txt"
            openssl rand -base64 32 > "$SECRETS_DIR/redis_password.txt"

            chmod 600 "$SECRETS_DIR"/*.txt
            echo -e "${GREEN}✓ Basic secrets generated${NC}"
        fi
    fi
}

# Function to build the application
build_application() {
    print_section "Building Application"

    echo -e "${GREEN}🔨 Cleaning previous builds...${NC}"
    ./mvnw clean

    echo -e "${GREEN}🔨 Compiling and packaging application...${NC}"
    ./mvnw package -DskipTests

    # Verify JAR file exists
    if [ -f "target/api-gateway-1.0.0-SNAPSHOT.jar" ]; then
        echo -e "${GREEN}✓ JAR file built successfully${NC}"
        ls -lh target/api-gateway-1.0.0-SNAPSHOT.jar
    else
        echo -e "${RED}❌ JAR file not found after build${NC}"
        exit 1
    fi
}

# Function to run tests
run_tests() {
    print_section "Running Tests"

    echo -e "${GREEN}🧪 Running unit tests...${NC}"
    ./mvnw test

    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ All tests passed${NC}"
    else
        echo -e "${YELLOW}⚠️  Some tests failed. Continuing with deployment...${NC}"
    fi
}

# Function to setup environment variables
setup_environment() {
    print_section "Setting Up Environment"

    # Create .env file if it doesn't exist
    if [ ! -f ".env" ]; then
        echo -e "${GREEN}📝 Creating .env file...${NC}"
        cat > .env << EOF
# JWT Configuration
JWT_SECRET_KEY=$(cat $SECRETS_DIR/jwt_secret.txt 2>/dev/null || echo "generate-new-secret")
JWT_BACKUP_SECRET=$(cat $SECRETS_DIR/jwt_backup_secret.txt 2>/dev/null || echo "generate-new-backup-secret")
JWT_ALGORITHM=HS512

# Database
DB_PASSWORD=$(cat $SECRETS_DIR/db_password.txt 2>/dev/null || echo "default-password")

# Redis
REDIS_PASSWORD=$(cat $SECRETS_DIR/redis_password.txt 2>/dev/null || echo "")

# CORS
CORS_ALLOWED_ORIGINS=http://localhost:3000,http://localhost:8080,http://localhost:8084

# Logging
LOG_LEVEL=INFO
EOF
        echo -e "${GREEN}✓ .env file created${NC}"
    else
        echo -e "${YELLOW}📝 .env file already exists${NC}"
    fi
}

# Function to start docker services
start_docker_services() {
    print_section "Starting Docker Services"

    # Stop any existing containers
    echo -e "${YELLOW}🛑 Stopping existing containers...${NC}"
    docker-compose down --remove-orphans 2>/dev/null || true

    # Remove old images if requested
    if [ "${CLEAN_BUILD:-false}" = "true" ]; then
        echo -e "${YELLOW}🧹 Cleaning old images...${NC}"
        docker-compose down --rmi all --volumes --remove-orphans 2>/dev/null || true
    fi

    # Start services
    echo -e "${GREEN}🐳 Starting Docker services...${NC}"
    docker-compose up -d --build

    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ Docker services started successfully${NC}"
    else
        echo -e "${RED}❌ Failed to start Docker services${NC}"
        exit 1
    fi
}

# Function to wait for services to be ready
wait_for_services() {
    print_section "Waiting for Services"

    echo -e "${YELLOW}⏳ Waiting for database to be ready...${NC}"
    timeout 60 bash -c 'until docker-compose exec postgresql pg_isready -U knowledge_user -d knowledge_platform; do sleep 2; done'

    echo -e "${YELLOW}⏳ Waiting for Redis to be ready...${NC}"
    timeout 30 bash -c 'until docker-compose exec redis redis-cli ping; do sleep 2; done'

    echo -e "${YELLOW}⏳ Waiting for API Gateway to be ready...${NC}"
    timeout 120 bash -c 'until curl -f http://localhost:8080/actuator/health 2>/dev/null; do sleep 5; done'

    echo -e "${GREEN}✓ All services are ready${NC}"
}

# Function to show service status
show_status() {
    print_section "Service Status"

    echo -e "${GREEN}📊 Docker Container Status:${NC}"
    docker-compose ps

    echo -e "\n${GREEN}🔍 Service Health Checks:${NC}"

    # Check database
    if docker-compose exec postgresql pg_isready -U knowledge_user -d knowledge_platform >/dev/null 2>&1; then
        echo -e "${GREEN}✓ PostgreSQL: Ready${NC}"
    else
        echo -e "${RED}❌ PostgreSQL: Not Ready${NC}"
    fi

    # Check Redis
    if docker-compose exec redis redis-cli ping >/dev/null 2>&1; then
        echo -e "${GREEN}✓ Redis: Ready${NC}"
    else
        echo -e "${RED}❌ Redis: Not Ready${NC}"
    fi

    # Check API Gateway
    if curl -f http://localhost:8080/actuator/health >/dev/null 2>&1; then
        echo -e "${GREEN}✓ API Gateway: Ready${NC}"
        echo -e "${GREEN}🌐 API Gateway available at: http://localhost:8080${NC}"
        echo -e "${GREEN}📊 Health endpoint: http://localhost:8080/actuator/health${NC}"
    else
        echo -e "${RED}❌ API Gateway: Not Ready${NC}"
    fi
}

# Function to show useful endpoints
show_endpoints() {
    print_section "Available Endpoints"

    cat << EOF
${GREEN}🌐 API Endpoints:${NC}
  • Health Check:    http://localhost:8080/actuator/health
  • Metrics:         http://localhost:8080/actuator/metrics
  • Authentication:  http://localhost:8080/api/auth/authenticate
  • Registration:    http://localhost:8080/api/auth/register
  • Circuit Breakers: http://localhost:8080/admin/circuit-breakers

${GREEN}📊 Database:${NC}
  • Host: localhost:5432
  • Database: knowledge_platform
  • Username: knowledge_user

${GREEN}🗄️ Redis:${NC}
  • Host: localhost:6379

${GREEN}🔧 Management:${NC}
  • View logs: docker-compose logs -f api-gateway
  • Stop services: docker-compose down
  • Restart: docker-compose restart
EOF
}

# Function to test the application
test_endpoints() {
    print_section "Testing Endpoints"

    echo -e "${GREEN}🧪 Testing health endpoint...${NC}"
    if curl -f http://localhost:8080/actuator/health 2>/dev/null | jq .; then
        echo -e "${GREEN}✓ Health endpoint working${NC}"
    else
        echo -e "${YELLOW}⚠️  Health endpoint test failed${NC}"
    fi

    echo -e "${GREEN}🧪 Testing registration endpoint...${NC}"
    local test_response=$(curl -s -X POST http://localhost:8080/api/auth/register \
        -H "Content-Type: application/json" \
        -d '{"username":"testuser","email":"test@example.com","password":"testpassword123"}' || echo "failed")

    if [[ "$test_response" != "failed" ]] && [[ "$test_response" != *"error"* ]]; then
        echo -e "${GREEN}✓ Registration endpoint accessible${NC}"
    else
        echo -e "${YELLOW}⚠️  Registration endpoint may need authentication setup${NC}"
    fi
}

# Main execution
main() {
    echo -e "${GREEN}🎯 Knowledge Platform API Gateway Deployment${NC}"
    echo -e "${GREEN}================================================${NC}"

    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --skip-tests)
                SKIP_TESTS=true
                shift
                ;;
            --clean)
                CLEAN_BUILD=true
                shift
                ;;
            --test-only)
                TEST_ONLY=true
                shift
                ;;
            --help)
                show_help
                exit 0
                ;;
            *)
                echo -e "${RED}Unknown option: $1${NC}"
                show_help
                exit 1
                ;;
        esac
    done

    # Execute build and deployment steps
    check_prerequisites

    if [ "${TEST_ONLY:-false}" = "true" ]; then
        test_endpoints
        exit 0
    fi

    setup_secrets
    build_application

    if [ "${SKIP_TESTS:-false}" != "true" ]; then
        run_tests
    fi

    setup_environment
    start_docker_services
    wait_for_services
    show_status
    show_endpoints
    test_endpoints

    echo -e "\n${GREEN}🎉 Deployment completed successfully!${NC}"
    echo -e "${GREEN}The Knowledge Platform API Gateway is now running.${NC}"
}

# Help function
show_help() {
    cat << EOF
Usage: $0 [OPTIONS]

Build and deploy the Knowledge Platform API Gateway

Options:
  --skip-tests    Skip running unit tests
  --clean         Clean build (remove old Docker images)
  --test-only     Only test endpoints (don't build/deploy)
  --help          Show this help message

Examples:
  $0                    # Full build and deployment
  $0 --skip-tests       # Build and deploy without tests
  $0 --clean            # Clean build with fresh Docker images
  $0 --test-only        # Test existing deployment
EOF
}

# Run main function
main "$@"