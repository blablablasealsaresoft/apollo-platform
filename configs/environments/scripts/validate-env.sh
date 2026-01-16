#!/bin/bash
# Apollo Platform - Environment Validation Script
# ===========================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Default environment
ENV="${1:-development}"

# Validation counters
ERRORS=0
WARNINGS=0

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}  Apollo Platform - Environment Validation${NC}"
echo -e "${BLUE}  Environment: ${ENV}${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Load environment file
ENV_FILE=".env.${ENV}"
if [ ! -f "$ENV_FILE" ]; then
    ENV_FILE=".env"
fi

if [ ! -f "$ENV_FILE" ]; then
    echo -e "${RED}✗ Environment file not found: $ENV_FILE${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Loading environment from: $ENV_FILE${NC}"
source "$ENV_FILE"
echo ""

# Function to check required variable
check_required() {
    local var_name=$1
    local var_value=${!var_name}

    if [ -z "$var_value" ]; then
        echo -e "${RED}✗ Missing required variable: $var_name${NC}"
        ((ERRORS++))
        return 1
    else
        echo -e "${GREEN}✓ $var_name is set${NC}"
        return 0
    fi
}

# Function to check optional variable
check_optional() {
    local var_name=$1
    local var_value=${!var_name}

    if [ -z "$var_value" ]; then
        echo -e "${YELLOW}⚠ Optional variable not set: $var_name${NC}"
        ((WARNINGS++))
        return 1
    else
        echo -e "${GREEN}✓ $var_name is set${NC}"
        return 0
    fi
}

# Function to check if value is still default/placeholder
check_not_placeholder() {
    local var_name=$1
    local var_value=${!var_name}
    local placeholder_pattern=$2

    if [[ "$var_value" =~ $placeholder_pattern ]]; then
        echo -e "${YELLOW}⚠ $var_name appears to be a placeholder value${NC}"
        ((WARNINGS++))
        return 1
    fi
    return 0
}

# Database Configuration
echo -e "${YELLOW}Validating Database Configuration...${NC}"
check_required "DATABASE_URL"
check_required "NEO4J_URI"
check_required "NEO4J_USER"
check_required "NEO4J_PASSWORD"
check_required "REDIS_URL"
check_required "MONGODB_URL"
check_required "RABBITMQ_URL"
check_required "TIMESCALE_URL"
echo ""

# Security Configuration
echo -e "${YELLOW}Validating Security Configuration...${NC}"
check_required "JWT_SECRET"
check_required "JWT_REFRESH_SECRET"
check_required "SESSION_SECRET"
check_required "ENCRYPTION_KEY"

# Check JWT secret length
if [ ${#JWT_SECRET} -lt 32 ]; then
    echo -e "${RED}✗ JWT_SECRET must be at least 32 characters (current: ${#JWT_SECRET})${NC}"
    ((ERRORS++))
fi

# Check if secrets are still default
if [ "$ENV" = "production" ]; then
    check_not_placeholder "JWT_SECRET" "GENERATE|CHANGE_ME|dev-|default"
    check_not_placeholder "JWT_REFRESH_SECRET" "GENERATE|CHANGE_ME|dev-|default"
    check_not_placeholder "SESSION_SECRET" "GENERATE|CHANGE_ME|dev-|default"
    check_not_placeholder "ENCRYPTION_KEY" "GENERATE|CHANGE_ME|dev-|default"
fi
echo ""

# AI Model API Keys
echo -e "${YELLOW}Validating AI Model Configuration...${NC}"
check_optional "OPENROUTER_API_KEY"
check_optional "OPENAI_API_KEY"
check_optional "ANTHROPIC_API_KEY"
check_optional "GOOGLE_AI_API_KEY"
check_optional "DEEPSEEK_API_KEY"

if [ "$ENV" = "production" ]; then
    check_not_placeholder "OPENROUTER_API_KEY" "your-|PRODUCTION-"
    check_not_placeholder "OPENAI_API_KEY" "your-|PRODUCTION-"
    check_not_placeholder "ANTHROPIC_API_KEY" "your-|PRODUCTION-"
fi
echo ""

# OSINT APIs
echo -e "${YELLOW}Validating OSINT Integration...${NC}"
check_optional "SHODAN_API_KEY"
check_optional "DEHASHED_API_KEY"
check_optional "HIBP_API_KEY"
check_optional "HUNTERIO_API_KEY"
check_optional "VIRUSTOTAL_API_KEY"
echo ""

# Blockchain APIs
echo -e "${YELLOW}Validating Blockchain Integration...${NC}"
check_optional "BLOCKCHAIN_API_KEY"
check_optional "ETHERSCAN_API_KEY"
echo ""

# File Paths
echo -e "${YELLOW}Validating File Paths...${NC}"
check_required "DATA_DIR"
check_required "UPLOAD_DIR"
check_required "TEMP_DIR"
check_required "EVIDENCE_DIR"

# Check if directories exist (create if in dev)
if [ "$ENV" = "development" ]; then
    mkdir -p "$DATA_DIR" "$UPLOAD_DIR" "$TEMP_DIR" "$EVIDENCE_DIR"
    echo -e "${GREEN}✓ Data directories created/verified${NC}"
fi
echo ""

# Production-specific checks
if [ "$ENV" = "production" ]; then
    echo -e "${YELLOW}Validating Production-Specific Configuration...${NC}"

    # SSL/TLS
    check_required "SSL_CERT_PATH"
    check_required "SSL_KEY_PATH"

    # Monitoring
    check_required "SENTRY_DSN"
    check_required "PROMETHEUS_URL"

    # Backups
    check_required "AWS_ACCESS_KEY_ID"
    check_required "AWS_SECRET_ACCESS_KEY"
    check_required "AWS_S3_BACKUP_BUCKET"

    # Check if MFA is enabled
    if [ "$MFA_ENABLED" != "true" ]; then
        echo -e "${RED}✗ MFA must be enabled in production${NC}"
        ((ERRORS++))
    else
        echo -e "${GREEN}✓ MFA is enabled${NC}"
    fi

    # Check if rate limiting is enabled
    if [ "$RATE_LIMIT_ENABLED" != "true" ]; then
        echo -e "${RED}✗ Rate limiting must be enabled in production${NC}"
        ((ERRORS++))
    else
        echo -e "${GREEN}✓ Rate limiting is enabled${NC}"
    fi

    # Check log level
    if [ "$LOG_LEVEL" = "debug" ]; then
        echo -e "${YELLOW}⚠ Log level is set to 'debug' in production${NC}"
        ((WARNINGS++))
    fi

    echo ""
fi

# Test database connections (optional)
if command -v pg_isready &> /dev/null && [ "$ENV" = "development" ]; then
    echo -e "${YELLOW}Testing Database Connections...${NC}"

    # Extract PostgreSQL connection info
    PG_HOST=$(echo "$DATABASE_URL" | sed -n 's/.*@\([^:]*\):.*/\1/p')
    PG_PORT=$(echo "$DATABASE_URL" | sed -n 's/.*:\([0-9]*\)\/.*/\1/p')

    if pg_isready -h "$PG_HOST" -p "$PG_PORT" &> /dev/null; then
        echo -e "${GREEN}✓ PostgreSQL is reachable${NC}"
    else
        echo -e "${YELLOW}⚠ PostgreSQL is not reachable (this is ok if not started yet)${NC}"
        ((WARNINGS++))
    fi

    echo ""
fi

# Summary
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}  Validation Summary${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

if [ $ERRORS -eq 0 ] && [ $WARNINGS -eq 0 ]; then
    echo -e "${GREEN}✅ Validation passed with no errors or warnings${NC}"
    exit 0
elif [ $ERRORS -eq 0 ]; then
    echo -e "${YELLOW}⚠  Validation passed with $WARNINGS warning(s)${NC}"
    echo -e "${YELLOW}   Please review the warnings above${NC}"
    exit 0
else
    echo -e "${RED}❌ Validation failed with $ERRORS error(s) and $WARNINGS warning(s)${NC}"
    echo -e "${RED}   Please fix the errors above before proceeding${NC}"
    exit 1
fi
