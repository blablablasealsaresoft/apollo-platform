#!/bin/bash
# Apollo Platform - Development Environment Setup Script
# ===========================================================

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
ENV_DIR="$PROJECT_ROOT/configs/environments/development"

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}  Apollo Platform - Development Environment Setup${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Check prerequisites
echo -e "${YELLOW}Checking prerequisites...${NC}"

# Check Docker
if ! command -v docker &> /dev/null; then
    echo -e "${RED}✗ Docker is not installed${NC}"
    echo "Please install Docker: https://docs.docker.com/get-docker/"
    exit 1
fi
echo -e "${GREEN}✓ Docker installed${NC}"

# Check Docker Compose
if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    echo -e "${RED}✗ Docker Compose is not installed${NC}"
    echo "Please install Docker Compose"
    exit 1
fi
echo -e "${GREEN}✓ Docker Compose installed${NC}"

# Check Node.js
if ! command -v node &> /dev/null; then
    echo -e "${RED}✗ Node.js is not installed${NC}"
    echo "Please install Node.js 18+: https://nodejs.org/"
    exit 1
fi
NODE_VERSION=$(node -v | cut -d'v' -f2 | cut -d'.' -f1)
if [ "$NODE_VERSION" -lt 18 ]; then
    echo -e "${RED}✗ Node.js version 18+ required (found v$NODE_VERSION)${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Node.js $(node -v) installed${NC}"

# Check npm
if ! command -v npm &> /dev/null; then
    echo -e "${RED}✗ npm is not installed${NC}"
    exit 1
fi
echo -e "${GREEN}✓ npm $(npm -v) installed${NC}"

echo ""
echo -e "${YELLOW}Setting up environment...${NC}"

# Copy environment file
if [ ! -f "$PROJECT_ROOT/.env" ]; then
    echo "Copying .env.development to .env..."
    cp "$ENV_DIR/.env.development" "$PROJECT_ROOT/.env"
    echo -e "${GREEN}✓ Environment file created${NC}"
    echo -e "${YELLOW}⚠  Please update API keys in .env file${NC}"
else
    echo -e "${YELLOW}⚠  .env file already exists, skipping...${NC}"
fi

# Create data directories
echo "Creating data directories..."
mkdir -p "$PROJECT_ROOT/data/dev/face_database"
mkdir -p "$PROJECT_ROOT/data/dev/voice_database"
mkdir -p "$PROJECT_ROOT/data/dev/config"
mkdir -p "$PROJECT_ROOT/data/uploads"
mkdir -p "$PROJECT_ROOT/data/temp"
mkdir -p "$PROJECT_ROOT/data/backups"
mkdir -p "$PROJECT_ROOT/data/evidence"
mkdir -p "$PROJECT_ROOT/logs/dev"
echo -e "${GREEN}✓ Data directories created${NC}"

# Start Docker containers
echo ""
echo -e "${YELLOW}Starting database services...${NC}"
COMPOSE_FILE="$PROJECT_ROOT/configs/environments/docker/docker-compose.dev.yml"

if [ ! -f "$COMPOSE_FILE" ]; then
    echo -e "${RED}✗ Docker Compose file not found: $COMPOSE_FILE${NC}"
    exit 1
fi

docker-compose -f "$COMPOSE_FILE" up -d

echo ""
echo -e "${YELLOW}Waiting for databases to be ready...${NC}"

# Wait for PostgreSQL
echo -n "Waiting for PostgreSQL..."
for i in {1..30}; do
    if docker-compose -f "$COMPOSE_FILE" exec -T postgres pg_isready -U apollo_admin -d apollo_dev &> /dev/null; then
        echo -e " ${GREEN}✓${NC}"
        break
    fi
    echo -n "."
    sleep 2
    if [ $i -eq 30 ]; then
        echo -e " ${RED}✗ Timeout${NC}"
        exit 1
    fi
done

# Wait for Redis
echo -n "Waiting for Redis..."
for i in {1..30}; do
    if docker-compose -f "$COMPOSE_FILE" exec -T redis redis-cli ping &> /dev/null; then
        echo -e " ${GREEN}✓${NC}"
        break
    fi
    echo -n "."
    sleep 2
    if [ $i -eq 30 ]; then
        echo -e " ${RED}✗ Timeout${NC}"
        exit 1
    fi
done

# Wait for MongoDB
echo -n "Waiting for MongoDB..."
for i in {1..30}; do
    if docker-compose -f "$COMPOSE_FILE" exec -T mongodb mongosh --eval "db.adminCommand('ping')" &> /dev/null; then
        echo -e " ${GREEN}✓${NC}"
        break
    fi
    echo -n "."
    sleep 2
    if [ $i -eq 30 ]; then
        echo -e " ${RED}✗ Timeout${NC}"
        exit 1
    fi
done

# Wait for RabbitMQ
echo -n "Waiting for RabbitMQ..."
for i in {1..30}; do
    if docker-compose -f "$COMPOSE_FILE" exec -T rabbitmq rabbitmq-diagnostics -q ping &> /dev/null; then
        echo -e " ${GREEN}✓${NC}"
        break
    fi
    echo -n "."
    sleep 2
    if [ $i -eq 30 ]; then
        echo -e " ${RED}✗ Timeout${NC}"
        exit 1
    fi
done

echo -e "${GREEN}✓ All databases are ready${NC}"

# Install dependencies
echo ""
echo -e "${YELLOW}Installing Node.js dependencies...${NC}"
cd "$PROJECT_ROOT"
npm install
echo -e "${GREEN}✓ Dependencies installed${NC}"

# Run database migrations
echo ""
echo -e "${YELLOW}Running database migrations...${NC}"

# Check if migration scripts exist
if [ -d "$PROJECT_ROOT/services/authentication" ]; then
    cd "$PROJECT_ROOT/services/authentication"
    if [ -f "package.json" ]; then
        npm install
        if npm run migrate:dev &> /dev/null; then
            echo -e "${GREEN}✓ Authentication service migrations complete${NC}"
        else
            echo -e "${YELLOW}⚠  Migration script not found (this is ok for initial setup)${NC}"
        fi
    fi
fi

# Seed initial data
echo ""
echo -e "${YELLOW}Seeding initial data...${NC}"
cd "$PROJECT_ROOT"

if npm run seed:dev &> /dev/null; then
    echo -e "${GREEN}✓ Initial data seeded${NC}"
else
    echo -e "${YELLOW}⚠  Seed script not found (this is ok for initial setup)${NC}"
fi

# Seed Ignatova case data
if npm run seed:ignatova &> /dev/null; then
    echo -e "${GREEN}✓ Ignatova case data seeded${NC}"
else
    echo -e "${YELLOW}⚠  Ignatova seed script not found (this is ok for initial setup)${NC}"
fi

# Summary
echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}✅ Development environment setup complete!${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${YELLOW}Database Services:${NC}"
echo "  PostgreSQL:     localhost:5432 (apollo_admin/dev_password)"
echo "  Neo4j Browser:  http://localhost:7474 (neo4j/dev_neo4j_pass)"
echo "  Redis:          localhost:6379"
echo "  Elasticsearch:  http://localhost:9200"
echo "  MongoDB:        localhost:27017"
echo "  RabbitMQ:       http://localhost:15672 (apollo/dev_rabbit)"
echo "  Adminer:        http://localhost:8081"
echo "  Prometheus:     http://localhost:9090"
echo "  Grafana:        http://localhost:3001 (admin/admin)"
echo ""
echo -e "${YELLOW}Next Steps:${NC}"
echo "  1. Update API keys in .env file"
echo "  2. Start development servers:"
echo "     ${GREEN}npm run dev${NC}"
echo ""
echo "  3. Access the application:"
echo "     Frontend:  ${GREEN}http://localhost:3000${NC}"
echo "     API:       ${GREEN}http://localhost:4000${NC}"
echo ""
echo -e "${YELLOW}Useful Commands:${NC}"
echo "  Stop databases:    ${GREEN}docker-compose -f configs/environments/docker/docker-compose.dev.yml down${NC}"
echo "  View logs:         ${GREEN}docker-compose -f configs/environments/docker/docker-compose.dev.yml logs -f${NC}"
echo "  Reset databases:   ${GREEN}docker-compose -f configs/environments/docker/docker-compose.dev.yml down -v${NC}"
echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
