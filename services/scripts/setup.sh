#!/bin/bash

# Apollo Backend Services Setup Script
# This script sets up the complete backend microservices architecture

set -e

echo "========================================="
echo "Apollo Platform - Backend Setup"
echo "========================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running from services directory
if [ ! -f "package.json" ]; then
    echo -e "${RED}Error: Please run this script from the apollo/services directory${NC}"
    exit 1
fi

# Check prerequisites
echo -e "${YELLOW}Checking prerequisites...${NC}"

command -v node >/dev/null 2>&1 || { echo -e "${RED}Node.js is required but not installed. Aborting.${NC}" >&2; exit 1; }
command -v npm >/dev/null 2>&1 || { echo -e "${RED}npm is required but not installed. Aborting.${NC}" >&2; exit 1; }
command -v docker >/dev/null 2>&1 || { echo -e "${RED}Docker is required but not installed. Aborting.${NC}" >&2; exit 1; }

echo -e "${GREEN}✓ All prerequisites met${NC}"
echo ""

# Create .env if it doesn't exist
if [ ! -f "../.env" ]; then
    echo -e "${YELLOW}Creating .env file from example...${NC}"
    cp .env.example ../.env
    echo -e "${GREEN}✓ .env file created. Please update it with your configuration.${NC}"
    echo ""
fi

# Install dependencies
echo -e "${YELLOW}Installing dependencies...${NC}"
cd ..
npm install
echo -e "${GREEN}✓ Dependencies installed${NC}"
echo ""

# Build shared package first
echo -e "${YELLOW}Building shared utilities...${NC}"
cd services/shared
npm run build
cd ../..
echo -e "${GREEN}✓ Shared utilities built${NC}"
echo ""

# Build all services
echo -e "${YELLOW}Building all services...${NC}"
npm run build --workspaces
echo -e "${GREEN}✓ All services built${NC}"
echo ""

# Start infrastructure
echo -e "${YELLOW}Starting infrastructure (PostgreSQL, Redis, Elasticsearch)...${NC}"
docker-compose up -d postgresql redis elasticsearch
echo ""
echo -e "${YELLOW}Waiting for databases to be ready (30 seconds)...${NC}"
sleep 30
echo -e "${GREEN}✓ Infrastructure started${NC}"
echo ""

# Initialize database
echo -e "${YELLOW}Initializing database schema...${NC}"
docker exec -i apollo-postgresql psql -U apollo -d apollo < infrastructure/databases/postgresql/schemas/01_init_schema.sql 2>/dev/null || echo -e "${YELLOW}Schema already exists or error occurred${NC}"
echo -e "${GREEN}✓ Database initialized${NC}"
echo ""

# Create logs directories
echo -e "${YELLOW}Creating log directories...${NC}"
mkdir -p services/shared/logs
mkdir -p services/authentication/logs
mkdir -p services/user-management/logs
mkdir -p services/operations/logs
mkdir -p services/intelligence/logs
mkdir -p services/notifications/logs
mkdir -p services/analytics/logs
mkdir -p services/search/logs
mkdir -p services/api-gateway/logs
echo -e "${GREEN}✓ Log directories created${NC}"
echo ""

# Summary
echo ""
echo "========================================="
echo -e "${GREEN}Setup Complete!${NC}"
echo "========================================="
echo ""
echo "Default Admin Credentials:"
echo "  Email: admin@apollo.local"
echo "  Password: Apollo@2026!"
echo ""
echo "Infrastructure Services:"
echo "  PostgreSQL: localhost:5432"
echo "  Redis: localhost:6379"
echo "  Elasticsearch: localhost:9200"
echo ""
echo "To start the backend services:"
echo "  Development: npm run dev:services"
echo "  Production: docker-compose -f services/docker-compose.services.yml up -d"
echo ""
echo "To view logs:"
echo "  docker-compose logs -f"
echo ""
echo "API Gateway will be available at: http://localhost:3000"
echo "Health check: http://localhost:3000/health"
echo ""
echo "========================================="
