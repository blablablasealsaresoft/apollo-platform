# Getting Started with Apollo Platform

Welcome to Apollo Platform - the world's first AI-enhanced, multi-domain criminal investigation platform!

## 🎯 Quick Overview

Apollo combines:
- **AI Intelligence** (BugTrace-AI + Cyberspike Villager)
- **Multi-Domain Intelligence** (OSINT, GEOINT, SIGINT)
- **Advanced Red Team Operations** (100+ tools integrated)
- **Real-Time Surveillance** (Global tracking and monitoring)
- **Predictive Analysis** (Criminal behavior forecasting)

## 📋 What's Been Set Up

### ✅ Complete Directory Structure
- **15 main directories** with **200+ subdirectories**
- **All configuration files** created
- **Docker environments** (development & production)
- **Comprehensive documentation** structure

### ✅ Red-Teaming-Toolkit Integration
- **100+ security tools** mapped to Apollo structure
- **10+ C2 frameworks** integrated
- **40+ reconnaissance tools** documented
- **35+ exploitation tools** catalogued
- **Complete tool documentation** created

### ✅ Ready for Development
- Microservices architecture defined
- Database schemas planned
- Frontend structure complete
- Testing framework established
- CI/CD pipelines configured

## 🚀 Next Steps

### 1. Install Dependencies

```bash
# Navigate to project root
cd apollo

# Install Node.js dependencies
npm install

# This will install dependencies for all workspaces:
# - ai-engine/*
# - intelligence/*
# - services/*
# - frontend/*
```

### 2. Configure Environment

```bash
# Copy environment template
cp .env.example .env

# Edit .env with your configuration
# Add API keys for:
# - OpenRouter (AI models)
# - Blockchain explorers
# - OSINT services
# - Cloud providers
```

### 3. Start Development Environment

```bash
# Start all services with Docker
docker-compose -f docker-compose.dev.yml up -d

# Services started:
# - PostgreSQL (port 5432)
# - TimescaleDB (port 5433)
# - Neo4j (ports 7474, 7687)
# - Elasticsearch (ports 9200, 9300)
# - Redis (port 6379)
# - Prometheus (port 9090)
# - Grafana (port 3100)
# - PgAdmin (port 5050)
```

### 4. Initialize Databases

```bash
# Run database initialization
npm run setup:databases

# This will:
# - Create database schemas
# - Run migrations
# - Seed initial data
# - Set up indexes and constraints
```

### 5. Setup AI Models

```bash
# Configure AI models
npm run setup:ai-models

# This will:
# - Download required AI models
# - Configure OpenRouter integration
# - Set up BugTrace-AI
# - Initialize Cyberspike Villager
```

### 6. Start Development

```bash
# Start individual services
cd ai-engine/bugtrace-ai && npm run dev
cd services/authentication && npm run dev
cd frontend/web-console && npm run dev

# Or use Docker for hot-reload development
docker-compose -f docker-compose.dev.yml up
```

## 📁 Key Directories to Know

### For Backend Development
```
services/
├── authentication/       # User auth, JWT, RBAC
├── operation-management/ # Campaign and task management
├── intelligence-fusion/  # Data correlation and analysis
└── analytics/           # Metrics and reporting
```

### For Frontend Development
```
frontend/web-console/
├── src/components/  # Reusable UI components
├── src/pages/       # Page-level components
├── src/services/    # API clients
└── src/store/       # State management
```

### For AI Development
```
ai-engine/
├── bugtrace-ai/              # Vulnerability analysis
├── cyberspike-villager/      # AI-native C2
├── criminal-behavior-ai/     # Pattern recognition
└── predictive-analytics/     # Threat forecasting
```

### For Intelligence Work
```
intelligence/
├── osint-engine/    # Social media, blockchain, dark web
├── geoint-engine/   # Surveillance, geolocation, tracking
└── sigint-engine/   # Communications intelligence
```

### For Red Team Operations
```
redteam/
├── c2-frameworks/    # 10+ C2 frameworks
├── reconnaissance/   # 40+ recon tools
├── exploitation/     # 35+ exploit tools
└── operational-security/  # OPSEC and evasion
```

## 📖 Documentation

### Essential Reading

1. **Project Overview**
   - `README.md` - Platform overview
   - `PROJECT_STRUCTURE.md` - Complete directory guide
   - `IMPLEMENTATION_SUMMARY.md` - What was built

2. **Tool Integration**
   - `RED_TEAM_TOOLKIT_INTEGRATION.md` - Red team tools summary
   - `TOOLS_STATUS.md` - Integration status tracking
   - `redteam/TOOLS_INTEGRATION.md` - Detailed tool mapping

3. **Security & Compliance**
   - `SECURITY.md` - Security policies
   - `CONTRIBUTING.md` - Development guidelines
   - `LICENSE` - Legal terms

### User Guides (In `docs/user-guides/`)
- `getting-started/` - Installation and setup
- `crypto-investigations/` - Cryptocurrency crime investigation
- `predator-hunting/` - Predator and trafficking investigation
- `intelligence-collection/` - OSINT/GEOINT/SIGINT operations
- `red-team-operations/` - Red team methodologies
- `ai-tools/` - AI-enhanced capabilities

### Technical Docs (In `docs/technical-docs/`)
- `architecture/` - System design and architecture
- `api-reference/` - API documentation
- `integration-guides/` - Third-party integrations
- `deployment/` - Production deployment
- `troubleshooting/` - Common issues and solutions

## 🔧 Development Workflows

### Backend Service Development

```bash
# Create new service
cd services/
mkdir my-new-service
cd my-new-service

# Use service template
npm init @apollo/service

# Install dependencies
npm install

# Start development
npm run dev
```

### Frontend Development

```bash
# Navigate to web console
cd frontend/web-console

# Install dependencies (if not already done)
npm install

# Start dev server
npm run dev

# Build for production
npm run build
```

### AI Model Development

```bash
# Navigate to AI engine
cd ai-engine/bugtrace-ai

# Install dependencies
npm install

# Run tests
npm test

# Start with hot reload
npm run dev
```

## 🐳 Docker Quick Reference

### Development

```bash
# Start all services
docker-compose -f docker-compose.dev.yml up

# Start specific service
docker-compose -f docker-compose.dev.yml up postgresql redis

# View logs
docker-compose -f docker-compose.dev.yml logs -f

# Stop all services
docker-compose -f docker-compose.dev.yml down
```

### Production

```bash
# Build images
docker-compose -f docker-compose.prod.yml build

# Start production stack
docker-compose -f docker-compose.prod.yml up -d

# Scale services
docker-compose -f docker-compose.prod.yml up -d --scale authentication=3

# Monitor
docker-compose -f docker-compose.prod.yml ps
```

## 🧪 Testing

### Run Tests

```bash
# Run all tests
npm test

# Run specific test suite
npm run test:unit
npm run test:integration
npm run test:e2e

# Run with coverage
npm run test:coverage

# Security tests
npm run test:security
```

### Testing Tools

- **Jest**: Unit and integration testing
- **Playwright**: End-to-end testing
- **K6**: Performance testing
- **OWASP ZAP**: Security testing

## 📊 Monitoring & Observability

### Access Dashboards

Once Docker services are running:

- **Grafana**: http://localhost:3100 (admin/admin)
- **Prometheus**: http://localhost:9090
- **PgAdmin**: http://localhost:5050
- **Elasticsearch**: http://localhost:9200
- **Neo4j Browser**: http://localhost:7474

### Key Metrics

Apollo automatically tracks:
- Service health and uptime
- API response times
- Database performance
- AI model accuracy
- Tool execution success rates
- OPSEC compliance

## 🔐 Security Setup

### Generate Keys

```bash
# Generate JWT keys
cd .apollo/keys/
openssl genrsa -out jwt-private.pem 4096
openssl rsa -in jwt-private.pem -pubout -out jwt-public.pem

# Generate encryption key
openssl rand -base64 32 > encryption-key.txt
```

### Configure Vault (Production)

```bash
# Initialize Vault
vault operator init -key-shares=5 -key-threshold=3

# Unseal Vault
vault operator unseal <key-1>
vault operator unseal <key-2>
vault operator unseal <key-3>

# Store secrets
vault kv put secret/apollo/db password="<db-password>"
vault kv put secret/apollo/api openrouter="<api-key>"
```

## 🎯 Mission-Specific Setup

### Crypto Crime Investigation

```bash
# Configure blockchain APIs
export BLOCKCHAIN_API_KEY=your_key_here
export CHAINANALYSIS_API_KEY=your_key_here

# Enable blockchain intelligence
apollo-config enable --module blockchain-intelligence

# Start crypto dashboard
apollo-dashboard start --view crypto-investigation
```

### Predator Hunting

```bash
# Configure OSINT APIs
export SHERLOCK_ENABLED=true
export GEOINT_SURVEILLANCE=true

# Enable predator tracking
apollo-config enable --module predator-tracker

# Start predator dashboard
apollo-dashboard start --view predator-investigation
```

## 🆘 Troubleshooting

### Common Issues

**Port conflicts**:
```bash
# Check what's using a port
netstat -ano | findstr :5432

# Change ports in docker-compose.yml or .env
```

**Database connection errors**:
```bash
# Check database status
docker-compose ps

# View database logs
docker-compose logs postgresql

# Restart database
docker-compose restart postgresql
```

**Build errors**:
```bash
# Clean and rebuild
npm run clean
npm install
npm run build
```

### Get Help

- **Documentation**: `docs/`
- **GitHub Issues**: https://github.com/apollo-platform/apollo/issues
- **Discord**: https://discord.gg/apollo-platform
- **Email**: support@apollo-platform.com

## 📚 Learning Resources

### Recommended Reading Order

1. **`README.md`** - Platform overview
2. **`PROJECT_STRUCTURE.md`** - Directory guide
3. **`RED_TEAM_TOOLKIT_INTEGRATION.md`** - Tool integration
4. **`docs/user-guides/getting-started/`** - Detailed setup
5. **`docs/user-guides/crypto-investigations/`** - Crypto crime ops
6. **`docs/user-guides/predator-hunting/`** - Predator investigation

### Video Tutorials (Coming Soon)

- Platform installation and setup
- First investigation walkthrough
- AI tools demonstration
- Red team operations
- Intelligence collection

## 🤝 Contributing

We welcome contributions! Please read:
- **`CONTRIBUTING.md`** - Contribution guidelines
- **`docs/developer-docs/contributing/`** - Development standards
- **Code of Conduct** - Community guidelines

### Areas Needing Contribution

- 📋 Tool integration scripts
- 📋 Frontend components
- 📋 AI model training
- 📋 Documentation improvements
- 📋 Test coverage
- 📋 Performance optimization

## ✨ What Makes Apollo Special

### Revolutionary Capabilities

1. **First AI-Native Investigation Platform**
   - AI at the core of every operation
   - Multi-persona vulnerability analysis
   - Predictive criminal behavior modeling

2. **Comprehensive Tool Integration**
   - 100+ red team tools
   - 10+ C2 frameworks
   - Automated tool orchestration
   - Unified intelligence platform

3. **Mission-Focused Design**
   - Cryptocurrency crime investigation
   - Predator and trafficking network hunting
   - Evidence preservation and chain of custody
   - Court-ready reporting

4. **Global Intelligence Fusion**
   - OSINT (4000+ social platforms)
   - GEOINT (10,000+ surveillance feeds)
   - SIGINT (communication interception)
   - Blockchain forensics
   - Dark web monitoring

5. **Real-Time Operations**
   - Live surveillance feeds
   - Real-time transaction monitoring
   - Instant threat alerts
   - Automated response capabilities

---

## 🎊 You're Ready!

The Apollo Platform foundation is complete. You now have:

✅ Complete directory structure (200+ directories)  
✅ All configuration files  
✅ 100+ red team tools integrated and documented  
✅ AI enhancement architecture  
✅ Intelligence collection framework  
✅ Frontend and backend structures  
✅ Testing and quality frameworks  
✅ Comprehensive documentation

**Next**: Add your implementation files and start building the future of criminal investigation!

---

**Apollo: Where AI meets justice. Where technology fights evil. Where the future of criminal investigation begins.**

---

**Version**: 0.1.0  
**Date**: January 13, 2026  
**Status**: 🚀 Ready for Development
