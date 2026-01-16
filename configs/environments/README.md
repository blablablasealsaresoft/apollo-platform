# Apollo Platform - Environment Configurations

This directory contains comprehensive configuration files for all deployment environments of the Apollo Platform.

## 📁 Directory Structure

```
configs/environments/
├── development/          # Development environment
│   ├── .env.development
│   ├── database.yaml
│   ├── services.yaml
│   ├── ai-models.yaml
│   ├── integrations.yaml
│   └── README.md
├── staging/             # Staging environment
│   ├── .env.staging
│   ├── database.yaml
│   ├── services.yaml
│   ├── ai-models.yaml
│   ├── integrations.yaml
│   └── README.md
├── production/          # Production environment
│   ├── .env.production.example
│   ├── database.yaml
│   ├── services.yaml
│   ├── ai-models.yaml
│   ├── integrations.yaml
│   ├── security.yaml
│   └── README.md
├── docker/              # Docker Compose configurations
│   ├── docker-compose.dev.yml
│   ├── docker-compose.staging.yml
│   ├── docker-compose.prod.yml
│   └── .dockerignore
├── kubernetes/          # Kubernetes configurations
│   ├── dev/
│   ├── staging/
│   └── prod/
├── scripts/             # Setup and utility scripts
│   ├── setup-dev.sh
│   ├── setup-staging.sh
│   ├── setup-production.sh
│   └── validate-env.sh
└── README.md           # This file
```

## 🚀 Quick Start

### Development Environment

```bash
# 1. Run setup script
chmod +x scripts/setup-dev.sh
./scripts/setup-dev.sh

# 2. Update API keys in .env file
nano .env

# 3. Validate configuration
./scripts/validate-env.sh development

# 4. Start services
npm run dev
```

### Staging Environment

```bash
# 1. Copy staging configuration
cp configs/environments/staging/.env.staging .env

# 2. Update credentials and API keys
nano .env

# 3. Start staging services
docker-compose -f configs/environments/docker/docker-compose.staging.yml up -d
```

### Production Environment

```bash
# 1. Copy production template
cp configs/environments/production/.env.production.example .env.production

# 2. Generate secrets and update all credentials
./scripts/setup-production.sh

# 3. Validate production configuration
./scripts/validate-env.sh production

# 4. Deploy to Kubernetes
kubectl apply -f configs/environments/kubernetes/prod/
```

## 🔧 Configuration Files

### Environment Variables (.env)

Each environment has its own `.env` file containing:
- Database connection strings
- API keys and secrets
- Feature flags
- Service configuration
- Security settings

**Security Note:**
- ⚠️ `.env.production` should NEVER be committed to version control
- Use `.env.production.example` as a template
- Store production secrets in a secure vault (Kubernetes Secrets, AWS Secrets Manager, HashiCorp Vault)

### Database Configuration (database.yaml)

Comprehensive database settings for:
- PostgreSQL (primary relational database)
- Neo4j (graph database)
- Redis (cache and sessions)
- Elasticsearch (search and analytics)
- MongoDB (document store)
- RabbitMQ (message queue)
- TimescaleDB (time-series data)

### Services Configuration (services.yaml)

Microservice settings including:
- Service replicas and scaling
- Port mappings
- Resource limits (CPU, memory)
- Health checks
- Feature toggles
- Worker configuration

### AI Models Configuration (ai-models.yaml)

AI/ML model settings:
- Model provider configuration (OpenRouter, OpenAI, Anthropic, Google, DeepSeek)
- Routing strategies
- Cost management
- Use case specific prompts
- Performance tuning

### Integrations Configuration (integrations.yaml)

External service integrations:
- OSINT tools (Shodan, DeHashed, HIBP, Hunter.io, VirusTotal)
- Blockchain APIs (Etherscan, Blockchain.com, CoinGecko)
- Social media (Twitter, LinkedIn, Reddit)
- Communication services (Email, SMS, Slack, Discord)
- Monitoring (Prometheus, Grafana, Sentry)

### Security Configuration (security.yaml)

Production-only security settings:
- Encryption (at rest and in transit)
- Authentication and authorization
- Network security
- Intrusion detection
- Compliance (CJIS, GDPR, SOC2, ISO27001)
- Incident response

## 🐳 Docker Compose

### Development (docker-compose.dev.yml)

Includes all required databases and services:
- PostgreSQL, Neo4j, Redis, Elasticsearch, MongoDB, RabbitMQ, TimescaleDB
- Prometheus, Grafana, Jaeger (distributed tracing)
- Admin UIs (Adminer, Redis Commander)

**Usage:**
```bash
# Start all services
docker-compose -f configs/environments/docker/docker-compose.dev.yml up -d

# View logs
docker-compose -f configs/environments/docker/docker-compose.dev.yml logs -f

# Stop services
docker-compose -f configs/environments/docker/docker-compose.dev.yml down

# Reset (delete all data)
docker-compose -f configs/environments/docker/docker-compose.dev.yml down -v
```

### Production (docker-compose.prod.yml)

Production-ready configuration with:
- High availability (replicas, failover)
- SSL/TLS encryption
- Resource limits
- Health checks
- Load balancing

**Note:** For true production deployments, use Kubernetes instead.

## ☸️ Kubernetes

### Production Deployment

```bash
# Create namespace
kubectl create namespace apollo-production

# Apply configurations
kubectl apply -f configs/environments/kubernetes/prod/configmap.yaml
kubectl apply -f configs/environments/kubernetes/prod/secrets.yaml

# Deploy applications
kubectl apply -f infrastructure/kubernetes/deployments/
kubectl apply -f infrastructure/kubernetes/services/

# Check status
kubectl get pods -n apollo-production
kubectl get services -n apollo-production
```

### Secrets Management

**Option 1: Kubernetes Secrets (Default)**
```bash
# Create secrets from file
kubectl create secret generic apollo-secrets \
  --from-env-file=.env.production \
  -n apollo-production
```

**Option 2: External Secrets Operator**
- Integrates with AWS Secrets Manager, Azure Key Vault, HashiCorp Vault
- Automatic secret rotation
- See `kubernetes/prod/secrets.yaml` for configuration

**Option 3: Sealed Secrets**
- Encrypt secrets with public key
- Store encrypted secrets in Git
- Decrypt in cluster with private key

## 📝 Scripts

### setup-dev.sh

Automated development environment setup:
- Checks prerequisites (Docker, Node.js)
- Copies environment files
- Creates data directories
- Starts Docker containers
- Waits for databases
- Installs dependencies
- Runs migrations
- Seeds initial data

### validate-env.sh

Validates environment configuration:
- Checks required variables
- Validates secret strength
- Tests database connections
- Verifies production security settings
- Reports errors and warnings

**Usage:**
```bash
./scripts/validate-env.sh development
./scripts/validate-env.sh staging
./scripts/validate-env.sh production
```

## 🔐 Security Best Practices

### Development
- Use weak passwords (acceptable for local dev)
- Keep `.env.development` in Git (no secrets)
- Disable SSL/TLS for simplicity
- Enable debug logging

### Staging
- Use stronger passwords than dev
- Keep secrets out of Git
- Enable SSL/TLS
- Mirror production configuration
- Use info-level logging

### Production
- Generate strong, random secrets (32+ characters)
- NEVER commit `.env.production` to Git
- Use secrets management system (Vault, AWS Secrets Manager)
- Require MFA for all users
- Enable all security features
- Use encryption at rest and in transit
- Enable comprehensive audit logging
- Regular security audits
- Automated vulnerability scanning

### Secret Generation

```bash
# JWT Secret (32+ characters)
openssl rand -base64 32

# AES-256 Key (64 hex characters)
openssl rand -hex 32

# Session Secret
openssl rand -base64 32

# Password (16 characters, complex)
openssl rand -base64 16 | tr -dc 'A-Za-z0-9!@#$%^&*'
```

## 🎯 Environment Comparison

| Feature | Development | Staging | Production |
|---------|-------------|---------|------------|
| **Purpose** | Local development | Pre-production testing | Live system |
| **SSL/TLS** | ❌ Disabled | ✅ Enabled | ✅ Required |
| **MFA** | ❌ Disabled | ⚠️ Optional | ✅ Required |
| **Rate Limiting** | ❌ Disabled | ✅ Enabled | ✅ Enabled |
| **Logging Level** | Debug | Info | Info/Warn |
| **Source Maps** | ✅ Enabled | ❌ Disabled | ❌ Disabled |
| **Minification** | ❌ Disabled | ✅ Enabled | ✅ Enabled |
| **Replicas** | 1 | 2 | 3+ |
| **Backups** | ❌ Disabled | ✅ Daily | ✅ Hourly |
| **Monitoring** | ⚠️ Basic | ✅ Full | ✅ Comprehensive |
| **GPU** | ❌ CPU only | ⚠️ Optional | ✅ Required |

## 📊 Database Credentials

### Development (Local Docker)

**PostgreSQL:**
- Host: `localhost:5432`
- Database: `apollo_dev`
- Username: `apollo_admin`
- Password: `dev_password`

**Neo4j:**
- URI: `bolt://localhost:7687`
- Browser: `http://localhost:7474`
- Username: `neo4j`
- Password: `dev_neo4j_pass`

**Redis:**
- Host: `localhost:6379`
- No password

**MongoDB:**
- URI: `mongodb://localhost:27017`
- Username: `apollo`
- Password: `dev_mongo_pass`

**RabbitMQ:**
- AMQP: `localhost:5672`
- Management: `http://localhost:15672`
- Username: `apollo`
- Password: `dev_rabbit`

### Production

⚠️ **Production credentials are stored in Kubernetes Secrets**

Access via:
```bash
kubectl get secret apollo-secrets -n apollo-production -o jsonpath='{.data.POSTGRES_PASSWORD}' | base64 -d
```

## 🔄 Configuration Updates

### Development

```bash
# Update .env file
nano .env

# Restart services
npm run dev
```

### Production (Kubernetes)

```bash
# Update ConfigMap
kubectl edit configmap apollo-config -n apollo-production

# Update Secret
kubectl edit secret apollo-secrets -n apollo-production

# Restart pods to pick up changes
kubectl rollout restart deployment -n apollo-production
```

## 🆘 Troubleshooting

### Database Connection Issues

```bash
# Check if containers are running
docker-compose -f configs/environments/docker/docker-compose.dev.yml ps

# View database logs
docker-compose -f configs/environments/docker/docker-compose.dev.yml logs postgres

# Restart specific service
docker-compose -f configs/environments/docker/docker-compose.dev.yml restart postgres
```

### Validation Failures

```bash
# Run validation script
./scripts/validate-env.sh development

# Check for missing variables
grep -v '^#' .env | grep '='

# Verify file permissions
ls -la .env
```

### Port Conflicts

If ports are already in use:
1. Stop conflicting services
2. Update port mappings in `docker-compose.*.yml`
3. Update corresponding ports in `.env` files

## 📚 Additional Resources

- [Docker Documentation](https://docs.docker.com/)
- [Kubernetes Documentation](https://kubernetes.io/docs/)
- [PostgreSQL Documentation](https://www.postgresql.org/docs/)
- [Neo4j Documentation](https://neo4j.com/docs/)
- [Redis Documentation](https://redis.io/documentation)

## 🤝 Support

For configuration issues:
1. Check validation script output
2. Review service logs
3. Verify environment variables
4. Consult environment-specific README
5. Check main Apollo documentation

---

**Last Updated:** 2024-01-14
**Apollo Platform Version:** 1.0.0
