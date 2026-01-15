# Apollo Platform Deployment Guide

> Complete guide for deploying Apollo Platform to production

Version: 1.0.0
Last Updated: January 2026

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Environment Setup](#environment-setup)
3. [Docker Deployment](#docker-deployment)
4. [Kubernetes Deployment](#kubernetes-deployment)
5. [Database Setup](#database-setup)
6. [SSL/TLS Configuration](#ssltls-configuration)
7. [Monitoring Setup](#monitoring-setup)
8. [Backup & Recovery](#backup--recovery)
9. [Security Hardening](#security-hardening)
10. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### System Requirements

**Minimum (Development)**:
- CPU: 4 cores
- RAM: 16GB
- Storage: 100GB SSD
- OS: Ubuntu 22.04 LTS / Windows Server 2022

**Recommended (Production)**:
- CPU: 16 cores (32+ for surveillance)
- RAM: 64GB (128GB+ for surveillance)
- Storage: 1TB NVMe SSD (RAID 10)
- GPU: NVIDIA RTX 4090 (for facial recognition)
- OS: Ubuntu 22.04 LTS

### Software Prerequisites

```bash
# Docker
Docker 24.0+
Docker Compose 2.20+

# Kubernetes (Production)
Kubernetes 1.28+
kubectl 1.28+
Helm 3.12+

# Node.js
Node.js 20.x LTS
npm 10.x

# Python
Python 3.11+
pip 23.x

# Database Clients
PostgreSQL Client 15+
Redis CLI 7.0+
Neo4j Desktop 1.5+
```

---

## Environment Setup

### 1. Clone Repository

```bash
git clone https://github.com/blablablasealsaresoft/apollo-platform.git
cd apollo-platform
```

### 2. Environment Variables

Create `.env` file in project root:

```bash
# Copy example environment
cp .env.example .env

# Edit with your configuration
nano .env
```

**Required Environment Variables**:

```bash
# Application
NODE_ENV=production
API_PORT=4000
FRONTEND_PORT=3000

# JWT Authentication
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production
JWT_REFRESH_SECRET=your-super-secret-refresh-key-change-this
JWT_EXPIRY=15m
JWT_REFRESH_EXPIRY=7d

# PostgreSQL
DATABASE_URL=postgresql://apollo_admin:SecurePassword123!@localhost:5432/apollo
POSTGRES_USER=apollo_admin
POSTGRES_PASSWORD=SecurePassword123!
POSTGRES_DB=apollo

# Neo4j
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=Neo4jSecurePass123!

# Redis
REDIS_URL=redis://localhost:6379
REDIS_PASSWORD=RedisSecurePass123!

# Elasticsearch
ELASTICSEARCH_URL=http://localhost:9200
ELASTICSEARCH_USERNAME=elastic
ELASTICSEARCH_PASSWORD=ElasticSecurePass123!

# RabbitMQ
RABBITMQ_URL=amqp://apollo:RabbitSecurePass123!@localhost:5672
RABBITMQ_USER=apollo
RABBITMQ_PASSWORD=RabbitSecurePass123!

# MongoDB
MONGODB_URL=mongodb://apollo:MongoSecurePass123!@localhost:27017/apollo
MONGODB_USER=apollo
MONGODB_PASSWORD=MongoSecurePass123!

# TimescaleDB
TIMESCALE_URL=postgresql://apollo_admin:SecurePassword123!@localhost:5432/apollo_timeseries

# OAuth (Optional)
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
MICROSOFT_CLIENT_ID=your-microsoft-client-id
MICROSOFT_CLIENT_SECRET=your-microsoft-client-secret
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret

# Surveillance
FACE_DATABASE_PATH=/data/face_database/ignatova_face_encodings.npy
VOICE_DATABASE_PATH=/data/voice_database/ignatova_voiceprint.npy
CAMERA_FEED_CONFIG=/data/config/camera_feeds.json

# Blockchain APIs
BLOCKCHAIN_API_KEY=your-blockchain-api-key
ETHERSCAN_API_KEY=your-etherscan-api-key
POLYGONSCAN_API_KEY=your-polygonscan-api-key

# OSINT APIs
DEHASHED_API_KEY=your-dehashed-api-key
HIBP_API_KEY=your-haveibeenpwned-api-key
HUNTER_API_KEY=your-hunter-api-key

# Monitoring
PROMETHEUS_PORT=9090
GRAFANA_PORT=3001
GRAFANA_ADMIN_PASSWORD=GrafanaSecurePass123!

# Secrets Management (Optional)
VAULT_ADDR=http://localhost:8200
VAULT_TOKEN=your-vault-token

# Logging
LOG_LEVEL=info
LOG_FILE=/var/log/apollo/apollo.log
```

---

## Docker Deployment

### Development Environment

```bash
# Start all services with Docker Compose
docker-compose -f docker-compose.dev.yml up -d

# Check service status
docker-compose ps

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

### Production Environment

```bash
# Build production images
docker-compose -f docker-compose.prod.yml build

# Start production services
docker-compose -f docker-compose.prod.yml up -d

# Scale services
docker-compose -f docker-compose.prod.yml up -d --scale backend=3
```

### Individual Service Deployment

```bash
# Build backend services
cd services
docker build -t apollo/authentication:latest -f authentication/Dockerfile .
docker build -t apollo/operations:latest -f operations/Dockerfile .
docker build -t apollo/intelligence:latest -f intelligence-fusion/Dockerfile .

# Build frontend
cd frontend/react-console
docker build -t apollo/frontend:latest .

# Build surveillance
cd intelligence/geoint-engine/surveillance-networks
docker build -t apollo/surveillance:latest .

# Run containers
docker run -d --name apollo-auth \
  --env-file .env \
  -p 4001:4001 \
  apollo/authentication:latest

docker run -d --name apollo-frontend \
  -p 3000:3000 \
  apollo/frontend:latest
```

---

## Kubernetes Deployment

### 1. Prepare Kubernetes Cluster

```bash
# Create namespace
kubectl create namespace apollo

# Set as default namespace
kubectl config set-context --current --namespace=apollo
```

### 2. Configure Secrets

```bash
# Create secret for database credentials
kubectl create secret generic apollo-db-secrets \
  --from-literal=postgres-password=SecurePassword123! \
  --from-literal=neo4j-password=Neo4jSecurePass123! \
  --from-literal=redis-password=RedisSecurePass123! \
  --from-literal=mongodb-password=MongoSecurePass123!

# Create secret for JWT
kubectl create secret generic apollo-jwt-secrets \
  --from-literal=jwt-secret=your-super-secret-jwt-key \
  --from-literal=jwt-refresh-secret=your-super-secret-refresh-key

# Create secret for API keys
kubectl create secret generic apollo-api-keys \
  --from-literal=blockchain-api-key=your-key \
  --from-literal=dehashed-api-key=your-key \
  --from-literal=hibp-api-key=your-key
```

### 3. Deploy Databases

```bash
# Deploy PostgreSQL
kubectl apply -f infrastructure/kubernetes/postgres-deployment.yaml
kubectl apply -f infrastructure/kubernetes/postgres-service.yaml

# Deploy Neo4j
kubectl apply -f infrastructure/kubernetes/neo4j-deployment.yaml
kubectl apply -f infrastructure/kubernetes/neo4j-service.yaml

# Deploy Redis
kubectl apply -f infrastructure/kubernetes/redis-deployment.yaml
kubectl apply -f infrastructure/kubernetes/redis-service.yaml

# Deploy Elasticsearch
kubectl apply -f infrastructure/kubernetes/elasticsearch-deployment.yaml
kubectl apply -f infrastructure/kubernetes/elasticsearch-service.yaml

# Deploy RabbitMQ
kubectl apply -f infrastructure/kubernetes/rabbitmq-deployment.yaml
kubectl apply -f infrastructure/kubernetes/rabbitmq-service.yaml

# Deploy MongoDB
kubectl apply -f infrastructure/kubernetes/mongodb-deployment.yaml
kubectl apply -f infrastructure/kubernetes/mongodb-service.yaml

# Wait for databases to be ready
kubectl wait --for=condition=ready pod -l app=postgres --timeout=300s
kubectl wait --for=condition=ready pod -l app=neo4j --timeout=300s
kubectl wait --for=condition=ready pod -l app=redis --timeout=300s
```

### 4. Deploy Backend Services

```bash
# Deploy authentication service
kubectl apply -f infrastructure/kubernetes/authentication-service.yaml

# Deploy operations service
kubectl apply -f infrastructure/kubernetes/operations-service.yaml

# Deploy intelligence fusion service
kubectl apply -f infrastructure/kubernetes/intelligence-service.yaml

# Deploy other services
kubectl apply -f infrastructure/kubernetes/redteam-service.yaml
kubectl apply -f infrastructure/kubernetes/notifications-service.yaml
kubectl apply -f infrastructure/kubernetes/alert-orchestration-service.yaml
kubectl apply -f infrastructure/kubernetes/audit-logging-service.yaml
kubectl apply -f infrastructure/kubernetes/evidence-service.yaml

# Wait for services
kubectl wait --for=condition=ready pod -l tier=backend --timeout=300s
```

### 5. Deploy Frontend

```bash
# Deploy React frontend
kubectl apply -f infrastructure/kubernetes/frontend-deployment.yaml
kubectl apply -f infrastructure/kubernetes/frontend-service.yaml

# Deploy ingress
kubectl apply -f infrastructure/kubernetes/ingress.yaml
```

### 6. Deploy Surveillance System

```bash
# Deploy facial recognition
kubectl apply -f infrastructure/kubernetes/facial-recognition-deployment.yaml

# Deploy voice recognition
kubectl apply -f infrastructure/kubernetes/voice-recognition-deployment.yaml

# Deploy camera feed manager
kubectl apply -f infrastructure/kubernetes/camera-manager-deployment.yaml
```

### 7. Configure Auto-scaling

```bash
# Deploy Horizontal Pod Autoscaler
kubectl apply -f infrastructure/kubernetes/hpa.yaml

# Verify HPA
kubectl get hpa
```

### 8. Deploy Monitoring

```bash
# Deploy Prometheus
kubectl apply -f infrastructure/monitoring/prometheus/

# Deploy Grafana
kubectl apply -f infrastructure/monitoring/grafana/

# Access Grafana
kubectl port-forward svc/grafana 3001:3000
# Visit: http://localhost:3001
```

### 9. Verify Deployment

```bash
# Check all pods
kubectl get pods

# Check services
kubectl get services

# Check ingress
kubectl get ingress

# View logs
kubectl logs -l tier=backend --tail=100

# Check resource usage
kubectl top pods
kubectl top nodes
```

---

## Database Setup

### PostgreSQL

```bash
# Connect to PostgreSQL
psql -h localhost -U apollo_admin -d apollo

# Run migrations
cd services/authentication
npm run migrate

cd ../operations
npm run migrate

# Seed initial data
npm run seed:initial

# Seed Ignatova case
npm run seed:ignatova
```

### Neo4j

```bash
# Access Neo4j Browser
# http://localhost:7474

# Import Ignatova network graph
LOAD CSV WITH HEADERS FROM 'file:///ignatova_network.csv' AS row
CREATE (p:Person {
  name: row.name,
  role: row.role,
  nationality: row.nationality
})

# Create relationships
MATCH (a:Person {name: 'Ruja Ignatova'})
MATCH (b:Person {name: 'Sebastian Greenwood'})
CREATE (a)-[:CO_FOUNDER]->(b)
```

### Redis

```bash
# Connect to Redis
redis-cli -h localhost -p 6379

# Test connection
PING

# Set initial configuration
SET apollo:config:version "1.0.0"
SET apollo:config:environment "production"
```

### Elasticsearch

```bash
# Create indices
curl -X PUT "localhost:9200/apollo_investigations" -H 'Content-Type: application/json' -d'
{
  "mappings": {
    "properties": {
      "title": { "type": "text" },
      "description": { "type": "text" },
      "status": { "type": "keyword" },
      "createdAt": { "type": "date" }
    }
  }
}'

# Create more indices
curl -X PUT "localhost:9200/apollo_evidence"
curl -X PUT "localhost:9200/apollo_alerts"
```

---

## SSL/TLS Configuration

### Generate SSL Certificates

```bash
# Using Let's Encrypt (Recommended)
certbot certonly --standalone -d apollo.yourdomain.com

# Or generate self-signed (Development only)
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /etc/ssl/private/apollo.key \
  -out /etc/ssl/certs/apollo.crt
```

### Configure Nginx

```nginx
server {
    listen 443 ssl http2;
    server_name apollo.yourdomain.com;

    ssl_certificate /etc/ssl/certs/apollo.crt;
    ssl_certificate_key /etc/ssl/private/apollo.key;
    ssl_protocols TLSv1.3 TLSv1.2;
    ssl_ciphers HIGH:!aNULL:!MD5;

    # Frontend
    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }

    # API
    location /api/ {
        proxy_pass http://localhost:4000;
        proxy_http_version 1.1;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name apollo.yourdomain.com;
    return 301 https://$server_name$request_uri;
}
```

---

## Monitoring Setup

### Prometheus Configuration

```yaml
# prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'apollo-backend'
    static_configs:
      - targets: ['localhost:4000']

  - job_name: 'apollo-surveillance'
    static_configs:
      - targets: ['localhost:5000']

  - job_name: 'postgres-exporter'
    static_configs:
      - targets: ['localhost:9187']

  - job_name: 'redis-exporter'
    static_configs:
      - targets: ['localhost:9121']

  - job_name: 'node-exporter'
    static_configs:
      - targets: ['localhost:9100']
```

### Grafana Dashboards

```bash
# Import pre-built dashboards
curl -X POST http://admin:password@localhost:3001/api/dashboards/import \
  -H "Content-Type: application/json" \
  -d @infrastructure/monitoring/grafana/dashboards/apollo-overview.json

# Access Grafana
# URL: http://localhost:3001
# Default: admin / GrafanaSecurePass123!
```

---

## Backup & Recovery

### Automated Backup Script

```bash
#!/bin/bash
# /opt/apollo/scripts/backup.sh

BACKUP_DIR="/backup/apollo/$(date +%Y%m%d)"
mkdir -p $BACKUP_DIR

# Backup PostgreSQL
pg_dump -h localhost -U apollo_admin apollo > $BACKUP_DIR/postgres.sql

# Backup Neo4j
neo4j-admin dump --database=neo4j --to=$BACKUP_DIR/neo4j.dump

# Backup Redis
redis-cli --rdb $BACKUP_DIR/redis.rdb

# Backup MongoDB
mongodump --uri="mongodb://localhost:27017/apollo" --out=$BACKUP_DIR/mongodb

# Backup Evidence Files
tar -czf $BACKUP_DIR/evidence.tar.gz /data/evidence

# Upload to S3 (Optional)
aws s3 sync $BACKUP_DIR s3://apollo-backups/$(date +%Y%m%d)/

# Remove backups older than 30 days
find /backup/apollo -type d -mtime +30 -exec rm -rf {} +
```

### Schedule Backups

```bash
# Add to crontab
crontab -e

# Run daily at 2 AM
0 2 * * * /opt/apollo/scripts/backup.sh >> /var/log/apollo/backup.log 2>&1
```

### Recovery Procedure

```bash
# Restore PostgreSQL
psql -h localhost -U apollo_admin apollo < /backup/apollo/20260114/postgres.sql

# Restore Neo4j
neo4j-admin load --from=/backup/apollo/20260114/neo4j.dump --database=neo4j --force

# Restore Redis
redis-cli --rdb /backup/apollo/20260114/redis.rdb

# Restore MongoDB
mongorestore --uri="mongodb://localhost:27017" /backup/apollo/20260114/mongodb

# Restore Evidence
tar -xzf /backup/apollo/20260114/evidence.tar.gz -C /
```

---

## Security Hardening

### 1. Firewall Configuration

```bash
# Allow SSH
ufw allow 22/tcp

# Allow HTTP/HTTPS
ufw allow 80/tcp
ufw allow 443/tcp

# Allow database ports (internal only)
ufw allow from 10.0.0.0/8 to any port 5432  # PostgreSQL
ufw allow from 10.0.0.0/8 to any port 7687  # Neo4j
ufw allow from 10.0.0.0/8 to any port 6379  # Redis

# Enable firewall
ufw enable
```

### 2. Database Security

```sql
-- PostgreSQL: Create read-only user for analysts
CREATE ROLE analyst WITH LOGIN PASSWORD 'AnalystSecurePass!';
GRANT CONNECT ON DATABASE apollo TO analyst;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO analyst;

-- Revoke dangerous permissions
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
```

### 3. Application Security

```bash
# Set restrictive file permissions
chmod 600 .env
chmod 700 /data/face_database
chmod 700 /data/voice_database

# Disable root SSH
sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
systemctl restart sshd

# Enable fail2ban
apt install fail2ban
systemctl enable fail2ban
systemctl start fail2ban
```

### 4. Secrets Management with HashiCorp Vault

```bash
# Start Vault
vault server -dev

# Store secrets
vault kv put secret/apollo/database \
  username=apollo_admin \
  password=SecurePassword123!

vault kv put secret/apollo/jwt \
  secret=your-jwt-secret \
  refresh_secret=your-refresh-secret

# Application retrieves secrets at runtime
```

---

## Troubleshooting

### Common Issues

**Issue**: Services can't connect to databases
```bash
# Check database status
docker-compose ps
kubectl get pods

# Check logs
docker-compose logs postgres
kubectl logs -l app=postgres

# Test connection
psql -h localhost -U apollo_admin -d apollo
```

**Issue**: High memory usage
```bash
# Check resource usage
docker stats
kubectl top pods

# Scale down surveillance cameras
# Edit config/camera_feeds.json
# Reduce concurrent cameras

# Increase memory limits
kubectl edit deployment facial-recognition
# Update resources.limits.memory
```

**Issue**: Facial recognition slow
```bash
# Enable GPU acceleration
# Edit docker-compose.yml
services:
  surveillance:
    deploy:
      resources:
        reservations:
          devices:
            - driver: nvidia
              count: 1
              capabilities: [gpu]

# Verify GPU available
nvidia-smi
```

**Issue**: SSL certificate errors
```bash
# Renew Let's Encrypt certificate
certbot renew

# Update certificate in Kubernetes
kubectl create secret tls apollo-tls \
  --cert=/etc/letsencrypt/live/apollo.domain.com/fullchain.pem \
  --key=/etc/letsencrypt/live/apollo.domain.com/privkey.pem \
  --dry-run=client -o yaml | kubectl apply -f -
```

### Health Checks

```bash
# Backend health
curl http://localhost:4000/health

# Database health
curl http://localhost:4000/health/database

# Surveillance health
curl http://localhost:5000/health

# Kubernetes health
kubectl get pods -o wide
kubectl describe pod <pod-name>
```

### Log Locations

```bash
# Application logs
/var/log/apollo/apollo.log
/var/log/apollo/error.log
/var/log/apollo/access.log

# Docker logs
docker-compose logs -f

# Kubernetes logs
kubectl logs -f <pod-name>
kubectl logs -f -l tier=backend --tail=100
```

---

## Production Checklist

Before going live:

- [ ] All environment variables configured
- [ ] SSL/TLS certificates installed
- [ ] Databases backed up and tested
- [ ] Firewall rules configured
- [ ] Monitoring dashboards set up
- [ ] Backup automation scheduled
- [ ] Security hardening applied
- [ ] Load testing completed
- [ ] Disaster recovery plan documented
- [ ] Team trained on operations
- [ ] Incident response plan ready
- [ ] Compliance audit completed

---

## Support

For deployment support:
- **Email**: devops@apollo-platform.local
- **Documentation**: [APOLLO_COMPLETE_STATUS.md](../APOLLO_COMPLETE_STATUS.md)
- **Emergency**: Contact system administrator

---

**Deployment Guide Version**: 1.0.0
**Last Updated**: January 2026
