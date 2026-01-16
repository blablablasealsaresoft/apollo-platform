# Sherlock OSINT - Deployment Guide

Complete guide for deploying Sherlock OSINT in production environments.

---

## Table of Contents

1. [Deployment Options](#deployment-options)
2. [Docker Deployment](#docker-deployment)
3. [Manual Deployment](#manual-deployment)
4. [Cloud Deployment](#cloud-deployment)
5. [Configuration](#configuration)
6. [Monitoring](#monitoring)
7. [Security](#security)
8. [Scaling](#scaling)

---

## Deployment Options

### 1. Docker (Recommended)

- Full stack deployment with all integrations
- Easy to manage and scale
- Includes Elasticsearch, Redis, Neo4j

### 2. Manual Deployment

- Direct installation on server
- More control over configuration
- Suitable for custom environments

### 3. Cloud Deployment

- AWS, Azure, GCP
- Kubernetes-ready
- Auto-scaling capabilities

---

## Docker Deployment

### Prerequisites

- Docker 20.10+
- Docker Compose 2.0+
- 4GB RAM minimum
- 20GB disk space

### Quick Start

```bash
# Clone repository
cd C:\SECURE_THREAT_INTEL\YoureGunnaHAveToShootMeToStopME\apollo\intelligence\osint-tools\sherlock

# Start all services
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f sherlock

# Access API
curl http://localhost:8000/api/health
```

### Services

| Service | Port | Description |
|---------|------|-------------|
| Sherlock API | 8000 | Main API server |
| Elasticsearch | 9200 | Results storage |
| Redis | 6379 | Caching layer |
| Neo4j | 7474, 7687 | Graph database |
| Kibana | 5601 | ES visualization |

### Stop Services

```bash
# Stop all services
docker-compose down

# Stop and remove volumes
docker-compose down -v
```

### Production Configuration

Edit `docker-compose.yml`:

```yaml
services:
  sherlock:
    environment:
      - SHERLOCK_ENV=production
      - SHERLOCK_MAX_CONCURRENT=100
      - API_WORKERS=8
```

---

## Manual Deployment

### System Requirements

- **OS**: Linux (Ubuntu 20.04+) or Windows Server
- **Python**: 3.8+
- **RAM**: 4GB minimum, 8GB recommended
- **CPU**: 2+ cores
- **Disk**: 20GB+

### Installation Steps

#### 1. Install Python Dependencies

```bash
cd sherlock
pip install -r requirements.txt
```

#### 2. Install External Services (Optional)

**Elasticsearch:**
```bash
# Ubuntu/Debian
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
echo "deb https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list
sudo apt-get update && sudo apt-get install elasticsearch
sudo systemctl start elasticsearch
```

**Redis:**
```bash
sudo apt-get install redis-server
sudo systemctl start redis-server
```

**Neo4j:**
```bash
wget -O - https://debian.neo4j.com/neotechnology.gpg.key | sudo apt-key add -
echo 'deb https://debian.neo4j.com stable latest' | sudo tee /etc/apt/sources.list.d/neo4j.list
sudo apt-get update && sudo apt-get install neo4j
sudo systemctl start neo4j
```

#### 3. Configure Environment

```bash
cp .env.example .env
nano .env
```

#### 4. Start API Server

**Development:**
```bash
python fastapi_endpoints.py
```

**Production (with Gunicorn):**
```bash
pip install gunicorn uvicorn[standard]

gunicorn fastapi_endpoints:app \
  --workers 4 \
  --worker-class uvicorn.workers.UvicornWorker \
  --bind 0.0.0.0:8000 \
  --timeout 120 \
  --access-logfile /var/log/sherlock/access.log \
  --error-logfile /var/log/sherlock/error.log
```

#### 5. Setup Systemd Service

Create `/etc/systemd/system/sherlock.service`:

```ini
[Unit]
Description=Sherlock OSINT API
After=network.target redis.service elasticsearch.service

[Service]
Type=notify
User=sherlock
Group=sherlock
WorkingDirectory=/opt/sherlock
Environment="PATH=/opt/sherlock/venv/bin"
ExecStart=/opt/sherlock/venv/bin/gunicorn fastapi_endpoints:app \
  --workers 4 \
  --worker-class uvicorn.workers.UvicornWorker \
  --bind 0.0.0.0:8000 \
  --timeout 120
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable sherlock
sudo systemctl start sherlock
```

---

## Cloud Deployment

### AWS Deployment

#### EC2 Instance

1. **Launch EC2 Instance**
   - AMI: Ubuntu 20.04 LTS
   - Instance Type: t3.medium or larger
   - Security Group: Allow ports 8000, 9200, 6379, 7687

2. **Install Docker**
   ```bash
   sudo apt-get update
   sudo apt-get install docker.io docker-compose
   sudo systemctl start docker
   ```

3. **Deploy Sherlock**
   ```bash
   git clone <repository>
   cd sherlock
   docker-compose up -d
   ```

#### ECS Deployment

Create `ecs-task-definition.json`:

```json
{
  "family": "sherlock-osint",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "1024",
  "memory": "2048",
  "containerDefinitions": [
    {
      "name": "sherlock",
      "image": "sherlock-osint:latest",
      "portMappings": [
        {
          "containerPort": 8000,
          "protocol": "tcp"
        }
      ],
      "environment": [
        {"name": "SHERLOCK_ENV", "value": "production"},
        {"name": "ELASTICSEARCH_HOST", "value": "elasticsearch.example.com"}
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/sherlock",
          "awslogs-region": "us-east-1",
          "awslogs-stream-prefix": "ecs"
        }
      }
    }
  ]
}
```

### Azure Deployment

```bash
# Create resource group
az group create --name sherlock-rg --location eastus

# Create container instance
az container create \
  --resource-group sherlock-rg \
  --name sherlock-osint \
  --image sherlock-osint:latest \
  --ports 8000 \
  --dns-name-label sherlock-osint \
  --environment-variables \
    SHERLOCK_ENV=production \
    ELASTICSEARCH_HOST=elasticsearch.example.com
```

### GCP Deployment

```bash
# Build and push image
gcloud builds submit --tag gcr.io/PROJECT_ID/sherlock-osint

# Deploy to Cloud Run
gcloud run deploy sherlock-osint \
  --image gcr.io/PROJECT_ID/sherlock-osint \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated \
  --set-env-vars SHERLOCK_ENV=production
```

### Kubernetes Deployment

Create `kubernetes-deployment.yaml`:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: sherlock-osint
spec:
  replicas: 3
  selector:
    matchLabels:
      app: sherlock
  template:
    metadata:
      labels:
        app: sherlock
    spec:
      containers:
      - name: sherlock
        image: sherlock-osint:latest
        ports:
        - containerPort: 8000
        env:
        - name: SHERLOCK_ENV
          value: "production"
        - name: ELASTICSEARCH_HOST
          value: "elasticsearch-service"
        resources:
          requests:
            memory: "1Gi"
            cpu: "500m"
          limits:
            memory: "2Gi"
            cpu: "1000m"
---
apiVersion: v1
kind: Service
metadata:
  name: sherlock-service
spec:
  type: LoadBalancer
  ports:
  - port: 80
    targetPort: 8000
  selector:
    app: sherlock
```

Deploy:
```bash
kubectl apply -f kubernetes-deployment.yaml
```

---

## Configuration

### Environment Variables

```bash
# Application
SHERLOCK_ENV=production
SHERLOCK_DEBUG=false
SHERLOCK_LOG_LEVEL=INFO

# Performance
SHERLOCK_MAX_CONCURRENT=50
SHERLOCK_TIMEOUT=10
API_WORKERS=4

# Integrations
ELASTICSEARCH_HOST=localhost:9200
REDIS_HOST=localhost:6379
NEO4J_HOST=bolt://localhost:7687
```

### Platform Configuration

Edit `platforms_config.json` to customize platforms:

```json
{
  "CustomPlatform": {
    "url": "https://example.com/users/{}",
    "errorType": "status_code",
    "errorCode": 404,
    "category": "custom",
    "reliable": true
  }
}
```

---

## Monitoring

### Health Checks

```bash
# API health
curl http://localhost:8000/api/health

# Elasticsearch
curl http://localhost:9200/_cluster/health

# Redis
redis-cli ping

# Neo4j
curl http://localhost:7474/db/neo4j/tx/commit
```

### Prometheus Metrics

Add to `fastapi_endpoints.py`:

```python
from prometheus_client import Counter, Histogram, generate_latest

requests_total = Counter('sherlock_requests_total', 'Total requests')
search_duration = Histogram('sherlock_search_duration_seconds', 'Search duration')

@app.get("/metrics")
def metrics():
    return Response(generate_latest(), media_type="text/plain")
```

### Logging

Configure centralized logging:

```python
import logging
from logging.handlers import RotatingFileHandler

handler = RotatingFileHandler(
    '/var/log/sherlock/app.log',
    maxBytes=10485760,  # 10MB
    backupCount=5
)

logging.basicConfig(
    handlers=[handler],
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
```

---

## Security

### API Authentication

Add API key authentication:

```python
from fastapi import Security, HTTPException
from fastapi.security import APIKeyHeader

api_key_header = APIKeyHeader(name="X-API-Key")

async def verify_api_key(api_key: str = Security(api_key_header)):
    if api_key != os.getenv("API_KEY"):
        raise HTTPException(status_code=403, detail="Invalid API key")
    return api_key

@app.post("/api/search", dependencies=[Security(verify_api_key)])
async def search_username(request: UsernameSearchRequest):
    # ... search logic
```

### Rate Limiting

```python
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

@app.post("/api/search")
@limiter.limit("10/minute")
async def search_username(request: Request):
    # ... search logic
```

### HTTPS/TLS

Use reverse proxy (Nginx):

```nginx
server {
    listen 443 ssl;
    server_name sherlock.example.com;

    ssl_certificate /etc/ssl/certs/sherlock.crt;
    ssl_certificate_key /etc/ssl/private/sherlock.key;

    location / {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

---

## Scaling

### Horizontal Scaling

**Docker Swarm:**
```bash
docker service create \
  --name sherlock \
  --replicas 5 \
  --publish 8000:8000 \
  sherlock-osint:latest
```

**Kubernetes:**
```bash
kubectl scale deployment sherlock-osint --replicas=5
```

### Load Balancing

**Nginx:**
```nginx
upstream sherlock_backend {
    least_conn;
    server sherlock1:8000;
    server sherlock2:8000;
    server sherlock3:8000;
}

server {
    location / {
        proxy_pass http://sherlock_backend;
    }
}
```

### Database Scaling

**Elasticsearch Cluster:**
```yaml
services:
  elasticsearch-1:
    image: elasticsearch:8.11.0
    environment:
      - cluster.name=sherlock-cluster
      - node.name=es-node-1
      - discovery.seed_hosts=elasticsearch-2,elasticsearch-3

  elasticsearch-2:
    image: elasticsearch:8.11.0
    # ... similar config

  elasticsearch-3:
    image: elasticsearch:8.11.0
    # ... similar config
```

**Redis Cluster:**
```yaml
services:
  redis-master:
    image: redis:7-alpine
    command: redis-server --appendonly yes

  redis-replica-1:
    image: redis:7-alpine
    command: redis-server --slaveof redis-master 6379

  redis-replica-2:
    image: redis:7-alpine
    command: redis-server --slaveof redis-master 6379
```

---

## Backup and Recovery

### Elasticsearch Backup

```bash
# Create snapshot repository
curl -X PUT "localhost:9200/_snapshot/sherlock_backup" -H 'Content-Type: application/json' -d'
{
  "type": "fs",
  "settings": {
    "location": "/backups/elasticsearch"
  }
}'

# Create snapshot
curl -X PUT "localhost:9200/_snapshot/sherlock_backup/snapshot_1?wait_for_completion=true"

# Restore snapshot
curl -X POST "localhost:9200/_snapshot/sherlock_backup/snapshot_1/_restore"
```

### Redis Backup

```bash
# Manual backup
redis-cli SAVE

# Copy RDB file
cp /var/lib/redis/dump.rdb /backups/redis/
```

### Neo4j Backup

```bash
# Backup
neo4j-admin backup --backup-dir=/backups/neo4j

# Restore
neo4j-admin restore --from=/backups/neo4j/neo4j-backup
```

---

## Troubleshooting

### Common Issues

**Issue: API not responding**
```bash
# Check logs
docker-compose logs sherlock

# Check service status
systemctl status sherlock
```

**Issue: Elasticsearch connection failed**
```bash
# Check Elasticsearch status
curl http://localhost:9200/_cluster/health

# Restart Elasticsearch
docker-compose restart elasticsearch
```

**Issue: High memory usage**
```bash
# Monitor resources
docker stats

# Reduce concurrent requests
export SHERLOCK_MAX_CONCURRENT=20
```

---

## Performance Tuning

### API Server

```python
# Increase workers
gunicorn --workers 8 fastapi_endpoints:app

# Adjust timeout
gunicorn --timeout 300 fastapi_endpoints:app
```

### Elasticsearch

```yaml
environment:
  - "ES_JAVA_OPTS=-Xms2g -Xmx2g"  # Increase heap size
```

### Redis

```bash
# Increase max memory
redis-cli CONFIG SET maxmemory 2gb
redis-cli CONFIG SET maxmemory-policy allkeys-lru
```

---

## Maintenance

### Updates

```bash
# Pull latest changes
git pull

# Update dependencies
pip install -r requirements.txt --upgrade

# Restart services
docker-compose restart sherlock
```

### Cleanup

```bash
# Clear old exports
find /app/exports -mtime +30 -delete

# Clear logs
find /var/log/sherlock -mtime +90 -delete

# Elasticsearch indices
curl -X DELETE "localhost:9200/sherlock-results-*?ignore_unavailable=true"
```

---

## Support

For deployment assistance:
- Documentation: `README_SHERLOCK.md`
- Quick Start: `QUICKSTART.md`
- Examples: `examples.py`

---

**Production Ready ✅**
