# Apollo Platform - Quick Reference Card

## Service Ports

### Backend Services (4000-4999)
| Service | Port | URL |
|---------|------|-----|
| Authentication | 4001 | http://localhost:4001 |
| Operations | 4002 | http://localhost:4002 |
| Intelligence Fusion | 4003 | http://localhost:4003 |
| Red Team Ops | 4004 | http://localhost:4004 |
| Notifications | 4005 | http://localhost:4005 |
| Alert Orchestration | 4006 | http://localhost:4006 |
| Audit Logging | 4007 | http://localhost:4007 |
| Evidence Management | 4008 | http://localhost:4008 |

### Frontend (3000)
| Service | Port | URL |
|---------|------|-----|
| React Console | 3000 | http://localhost:3000 |

### AI Engines (8000-8999, 37695)
| Service | Port | URL |
|---------|------|-----|
| BugTrace-AI | 8001 | http://localhost:8001 |
| Criminal Behavior AI | 8002 | http://localhost:8002 |
| Predictive Analytics | 8003 | http://localhost:8003 |
| Cyberspike Villager | 37695 | http://localhost:37695 |

### Intelligence Services (5000-6999)
| Service | Port | URL |
|---------|------|-----|
| Surveillance System | 5000 | http://localhost:5000 |
| OSINT Engine | 5001 | http://localhost:5001 |
| GEOINT Engine | 5002 | http://localhost:5002 |
| Blockchain Forensics | 6000 | http://localhost:6000 |

### Monitoring (3001, 3100, 9090-9100)
| Service | Port | URL |
|---------|------|-----|
| Grafana | 3001 | http://localhost:3001 |
| Loki | 3100 | http://localhost:3100 |
| Prometheus | 9090 | http://localhost:9090 |
| Alertmanager | 9093 | http://localhost:9093 |
| Node Exporter | 9100 | http://localhost:9100 |

## Health Check Commands

```bash
# Check all backend services
for port in {4001..4008}; do
  echo "Port $port: $(curl -s http://localhost:$port/health | jq -r .status 2>/dev/null || echo 'DOWN')"
done

# Check AI engines
curl http://localhost:8001/health  # BugTrace-AI
curl http://localhost:8002/health  # Criminal Behavior AI
curl http://localhost:8003/health  # Predictive Analytics
curl http://localhost:37695/health # Cyberspike Villager

# Check intelligence services
curl http://localhost:5000/health  # Surveillance
curl http://localhost:5001/health  # OSINT
curl http://localhost:5002/health  # GEOINT
curl http://localhost:6000/health  # Blockchain

# Check monitoring
curl http://localhost:9090/-/healthy  # Prometheus
curl http://localhost:3001/api/health # Grafana
```

## Docker Compose Commands

```bash
# Start all services
docker-compose up -d

# Start specific service group
docker-compose up -d backend
docker-compose up -d ai-engines
docker-compose up -d intelligence
docker-compose up -d monitoring

# View logs
docker-compose logs -f authentication
docker-compose logs -f --tail=100 operations

# Restart service
docker-compose restart operations

# Scale service
docker-compose up -d --scale operations=3

# Stop all services
docker-compose down

# Stop and remove volumes
docker-compose down -v
```

## Environment Variables Quick Setup

```bash
# Copy example environment file
cp .env.example .env

# Required variables
export DATABASE_URL="postgresql://apollo:password@postgres:5432/apollo"
export REDIS_URL="redis://redis:6379"
export NEO4J_URI="bolt://neo4j:7687"
export ELASTICSEARCH_URL="http://elasticsearch:9200"

# AI API Keys
export GOOGLE_API_KEY="your_google_api_key"
export ANTHROPIC_API_KEY="your_anthropic_api_key"
export OPENAI_API_KEY="your_openai_api_key"
export DEEPSEEK_API_KEY="your_deepseek_api_key"

# OAuth
export GOOGLE_CLIENT_ID="your_google_client_id"
export GOOGLE_CLIENT_SECRET="your_google_client_secret"

# Storage
export S3_EVIDENCE_BUCKET="apollo-evidence"
export S3_SURVEILLANCE_BUCKET="apollo-surveillance"
```

## Common API Endpoints

### Authentication Service (4001)
```bash
POST /api/v1/auth/login          # User login
POST /api/v1/auth/logout         # User logout
POST /api/v1/auth/refresh        # Refresh token
POST /api/v1/auth/register       # User registration
GET  /api/v1/auth/me             # Current user info
```

### Operations Service (4002)
```bash
GET    /api/v1/investigations              # List investigations
POST   /api/v1/investigations              # Create investigation
GET    /api/v1/investigations/{id}         # Get investigation
PUT    /api/v1/investigations/{id}         # Update investigation
DELETE /api/v1/investigations/{id}         # Delete investigation
POST   /api/v1/investigations/{id}/targets # Add target
GET    /api/v1/investigations/{id}/timeline # Get timeline
```

### Intelligence Fusion Service (4003)
```bash
POST /api/v1/correlate           # Correlate data
GET  /api/v1/graph/{entity_id}   # Get entity graph
POST /api/v1/analyze             # Analyze patterns
GET  /api/v1/threats             # Get threat scores
```

### Surveillance System (5000)
```bash
GET  /api/v1/feeds               # List camera feeds
POST /api/v1/feeds               # Add camera feed
GET  /api/v1/matches             # Get facial matches
POST /api/v1/enroll              # Enroll face
GET  /api/v1/alerts              # Get alerts
```

## Monitoring Quick Access

### Prometheus Queries
```promql
# CPU usage per service
rate(process_cpu_seconds_total[5m])

# Memory usage
process_resident_memory_bytes

# Request rate
rate(http_requests_total[5m])

# Error rate
rate(http_requests_total{status=~"5.."}[5m])

# P95 latency
histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))
```

### Grafana Dashboards
- Apollo Overview: http://localhost:3001/d/apollo-overview
- Backend Services: http://localhost:3001/d/backend-services
- AI Engines: http://localhost:3001/d/ai-engines
- Surveillance: http://localhost:3001/d/surveillance
- Intelligence: http://localhost:3001/d/intelligence

### Loki Queries
```logql
# All logs from operations service
{service="operations"}

# Error logs across all services
{} |= "error" | json

# Logs for specific investigation
{service="operations"} | json | investigation_id="123"

# High severity logs
{} | json | level="error" or level="critical"
```

## Database Access

### PostgreSQL
```bash
docker-compose exec postgres psql -U apollo

# Common queries
\dt                              # List tables
\d+ investigations               # Describe table
SELECT COUNT(*) FROM investigations;
```

### Redis
```bash
docker-compose exec redis redis-cli

# Common commands
KEYS *                           # List all keys
GET session:user:123             # Get value
HGETALL user:456                 # Get hash
```

### Neo4j
```bash
# Browser: http://localhost:7474
# Bolt: bolt://localhost:7687

# Cypher queries
MATCH (n) RETURN count(n);                    # Count nodes
MATCH (n:Person) RETURN n LIMIT 10;           # Get persons
MATCH p=()-[r:ASSOCIATED_WITH]->() RETURN p;  # Get relationships
```

### Elasticsearch
```bash
# List indices
curl http://localhost:9200/_cat/indices?v

# Search logs
curl -X POST "http://localhost:9200/apollo-logs-*/_search?pretty" -H 'Content-Type: application/json' -d'
{
  "query": {
    "match": {
      "service": "operations"
    }
  }
}'
```

## Troubleshooting

### Service Won't Start
```bash
# Check logs
docker-compose logs service-name

# Check if port is in use
netstat -ano | findstr :4001

# Verify environment variables
docker-compose config
```

### Database Connection Issues
```bash
# Test PostgreSQL connection
docker-compose exec authentication-service pg_isready -h postgres -p 5432

# Test Redis connection
docker-compose exec authentication-service redis-cli -h redis ping
```

### High Memory Usage
```bash
# Check container stats
docker stats

# Check specific service memory
docker stats authentication-service --no-stream
```

### Performance Issues
```bash
# Check Prometheus for service metrics
curl http://localhost:9090/api/v1/query?query=process_resident_memory_bytes

# Check database query performance
docker-compose exec postgres psql -U apollo -c "SELECT * FROM pg_stat_statements ORDER BY mean_exec_time DESC LIMIT 10;"
```

## Resource Requirements

### Minimum (Development)
- CPU: 8 cores
- RAM: 32GB
- Storage: 500GB SSD
- GPU: Optional

### Recommended (Staging)
- CPU: 16 cores
- RAM: 64GB
- Storage: 1TB SSD
- GPU: 1x NVIDIA (8GB VRAM)

### Production
- CPU: 32+ cores
- RAM: 128GB+
- Storage: 2TB+ NVMe SSD
- GPU: 4x NVIDIA A100 (40GB VRAM)

## Security Best Practices

1. **Change default passwords** in all configuration files
2. **Use strong JWT secrets** (32+ characters)
3. **Enable HTTPS** for all external-facing services
4. **Configure firewall** to restrict access
5. **Enable audit logging** on all services
6. **Rotate API keys** regularly
7. **Use least privilege** for service accounts
8. **Enable MFA** for admin accounts
9. **Regular security updates** of all dependencies
10. **Monitor security logs** for anomalies

## Backup Commands

```bash
# Database backup
docker-compose exec postgres pg_dump -U apollo apollo > backup-$(date +%Y%m%d).sql

# Redis backup
docker-compose exec redis redis-cli SAVE
docker cp apollo_redis_1:/data/dump.rdb ./backup/redis-$(date +%Y%m%d).rdb

# Neo4j backup
docker-compose exec neo4j neo4j-admin dump --to=/backups/neo4j-$(date +%Y%m%d).dump

# Configuration backup
tar -czf configs-backup-$(date +%Y%m%d).tar.gz configs/
```

## Scaling Guide

### Horizontal Scaling
```bash
# Scale operations service to 3 replicas
docker-compose up -d --scale operations=3

# Scale OSINT engine to 5 replicas
docker-compose up -d --scale osint-engine=5
```

### Vertical Scaling
Edit service YAML files:
```yaml
runtime:
  workers: 16              # Increase workers
  max_memory: 16GB         # Increase memory
```

## Support Contacts

- **Documentation**: /docs directory
- **Logs**: /var/log/apollo/
- **Metrics**: http://localhost:9090
- **Dashboards**: http://localhost:3001

---

**Quick Reference Version**: 1.0.0
**Last Updated**: January 14, 2026
