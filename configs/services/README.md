# Apollo Platform Service Configurations

Comprehensive service configuration files for all Apollo Platform microservices, AI engines, intelligence services, and monitoring infrastructure.

## Directory Structure

```
configs/services/
├── backend/                      # Backend microservices (8 services)
│   ├── authentication-service.yaml
│   ├── operations-service.yaml
│   ├── intelligence-fusion-service.yaml
│   ├── redteam-ops-service.yaml
│   ├── notifications-service.yaml
│   ├── alert-orchestration-service.yaml
│   ├── audit-logging-service.yaml
│   └── evidence-management-service.yaml
├── frontend/                     # Frontend services
│   ├── react-console.yaml
│   └── build-config.yaml
├── ai-engines/                   # AI/ML services (4 engines)
│   ├── bugtrace-ai.yaml
│   ├── cyberspike-villager.yaml
│   ├── criminal-behavior-ai.yaml
│   └── predictive-analytics.yaml
├── intelligence/                 # Intelligence engines (4 services)
│   ├── osint-engine.yaml
│   ├── geoint-engine.yaml
│   ├── surveillance-system.yaml
│   └── blockchain-forensics.yaml
├── monitoring/                   # Monitoring and observability
│   ├── prometheus.yaml
│   ├── grafana.yaml
│   ├── alertmanager.yaml
│   └── logging.yaml
└── README.md
```

## Service Overview

### Backend Services (Port 4000-4999)

#### 1. Authentication Service (Port 4001)
- **Purpose**: Enterprise authentication and authorization
- **Features**: JWT, OAuth (Google, Microsoft, GitHub), MFA, RBAC
- **Workers**: 4 workers, 2 threads each
- **Memory**: 2GB
- **Security**: Password policy, rate limiting, session management

#### 2. Operations Service (Port 4002)
- **Purpose**: Investigation and case management
- **Features**: Investigation tracking, target management, timeline analysis
- **Workers**: 8 workers
- **Memory**: 4GB
- **Databases**: PostgreSQL, Neo4j, Redis, Elasticsearch

#### 3. Intelligence Fusion Service (Port 4003)
- **Purpose**: Multi-source intelligence correlation
- **Features**: 1686+ tools/APIs, graph analysis, threat scoring
- **Workers**: 6 workers
- **Memory**: 8GB
- **Capabilities**: Entity resolution, pattern recognition, anomaly detection

#### 4. Red Team Operations Service (Port 4004)
- **Purpose**: Security testing coordination
- **Features**: Campaign management, vulnerability tracking, BugTrace-AI integration
- **Workers**: 6 workers
- **Memory**: 6GB
- **Tools**: Kali (600+), BugTrace-AI, Cyberspike Villager

#### 5. Notifications Service (Port 4005)
- **Purpose**: Multi-channel notification delivery
- **Features**: Email, Slack, Teams, webhooks, in-app, push notifications
- **Workers**: 4 workers
- **Memory**: 2GB
- **Channels**: 6 notification channels

#### 6. Alert Orchestration Service (Port 4006)
- **Purpose**: Intelligent alert routing and correlation
- **Features**: Alert correlation, deduplication, priority escalation
- **Workers**: 6 workers
- **Memory**: 4GB
- **Processing**: Real-time correlation with 5-minute window

#### 7. Audit Logging Service (Port 4007)
- **Purpose**: Compliance and audit trail
- **Features**: Tamper detection, multi-tier storage, compliance tracking
- **Workers**: 4 workers
- **Memory**: 3GB
- **Retention**: 7 years (cold storage)

#### 8. Evidence Management Service (Port 4008)
- **Purpose**: Digital evidence with chain of custody
- **Features**: File upload, encryption, deduplication, versioning
- **Workers**: 6 workers
- **Memory**: 8GB
- **Storage**: S3 with AES-256 encryption

### Frontend Services

#### React Console (Port 3000)
- **Purpose**: Web-based investigation console
- **Framework**: React 18.x with Vite
- **Features**: 7 modules (dashboard, investigations, intelligence, surveillance, evidence, redteam, analytics)
- **State Management**: Redux Toolkit
- **UI**: Material-UI (MUI)
- **Build**: Production-optimized with code splitting

### AI Engines (Port 8000-8999)

#### 1. BugTrace-AI (Port 8001)
- **Purpose**: AI-powered security testing
- **Models**: Gemini Flash (primary), Claude Sonnet (fallback)
- **Analyzers**: 4 core, 4 specialized, 3 reconnaissance, 2 payload
- **Capabilities**: Multi-persona analysis (5 personas, depth 5), 95% accuracy target
- **Memory**: 8GB

#### 2. Cyberspike Villager (Port 37695)
- **Purpose**: AI-native C2 server with autonomous orchestration
- **Models**: Claude Opus (primary), DeepSeek-v3 (fallback)
- **Tools**: 1686+ (686 OSINT + 1000 APIs + Kali tools)
- **Modes**: Supervised, autonomous, collaborative
- **Memory**: 16GB

#### 3. Criminal Behavior AI (Port 8002)
- **Purpose**: Behavioral profiling and pattern analysis
- **Models**: Claude Opus (primary), Gemini Flash (fallback)
- **Capabilities**: Behavioral profiling, threat assessment, prediction, modus operandi
- **Analysis**: Social network, temporal patterns, risk scoring
- **Memory**: 6GB

#### 4. Predictive Analytics (Port 8003)
- **Purpose**: Forecasting and predictive modeling
- **Models**: Gemini Flash (primary), GPT-4 (fallback)
- **Predictions**: Location, activity, associations, resources, threats
- **ML Frameworks**: TensorFlow, PyTorch, scikit-learn, XGBoost
- **Memory**: 8GB

### Intelligence Services (Port 5000-6999)

#### 1. OSINT Engine (Port 5001)
- **Purpose**: Open-source intelligence collection
- **Tools**: 686 tools across 9 categories
- **APIs**: 1000+ public APIs
- **Categories**: Reconnaissance (100+), Social Media (400+), Blockchain (50+), Dark Web (30+), Email (20+), Phone (15+), Domain (25+), Image (10+), Geolocation (10+)
- **Memory**: 16GB

#### 2. GEOINT Engine (Port 5002)
- **Purpose**: Geospatial intelligence
- **Features**: IP/cell tower/WiFi geolocation, proximity analysis, route analysis
- **Data Sources**: MaxMind, IPStack, OpenStreetMap, Google Maps
- **Accuracy**: Country (100%), City (90%), Street (60%)
- **Memory**: 8GB

#### 3. Surveillance System (Port 5000)
- **Purpose**: Advanced surveillance with facial/voice recognition
- **Facial Recognition**: 95%+ accuracy, 50-100ms GPU processing
- **Voice Recognition**: 90%+ accuracy, <50ms matching
- **Age Progression**: +7, +9, +12 year variants
- **Max Feeds**: 10,000 concurrent camera feeds
- **Memory**: 32GB (16GB GPU)

#### 4. Blockchain Forensics (Port 6000)
- **Purpose**: Cryptocurrency tracking and analysis
- **Blockchains**: Bitcoin, Ethereum, Monero, Litecoin, Ripple, Cardano, Binance Chain, and others
- **Capabilities**: Wallet tracking, transaction analysis, exchange monitoring, mixer detection, entity clustering
- **Memory**: 12GB

### Monitoring Services

#### 1. Prometheus (Port 9090)
- **Purpose**: Metrics collection and alerting
- **Scrape Interval**: 15s
- **Retention**: 30 days / 50GB
- **Targets**: All Apollo services, databases, infrastructure
- **Jobs**: 9 scrape configurations

#### 2. Grafana (Port 3001)
- **Purpose**: Visualization and dashboards
- **Datasources**: Prometheus, Loki, PostgreSQL, Elasticsearch
- **Dashboards**: Apollo Overview, Backend Services, AI Engines, Surveillance, Intelligence
- **Authentication**: Admin + LDAP/OAuth support

#### 3. Alertmanager (Port 9093)
- **Purpose**: Alert routing and notification
- **Receivers**: Email, Slack, webhooks
- **Routes**: Critical, surveillance, database, backend, AI, infrastructure
- **Inhibition**: Smart alert suppression

#### 4. Logging Stack
- **Collector**: Fluentd (Port 24224)
- **Aggregator**: Loki (Port 3100)
- **Retention**: Hot (7d), Warm (30d), Cold (90d), Archive (365d)
- **Format**: JSON with structured fields

## Configuration Management

### Environment Variables

All services use environment variables for sensitive configuration:

```bash
# Database
DATABASE_URL=postgresql://user:pass@postgres:5432/apollo
REDIS_URL=redis://redis:6379
NEO4J_URI=bolt://neo4j:7687
ELASTICSEARCH_URL=http://elasticsearch:9200
MONGODB_URI=mongodb://mongodb:27017

# AI Models
GOOGLE_API_KEY=your_google_api_key
ANTHROPIC_API_KEY=your_anthropic_api_key
OPENAI_API_KEY=your_openai_api_key
DEEPSEEK_API_KEY=your_deepseek_api_key

# OAuth
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
MICROSOFT_CLIENT_ID=your_microsoft_client_id
MICROSOFT_CLIENT_SECRET=your_microsoft_client_secret
GITHUB_CLIENT_ID=your_github_client_id
GITHUB_CLIENT_SECRET=your_github_client_secret

# Storage
S3_EVIDENCE_BUCKET=apollo-evidence
S3_SURVEILLANCE_BUCKET=apollo-surveillance
S3_AUDIT_BUCKET=apollo-audit
S3_REGION=us-east-1

# Monitoring
GRAFANA_ADMIN_PASSWORD=secure_password
GRAFANA_SECRET_KEY=secure_secret_key
SLACK_WEBHOOK_URL=https://hooks.slack.com/...
```

### Service Discovery

All services support Consul service discovery:

```yaml
service_discovery:
  consul:
    enabled: true
    address: consul:8500
    service_name: service-name
    health_check_interval: 10s
```

### Health Checks

Standard health check endpoints:

- `/health` - Basic health check
- `/ready` - Readiness probe
- `/live` - Liveness probe
- `/metrics` - Prometheus metrics

## Deployment

### Docker Compose

```bash
# Start all services
docker-compose up -d

# Start specific service category
docker-compose up -d backend
docker-compose up -d ai-engines
docker-compose up -d intelligence
docker-compose up -d monitoring

# View logs
docker-compose logs -f service-name

# Scale services
docker-compose up -d --scale operations=3
```

### Kubernetes

```bash
# Apply configurations
kubectl apply -f k8s/backend/
kubectl apply -f k8s/ai-engines/
kubectl apply -f k8s/intelligence/
kubectl apply -f k8s/monitoring/

# Check status
kubectl get pods -n apollo
kubectl get svc -n apollo

# Scale deployments
kubectl scale deployment operations --replicas=3 -n apollo
```

## Performance Tuning

### Worker Configuration

Adjust workers based on workload:

```yaml
runtime:
  workers: 8                    # Number of worker processes
  threads_per_worker: 2         # Threads per worker (if applicable)
  max_memory: 4GB              # Memory limit
  timeout: 60s                 # Request timeout
```

### Database Connection Pools

Optimize based on concurrent requests:

```yaml
database:
  postgresql:
    pool_size: 30              # Connections per service
    pool_timeout: 30s

  redis:
    max_connections: 50

  neo4j:
    max_connections: 100
```

### Caching Strategy

```yaml
cache:
  redis_enabled: true
  ttl:
    investigations: 5m
    targets: 10m
    timelines: 15m
  invalidation_events:
    - update
    - delete
```

## Security Considerations

### Network Security

- All services communicate over private network
- TLS/SSL for external-facing services
- Mutual TLS (mTLS) for service-to-service communication

### Authentication & Authorization

- JWT tokens for API authentication
- RBAC for authorization
- OAuth 2.0 for third-party integrations
- MFA for administrative access

### Data Protection

- Encryption at rest (AES-256)
- Encryption in transit (TLS 1.3)
- Sensitive field masking in logs
- Chain of custody for evidence

### Rate Limiting

All services implement rate limiting:

```yaml
rate_limiting:
  api_calls: 500/minute
  login_attempts: 5/minute
  password_reset: 3/hour
```

## Monitoring & Observability

### Metrics

All services expose Prometheus metrics:

- Request count/rate
- Request duration
- Error rate
- Resource utilization (CPU, memory, disk)
- Custom business metrics

### Logging

Structured JSON logging with:

- Timestamp (ISO8601)
- Service name
- Log level
- Message
- Trace ID / Span ID
- User ID
- Investigation ID
- Stack trace (for errors)

### Tracing

Distributed tracing with Jaeger:

- Request path visualization
- Performance bottleneck identification
- Service dependency mapping

### Alerting

Automated alerts for:

- Service down
- High error rate
- Resource exhaustion
- Security events
- Surveillance matches

## Troubleshooting

### Common Issues

#### Service Won't Start

```bash
# Check logs
docker-compose logs service-name

# Verify environment variables
docker-compose config

# Check dependencies
docker-compose ps
```

#### Database Connection Issues

```bash
# Test database connectivity
docker-compose exec service-name ping postgres

# Verify credentials
docker-compose exec postgres psql -U user -d apollo
```

#### High Memory Usage

```bash
# Check current usage
docker stats

# Adjust memory limits in service config
runtime:
  max_memory: 8GB
```

#### Slow Performance

1. Check database indexes
2. Review query performance
3. Adjust worker count
4. Enable caching
5. Optimize batch sizes

## Maintenance

### Backup

```bash
# Database backup
./scripts/backup-databases.sh

# Configuration backup
tar -czf configs-backup.tar.gz configs/

# Evidence backup (already in S3)
aws s3 sync s3://apollo-evidence /backup/evidence/
```

### Updates

```bash
# Pull latest images
docker-compose pull

# Restart with zero downtime
docker-compose up -d --no-deps --build service-name

# Verify health
curl http://localhost:port/health
```

### Log Rotation

Configured in logging.yaml:

- Hot logs: 7 days
- Warm logs: 30 days
- Cold logs: 90 days
- Archive: 365 days

## Support

For issues or questions:

1. Check service logs: `docker-compose logs -f service-name`
2. Verify configuration: Review YAML files in this directory
3. Check monitoring: Grafana dashboards at https://grafana.apollo.local
4. Review documentation: `docs/` directory

## License

Apollo Platform - Elite Cyber Investigation Platform
Copyright (c) 2024-2025
