# Intelligence Fusion Engine - Deployment Guide

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Intelligence Sources                         │
├──────────┬──────────┬──────────┬──────────┬──────────┬─────────┤
│  OSINT   │  Breach  │Blockchain│  SOCMINT │ Sherlock │  Custom │
└──────────┴──────────┴──────────┴──────────┴──────────┴─────────┘
           │           │           │           │           │
           └───────────┴───────────┴───────────┴───────────┘
                              │
                              ▼
           ┌──────────────────────────────────────────┐
           │     Intelligence Fusion Engine           │
           ├──────────────────────────────────────────┤
           │  • Entity Resolver                       │
           │  • Correlation Engine                    │
           │  • Confidence Scorer                     │
           │  • Risk Assessor                         │
           │  • Timeline Builder                      │
           │  • Graph Analyzer                        │
           └──────────────────────────────────────────┘
                              │
                              ▼
           ┌──────────────────────────────────────────┐
           │         Entity Profiles                  │
           ├──────────────────────────────────────────┤
           │  • Confidence Scores                     │
           │  • Risk Assessments                      │
           │  • Relationships                         │
           │  • Timelines                             │
           │  • Network Analysis                      │
           └──────────────────────────────────────────┘
                              │
                              ▼
           ┌──────────────────────────────────────────┐
           │              Outputs                     │
           ├──────────────────────────────────────────┤
           │  • JSON/Markdown/HTML Reports            │
           │  • Graph Exports (GEXF, GraphML)         │
           │  • Timeline Visualizations               │
           │  • Alert Triggers                        │
           └──────────────────────────────────────────┘
```

## Production Deployment

### 1. Environment Setup

```bash
# Create virtual environment
python -m venv fusion_env
source fusion_env/bin/activate  # Linux/Mac
# OR
fusion_env\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt
```

### 2. Configuration

**Production config: `fusion_rules_production.yaml`**

```yaml
# High-security production settings
entity_resolution:
  fuzzy_threshold: 0.90  # Stricter matching
  email_exact_match: true
  phone_normalize: true

correlation:
  min_correlation_score: 0.70  # Higher threshold
  time_window_days: 730  # 2 years
  max_graph_depth: 4

confidence:
  source_weights:
    verified_source: 0.98
    blockchain: 0.95
    breach: 0.85
    osint: 0.70
  freshness_decay_days: 90  # Faster decay
  corroboration_bonus: 0.20  # Higher bonus

risk:
  critical_threshold: 85
  high_threshold: 70
  medium_threshold: 45

# Production logging
logging:
  level: WARNING
  file: /var/log/fusion_engine/fusion.log

# Performance optimization
performance:
  max_workers: 8
  batch_size: 200
  enable_caching: true
  cache_size_mb: 2048
```

### 3. Database Integration (Optional)

**Neo4j Setup:**

```bash
# Install Neo4j
docker run -d \
  --name neo4j \
  -p 7474:7474 -p 7687:7687 \
  -e NEO4J_AUTH=neo4j/your_password \
  neo4j:latest

# Update fusion_rules.yaml
graph:
  neo4j_enabled: true
  neo4j_uri: bolt://localhost:7687
  neo4j_user: neo4j
  neo4j_password: your_password
```

### 4. API Wrapper (Optional)

**Flask API wrapper: `fusion_api.py`**

```python
from flask import Flask, request, jsonify
from fusion_engine import IntelligenceFusion

app = Flask(__name__)
fusion = IntelligenceFusion(config_path='fusion_rules_production.yaml')

@app.route('/api/ingest', methods=['POST'])
def ingest():
    data = request.json
    source_id = fusion.ingest_intelligence(
        data['intelligence'],
        data['source_type']
    )
    return jsonify({'source_id': source_id})

@app.route('/api/profile/<target>', methods=['GET'])
def get_profile(target):
    profile = fusion.build_profile(target)
    return jsonify(profile.to_dict())

@app.route('/api/report/<entity_id>', methods=['GET'])
def get_report(entity_id):
    format = request.args.get('format', 'json')
    report = fusion.generate_intelligence_report(entity_id, format)
    return report

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
```

### 5. Docker Deployment

**Dockerfile:**

```dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PYTHONUNBUFFERED=1

CMD ["python", "fusion_api.py"]
```

**docker-compose.yml:**

```yaml
version: '3.8'

services:
  fusion-engine:
    build: .
    ports:
      - "5000:5000"
    volumes:
      - ./fusion_rules_production.yaml:/app/fusion_rules.yaml
      - ./logs:/var/log/fusion_engine
    environment:
      - FUSION_CONFIG=/app/fusion_rules.yaml
    depends_on:
      - neo4j

  neo4j:
    image: neo4j:latest
    ports:
      - "7474:7474"
      - "7687:7687"
    environment:
      - NEO4J_AUTH=neo4j/production_password
    volumes:
      - neo4j_data:/data

volumes:
  neo4j_data:
```

**Deploy:**

```bash
docker-compose up -d
```

### 6. Kubernetes Deployment

**fusion-deployment.yaml:**

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: fusion-engine
spec:
  replicas: 3
  selector:
    matchLabels:
      app: fusion-engine
  template:
    metadata:
      labels:
        app: fusion-engine
    spec:
      containers:
      - name: fusion-engine
        image: your-registry/fusion-engine:latest
        ports:
        - containerPort: 5000
        env:
        - name: FUSION_CONFIG
          value: /config/fusion_rules_production.yaml
        volumeMounts:
        - name: config
          mountPath: /config
      volumes:
      - name: config
        configMap:
          name: fusion-config
```

## Security Considerations

### 1. Data Protection

```python
# Encrypt sensitive data at rest
from cryptography.fernet import Fernet

class SecureFusion(IntelligenceFusion):
    def __init__(self, encryption_key):
        super().__init__()
        self.cipher = Fernet(encryption_key)

    def ingest_intelligence(self, data, source_type):
        # Encrypt sensitive fields
        if 'password_hash' in data:
            data['password_hash'] = self.cipher.encrypt(
                data['password_hash'].encode()
            ).decode()

        return super().ingest_intelligence(data, source_type)
```

### 2. Access Control

```python
# Add authentication
from functools import wraps
from flask import request, abort

def require_api_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if not api_key or not validate_api_key(api_key):
            abort(401)
        return f(*args, **kwargs)
    return decorated_function

@app.route('/api/profile/<target>')
@require_api_key
def get_profile(target):
    # ...
```

### 3. Rate Limiting

```python
from flask_limiter import Limiter

limiter = Limiter(
    app,
    key_func=lambda: request.headers.get('X-API-Key'),
    default_limits=["100 per hour"]
)

@app.route('/api/profile/<target>')
@limiter.limit("10 per minute")
def get_profile(target):
    # ...
```

## Performance Optimization

### 1. Caching

```python
from functools import lru_cache
import redis

# Redis caching
cache = redis.Redis(host='localhost', port=6379)

def get_cached_profile(entity_id):
    cached = cache.get(f"profile:{entity_id}")
    if cached:
        return json.loads(cached)
    return None

def cache_profile(entity_id, profile):
    cache.setex(
        f"profile:{entity_id}",
        3600,  # 1 hour TTL
        json.dumps(profile.to_dict(), default=str)
    )
```

### 2. Batch Processing

```python
from concurrent.futures import ThreadPoolExecutor

def batch_process_targets(targets, max_workers=8):
    fusion = IntelligenceFusion()

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        profiles = list(executor.map(
            lambda t: fusion.build_profile(t),
            targets
        ))

    return profiles
```

### 3. Database Optimization

```python
# Use connection pooling
from neo4j import GraphDatabase

class OptimizedGraphAnalyzer(GraphAnalyzer):
    def __init__(self, config):
        super().__init__(config)
        self.driver = GraphDatabase.driver(
            self.neo4j_uri,
            auth=(self.neo4j_user, self.neo4j_password),
            max_connection_lifetime=3600,
            max_connection_pool_size=50
        )
```

## Monitoring & Logging

### 1. Structured Logging

```python
import structlog

logger = structlog.get_logger()

class MonitoredFusion(IntelligenceFusion):
    def build_profile(self, target, **kwargs):
        logger.info("profile_build_start", target=target)
        start_time = time.time()

        try:
            profile = super().build_profile(target, **kwargs)

            logger.info(
                "profile_build_complete",
                target=target,
                duration=time.time() - start_time,
                confidence=profile.confidence_score,
                risk=profile.risk_score
            )

            return profile
        except Exception as e:
            logger.error(
                "profile_build_failed",
                target=target,
                error=str(e)
            )
            raise
```

### 2. Metrics Collection

```python
from prometheus_client import Counter, Histogram

profile_builds = Counter('fusion_profile_builds_total', 'Total profile builds')
build_duration = Histogram('fusion_build_duration_seconds', 'Profile build duration')

@build_duration.time()
def monitored_build_profile(fusion, target):
    profile_builds.inc()
    return fusion.build_profile(target)
```

### 3. Health Checks

```python
@app.route('/health')
def health_check():
    return jsonify({
        'status': 'healthy',
        'version': '1.0.0',
        'entities_cached': len(fusion.entities),
        'raw_intelligence': len(fusion.raw_intelligence)
    })
```

## Backup & Recovery

### 1. Entity Profile Backup

```python
def backup_profiles(output_dir):
    import os
    import json
    from datetime import datetime

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_file = os.path.join(output_dir, f'profiles_{timestamp}.json')

    profiles = [
        profile.to_dict()
        for profile in fusion.entities.values()
    ]

    with open(backup_file, 'w') as f:
        json.dump(profiles, f, default=str)

    return backup_file
```

### 2. Restore Profiles

```python
def restore_profiles(backup_file):
    import json

    with open(backup_file, 'r') as f:
        profiles_data = json.load(f)

    for profile_data in profiles_data:
        profile = EntityProfile(**profile_data)
        fusion.entities[profile.entity_id] = profile
```

## Production Checklist

- [ ] Configure production settings in `fusion_rules_production.yaml`
- [ ] Set up secure database (Neo4j with authentication)
- [ ] Implement API authentication and rate limiting
- [ ] Enable HTTPS/TLS for API endpoints
- [ ] Configure structured logging
- [ ] Set up monitoring and alerting
- [ ] Implement data backup strategy
- [ ] Configure data retention policies
- [ ] Test disaster recovery procedures
- [ ] Document API endpoints
- [ ] Set up CI/CD pipeline
- [ ] Perform security audit
- [ ] Load testing and performance tuning
- [ ] Configure auto-scaling (if using Kubernetes)
- [ ] Set up log aggregation (ELK stack)

## Scaling Recommendations

### Small Deployment (< 1000 profiles/day)
- Single server
- SQLite or file-based storage
- No Neo4j required
- 2-4 CPU cores, 8GB RAM

### Medium Deployment (1000-10000 profiles/day)
- 2-3 application servers
- Redis caching
- Neo4j for graph analysis
- Load balancer
- 4-8 CPU cores, 16GB RAM per server

### Large Deployment (> 10000 profiles/day)
- Kubernetes cluster with auto-scaling
- Distributed Redis cluster
- Neo4j cluster
- Elasticsearch for profile search
- 8+ CPU cores, 32GB RAM per node
- CDN for report delivery

## Support & Maintenance

### Regular Maintenance Tasks

1. **Weekly:**
   - Review error logs
   - Check cache hit rates
   - Monitor disk usage

2. **Monthly:**
   - Backup profile database
   - Update fusion_rules.yaml thresholds based on analytics
   - Review and archive old intelligence

3. **Quarterly:**
   - Security audit
   - Performance testing
   - Dependency updates

### Troubleshooting

**High Memory Usage:**
- Reduce cache_size_mb in config
- Implement profile expiration
- Use database instead of in-memory storage

**Slow Profile Building:**
- Enable caching
- Reduce max_graph_depth
- Optimize correlation thresholds
- Use batch processing

**Low Confidence Scores:**
- Review source weights
- Check data freshness
- Increase corroboration bonus

---

**Production-ready deployment for enterprise-scale intelligence fusion.**
