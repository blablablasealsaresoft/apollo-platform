# Apollo Monitoring Stack

Comprehensive observability infrastructure for the Apollo Platform, providing metrics collection, alerting, log aggregation, and distributed tracing.

## Components

### Metrics & Alerting
- **Prometheus** - Time-series metrics collection and storage
- **Alertmanager** - Alert routing, grouping, and notification delivery
- **Custom Metrics Exporter** - Apollo-specific business metrics

### Visualization
- **Grafana** - Dashboards and visualizations
  - Overview Dashboard - High-level system health
  - Services Dashboard - Per-service metrics
  - Security Dashboard - Authentication and access patterns
  - Database Dashboard - PostgreSQL, Redis, Elasticsearch metrics

### Logging
- **Elasticsearch** - Log storage and search
- **Logstash** - Log processing and enrichment
- **Kibana** - Log exploration and visualization
- **Filebeat** - Log shipping from services

### Tracing
- **Jaeger** - Distributed tracing for request flows

### Infrastructure Metrics
- **Node Exporter** - System-level metrics (CPU, memory, disk)
- **cAdvisor** - Container-level metrics

## Quick Start

### Using Docker Compose

```bash
# Start the monitoring stack
cd infrastructure/monitoring
docker-compose -f docker-compose.monitoring.yml up -d

# Check service status
docker-compose -f docker-compose.monitoring.yml ps
```

### Access Points

| Service | URL | Default Credentials |
|---------|-----|---------------------|
| Grafana | http://localhost:3000 | admin / admin |
| Prometheus | http://localhost:9090 | - |
| Alertmanager | http://localhost:9093 | - |
| Kibana | http://localhost:5601 | - |
| Jaeger UI | http://localhost:16686 | - |

## Configuration

### Environment Variables

Create a `.env` file with the following variables:

```bash
# Grafana
GRAFANA_ADMIN_USER=admin
GRAFANA_ADMIN_PASSWORD=<secure-password>

# Alertmanager
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
PAGERDUTY_SERVICE_KEY=<key>
PAGERDUTY_SECURITY_KEY=<key>
PAGERDUTY_DATABASE_KEY=<key>
PAGERDUTY_OPERATIONS_KEY=<key>

# SMTP
SMTP_HOST=smtp.example.com:587
SMTP_USERNAME=<username>
SMTP_PASSWORD=<password>

# Database (for custom metrics)
DB_HOST=apollo-postgres
REDIS_HOST=apollo-redis
```

### Prometheus Configuration

Key configuration files:
- `prometheus/prometheus.yml` - Scrape targets and global settings
- `prometheus/alert-rules.yml` - Alert definitions
- `prometheus/recording-rules.yml` - Pre-computed metrics aggregations
- `prometheus/alertmanager.yml` - Alert routing and receivers

### Adding New Scrape Targets

```yaml
# In prometheus.yml
scrape_configs:
  - job_name: 'new-service'
    static_configs:
      - targets: ['new-service:9090']
```

### Adding New Alerts

```yaml
# In alert-rules.yml
groups:
  - name: custom_alerts
    rules:
      - alert: CustomAlert
        expr: custom_metric > threshold
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Custom alert description"
```

## Dashboards

### Overview Dashboard (`apollo-overview`)
- Service health status grid
- Key performance indicators
- Request rate and latency trends
- Error rates by service
- Resource utilization

### Services Dashboard (`apollo-services`)
- Per-service detailed metrics
- Authentication service monitoring
- Intelligence fusion metrics
- Facial recognition performance
- Blockchain tracking status
- Queue depths and processing rates

### Security Dashboard (`apollo-security`)
- Authentication attempts and failures
- Failed login sources (IP-based)
- Rate limit violations
- API key usage patterns
- Admin access monitoring
- Security alert list

### Database Dashboard (`apollo-database`)
- PostgreSQL connection pools
- Transaction rates and cache hit ratios
- Redis memory and operations
- Elasticsearch cluster health
- RabbitMQ queue depths

## Alert Categories

### Infrastructure Alerts
- High CPU/Memory usage
- Disk space warnings
- Service down
- Pod restart loops
- Node health issues

### Application Alerts
- High error rates (>1%, >5%)
- Slow response times (P95 > 500ms)
- Rate limit exceeded
- Queue processing delays

### Security Alerts
- Multiple failed logins
- Brute force detection
- API key abuse
- Unusual access patterns
- DDoS detection
- Privilege escalation attempts

### Business Alerts
- Investigation processing backlog
- Facial recognition system issues
- Blockchain tracker lag
- OSINT collection anomalies
- Target match detection

## Custom Metrics

The Apollo metrics exporter (`apollo-metrics-exporter.py`) provides domain-specific metrics:

### Investigation Metrics
- `apollo_active_investigations` - Active investigation count
- `investigation_queue_depth` - Processing backlog

### Surveillance Metrics
- `apollo_surveillance_matches` - Match detections
- `facial_recognition_health` - System health status
- `facial_recognition_scans_total` - Total scans performed

### Blockchain Metrics
- `blockchain_tracker_health` - Tracker status
- `blockchain_tracker_lag_seconds` - Block lag by chain
- `blockchain_wallets_monitored` - Monitored wallet count

### OSINT Metrics
- `osint_records_collected_total` - Collection rate by source
- `osint_collector_health` - Collector status

## Runbooks

Incident response documentation is available in `/docs/runbooks/`:

- `high-cpu.md` - High CPU usage response
- `service-down.md` - Service outage response
- `database-issues.md` - Database troubleshooting
- `security-incident.md` - Security incident response

## Log Pipeline

### Log Flow
1. Services write logs (JSON format recommended)
2. Filebeat ships logs to Logstash
3. Logstash parses, enriches (GeoIP, user agent), and routes
4. Elasticsearch stores logs with appropriate indices
5. Kibana provides search and visualization

### Index Patterns
- `apollo-*` - General application logs
- `apollo-security-*` - Security-related events
- `apollo-audit-*` - Audit trail logs
- `apollo-investigations-*` - Investigation service logs
- `apollo-surveillance-*` - Surveillance logs
- `apollo-blockchain-*` - Blockchain tracking logs

## Kubernetes Deployment

For Kubernetes environments, apply the configurations:

```bash
# Apply Prometheus configuration
kubectl apply -f prometheus/prometheus-configmap.yaml

# Deploy monitoring stack
kubectl apply -k infrastructure/kubernetes/monitoring/
```

## Troubleshooting

### Prometheus Not Scraping Targets
```bash
# Check target status
curl http://localhost:9090/api/v1/targets

# Validate configuration
promtool check config prometheus.yml
```

### Alertmanager Not Sending Notifications
```bash
# Test configuration
amtool check-config alertmanager.yml

# Check alert status
curl http://localhost:9093/api/v2/alerts
```

### Elasticsearch Issues
```bash
# Check cluster health
curl http://localhost:9200/_cluster/health?pretty

# Check indices
curl http://localhost:9200/_cat/indices?v
```

## Maintenance

### Data Retention
- Prometheus: 30 days (configurable)
- Elasticsearch: ILM policy manages retention
- Logs: 90 days default, security logs 1 year

### Backup
- Grafana dashboards are provisioned from files (git-managed)
- Prometheus data: Use TSDB snapshots
- Elasticsearch: Use snapshot/restore API

## Security Considerations

1. All credentials stored in environment variables or secrets
2. TLS termination via infrastructure/security configurations
3. RBAC configured for Grafana access
4. Network policies restrict inter-service communication
5. Audit logging enabled for admin actions

## Support

- Platform Team: platform-team@apollo.internal
- Security Team: security-team@apollo.internal
- On-call: Check PagerDuty schedule
