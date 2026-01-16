# Apollo Platform - Production Environment

⚠️ **CRITICAL: Production deployment requires careful planning and security review**

## Prerequisites

Before deploying to production:

- [ ] Security audit completed
- [ ] Penetration testing performed
- [ ] Load testing completed
- [ ] Disaster recovery plan documented
- [ ] Backup strategy implemented
- [ ] Monitoring configured
- [ ] Incident response procedures defined
- [ ] Compliance requirements met (CJIS, GDPR, etc.)
- [ ] SSL/TLS certificates obtained
- [ ] Secrets management system configured
- [ ] High availability tested
- [ ] Failover procedures tested

## Configuration Files

### .env.production.example

**NEVER USE THIS FILE DIRECTLY**

This is a template. Copy it to `.env.production` and replace ALL placeholder values:

```bash
cp .env.production.example .env.production
```

**NEVER commit `.env.production` to version control**

### database.yaml

Production database configuration with:
- High availability (replication, clustering)
- SSL/TLS encryption
- Connection pooling
- Performance tuning
- Backup configuration
- Disaster recovery

### services.yaml

Microservice configuration with:
- Multiple replicas for HA
- Resource limits (CPU, memory)
- Auto-scaling policies
- Health checks
- Circuit breakers
- Service mesh integration

### security.yaml

Comprehensive security configuration:
- Encryption (at rest and in transit)
- Authentication (MFA required)
- Authorization (RBAC, ABAC)
- Network security
- Intrusion detection
- Compliance settings
- Audit logging

### ai-models.yaml

AI model configuration:
- Production API keys
- Cost management
- Rate limiting
- Routing strategies
- Performance optimization

### integrations.yaml

External service integrations with production credentials

## Secret Generation

Generate all secrets using cryptographically secure methods:

### JWT Secrets

```bash
# JWT Secret (minimum 32 characters)
openssl rand -base64 32

# JWT Refresh Secret (different from JWT Secret)
openssl rand -base64 32
```

### Session Secret

```bash
openssl rand -base64 32
```

### Encryption Key (AES-256)

```bash
# Generate 32-byte (256-bit) key as hex (64 characters)
openssl rand -hex 32
```

### Database Passwords

```bash
# Generate strong password (24 characters, alphanumeric + special)
openssl rand -base64 24 | tr -dc 'A-Za-z0-9!@#$%^&*' | head -c 24
```

## Deployment Methods

### Method 1: Kubernetes (Recommended)

```bash
# 1. Create namespace
kubectl create namespace apollo-production

# 2. Create secrets
kubectl create secret generic apollo-secrets \
  --from-env-file=.env.production \
  -n apollo-production

# 3. Apply configurations
kubectl apply -f configs/environments/kubernetes/prod/configmap.yaml
kubectl apply -f configs/environments/kubernetes/prod/secrets.yaml

# 4. Deploy application
kubectl apply -f infrastructure/kubernetes/

# 5. Verify deployment
kubectl get pods -n apollo-production
kubectl get services -n apollo-production

# 6. Check health
kubectl exec -it deploy/api-gateway -n apollo-production -- curl http://localhost:9000/health
```

### Method 2: Docker Compose (Not Recommended for Production)

Docker Compose is NOT recommended for production. Use for testing only.

```bash
# Copy environment file
cp .env.production.example .env.production

# Edit and fill in all secrets
nano .env.production

# Start services (testing only)
docker-compose -f configs/environments/docker/docker-compose.prod.yml up -d
```

## Security Checklist

### Before Deployment

- [ ] All default passwords changed
- [ ] All API keys are production keys
- [ ] JWT secrets generated (32+ characters, unique)
- [ ] Session secret generated
- [ ] AES-256 encryption key generated
- [ ] Database passwords are strong (16+ characters)
- [ ] SSL/TLS certificates installed
- [ ] MFA enabled for all admin accounts
- [ ] Rate limiting enabled
- [ ] Audit logging enabled
- [ ] Firewall rules configured
- [ ] VPN access configured
- [ ] Secrets stored in vault (not in environment files)

### Network Security

- [ ] Private network for databases
- [ ] Public load balancer for API/frontend
- [ ] DDoS protection enabled
- [ ] WAF (Web Application Firewall) configured
- [ ] IP whitelisting for admin access
- [ ] Zero-trust network architecture

### Database Security

- [ ] Encryption at rest enabled
- [ ] Encryption in transit (SSL/TLS)
- [ ] Replication configured
- [ ] Automated backups enabled
- [ ] Backup encryption enabled
- [ ] Point-in-time recovery configured
- [ ] Connection pooling configured
- [ ] Query logging disabled (performance)
- [ ] Slow query logging enabled

### Application Security

- [ ] Debug mode disabled
- [ ] Source maps disabled
- [ ] Error details hidden from users
- [ ] CORS configured correctly
- [ ] Security headers configured (HSTS, CSP, etc.)
- [ ] Input validation on all endpoints
- [ ] SQL injection prevention
- [ ] XSS prevention
- [ ] CSRF protection
- [ ] File upload restrictions

### Monitoring & Logging

- [ ] Prometheus metrics configured
- [ ] Grafana dashboards set up
- [ ] Sentry error tracking configured
- [ ] Log aggregation configured
- [ ] Alert rules configured
- [ ] PagerDuty/OpsGenie integration
- [ ] Uptime monitoring
- [ ] Performance monitoring

## High Availability

### Database HA

**PostgreSQL:**
- Primary-standby replication
- Automatic failover
- Connection pooling

**Redis:**
- Sentinel for failover
- Master-replica replication
- Automatic failover

**RabbitMQ:**
- Cluster mode (3+ nodes)
- Queue mirroring
- High availability queues

**Elasticsearch:**
- Cluster mode (3+ nodes)
- Replica shards
- Snapshot repository

**MongoDB:**
- Replica set (3+ nodes)
- Automatic failover
- Read preference: primaryPreferred

### Application HA

- Minimum 3 replicas per service
- Load balancing across replicas
- Health checks and auto-restart
- Graceful shutdown
- Rolling updates
- Circuit breakers

## Backup Strategy

### Database Backups

**PostgreSQL:**
- Full backup: Daily at 2 AM UTC
- Incremental backup: Hourly
- WAL archival: Continuous
- Retention: 90 days
- Storage: S3 with encryption

**Neo4j:**
- Full backup: Daily
- Retention: 90 days

**MongoDB:**
- Replica set snapshots: Daily
- Oplog backup: Continuous
- Retention: 90 days

**Redis:**
- RDB snapshots: Every 6 hours
- AOF: Enabled
- Retention: 7 days

### Application Backups

- Configuration: Version controlled in Git
- Secrets: Backed up in vault
- Evidence files: Replicated to S3
- Surveillance data: Tiered storage

### Backup Testing

- Monthly restore testing
- Quarterly disaster recovery drill
- Document all procedures

## Disaster Recovery

### RTO (Recovery Time Objective)

- Critical services: 1 hour
- Non-critical services: 4 hours
- Complete system: 8 hours

### RPO (Recovery Point Objective)

- Database data: 1 hour
- Evidence files: 24 hours
- Surveillance data: 24 hours

### DR Procedures

1. **Minor Incident (Service Degradation)**
   - Auto-scaling triggers
   - Circuit breaker activation
   - Alert team
   - Investigate and fix

2. **Major Incident (Service Outage)**
   - Activate incident response team
   - Assess impact
   - Execute failover if needed
   - Restore from backup if needed
   - Post-mortem analysis

3. **Disaster (Complete Data Center Loss)**
   - Activate DR site
   - Restore from S3 backups
   - Update DNS to DR site
   - Verify functionality
   - Communicate with stakeholders

## Monitoring

### Key Metrics

**System:**
- CPU usage
- Memory usage
- Disk usage
- Network I/O

**Application:**
- Request rate
- Error rate
- Response time (p50, p95, p99)
- Active connections

**Database:**
- Connection pool usage
- Query performance
- Replication lag
- Cache hit ratio

**Business:**
- Active cases
- Surveillance events
- Alert volume
- API usage

### Alerting Rules

**Critical (PagerDuty):**
- Service down
- Database down
- Replication lag > 60s
- Error rate > 5%
- Disk usage > 90%

**High (Slack):**
- Response time > 5s
- CPU usage > 80%
- Memory usage > 85%
- Failed backups

**Medium (Slack):**
- Response time > 2s
- Cache miss rate > 20%
- Queue depth > 1000

## Scaling

### Vertical Scaling

Increase resources for individual services:
- CPU: 2-16 cores
- Memory: 4-64 GB
- Storage: SSD with auto-expansion

### Horizontal Scaling

Add more replicas:
- API Gateway: 3-10 replicas
- Intelligence Fusion: 4-20 replicas
- Surveillance: 4-10 replicas
- Workers: 5-50 replicas

### Auto-Scaling

Based on metrics:
- CPU > 70%: Scale up
- Memory > 80%: Scale up
- Queue depth > 1000: Scale workers
- Request rate > 1000/s: Scale API

## Compliance

### CJIS (Criminal Justice Information Services)

- Advanced authentication (MFA)
- Audit logging
- Encryption at rest and in transit
- Personnel security
- Physical security
- Access control

### GDPR (General Data Protection Regulation)

- Data minimization
- Right to erasure
- Data portability
- Privacy by design
- DPIA conducted

### SOC 2

- Security controls
- Availability monitoring
- Processing integrity
- Confidentiality
- Privacy protection

### ISO 27001

- Information security policies
- Asset management
- Access control
- Cryptography
- Operations security
- Incident management

## Cost Optimization

### Database

- Use read replicas for read-heavy workloads
- Enable query caching
- Archive old data to cheaper storage
- Use reserved instances for stable workloads

### Compute

- Right-size instances based on metrics
- Use spot instances for non-critical workers
- Enable auto-scaling
- Optimize container images

### Storage

- Use lifecycle policies for S3
- Compress backups
- Implement data retention policies
- Use tiered storage

### AI Models

- Route to cost-effective models when possible
- Cache responses
- Batch requests
- Set daily/monthly spending limits

## Troubleshooting

### Service Not Starting

```bash
# Check pod status
kubectl get pods -n apollo-production

# View pod logs
kubectl logs -f pod/api-gateway-xxxxx -n apollo-production

# Describe pod for events
kubectl describe pod api-gateway-xxxxx -n apollo-production

# Check environment variables
kubectl exec -it deploy/api-gateway -n apollo-production -- env
```

### Database Connection Issues

```bash
# Test connectivity
kubectl exec -it deploy/api-gateway -n apollo-production -- \
  nc -zv postgres.apollo-production.svc.cluster.local 5432

# Check secrets
kubectl get secret apollo-secrets -n apollo-production -o yaml

# View database logs
kubectl logs -f statefulset/postgres -n apollo-production
```

### High Memory Usage

```bash
# Check resource usage
kubectl top pods -n apollo-production

# Increase memory limits
kubectl set resources deployment api-gateway \
  --limits=memory=8Gi -n apollo-production

# Restart pod
kubectl rollout restart deployment/api-gateway -n apollo-production
```

## Support Contacts

- **Infrastructure:** infrastructure-team@yourdomain.com
- **Security:** security-team@yourdomain.com
- **On-Call:** oncall@yourdomain.com
- **PagerDuty:** +1-XXX-XXX-XXXX

## Emergency Procedures

### Data Breach

1. Isolate affected systems
2. Preserve evidence
3. Notify security team immediately
4. Notify legal team
5. Follow incident response playbook
6. Prepare breach notification

### Ransomware

1. Isolate infected systems immediately
2. DO NOT pay ransom
3. Activate DR site
4. Restore from backup
5. Investigate infection vector
6. Implement additional controls

### Complete Outage

1. Activate incident response team
2. Assess cause and impact
3. Execute DR plan
4. Communicate with stakeholders
5. Restore services
6. Post-mortem and improvements

---

**Last Updated:** 2024-01-14
**Reviewed By:** Security Team, DevOps Team
**Next Review:** 2024-04-14
