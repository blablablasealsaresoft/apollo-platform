# Apollo Platform - Production Deployment Checklist

## Pre-Deployment Checklist

### Infrastructure Verification
- [ ] Kubernetes cluster is running and accessible
- [ ] All nodes are healthy and have sufficient resources
- [ ] Network policies are configured
- [ ] Load balancer is provisioned
- [ ] DNS records are configured
- [ ] SSL/TLS certificates are valid and installed
- [ ] Container registry access is configured
- [ ] Backup storage is configured and tested

### Security Verification
- [ ] All secrets are created in Kubernetes
- [ ] Database credentials are secure and rotated
- [ ] JWT secrets are generated and stored
- [ ] API keys for external services are configured
- [ ] RBAC policies are applied
- [ ] Network policies are enforced
- [ ] Security scanning completed (no critical issues)
- [ ] Vulnerability scanning completed
- [ ] Penetration testing completed (if required)
- [ ] Security incident response plan documented

### Database Preparation
- [ ] PostgreSQL database is provisioned
- [ ] Database backups are configured
- [ ] Database migrations are tested in staging
- [ ] Redis cache is provisioned and tested
- [ ] Elasticsearch cluster is running
- [ ] RabbitMQ is configured
- [ ] Database connection pooling is configured
- [ ] Database performance tuning completed
- [ ] Backup restoration tested

### Application Configuration
- [ ] All ConfigMaps are created
- [ ] Environment variables are set correctly
- [ ] Feature flags are configured
- [ ] Rate limiting is configured
- [ ] CORS settings are correct
- [ ] File upload limits are set
- [ ] Session duration configured
- [ ] Logging level is appropriate for production
- [ ] External API integrations tested

### Monitoring and Observability
- [ ] Prometheus is installed and scraping metrics
- [ ] Grafana dashboards are imported
- [ ] Alert rules are configured
- [ ] Alertmanager is configured with notification channels
- [ ] Log aggregation (ELK/EFK) is set up
- [ ] Application Performance Monitoring (APM) configured
- [ ] Uptime monitoring configured
- [ ] Error tracking (Sentry) configured

### Testing Verification
- [ ] All unit tests passing (>80% coverage)
- [ ] All integration tests passing
- [ ] E2E tests passing in staging
- [ ] Load tests completed successfully
- [ ] Security tests passing
- [ ] Smoke tests prepared
- [ ] Performance benchmarks met

### Documentation
- [ ] Deployment guide updated
- [ ] API documentation generated
- [ ] Operations manual updated
- [ ] Runbooks created for common issues
- [ ] Architecture diagrams updated
- [ ] Security documentation completed
- [ ] Disaster recovery plan documented

### Team Readiness
- [ ] On-call rotation scheduled
- [ ] Team notified of deployment window
- [ ] Rollback plan communicated
- [ ] Emergency contacts updated
- [ ] Stakeholders notified

---

## Deployment Execution Checklist

### Step 1: Pre-Deployment Tasks
- [ ] Announce deployment maintenance window
- [ ] Create database backup
- [ ] Tag release in Git
- [ ] Generate release notes
- [ ] Set deployment environment variables

### Step 2: Deploy Infrastructure Components
- [ ] Apply namespace configuration
- [ ] Create/update secrets
- [ ] Apply ConfigMaps
- [ ] Deploy PostgreSQL (if not external)
- [ ] Deploy Redis
- [ ] Deploy Elasticsearch
- [ ] Deploy RabbitMQ
- [ ] Verify all infrastructure pods are running

### Step 3: Run Database Migrations
- [ ] Create migration job
- [ ] Execute migrations
- [ ] Verify migration success
- [ ] Check database schema
- [ ] Seed initial data (if fresh install)

### Step 4: Deploy Backend Services
- [ ] Deploy authentication service
- [ ] Deploy investigation service
- [ ] Deploy intelligence fusion service
- [ ] Deploy search service
- [ ] Deploy notification service
- [ ] Deploy analytics service
- [ ] Deploy file storage service
- [ ] Deploy reporting service
- [ ] Wait for all deployments to be ready
- [ ] Verify pod health checks passing

### Step 5: Deploy Frontend
- [ ] Deploy web console
- [ ] Verify static assets served
- [ ] Check frontend connects to backend
- [ ] Verify WebSocket connections

### Step 6: Configure Ingress
- [ ] Apply ingress configuration
- [ ] Verify TLS certificate
- [ ] Test HTTP to HTTPS redirect
- [ ] Verify routing rules

### Step 7: Monitoring Setup
- [ ] Verify Prometheus scraping targets
- [ ] Check Grafana dashboards loading
- [ ] Test alert rules
- [ ] Verify log aggregation working

---

## Post-Deployment Verification Checklist

### Health Checks
- [ ] All pods are in Running state
- [ ] All containers are ready
- [ ] No pod restarts detected
- [ ] All health endpoints responding
- [ ] Database connections established
- [ ] Cache connections working
- [ ] Message queue connected

### Functional Testing
- [ ] User can login
- [ ] Can create investigation
- [ ] Can add target to investigation
- [ ] Can upload evidence
- [ ] Search functionality working
- [ ] Real-time notifications working
- [ ] Facial recognition API responsive
- [ ] Blockchain tracking working
- [ ] Report generation working
- [ ] File upload/download working

### Performance Verification
- [ ] API response times < 100ms (p50)
- [ ] API response times < 500ms (p99)
- [ ] Database query times acceptable
- [ ] Memory usage within limits
- [ ] CPU usage within limits
- [ ] Network latency acceptable
- [ ] Concurrent user load handled

### Security Verification
- [ ] HTTPS enforced
- [ ] Authentication required
- [ ] Authorization working correctly
- [ ] Rate limiting active
- [ ] SQL injection protection verified
- [ ] XSS protection verified
- [ ] CSRF protection verified
- [ ] Secrets not exposed in logs
- [ ] Security headers present

### Monitoring Verification
- [ ] Metrics being collected
- [ ] Dashboards showing data
- [ ] Alerts can be triggered
- [ ] Logs being aggregated
- [ ] Error tracking working
- [ ] APM traces visible

### Integration Verification
- [ ] External API integrations working
- [ ] Email notifications sending
- [ ] SMS alerts working (if configured)
- [ ] Webhook integrations active
- [ ] Third-party services connected

---

## Rollback Procedures

### Quick Reference: Rollback Commands

```bash
# Kubernetes deployment rollback (all services)
NAMESPACE="apollo-production"  # or apollo-staging

# View rollout history
kubectl rollout history deployment/apollo-authentication -n $NAMESPACE

# Rollback to previous version
kubectl rollout undo deployment/apollo-authentication -n $NAMESPACE
kubectl rollout undo deployment/apollo-intelligence -n $NAMESPACE
kubectl rollout undo deployment/apollo-operations -n $NAMESPACE
kubectl rollout undo deployment/apollo-search -n $NAMESPACE
kubectl rollout undo deployment/apollo-notifications -n $NAMESPACE
kubectl rollout undo deployment/apollo-analytics -n $NAMESPACE
kubectl rollout undo deployment/apollo-user-management -n $NAMESPACE
kubectl rollout undo deployment/apollo-api-gateway -n $NAMESPACE

# Rollback to specific revision
kubectl rollout undo deployment/apollo-authentication -n $NAMESPACE --to-revision=2

# Check rollback status
kubectl rollout status deployment/apollo-authentication -n $NAMESPACE
```

### Rollback Decision Matrix

| Issue Type | Severity | Recommended Action |
|------------|----------|-------------------|
| Single service failure | Low | Restart pod, monitor |
| Single service failure | High | Rollback single service |
| Multiple service failures | High | Full rollback |
| Data corruption | Critical | Stop traffic, restore backup |
| Security breach | Critical | Immediate shutdown, investigate |
| Performance degradation | Medium | Scale up, then investigate |
| Database migration failure | High | Rollback migration, then deployment |

### Rollback Checklist

#### Step 1: Assess the Situation
- [ ] Identify which services are affected
- [ ] Determine the severity level (Low/Medium/High/Critical)
- [ ] Check if the issue is deployment-related or external
- [ ] Review recent deployment changes
- [ ] Consult error logs and monitoring dashboards

#### Step 2: Decision Point
- [ ] Can the issue be fixed with a hotfix? (< 15 minutes to deploy)
- [ ] Is the issue affecting user experience?
- [ ] Is the issue causing data corruption?
- [ ] Make Go/No-Go decision for rollback
- [ ] Notify team lead and stakeholders

#### Step 3: Execute Rollback

**Option A: GitHub Actions Rollback (Recommended)**
1. Go to GitHub Actions > Deploy to Production workflow
2. Click "Run workflow"
3. Select "production" environment
4. Enter the previous stable version in "rollback_version"
5. Click "Run workflow"

**Option B: Manual Kubernetes Rollback**
```bash
# Set namespace
NAMESPACE="apollo-production"

# Rollback all services
for service in authentication intelligence operations search notifications analytics user-management api-gateway; do
  kubectl rollout undo deployment/apollo-$service -n $NAMESPACE
done

# Wait for rollback completion
for service in authentication intelligence operations search notifications analytics user-management api-gateway; do
  kubectl rollout status deployment/apollo-$service -n $NAMESPACE --timeout=300s
done
```

**Option C: Database Migration Rollback**
1. Go to GitHub Actions > Database Migrations workflow
2. Select environment and "rollback" action
3. Specify number of migrations to rollback
4. Approve the rollback (requires approval for production)

#### Step 4: Verify Rollback Success
- [ ] All pods are running and healthy
- [ ] Health check endpoints return 200
- [ ] User authentication works
- [ ] Core functionality verified
- [ ] Error rates returned to normal
- [ ] No new errors in logs

#### Step 5: Post-Rollback Actions
- [ ] Update status page with incident details
- [ ] Send notification to stakeholders
- [ ] Document the issue in incident log
- [ ] Create Jira ticket for root cause analysis
- [ ] Schedule post-mortem meeting within 48 hours

### Database Rollback Procedures

#### Scenario 1: Migration Failed - Data Not Modified
```bash
# Use the database-migrations workflow with "rollback" action
# Or manually:
kubectl create job db-rollback-$(date +%s) \
  --from=cronjob/db-migration-template \
  -n apollo-production \
  -- npm run db:rollback
```

#### Scenario 2: Migration Succeeded But Caused Issues
```bash
# Run specific number of rollbacks
kubectl exec -it deployment/apollo-authentication -n apollo-production \
  -- npm run db:rollback -- --steps=1
```

#### Scenario 3: Data Corruption - Restore from Backup
```bash
# 1. Stop all application traffic
kubectl scale deployment --all --replicas=0 -n apollo-production

# 2. Identify the backup to restore
aws s3 ls s3://apollo-backups/production/

# 3. Restore database
kubectl exec -it deployment/postgres -n apollo-production -- \
  pg_restore -U postgres -d apollo /backup/backup-file.dump

# 4. Verify data integrity
kubectl exec -it deployment/postgres -n apollo-production -- \
  psql -U postgres -d apollo -c "SELECT COUNT(*) FROM users;"

# 5. Restart services
kubectl scale deployment --all --replicas=3 -n apollo-production
```

### Rollback Communication Templates

#### Slack Notification
```
:rotating_light: *PRODUCTION ROLLBACK INITIATED*
*Time:* [TIMESTAMP]
*Triggered by:* [NAME]
*Reason:* [BRIEF DESCRIPTION]
*Services affected:* [LIST]
*Expected duration:* [ESTIMATE]
*Status:* In Progress
```

#### Stakeholder Email
```
Subject: [URGENT] Apollo Platform - Production Rollback in Progress

Team,

We have initiated a rollback of the Apollo Platform production deployment.

- Time: [TIMESTAMP]
- Issue: [DESCRIPTION]
- Impact: [USER IMPACT]
- ETA for Resolution: [ESTIMATE]

We will send an update once the rollback is complete and the system is stable.

Regards,
[NAME]
DevOps Team
```

### Rollback Verification Checklist
- [ ] All deployments show "Running" status
- [ ] Pod restart count is 0 after rollback
- [ ] `/health` endpoints return 200 for all services
- [ ] Login functionality works
- [ ] Dashboard loads correctly
- [ ] No 5xx errors in last 5 minutes
- [ ] Database connections are stable
- [ ] Redis cache is responding
- [ ] Elasticsearch queries work
- [ ] Error rate in Grafana < 0.1%

---

## Post-Deployment Tasks

### Immediate (Within 1 hour)
- [ ] Monitor error rates for 1 hour
- [ ] Check for memory leaks
- [ ] Monitor database performance
- [ ] Verify backup job runs successfully
- [ ] Update deployment log
- [ ] Close deployment ticket

### Short-term (Within 24 hours)
- [ ] Review application logs for errors
- [ ] Check performance metrics
- [ ] Verify scheduled jobs running
- [ ] Review security alerts
- [ ] Update status page
- [ ] Send deployment summary to team

### Medium-term (Within 1 week)
- [ ] Conduct deployment retrospective
- [ ] Document lessons learned
- [ ] Update procedures based on issues
- [ ] Review and tune autoscaling
- [ ] Optimize database queries if needed
- [ ] Review cost metrics

---

## Emergency Contacts

### On-Call Team
- Primary: [Name] - [Phone] - [Email]
- Secondary: [Name] - [Phone] - [Email]
- Manager: [Name] - [Phone] - [Email]

### External Support
- Cloud Provider Support: [Phone/Portal]
- Database Support: [Contact]
- CDN Support: [Contact]

### Escalation Path
1. On-call engineer
2. Team lead
3. Engineering manager
4. CTO

---

## Sign-Off

### Deployment Approved By:
- [ ] Engineering Lead: _________________ Date: _______
- [ ] DevOps Lead: _________________ Date: _______
- [ ] Security Lead: _________________ Date: _______
- [ ] Product Manager: _________________ Date: _______

### Deployment Executed By:
- Name: _________________
- Date: _________________
- Time: _________________
- Duration: _________________

### Post-Deployment Verification By:
- Name: _________________
- Date: _________________
- Status: [ ] Success [ ] Partial [ ] Rolled Back

### Notes:
```
[Add any additional notes or observations here]
```
