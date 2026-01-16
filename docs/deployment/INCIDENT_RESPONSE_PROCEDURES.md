# Apollo Platform - Incident Response Procedures

## Table of Contents
1. [Incident Classification](#incident-classification)
2. [Response Team Structure](#response-team-structure)
3. [Incident Response Workflow](#incident-response-workflow)
4. [Communication Procedures](#communication-procedures)
5. [Specific Incident Runbooks](#specific-incident-runbooks)
6. [Post-Incident Procedures](#post-incident-procedures)
7. [Tools and Access](#tools-and-access)

---

## Incident Classification

### Severity Levels

| Level | Name | Description | Response Time | Example |
|-------|------|-------------|---------------|---------|
| SEV-1 | Critical | Complete system outage, data breach, security incident | Immediate (< 15 min) | Production down, data leak |
| SEV-2 | High | Major feature unavailable, significant performance degradation | < 30 min | Authentication failing, search broken |
| SEV-3 | Medium | Minor feature issues, partial degradation | < 2 hours | Single service degraded, slow queries |
| SEV-4 | Low | Cosmetic issues, minor bugs | < 24 hours | UI glitches, non-critical errors |

### Impact Assessment Criteria

**User Impact:**
- How many users are affected?
- Is the core functionality impacted?
- Is data at risk?

**Business Impact:**
- Revenue impact
- Reputation risk
- Compliance/legal implications

**Technical Impact:**
- Infrastructure stability
- Data integrity
- Security posture

---

## Response Team Structure

### Incident Commander (IC)
- **Role:** Coordinates response, makes decisions, communicates status
- **Primary:** On-call DevOps Engineer
- **Backup:** Engineering Manager

### Technical Lead
- **Role:** Leads technical investigation and resolution
- **Primary:** Senior Engineer on rotation
- **Backup:** Team Lead

### Communications Lead
- **Role:** Handles stakeholder and external communications
- **Primary:** Engineering Manager
- **Backup:** Product Manager

### Scribe
- **Role:** Documents timeline, actions, and decisions
- **Primary:** Available engineer not actively troubleshooting
- **Backup:** IC takes notes

### On-Call Rotation
```
Week 1: Engineer A (Primary), Engineer B (Secondary)
Week 2: Engineer B (Primary), Engineer C (Secondary)
Week 3: Engineer C (Primary), Engineer D (Secondary)
Week 4: Engineer D (Primary), Engineer A (Secondary)
```

---

## Incident Response Workflow

### Phase 1: Detection & Alerting (0-5 minutes)

1. **Alert Received**
   - PagerDuty alert triggers
   - Monitoring dashboard alerts
   - User/customer report

2. **Initial Assessment**
   ```
   [ ] Acknowledge alert in PagerDuty
   [ ] Check Grafana dashboards for system health
   [ ] Review recent deployments in GitHub
   [ ] Check error logs in Kibana
   [ ] Determine initial severity level
   ```

3. **Open Incident Channel**
   ```bash
   # Slack channel naming: #incident-YYYYMMDD-brief-description
   # Example: #incident-20260116-auth-outage
   ```

### Phase 2: Triage & Assessment (5-15 minutes)

1. **Gather Information**
   ```
   [ ] What services are affected?
   [ ] When did the issue start?
   [ ] What changed recently? (deployments, config changes)
   [ ] What is the user impact?
   [ ] Is the issue getting worse?
   ```

2. **Confirm Severity**
   - Upgrade/downgrade severity based on assessment
   - Page additional responders if needed

3. **Initial Communication**
   - Post in incident channel
   - Update status page if SEV-1 or SEV-2

### Phase 3: Investigation & Diagnosis (15-60 minutes)

1. **Systematic Investigation**
   ```bash
   # Check pod status
   kubectl get pods -n apollo-production -o wide

   # Check recent events
   kubectl get events -n apollo-production --sort-by='.lastTimestamp'

   # Check logs
   kubectl logs -l app=apollo -n apollo-production --tail=100

   # Check resource usage
   kubectl top pods -n apollo-production
   ```

2. **Common Investigation Steps**
   - Review Grafana dashboards
   - Check database connections and performance
   - Review application logs in Kibana
   - Check external service dependencies
   - Review recent changes in Git

3. **Document Findings**
   - Update incident channel with findings
   - Note timeline of events
   - Record hypotheses tested

### Phase 4: Mitigation & Resolution (Variable)

1. **Implement Fix**
   - Rollback if deployment-related
   - Scale resources if capacity issue
   - Failover if infrastructure issue
   - Apply hotfix if code issue

2. **Verify Resolution**
   ```
   [ ] Health checks passing
   [ ] Error rates returning to normal
   [ ] User functionality restored
   [ ] No new errors appearing
   ```

3. **Monitor Stability**
   - Watch for 15-30 minutes after fix
   - Confirm no regression

### Phase 5: Recovery & Communication

1. **Confirm Resolution**
   - All affected services healthy
   - Metrics back to baseline
   - No user complaints

2. **Update Communications**
   - Update status page
   - Notify stakeholders
   - Close incident channel (keep for reference)

---

## Communication Procedures

### Internal Communication

**Slack Channels:**
- `#incident-active` - Real-time incident coordination
- `#engineering-alerts` - Automated alert notifications
- `#devops` - DevOps team coordination

**Status Updates:**
Post updates every 15-30 minutes during active incidents:
```
**Incident Update - [TIME]**
- Status: [Investigating/Identified/Monitoring/Resolved]
- Summary: [Brief description of current state]
- Next Steps: [What's being done]
- ETA: [If known]
```

### External Communication

**Status Page Updates:**
- URL: https://status.apollo-platform.com
- Update within 10 minutes for SEV-1/SEV-2

**Status Page Template:**
```
[INVESTIGATING] We are investigating reports of [issue description].
Users may experience [impact]. We are working to resolve this as
quickly as possible. Updates will be posted every 30 minutes.
```

**Customer Communication:**
- SEV-1: Direct customer contact + email
- SEV-2: Email to affected customers
- SEV-3/4: Status page only

### Escalation Matrix

| Time Elapsed | Action |
|--------------|--------|
| 15 minutes | Page secondary on-call if no progress |
| 30 minutes | Escalate to Engineering Manager |
| 1 hour | Escalate to Director of Engineering |
| 2 hours | Executive notification |

---

## Specific Incident Runbooks

### Runbook: Complete Service Outage

**Symptoms:**
- All health checks failing
- No user access to platform
- Multiple services showing errors

**Steps:**
```bash
# 1. Check cluster health
kubectl get nodes
kubectl get pods -A | grep -v Running

# 2. Check ingress/load balancer
kubectl get ingress -n apollo-production
kubectl describe ingress apollo-ingress -n apollo-production

# 3. Check DNS
nslookup apollo-platform.com
dig apollo-platform.com

# 4. Check certificate
echo | openssl s_client -connect apollo-platform.com:443 2>/dev/null | openssl x509 -noout -dates

# 5. If recent deployment, rollback
kubectl rollout undo deployment/apollo-api-gateway -n apollo-production
```

### Runbook: Database Connectivity Issues

**Symptoms:**
- Services failing to start
- "Connection refused" errors
- Slow query responses

**Steps:**
```bash
# 1. Check database pod status
kubectl get pods -l app=postgres -n apollo-production

# 2. Check connection pool
kubectl exec -it deployment/apollo-authentication -n apollo-production -- \
  npm run db:check-connections

# 3. Check database logs
kubectl logs -l app=postgres -n apollo-production --tail=200

# 4. Check database metrics in Grafana
# Dashboard: Database Performance

# 5. If connection pool exhausted, restart services
kubectl rollout restart deployment/apollo-authentication -n apollo-production

# 6. If database is down, check PVC and restart
kubectl delete pod -l app=postgres -n apollo-production
```

### Runbook: High Error Rate

**Symptoms:**
- Error rate > 1% in Grafana
- 5xx responses in logs
- User complaints

**Steps:**
```bash
# 1. Identify affected service(s)
# Check Grafana: Service Error Rates dashboard

# 2. Check logs for error patterns
kubectl logs -l app=apollo -n apollo-production --tail=500 | grep -i error

# 3. Check for recent deployments
git log --oneline -10

# 4. Check resource constraints
kubectl top pods -n apollo-production

# 5. Check external dependencies
curl -w "%{http_code}" https://external-api.example.com/health

# 6. If deployment-related, rollback
kubectl rollout undo deployment/<affected-service> -n apollo-production
```

### Runbook: Memory/CPU Exhaustion

**Symptoms:**
- OOMKilled pods
- High CPU throttling
- Slow response times

**Steps:**
```bash
# 1. Check resource usage
kubectl top pods -n apollo-production

# 2. Check for memory leaks (pod restarts)
kubectl get pods -n apollo-production -o jsonpath='{range .items[*]}{.metadata.name}{" restarts: "}{.status.containerStatuses[0].restartCount}{"\n"}{end}'

# 3. Scale up affected deployment
kubectl scale deployment/apollo-authentication -n apollo-production --replicas=5

# 4. Check HPA status
kubectl get hpa -n apollo-production

# 5. Analyze memory usage patterns in Grafana
# Dashboard: Resource Usage

# 6. If persistent, consider increasing resource limits
kubectl edit deployment/apollo-authentication -n apollo-production
```

### Runbook: Security Incident

**Symptoms:**
- Unauthorized access detected
- Suspicious activity in logs
- Security alert from monitoring

**IMMEDIATE ACTIONS:**
```bash
# 1. Assess scope
# - What systems are affected?
# - What data may be compromised?

# 2. Contain the incident
# Revoke compromised credentials
kubectl delete secret compromised-secret -n apollo-production

# Block suspicious IPs
kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: block-suspicious-ip
  namespace: apollo-production
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  ingress:
  - from:
    - ipBlock:
        cidr: 0.0.0.0/0
        except:
        - <suspicious-ip>/32
EOF

# 3. Preserve evidence
kubectl logs -l app=apollo -n apollo-production --since=1h > /tmp/incident-logs-$(date +%s).txt

# 4. Escalate immediately
# - Notify Security Team
# - Notify Legal/Compliance
# - Notify Executive Team

# 5. Follow security incident protocol
# - Document all actions
# - Do not modify evidence
# - Prepare for forensic analysis
```

### Runbook: Certificate Expiration

**Symptoms:**
- SSL/TLS errors
- Browser security warnings
- Health checks failing with SSL errors

**Steps:**
```bash
# 1. Check certificate expiration
echo | openssl s_client -connect apollo-platform.com:443 2>/dev/null | openssl x509 -noout -dates

# 2. Check cert-manager status
kubectl get certificates -n apollo-production
kubectl describe certificate apollo-tls -n apollo-production

# 3. Force certificate renewal
kubectl delete certificate apollo-tls -n apollo-production
# cert-manager will automatically recreate

# 4. If using Let's Encrypt, check rate limits
kubectl logs -l app=cert-manager -n cert-manager

# 5. As temporary fix, use backup certificate
kubectl create secret tls apollo-tls-backup \
  --cert=backup-cert.pem \
  --key=backup-key.pem \
  -n apollo-production
```

---

## Post-Incident Procedures

### Immediate (Within 24 hours)

1. **Document Incident**
   - Complete incident report template
   - Gather logs and metrics
   - Collect timeline of events

2. **Customer Follow-up**
   - Send resolution notification
   - Provide RCA timeline (for SEV-1/SEV-2)

### Short-term (Within 1 week)

1. **Post-Mortem Meeting**
   - Schedule within 48-72 hours
   - All responders attend
   - Blameless analysis

2. **Post-Mortem Document**
   ```markdown
   # Incident Post-Mortem: [Incident Title]

   ## Summary
   - Date/Time:
   - Duration:
   - Severity:
   - Impact:

   ## Timeline
   [Detailed chronological events]

   ## Root Cause
   [Technical explanation]

   ## Contributing Factors
   [What made this worse]

   ## What Went Well
   [Positive aspects of response]

   ## What Went Poorly
   [Areas for improvement]

   ## Action Items
   | Action | Owner | Due Date | Status |
   |--------|-------|----------|--------|

   ## Lessons Learned
   [Key takeaways]
   ```

3. **Action Items**
   - Create Jira tickets for all action items
   - Assign owners and due dates
   - Track in weekly meetings

### Long-term (Ongoing)

1. **Review Trends**
   - Monthly incident review
   - Track MTTD, MTTR metrics
   - Identify recurring issues

2. **Update Procedures**
   - Improve runbooks based on learnings
   - Update monitoring and alerting
   - Enhance automation

---

## Tools and Access

### Monitoring & Observability
| Tool | URL | Purpose |
|------|-----|---------|
| Grafana | https://grafana.apollo-platform.com | Metrics dashboards |
| Kibana | https://kibana.apollo-platform.com | Log analysis |
| Prometheus | https://prometheus.apollo-platform.com | Metrics queries |
| PagerDuty | https://apollo.pagerduty.com | Alerting |

### Infrastructure Access
| Tool | Access Method |
|------|---------------|
| Kubernetes | `kubectl` with KUBECONFIG |
| AWS Console | SSO via Okta |
| GitHub | Organization membership |
| Database | Via Kubernetes port-forward |

### Important Dashboards
- **System Health:** Grafana > Apollo > System Overview
- **Service Errors:** Grafana > Apollo > Service Error Rates
- **Database:** Grafana > Apollo > Database Performance
- **Resources:** Grafana > Apollo > Resource Usage

### Quick Access Commands
```bash
# Port-forward to production database
kubectl port-forward svc/postgres 5432:5432 -n apollo-production

# Access production logs
kubectl logs -f -l app=apollo -n apollo-production

# Quick health check
curl -s https://apollo-platform.com/api/health | jq .

# Check all pod status
kubectl get pods -n apollo-production -o wide
```

---

## Appendix: Contact Information

### Internal Contacts
| Role | Name | Phone | Email |
|------|------|-------|-------|
| On-Call Primary | See Rotation | PagerDuty | oncall@apollo.local |
| Engineering Manager | [Name] | [Phone] | [Email] |
| Director of Engineering | [Name] | [Phone] | [Email] |
| Security Lead | [Name] | [Phone] | [Email] |

### External Contacts
| Service | Support Contact |
|---------|-----------------|
| AWS | Support Console |
| Cloudflare | [Contact] |
| PagerDuty | support@pagerduty.com |

### Emergency Escalation
1. Primary On-Call: PagerDuty
2. Secondary On-Call: PagerDuty (auto-escalate after 5 min)
3. Engineering Manager: Direct phone
4. Director: Direct phone
5. CTO: Direct phone (SEV-1 only)
