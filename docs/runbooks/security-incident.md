# Runbook: Security Incident Response

## Alert Names
- `MultipleFailedLogins`
- `BruteForceAttackDetected`
- `HighAuthFailureRate`
- `APIKeyAbuse`
- `NewIPAccessingAdmin`
- `UnusualAccessPattern`
- `PotentialDDoSAttack`
- `SuspiciousUserAgent`
- `PrivilegeEscalationAttempt`

## Severity
- Warning to Critical (depending on alert type)

## Impact
- Potential unauthorized access
- Data breach risk
- Service availability (DDoS)
- Compliance implications
- Reputational damage

---

## Immediate Response Protocol

### 1. Initial Assessment (First 5 Minutes)

1. **Acknowledge the alert** in PagerDuty/Slack
2. **Identify the threat type** from alert details
3. **Assess scope**: Single target or multiple systems affected
4. **Determine if active or historical**: Is the attack ongoing?

### 2. Containment (If Attack is Active)

#### For Brute Force / Multiple Failed Logins

```bash
# Block offending IP immediately
kubectl exec -it apollo-api-gateway-0 -n apollo-production -- \
  /usr/local/bin/block-ip.sh <source_ip>

# Or via WAF rules
curl -X POST "https://waf.apollo.internal/api/v1/blocklist" \
  -H "Authorization: Bearer $WAF_TOKEN" \
  -d '{"ip": "<source_ip>", "reason": "brute_force", "duration": "24h"}'
```

#### For DDoS Attack

```bash
# Enable DDoS protection mode
kubectl exec -it apollo-api-gateway-0 -n apollo-production -- \
  /usr/local/bin/enable-ddos-protection.sh

# Scale up API gateway replicas
kubectl scale deployment/apollo-api-gateway -n apollo-production --replicas=10

# Contact CloudFlare/CDN provider if needed
```

#### For API Key Abuse

```bash
# Revoke the compromised API key
curl -X DELETE "https://api.apollo.internal/v1/admin/api-keys/<key_id>" \
  -H "Authorization: Bearer $ADMIN_TOKEN"

# Notify the API key owner
```

#### For Privilege Escalation Attempt

```bash
# Lock the user account
curl -X POST "https://api.apollo.internal/v1/admin/users/<user_id>/lock" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{"reason": "suspected_privilege_escalation"}'

# Invalidate all sessions
curl -X DELETE "https://api.apollo.internal/v1/admin/users/<user_id>/sessions" \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

---

## Investigation Steps

### 3. Evidence Collection

#### Authentication Logs
```bash
# Query ELK for auth events
curl -X POST "http://elasticsearch:9200/apollo-security-*/_search" \
  -H 'Content-Type: application/json' \
  -d '{
    "query": {
      "bool": {
        "must": [
          {"term": {"source_ip": "<suspicious_ip>"}},
          {"range": {"@timestamp": {"gte": "now-24h"}}}
        ]
      }
    },
    "size": 1000
  }'
```

#### API Access Logs
```bash
# Get all requests from suspicious IP
kubectl logs -l app=api-gateway -n apollo-production --since=1h | \
  grep "<source_ip>"
```

#### User Activity
```bash
# Query audit logs for specific user
curl -X POST "http://elasticsearch:9200/apollo-audit-*/_search" \
  -H 'Content-Type: application/json' \
  -d '{
    "query": {
      "term": {"user_id": "<suspected_user>"}
    },
    "sort": [{"@timestamp": "desc"}],
    "size": 500
  }'
```

### 4. Impact Assessment

1. **Was any data accessed?**
   - Check access logs for successful requests
   - Review database audit logs

2. **Were any accounts compromised?**
   - Check for successful logins after failed attempts
   - Review session creation logs

3. **Was any data modified?**
   - Check audit logs for write operations
   - Compare with recent backups if needed

---

## Specific Incident Types

### Brute Force Attack

**Indicators:**
- High rate of failed login attempts
- Single IP targeting multiple accounts
- Sequential password attempts

**Response:**
1. Block source IP(s)
2. Enable CAPTCHA if not already active
3. Notify potentially targeted users
4. Review if any accounts were compromised

### API Key Compromise

**Indicators:**
- Unusual API usage patterns
- Requests from unexpected geolocations
- High error rates from specific key

**Response:**
1. Revoke the API key immediately
2. Issue new key to legitimate owner
3. Audit all actions performed with the key
4. Review how key was compromised (logs, etc.)

### DDoS Attack

**Indicators:**
- Extreme request volume
- Distributed source IPs
- Specific endpoints targeted

**Response:**
1. Enable DDoS protection
2. Scale infrastructure
3. Engage CDN/WAF provider
4. Consider geo-blocking if attack is regional

### Admin Access from New IP

**Indicators:**
- Admin login from previously unseen IP
- Different geolocation from usual
- Outside normal working hours

**Response:**
1. Verify with the admin user out-of-band
2. If unauthorized, lock account immediately
3. Invalidate sessions
4. Review all admin actions from that session

---

## Post-Incident Actions

### 5. Recovery

1. **Remove blocks** once attack has ceased and investigation complete
2. **Restore normal operations** (disable DDoS protection mode)
3. **Reset compromised credentials** if any
4. **Re-enable locked accounts** after verification

### 6. Documentation

Create incident report including:
- Timeline of events
- Indicators of compromise (IOCs)
- Actions taken
- Evidence collected
- Impact assessment
- Lessons learned

### 7. Preventive Measures

Based on incident type:
- Update rate limiting rules
- Enhance monitoring and alerting
- Implement additional authentication controls
- Review access control policies
- Update security training materials

---

## Escalation Path

| Level | Condition | Action |
|-------|-----------|--------|
| L1 | Warning alert | Security team investigates |
| L2 | Critical alert | Page on-call + Security Lead |
| L3 | Confirmed breach | CISO + Legal + Executive team |
| L4 | Data exfiltration | Incident Response Team + External |

## Communication Templates

### Internal Notification
```
SECURITY INCIDENT DETECTED
Time: [TIMESTAMP]
Type: [INCIDENT_TYPE]
Status: [INVESTIGATING/CONTAINED/RESOLVED]
Impact: [DESCRIPTION]
Current Actions: [ACTIONS]
ETA for Update: [TIME]
```

### External Notification (if required)
```
[FOLLOW LEGAL/COMPLIANCE APPROVED TEMPLATES]
```

## Related Dashboards

- [Security Dashboard](https://grafana.apollo.internal/d/apollo-security)
- [Access Logs](https://kibana.apollo.internal/app/security-logs)

## Emergency Contacts

- Security Team: security-oncall@apollo.internal
- CISO: ciso@apollo.internal
- Legal: legal@apollo.internal
- External IR Firm: [CONTACT_DETAILS]

## Changelog

| Date | Author | Change |
|------|--------|--------|
| 2026-01-16 | Security Team | Initial version |
