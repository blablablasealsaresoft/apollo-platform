# Runbook: High CPU Usage

## Alert Names
- `HighCPUUsageWarning`
- `HighCPUUsageCritical`

## Severity
- Warning: CPU > 70% for 10 minutes
- Critical: CPU > 90% for 5 minutes

## Impact
- Degraded service performance
- Increased response latency
- Potential service unavailability
- Risk of cascading failures

## Diagnosis Steps

### 1. Identify the Affected Pod/Service

```bash
# Get pods with high CPU usage
kubectl top pods -n apollo-production --sort-by=cpu

# Get detailed pod information
kubectl describe pod <pod-name> -n apollo-production
```

### 2. Check Recent Deployments

```bash
# Check recent rollouts
kubectl rollout history deployment/<deployment-name> -n apollo-production

# Check if there was a recent change
kubectl get events -n apollo-production --sort-by='.lastTimestamp'
```

### 3. Analyze Container Metrics

```bash
# Check container resource usage
kubectl exec -it <pod-name> -n apollo-production -- top -bn1

# Check process list
kubectl exec -it <pod-name> -n apollo-production -- ps aux --sort=-%cpu
```

### 4. Review Application Logs

```bash
# Get recent logs
kubectl logs <pod-name> -n apollo-production --tail=500

# Check for errors or warnings
kubectl logs <pod-name> -n apollo-production | grep -i "error\|warn\|exception"
```

### 5. Check for Traffic Spikes

```bash
# Query Prometheus for request rate
curl -s "http://prometheus:9090/api/v1/query?query=sum(rate(http_requests_total{service='<service>'}[5m]))"
```

## Resolution Steps

### Immediate Actions

1. **Scale Up Horizontally** (if applicable)
   ```bash
   kubectl scale deployment/<deployment-name> -n apollo-production --replicas=<current+2>
   ```

2. **Restart the Pod** (if a single pod is affected)
   ```bash
   kubectl delete pod <pod-name> -n apollo-production
   ```

3. **Increase Resource Limits** (temporary measure)
   ```bash
   kubectl set resources deployment/<deployment-name> -n apollo-production \
     --limits=cpu=2000m --requests=cpu=1000m
   ```

### Root Cause Analysis

1. **Memory Leak**
   - Check heap dumps if Java/Node.js
   - Review recent code changes
   - Enable profiling

2. **Inefficient Query/Algorithm**
   - Review slow query logs
   - Check for missing database indexes
   - Profile code hot paths

3. **Traffic Spike**
   - Implement rate limiting
   - Add caching layer
   - Consider auto-scaling policies

4. **Resource Contention**
   - Check node resource utilization
   - Consider pod anti-affinity rules
   - Review resource quotas

### Long-term Fixes

1. Update HPA (Horizontal Pod Autoscaler):
   ```yaml
   apiVersion: autoscaling/v2
   kind: HorizontalPodAutoscaler
   metadata:
     name: <service>-hpa
     namespace: apollo-production
   spec:
     scaleTargetRef:
       apiVersion: apps/v1
       kind: Deployment
       name: <deployment>
     minReplicas: 2
     maxReplicas: 10
     metrics:
     - type: Resource
       resource:
         name: cpu
         target:
           type: Utilization
           averageUtilization: 70
   ```

2. Optimize application code
3. Implement caching where appropriate
4. Review and optimize database queries

## Escalation Path

1. **Warning Level**: On-call engineer investigates
2. **Critical Level**:
   - Page platform team lead
   - Notify service owner
   - If unresolved in 15 min, escalate to senior engineer

## Related Dashboards

- [Service Overview](https://grafana.apollo.internal/d/apollo-services)
- [Resource Utilization](https://grafana.apollo.internal/d/apollo-overview)

## Related Alerts

- `HighMemoryUsage`
- `ServiceDown`
- `HighResponseTime`

## Changelog

| Date | Author | Change |
|------|--------|--------|
| 2026-01-16 | Platform Team | Initial version |
