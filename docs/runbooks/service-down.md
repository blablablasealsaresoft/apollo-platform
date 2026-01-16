# Runbook: Service Down

## Alert Names
- `ServiceDown`
- `NodeNotReady`
- `PodRestartLoop`

## Severity
- Critical

## Impact
- Service unavailability
- User-facing errors
- Potential data processing backlog
- Dependent services may be affected

## Diagnosis Steps

### 1. Identify the Down Service

```bash
# Check service status
kubectl get pods -n apollo-production -l app=<service-name>

# Get pod status details
kubectl describe pod <pod-name> -n apollo-production

# Check all services
kubectl get pods -n apollo-production --field-selector=status.phase!=Running
```

### 2. Check Pod Events

```bash
# Get recent events for the pod
kubectl get events -n apollo-production --field-selector involvedObject.name=<pod-name>

# Get events sorted by time
kubectl get events -n apollo-production --sort-by='.lastTimestamp' | tail -20
```

### 3. Check Node Health

```bash
# Check node status
kubectl get nodes

# Describe problematic node
kubectl describe node <node-name>

# Check node resources
kubectl top nodes
```

### 4. Review Container Logs

```bash
# Get logs from current container
kubectl logs <pod-name> -n apollo-production

# Get logs from previous container (if restarting)
kubectl logs <pod-name> -n apollo-production --previous

# Stream logs
kubectl logs -f <pod-name> -n apollo-production
```

### 5. Check Dependencies

```bash
# Check database connectivity
kubectl exec -it <pod-name> -n apollo-production -- \
  nc -zv apollo-postgres 5432

# Check Redis connectivity
kubectl exec -it <pod-name> -n apollo-production -- \
  nc -zv apollo-redis 6379
```

## Resolution Steps

### Immediate Actions

1. **Restart the Pod**
   ```bash
   kubectl delete pod <pod-name> -n apollo-production
   ```

2. **Rollback Recent Deployment** (if recent change caused issue)
   ```bash
   kubectl rollout undo deployment/<deployment-name> -n apollo-production
   ```

3. **Check and Fix Configuration**
   ```bash
   # Check ConfigMap
   kubectl get configmap <config-name> -n apollo-production -o yaml

   # Check Secrets
   kubectl get secret <secret-name> -n apollo-production -o yaml
   ```

### Common Failure Scenarios

#### Scenario 1: OOMKilled (Out of Memory)
```bash
# Check if OOMKilled
kubectl get pod <pod-name> -n apollo-production -o jsonpath='{.status.containerStatuses[*].lastState.terminated.reason}'

# Solution: Increase memory limits
kubectl set resources deployment/<deployment-name> -n apollo-production \
  --limits=memory=2Gi --requests=memory=1Gi
```

#### Scenario 2: CrashLoopBackOff
```bash
# Check logs for crash reason
kubectl logs <pod-name> -n apollo-production --previous

# Common causes:
# - Missing configuration
# - Database connection failure
# - Invalid environment variables
```

#### Scenario 3: ImagePullBackOff
```bash
# Check image details
kubectl describe pod <pod-name> -n apollo-production | grep -A5 "Image:"

# Solutions:
# - Verify image exists
# - Check image pull secrets
# - Check registry connectivity
```

#### Scenario 4: Pending Pod
```bash
# Check why pod is pending
kubectl describe pod <pod-name> -n apollo-production | grep -A10 "Events:"

# Common causes:
# - Insufficient resources
# - Node selector mismatch
# - PVC binding issues
```

### Node-Level Issues

1. **Node Not Ready**
   ```bash
   # Check node conditions
   kubectl describe node <node-name> | grep -A10 Conditions

   # If node is unrecoverable, cordon and drain
   kubectl cordon <node-name>
   kubectl drain <node-name> --ignore-daemonsets --delete-emptydir-data
   ```

2. **Node Resource Pressure**
   ```bash
   # Check disk pressure
   kubectl describe node <node-name> | grep -i pressure

   # Clean up unused images
   docker system prune -af
   ```

## Verification Steps

1. **Confirm Pod is Running**
   ```bash
   kubectl get pod <pod-name> -n apollo-production
   # Should show Running status
   ```

2. **Check Service Endpoint**
   ```bash
   kubectl get endpoints <service-name> -n apollo-production
   # Should show pod IPs
   ```

3. **Test Health Endpoint**
   ```bash
   kubectl exec -it <any-pod> -n apollo-production -- \
     curl -s http://<service-name>:8080/health
   ```

4. **Verify Prometheus Target**
   - Check Prometheus targets page
   - Ensure service shows as "UP"

## Escalation Path

1. **0-5 minutes**: On-call engineer attempts restart
2. **5-15 minutes**: Escalate to service owner
3. **15+ minutes**: Escalate to platform team lead
4. **30+ minutes**: All-hands incident response

## Communication

1. Post in `#apollo-incidents` Slack channel
2. Update status page if user-facing
3. Create incident ticket in tracking system

## Related Dashboards

- [Service Health](https://grafana.apollo.internal/d/apollo-services)
- [Overview](https://grafana.apollo.internal/d/apollo-overview)

## Related Alerts

- `HighErrorRate`
- `HighCPUUsage`
- `HighMemoryUsage`

## Post-Incident

1. Document root cause
2. Update runbook if new failure mode discovered
3. Implement preventive measures
4. Schedule post-mortem if major outage

## Changelog

| Date | Author | Change |
|------|--------|--------|
| 2026-01-16 | Platform Team | Initial version |
