# Runbook: Database Issues

## Alert Names
- `DatabaseConnectionPoolExhausted`
- `DatabaseConnectionPoolCritical`
- `DatabaseSlowQueries`
- `HighDatabaseConnections`
- `DatabaseReplicationLag`
- `DatabaseDeadlocks`
- `RedisHighMemoryUsage`
- `RedisDown`
- `ElasticsearchClusterUnhealthy`

## Severity
- Warning to Critical (depending on alert)

## Impact
- Application timeouts
- Data inconsistency (replication lag)
- Service degradation or complete outage
- Potential data loss in extreme cases

---

## PostgreSQL Issues

### Connection Pool Exhaustion

#### Diagnosis
```bash
# Check current connections
kubectl exec -it apollo-postgres-0 -n apollo-production -- \
  psql -U apollo -c "SELECT count(*) FROM pg_stat_activity;"

# Check connections by state
kubectl exec -it apollo-postgres-0 -n apollo-production -- \
  psql -U apollo -c "SELECT state, count(*) FROM pg_stat_activity GROUP BY state;"

# Check connections by application
kubectl exec -it apollo-postgres-0 -n apollo-production -- \
  psql -U apollo -c "SELECT application_name, count(*) FROM pg_stat_activity GROUP BY application_name;"

# Find long-running queries
kubectl exec -it apollo-postgres-0 -n apollo-production -- \
  psql -U apollo -c "SELECT pid, now() - pg_stat_activity.query_start AS duration, query
  FROM pg_stat_activity
  WHERE state != 'idle'
  ORDER BY duration DESC LIMIT 10;"
```

#### Resolution
1. **Terminate Idle Connections**
   ```sql
   -- Terminate idle connections older than 10 minutes
   SELECT pg_terminate_backend(pid)
   FROM pg_stat_activity
   WHERE state = 'idle'
   AND query_start < now() - interval '10 minutes'
   AND pid != pg_backend_pid();
   ```

2. **Kill Long-Running Queries**
   ```sql
   -- Terminate queries running longer than 5 minutes
   SELECT pg_terminate_backend(pid)
   FROM pg_stat_activity
   WHERE state != 'idle'
   AND query_start < now() - interval '5 minutes'
   AND pid != pg_backend_pid();
   ```

3. **Increase Max Connections** (temporary)
   ```sql
   ALTER SYSTEM SET max_connections = 200;
   -- Requires restart
   ```

4. **Review Application Connection Pooling**
   - Check PgBouncer configuration
   - Review application pool settings

### Slow Queries

#### Diagnosis
```bash
# Check slow query log
kubectl exec -it apollo-postgres-0 -n apollo-production -- \
  tail -100 /var/log/postgresql/slow-queries.log

# Check for missing indexes
kubectl exec -it apollo-postgres-0 -n apollo-production -- \
  psql -U apollo -c "SELECT schemaname, tablename, indexname, idx_scan
  FROM pg_stat_user_indexes
  WHERE idx_scan = 0
  ORDER BY schemaname, tablename;"

# Check table statistics
kubectl exec -it apollo-postgres-0 -n apollo-production -- \
  psql -U apollo -c "SELECT relname, n_live_tup, n_dead_tup, last_vacuum, last_analyze
  FROM pg_stat_user_tables
  ORDER BY n_dead_tup DESC LIMIT 10;"
```

#### Resolution
1. **Analyze Tables**
   ```sql
   ANALYZE VERBOSE <table_name>;
   ```

2. **Add Missing Indexes**
   ```sql
   CREATE INDEX CONCURRENTLY idx_<name> ON <table>(<columns>);
   ```

3. **Vacuum Tables**
   ```sql
   VACUUM ANALYZE <table_name>;
   ```

### Replication Lag

#### Diagnosis
```bash
# Check replication status
kubectl exec -it apollo-postgres-0 -n apollo-production -- \
  psql -U apollo -c "SELECT client_addr, state, sent_lsn, write_lsn, flush_lsn, replay_lsn,
  pg_wal_lsn_diff(sent_lsn, replay_lsn) AS lag_bytes
  FROM pg_stat_replication;"

# Check replica status
kubectl exec -it apollo-postgres-1 -n apollo-production -- \
  psql -U apollo -c "SELECT pg_last_wal_receive_lsn(), pg_last_wal_replay_lsn(),
  pg_last_xact_replay_timestamp();"
```

#### Resolution
1. **Check Network Issues** between primary and replica
2. **Review Replica Resources** (CPU, disk I/O)
3. **Increase WAL Senders** if needed
4. **Rebuild Replica** if severely behind

---

## Redis Issues

### High Memory Usage

#### Diagnosis
```bash
# Check memory usage
kubectl exec -it apollo-redis-0 -n apollo-production -- \
  redis-cli INFO memory

# Check key distribution
kubectl exec -it apollo-redis-0 -n apollo-production -- \
  redis-cli DEBUG object <key>

# Find large keys
kubectl exec -it apollo-redis-0 -n apollo-production -- \
  redis-cli --bigkeys
```

#### Resolution
1. **Evict Keys** (if eviction policy allows)
   ```bash
   redis-cli CONFIG SET maxmemory-policy allkeys-lru
   ```

2. **Clear Expired Keys**
   ```bash
   redis-cli BGSAVE
   redis-cli DEBUG SLEEP 0  # Force lazy-free
   ```

3. **Increase Memory Limit** (if possible)
   ```bash
   redis-cli CONFIG SET maxmemory 4gb
   ```

4. **Review TTL Settings** in application

### Redis Down

#### Diagnosis
```bash
# Check pod status
kubectl get pods -n apollo-production -l app=redis

# Check logs
kubectl logs apollo-redis-0 -n apollo-production

# Test connection
kubectl exec -it <any-pod> -n apollo-production -- \
  redis-cli -h apollo-redis ping
```

#### Resolution
1. **Restart Pod**
   ```bash
   kubectl delete pod apollo-redis-0 -n apollo-production
   ```

2. **Check Persistent Volume**
   ```bash
   kubectl describe pvc redis-data -n apollo-production
   ```

3. **Restore from Backup** (if data corruption)

---

## Elasticsearch Issues

### Cluster Unhealthy (RED)

#### Diagnosis
```bash
# Check cluster health
kubectl exec -it apollo-elasticsearch-0 -n apollo-production -- \
  curl -s localhost:9200/_cluster/health?pretty

# Check unassigned shards
kubectl exec -it apollo-elasticsearch-0 -n apollo-production -- \
  curl -s localhost:9200/_cat/shards?v | grep UNASSIGNED

# Check node status
kubectl exec -it apollo-elasticsearch-0 -n apollo-production -- \
  curl -s localhost:9200/_cat/nodes?v
```

#### Resolution
1. **Reassign Unassigned Shards**
   ```bash
   curl -X POST "localhost:9200/_cluster/reroute?retry_failed=true"
   ```

2. **Check Disk Space**
   ```bash
   curl -s localhost:9200/_cat/allocation?v
   ```

3. **Disable Shard Allocation** (for maintenance)
   ```bash
   curl -X PUT "localhost:9200/_cluster/settings" -H 'Content-Type: application/json' -d'
   {
     "persistent": {
       "cluster.routing.allocation.enable": "none"
     }
   }'
   ```

4. **Scale Up Nodes** if cluster is overwhelmed

---

## General Database Checklist

1. [ ] Check service connectivity from application pods
2. [ ] Verify credentials and secrets are correct
3. [ ] Check disk space on database nodes
4. [ ] Review recent schema changes
5. [ ] Check for backup job interference
6. [ ] Verify network policies allow traffic

## Escalation Path

1. **Warning Level**: DBA team investigates
2. **Critical Level**: Page on-call DBA + platform engineer
3. **Data Loss Risk**: Escalate to database team lead

## Related Dashboards

- [Database Dashboard](https://grafana.apollo.internal/d/apollo-database)
- [Service Overview](https://grafana.apollo.internal/d/apollo-services)

## Changelog

| Date | Author | Change |
|------|--------|--------|
| 2026-01-16 | DBA Team | Initial version |
