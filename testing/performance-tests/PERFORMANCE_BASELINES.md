# Apollo Platform - Performance Baselines

This document defines the performance baselines and thresholds for the Apollo Intelligence Platform. These baselines serve as benchmarks for load testing, capacity planning, and performance monitoring.

## Table of Contents

1. [Overview](#overview)
2. [Performance Targets](#performance-targets)
3. [Test Scenarios](#test-scenarios)
4. [API Performance Baselines](#api-performance-baselines)
5. [Database Performance Baselines](#database-performance-baselines)
6. [WebSocket Performance Baselines](#websocket-performance-baselines)
7. [Stress Test Thresholds](#stress-test-thresholds)
8. [Capacity Planning](#capacity-planning)
9. [Running Tests](#running-tests)

---

## Overview

Performance testing ensures the Apollo platform can handle expected load while maintaining acceptable response times and reliability. These baselines are established through iterative testing and represent the minimum acceptable performance levels.

### Key Performance Indicators (KPIs)

| Metric | Target | Critical Threshold |
|--------|--------|-------------------|
| API Response Time (p95) | < 200ms | < 500ms |
| API Response Time (p99) | < 500ms | < 1000ms |
| Error Rate | < 1% | < 5% |
| Throughput | > 100 req/s | > 50 req/s |
| Availability | > 99.9% | > 99% |

---

## Performance Targets

### Tier 1: Critical APIs (p95 < 200ms)

These endpoints are accessed frequently and must respond quickly:

| Endpoint | Method | Target p95 | Target p99 |
|----------|--------|------------|------------|
| `/auth/login` | POST | 200ms | 400ms |
| `/auth/validate` | GET | 100ms | 200ms |
| `/auth/refresh` | POST | 150ms | 300ms |
| `/auth/logout` | POST | 100ms | 200ms |
| `/health` | GET | 50ms | 100ms |

### Tier 2: Read Operations (p95 < 300ms)

Standard read operations with pagination:

| Endpoint | Method | Target p95 | Target p99 |
|----------|--------|------------|------------|
| `/investigations` | GET | 200ms | 400ms |
| `/targets` | GET | 200ms | 400ms |
| `/evidence` | GET | 250ms | 500ms |
| `/intelligence` | GET | 300ms | 600ms |
| `/operations` | GET | 200ms | 400ms |
| `/search` | GET | 300ms | 500ms |

### Tier 3: Write Operations (p95 < 500ms)

Create and update operations:

| Endpoint | Method | Target p95 | Target p99 |
|----------|--------|------------|------------|
| `/investigations` | POST | 300ms | 600ms |
| `/investigations/:id` | PATCH | 200ms | 400ms |
| `/targets` | POST | 300ms | 600ms |
| `/evidence` | POST | 500ms | 1000ms |

### Tier 4: Complex Operations (p95 < 1000ms)

Intelligence and analytics operations:

| Endpoint | Method | Target p95 | Target p99 |
|----------|--------|------------|------------|
| `/intelligence/osint/*` | POST | 1000ms | 2000ms |
| `/intelligence/blockchain/*` | POST | 2000ms | 5000ms |
| `/intelligence/correlate` | POST | 500ms | 1000ms |
| `/analytics/dashboard` | POST | 500ms | 1000ms |
| `/reports/generate` | POST | 3000ms | 5000ms |

---

## Test Scenarios

### Smoke Test

Quick validation of system functionality.

```
Users: 1-5
Duration: 1-2 minutes
Purpose: Verify basic functionality
```

**Expected Results:**
- 100% success rate
- All responses < 500ms
- No errors

### Load Test

Normal expected traffic patterns.

```
Users: 50-100
Duration: 15-20 minutes
Ramp-up: 2-5 minutes
Purpose: Verify system handles normal load
```

**Expected Results:**
- > 99% success rate
- p95 response time < 200ms
- Error rate < 1%
- Throughput > 100 req/s

### Stress Test

Push system beyond normal capacity.

```
Users: 200-500
Duration: 15-20 minutes
Ramp-up: 5-10 minutes
Purpose: Find performance degradation points
```

**Expected Results:**
- > 95% success rate
- p95 response time < 1000ms
- Error rate < 5%
- System recovers after load decreases

### Spike Test

Sudden traffic burst simulation.

```
Users: 20 -> 500 -> 20 (sudden jump)
Duration: 10-15 minutes
Purpose: Test system reaction to sudden load
```

**Expected Results:**
- > 90% success rate during spike
- System stabilizes after spike
- No cascading failures

### Soak Test

Extended duration testing.

```
Users: 50-100
Duration: 1-4 hours
Purpose: Detect memory leaks and resource exhaustion
```

**Expected Results:**
- Consistent response times
- No memory leaks
- Stable resource usage
- Error rate remains constant

---

## API Performance Baselines

### Authentication Service

| Metric | Smoke | Load | Stress |
|--------|-------|------|--------|
| Login p95 | < 150ms | < 200ms | < 400ms |
| Token Refresh p95 | < 100ms | < 150ms | < 300ms |
| Logout p95 | < 80ms | < 100ms | < 200ms |
| Success Rate | 100% | > 99% | > 95% |

### Search Service

| Metric | Smoke | Load | Stress |
|--------|-------|------|--------|
| Simple Search p95 | < 100ms | < 150ms | < 300ms |
| Complex Search p95 | < 200ms | < 300ms | < 600ms |
| Full-text Search p95 | < 200ms | < 300ms | < 500ms |
| Autocomplete p95 | < 50ms | < 100ms | < 200ms |

### Intelligence Service

| Metric | Smoke | Load | Stress |
|--------|-------|------|--------|
| OSINT Query p95 | < 800ms | < 1000ms | < 2000ms |
| Blockchain Query p95 | < 1500ms | < 2000ms | < 5000ms |
| Correlation p95 | < 400ms | < 500ms | < 1000ms |
| Alert Query p95 | < 200ms | < 300ms | < 600ms |

---

## Database Performance Baselines

### PostgreSQL

| Operation | Target p95 | Target p99 | Max Acceptable |
|-----------|------------|------------|----------------|
| Simple SELECT | 30ms | 50ms | 100ms |
| Complex SELECT | 100ms | 200ms | 400ms |
| JOIN Query | 80ms | 150ms | 300ms |
| INSERT | 50ms | 100ms | 200ms |
| UPDATE | 50ms | 100ms | 200ms |
| DELETE | 50ms | 100ms | 200ms |
| Full-text Search | 150ms | 300ms | 500ms |
| Aggregation | 200ms | 400ms | 800ms |

### TimescaleDB

| Operation | Target p95 | Target p99 | Max Acceptable |
|-----------|------------|------------|----------------|
| Latest Value | 30ms | 50ms | 100ms |
| Time Range Query | 150ms | 300ms | 500ms |
| Aggregate Query | 200ms | 400ms | 600ms |
| Continuous Agg | 100ms | 200ms | 400ms |
| Single Insert | 30ms | 50ms | 100ms |
| Batch Insert | 300ms | 500ms | 1000ms |
| Downsample | 150ms | 300ms | 500ms |
| Percentile Query | 200ms | 400ms | 600ms |

---

## WebSocket Performance Baselines

| Metric | Target | Acceptable | Maximum |
|--------|--------|------------|---------|
| Connection Time | < 300ms | < 500ms | < 1000ms |
| Message Send | < 50ms | < 100ms | < 200ms |
| Message Latency | < 100ms | < 200ms | < 500ms |
| Subscription Time | < 200ms | < 300ms | < 500ms |
| Connection Success Rate | > 99% | > 95% | > 90% |

### Concurrent Connections

| Scenario | Target Connections | Expected Behavior |
|----------|-------------------|-------------------|
| Normal | 100 | Full functionality |
| Peak | 500 | Minor degradation acceptable |
| Stress | 1000 | Service degradation expected |
| Maximum | 2000+ | Graceful rejection |

---

## Stress Test Thresholds

### API Stress Thresholds

| Intensity | VUs | Target Error Rate | Target p95 |
|-----------|-----|-------------------|------------|
| Medium | 200 | < 5% | < 1000ms |
| High | 500 | < 10% | < 2000ms |
| Extreme | 1000 | < 15% | < 5000ms |
| Breaking | 1500+ | Find limit | Find limit |

### Concurrent User Thresholds

| Scenario | Users | Login Success | Session Success | Action Success |
|----------|-------|---------------|-----------------|----------------|
| Standard | 100 | > 99% | > 95% | > 95% |
| Peak | 250 | > 95% | > 90% | > 90% |
| Burst | 300 | > 90% | > 85% | > 85% |
| Breaking | 500+ | Find limit | Find limit | Find limit |

---

## Capacity Planning

### Resource Requirements by Load Level

#### Low Load (< 50 concurrent users)

```
CPU: 2 cores
Memory: 4 GB
Database Connections: 20
Redis Connections: 50
```

#### Medium Load (50-200 concurrent users)

```
CPU: 4 cores
Memory: 8 GB
Database Connections: 50
Redis Connections: 100
```

#### High Load (200-500 concurrent users)

```
CPU: 8 cores
Memory: 16 GB
Database Connections: 100
Redis Connections: 200
```

#### Peak Load (500+ concurrent users)

```
CPU: 16+ cores
Memory: 32+ GB
Database Connections: 200
Redis Connections: 500
Horizontal scaling recommended
```

### Scaling Recommendations

1. **Horizontal Scaling Triggers:**
   - CPU utilization > 70% sustained
   - Memory utilization > 80%
   - Response time p95 > 500ms
   - Error rate > 2%

2. **Database Scaling Triggers:**
   - Connection pool exhaustion
   - Query time increase > 50%
   - Disk I/O saturation

3. **Cache Scaling Triggers:**
   - Hit rate < 80%
   - Memory utilization > 85%
   - Eviction rate increase

---

## Running Tests

### Prerequisites

1. Install k6:
   ```bash
   # macOS
   brew install k6

   # Linux
   snap install k6

   # Docker
   docker pull grafana/k6
   ```

2. Ensure test users exist in the database

3. Configure environment variables

### Load Tests

```bash
# Run all load tests with default settings
./testing/scripts/run-load-tests.sh

# Run specific test with scenario
./testing/scripts/run-load-tests.sh -t auth -s smoke
./testing/scripts/run-load-tests.sh -t search -s load
./testing/scripts/run-load-tests.sh -t all -s stress

# With custom API URL
./testing/scripts/run-load-tests.sh -u http://api.example.com/api -t all -s load
```

### Stress Tests

```bash
# Run all stress tests
./testing/scripts/run-stress-tests.sh

# Run specific intensity
./testing/scripts/run-stress-tests.sh -t api -i extreme
./testing/scripts/run-stress-tests.sh -t concurrent -s breaking

# Database stress tests
./testing/scripts/run-stress-tests.sh -t database
```

### Individual Test Files

```bash
# Authentication
k6 run -e SCENARIO=load testing/performance-tests/load-tests/auth-load.js

# Search
k6 run -e SCENARIO=stress testing/performance-tests/load-tests/search-load.js

# Intelligence
k6 run -e SCENARIO=spike testing/performance-tests/load-tests/intelligence-load.js

# WebSocket
k6 run -e SCENARIO=soak testing/performance-tests/load-tests/websocket-load.js

# PostgreSQL
k6 run -e SCENARIO=stress testing/performance-tests/database/postgresql-perf.js

# TimescaleDB
k6 run -e SCENARIO=stress testing/performance-tests/database/timescale-perf.js

# API Stress
k6 run -e INTENSITY=extreme testing/performance-tests/stress-tests/api-stress.js

# Concurrent Users
k6 run -e SCENARIO=breaking testing/performance-tests/stress-tests/concurrent-users.js
```

---

## Test Results Analysis

### Interpreting Results

1. **Response Time:**
   - p50 (median): Typical user experience
   - p95: Experience for 95% of users
   - p99: Worst-case scenario for most users
   - max: Absolute worst case

2. **Error Rate:**
   - < 1%: Excellent
   - 1-5%: Acceptable under stress
   - > 5%: Requires investigation

3. **Throughput:**
   - Requests per second
   - Should remain stable under load
   - Decrease indicates bottleneck

### Baseline Comparison

Compare test results against baselines:

```
| Metric          | Baseline | Actual | Status |
|-----------------|----------|--------|--------|
| p95 Response    | < 200ms  | 150ms  | PASS   |
| Error Rate      | < 1%     | 0.5%   | PASS   |
| Throughput      | > 100/s  | 120/s  | PASS   |
```

### Recommended Actions

| Finding | Action |
|---------|--------|
| p95 > baseline | Investigate slow endpoints, optimize queries |
| Error rate > 1% | Check logs, review error types |
| Throughput < baseline | Check resource utilization, scale if needed |
| Memory growth | Investigate memory leaks |
| Connection errors | Review connection pool settings |

---

## Maintenance

### Updating Baselines

Baselines should be updated when:

1. Infrastructure changes (hardware, cloud instance types)
2. Major application changes
3. Database schema changes
4. New features with different performance characteristics

### Regular Testing Schedule

| Test Type | Frequency | Trigger |
|-----------|-----------|---------|
| Smoke | Every deployment | CI/CD pipeline |
| Load | Weekly | Scheduled job |
| Stress | Monthly | Manual or scheduled |
| Soak | Quarterly | Pre-release |
| Breaking | As needed | Capacity planning |

---

*Document Version: 1.0*
*Last Updated: January 2026*
*Maintained by: Apollo Platform Team*
