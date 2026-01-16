/**
 * Apollo Platform - TimescaleDB Performance Test
 *
 * Tests TimescaleDB time-series database performance.
 * Measures time-series queries, continuous aggregates, and data retention.
 *
 * Run: k6 run timescale-perf.js
 * Run with env: k6 run -e API_URL=http://localhost:3000/api timescale-perf.js
 * Run specific scenario: k6 run --env SCENARIO=stress timescale-perf.js
 */

import http from 'k6/http';
import { check, group, sleep } from 'k6';
import { Rate, Trend, Counter, Gauge } from 'k6/metrics';
import { randomIntBetween, randomItem, randomString } from 'https://jslib.k6.io/k6-utils/1.4.0/index.js';

// ============================================================================
// CUSTOM METRICS
// ============================================================================

// Time-series query metrics
const timeRangeQueryDuration = new Trend('ts_time_range_query_duration_ms');
const latestQueryDuration = new Trend('ts_latest_query_duration_ms');
const aggregateQueryDuration = new Trend('ts_aggregate_query_duration_ms');
const continuousAggQueryDuration = new Trend('ts_continuous_agg_duration_ms');
const downsampleQueryDuration = new Trend('ts_downsample_duration_ms');
const gapFillQueryDuration = new Trend('ts_gapfill_duration_ms');

// Data ingestion metrics
const singleInsertDuration = new Trend('ts_single_insert_duration_ms');
const batchInsertDuration = new Trend('ts_batch_insert_duration_ms');
const highCardinalityQueryDuration = new Trend('ts_high_cardinality_duration_ms');

// Analytics metrics
const movingAverageQueryDuration = new Trend('ts_moving_avg_duration_ms');
const percentileQueryDuration = new Trend('ts_percentile_duration_ms');
const anomalyDetectionDuration = new Trend('ts_anomaly_detection_duration_ms');

// General metrics
const querySuccessRate = new Rate('ts_query_success_rate');
const errorRate = new Rate('ts_errors');
const requestCounter = new Counter('ts_total_requests');
const dataPointsProcessed = new Counter('ts_data_points_processed');
const activeQueries = new Gauge('ts_active_queries');

// ============================================================================
// CONFIGURATION
// ============================================================================

const BASE_URL = __ENV.API_URL || 'http://localhost:3000/api';
const SCENARIO = __ENV.SCENARIO || 'load';

const scenarios = {
  smoke: {
    executor: 'constant-vus',
    vus: 5,
    duration: '2m',
  },
  load: {
    executor: 'ramping-vus',
    startVUs: 0,
    stages: [
      { duration: '1m', target: 20 },
      { duration: '3m', target: 20 },
      { duration: '1m', target: 40 },
      { duration: '3m', target: 40 },
      { duration: '1m', target: 80 },
      { duration: '3m', target: 80 },
      { duration: '1m', target: 0 },
    ],
    gracefulRampDown: '30s',
  },
  stress: {
    executor: 'ramping-vus',
    startVUs: 0,
    stages: [
      { duration: '1m', target: 80 },
      { duration: '2m', target: 80 },
      { duration: '1m', target: 150 },
      { duration: '2m', target: 150 },
      { duration: '1m', target: 250 },
      { duration: '3m', target: 250 },
      { duration: '1m', target: 0 },
    ],
    gracefulRampDown: '1m',
  },
  spike: {
    executor: 'ramping-vus',
    startVUs: 1,
    stages: [
      { duration: '30s', target: 20 },
      { duration: '15s', target: 300 },
      { duration: '1m', target: 300 },
      { duration: '15s', target: 20 },
      { duration: '30s', target: 20 },
      { duration: '15s', target: 0 },
    ],
    gracefulRampDown: '30s',
  },
  soak: {
    executor: 'constant-vus',
    vus: 40,
    duration: '30m',
  },
};

export const options = {
  scenarios: {
    timescale_test: scenarios[SCENARIO],
  },
  thresholds: {
    // Time-series query thresholds
    http_req_duration: ['p(95)<300', 'p(99)<600'],
    ts_time_range_query_duration_ms: ['p(95)<200', 'p(99)<400'],
    ts_latest_query_duration_ms: ['p(95)<50', 'p(99)<100'],
    ts_aggregate_query_duration_ms: ['p(95)<300', 'p(99)<600'],
    ts_continuous_agg_duration_ms: ['p(95)<150', 'p(99)<300'],
    ts_downsample_duration_ms: ['p(95)<200', 'p(99)<400'],
    ts_gapfill_duration_ms: ['p(95)<300', 'p(99)<600'],

    // Ingestion thresholds
    ts_single_insert_duration_ms: ['p(95)<50', 'p(99)<100'],
    ts_batch_insert_duration_ms: ['p(95)<500', 'p(99)<1000'],
    ts_high_cardinality_duration_ms: ['p(95)<400', 'p(99)<800'],

    // Analytics thresholds
    ts_moving_avg_duration_ms: ['p(95)<250', 'p(99)<500'],
    ts_percentile_duration_ms: ['p(95)<300', 'p(99)<600'],
    ts_anomaly_detection_duration_ms: ['p(95)<500', 'p(99)<1000'],

    // Error thresholds
    http_req_failed: ['rate<0.01'],
    ts_errors: ['rate<0.05'],
    ts_query_success_rate: ['rate>0.95'],
  },
  tags: {
    testType: 'timescale-performance',
    scenario: SCENARIO,
  },
};

// ============================================================================
// TEST DATA
// ============================================================================

const metricTypes = [
  'cpu_usage',
  'memory_usage',
  'network_io',
  'disk_io',
  'request_latency',
  'error_rate',
  'transaction_volume',
  'alert_count',
];

const entityTypes = ['server', 'service', 'endpoint', 'target', 'investigation'];
const timeIntervals = ['1m', '5m', '15m', '1h', '6h', '24h', '7d'];
const aggregateFunctions = ['avg', 'min', 'max', 'sum', 'count', 'first', 'last'];

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

function getHeaders(token) {
  return {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    'Authorization': `Bearer ${token}`,
    'X-Request-ID': `ts-test-${__VU}-${__ITER}-${Date.now()}`,
  };
}

function generateTimeSeriesData(count = 10) {
  const data = [];
  const now = Date.now();
  const metric = randomItem(metricTypes);
  const entityId = `${randomItem(entityTypes)}-${randomIntBetween(1, 100)}`;

  for (let i = 0; i < count; i++) {
    data.push({
      timestamp: new Date(now - i * 60000).toISOString(), // 1 minute intervals
      metric: metric,
      entityId: entityId,
      value: Math.random() * 100,
      tags: {
        environment: randomItem(['production', 'staging', 'development']),
        region: randomItem(['us-east', 'us-west', 'eu-west', 'ap-south']),
      },
    });
  }

  return data;
}

function getTimeRange(interval) {
  const now = new Date();
  let start;

  switch (interval) {
    case '1m':
      start = new Date(now - 60 * 1000);
      break;
    case '5m':
      start = new Date(now - 5 * 60 * 1000);
      break;
    case '15m':
      start = new Date(now - 15 * 60 * 1000);
      break;
    case '1h':
      start = new Date(now - 60 * 60 * 1000);
      break;
    case '6h':
      start = new Date(now - 6 * 60 * 60 * 1000);
      break;
    case '24h':
      start = new Date(now - 24 * 60 * 60 * 1000);
      break;
    case '7d':
      start = new Date(now - 7 * 24 * 60 * 60 * 1000);
      break;
    default:
      start = new Date(now - 60 * 60 * 1000);
  }

  return {
    start: start.toISOString(),
    end: now.toISOString(),
  };
}

// ============================================================================
// SETUP
// ============================================================================

export function setup() {
  console.log(`Starting TimescaleDB Performance Test - Scenario: ${SCENARIO}`);
  console.log(`API URL: ${BASE_URL}`);

  // Login to get auth token
  const loginRes = http.post(
    `${BASE_URL}/auth/login`,
    JSON.stringify({
      email: 'loadtest@apollo.com',
      password: 'LoadTest123!',
    }),
    { headers: { 'Content-Type': 'application/json' } }
  );

  let token = '';
  if (loginRes.status === 200) {
    try {
      const body = loginRes.json();
      token = body.token || body.accessToken || '';
    } catch (e) {
      console.error('Failed to parse login response');
    }
  }

  return {
    token: token,
    startTime: Date.now(),
    scenario: SCENARIO,
  };
}

// ============================================================================
// MAIN TEST FUNCTION
// ============================================================================

export default function(data) {
  const headers = getHeaders(data.token);

  activeQueries.add(1);

  // -------------------------------------------------------------------------
  // Test 1: Latest value query (most recent data point)
  // -------------------------------------------------------------------------
  group('TimescaleDB - Latest Value Query', () => {
    const metric = randomItem(metricTypes);
    const queryStart = Date.now();

    const res = http.get(
      `${BASE_URL}/analytics/metrics/${metric}/latest`,
      { headers, tags: { name: 'ts-latest-value' } }
    );

    const queryTime = Date.now() - queryStart;
    latestQueryDuration.add(queryTime);
    requestCounter.add(1);

    const success = check(res, {
      'latest value status 200 or 404': (r) => r.status === 200 || r.status === 404,
      'latest value time < 50ms': (r) => r.timings.duration < 50,
    });

    querySuccessRate.add(success);
    errorRate.add(res.status >= 500);
  });

  sleep(randomIntBetween(1, 2));

  // -------------------------------------------------------------------------
  // Test 2: Time range query
  // -------------------------------------------------------------------------
  group('TimescaleDB - Time Range Query', () => {
    const metric = randomItem(metricTypes);
    const interval = randomItem(timeIntervals);
    const { start, end } = getTimeRange(interval);
    const queryStart = Date.now();

    const res = http.get(
      `${BASE_URL}/analytics/metrics/${metric}?start=${start}&end=${end}&limit=1000`,
      { headers, tags: { name: 'ts-time-range' } }
    );

    const queryTime = Date.now() - queryStart;
    timeRangeQueryDuration.add(queryTime);
    requestCounter.add(1);

    const success = check(res, {
      'time range status 200 or 404': (r) => r.status === 200 || r.status === 404,
      'time range time < 200ms': (r) => r.timings.duration < 200,
    });

    querySuccessRate.add(success);
    errorRate.add(res.status >= 500);

    if (res.status === 200) {
      try {
        const body = res.json();
        const count = body.data?.length || body.length || 0;
        dataPointsProcessed.add(count);
      } catch (e) {
        // Ignore
      }
    }
  });

  sleep(randomIntBetween(1, 2));

  // -------------------------------------------------------------------------
  // Test 3: Aggregate query (time bucket)
  // -------------------------------------------------------------------------
  group('TimescaleDB - Aggregate Query', () => {
    const metric = randomItem(metricTypes);
    const interval = randomItem(['1h', '6h', '24h']);
    const { start, end } = getTimeRange(interval);
    const agg = randomItem(aggregateFunctions);
    const bucket = randomItem(['5m', '15m', '1h']);
    const queryStart = Date.now();

    const res = http.get(
      `${BASE_URL}/analytics/metrics/${metric}/aggregate?start=${start}&end=${end}&bucket=${bucket}&agg=${agg}`,
      { headers, tags: { name: 'ts-aggregate' } }
    );

    const queryTime = Date.now() - queryStart;
    aggregateQueryDuration.add(queryTime);
    requestCounter.add(1);

    const success = check(res, {
      'aggregate status 200 or 404': (r) => r.status === 200 || r.status === 404,
      'aggregate time < 300ms': (r) => r.timings.duration < 300,
    });

    querySuccessRate.add(success);
    errorRate.add(res.status >= 500);
  });

  sleep(randomIntBetween(1, 2));

  // -------------------------------------------------------------------------
  // Test 4: Continuous aggregate query (materialized view)
  // -------------------------------------------------------------------------
  group('TimescaleDB - Continuous Aggregate', () => {
    const metric = randomItem(metricTypes);
    const { start, end } = getTimeRange('24h');
    const queryStart = Date.now();

    const res = http.get(
      `${BASE_URL}/analytics/metrics/${metric}/hourly?start=${start}&end=${end}`,
      { headers, tags: { name: 'ts-continuous-agg' } }
    );

    const queryTime = Date.now() - queryStart;
    continuousAggQueryDuration.add(queryTime);
    requestCounter.add(1);

    const success = check(res, {
      'continuous agg status 200 or 404': (r) => r.status === 200 || r.status === 404,
      'continuous agg time < 150ms': (r) => r.timings.duration < 150,
    });

    querySuccessRate.add(success);
    errorRate.add(res.status >= 500);
  });

  sleep(randomIntBetween(1, 2));

  // -------------------------------------------------------------------------
  // Test 5: Single data point insert
  // -------------------------------------------------------------------------
  group('TimescaleDB - Single Insert', () => {
    const metric = randomItem(metricTypes);
    const queryStart = Date.now();

    const res = http.post(
      `${BASE_URL}/analytics/metrics`,
      JSON.stringify({
        timestamp: new Date().toISOString(),
        metric: metric,
        entityId: `entity-${__VU}`,
        value: Math.random() * 100,
        tags: {
          source: 'load-test',
          vu: __VU.toString(),
        },
      }),
      { headers, tags: { name: 'ts-single-insert' } }
    );

    const queryTime = Date.now() - queryStart;
    singleInsertDuration.add(queryTime);
    requestCounter.add(1);

    const success = check(res, {
      'single insert status 201 or 200 or 404': (r) => r.status === 201 || r.status === 200 || r.status === 404,
      'single insert time < 50ms': (r) => r.timings.duration < 50,
    });

    querySuccessRate.add(success);
    errorRate.add(res.status >= 500);

    if (res.status === 201 || res.status === 200) {
      dataPointsProcessed.add(1);
    }
  });

  sleep(randomIntBetween(1, 2));

  // -------------------------------------------------------------------------
  // Test 6: Batch insert
  // -------------------------------------------------------------------------
  group('TimescaleDB - Batch Insert', () => {
    const batchSize = randomIntBetween(50, 200);
    const batch = generateTimeSeriesData(batchSize);
    const queryStart = Date.now();

    const res = http.post(
      `${BASE_URL}/analytics/metrics/batch`,
      JSON.stringify({ data: batch }),
      { headers, tags: { name: 'ts-batch-insert' } }
    );

    const queryTime = Date.now() - queryStart;
    batchInsertDuration.add(queryTime);
    requestCounter.add(1);

    const success = check(res, {
      'batch insert status 201 or 200 or 404': (r) => r.status === 201 || r.status === 200 || r.status === 404,
      'batch insert time < 500ms': (r) => r.timings.duration < 500,
    });

    querySuccessRate.add(success);
    errorRate.add(res.status >= 500);

    if (res.status === 201 || res.status === 200) {
      dataPointsProcessed.add(batchSize);
    }
  });

  sleep(randomIntBetween(1, 2));

  // -------------------------------------------------------------------------
  // Test 7: Downsample query
  // -------------------------------------------------------------------------
  group('TimescaleDB - Downsample Query', () => {
    const metric = randomItem(metricTypes);
    const { start, end } = getTimeRange('7d');
    const queryStart = Date.now();

    const res = http.get(
      `${BASE_URL}/analytics/metrics/${metric}/downsample?start=${start}&end=${end}&bucket=1h`,
      { headers, tags: { name: 'ts-downsample' } }
    );

    const queryTime = Date.now() - queryStart;
    downsampleQueryDuration.add(queryTime);
    requestCounter.add(1);

    const success = check(res, {
      'downsample status 200 or 404': (r) => r.status === 200 || r.status === 404,
      'downsample time < 200ms': (r) => r.timings.duration < 200,
    });

    querySuccessRate.add(success);
    errorRate.add(res.status >= 500);
  });

  sleep(randomIntBetween(1, 2));

  // -------------------------------------------------------------------------
  // Test 8: Gap fill query
  // -------------------------------------------------------------------------
  group('TimescaleDB - Gap Fill Query', () => {
    const metric = randomItem(metricTypes);
    const { start, end } = getTimeRange('6h');
    const queryStart = Date.now();

    const res = http.get(
      `${BASE_URL}/analytics/metrics/${metric}/gapfill?start=${start}&end=${end}&bucket=15m&fill=linear`,
      { headers, tags: { name: 'ts-gapfill' } }
    );

    const queryTime = Date.now() - queryStart;
    gapFillQueryDuration.add(queryTime);
    requestCounter.add(1);

    const success = check(res, {
      'gapfill status 200 or 404': (r) => r.status === 200 || r.status === 404,
      'gapfill time < 300ms': (r) => r.timings.duration < 300,
    });

    querySuccessRate.add(success);
    errorRate.add(res.status >= 500);
  });

  sleep(randomIntBetween(1, 2));

  // -------------------------------------------------------------------------
  // Test 9: Moving average query
  // -------------------------------------------------------------------------
  group('TimescaleDB - Moving Average', () => {
    const metric = randomItem(metricTypes);
    const { start, end } = getTimeRange('24h');
    const queryStart = Date.now();

    const res = http.get(
      `${BASE_URL}/analytics/metrics/${metric}/moving-avg?start=${start}&end=${end}&window=12`,
      { headers, tags: { name: 'ts-moving-avg' } }
    );

    const queryTime = Date.now() - queryStart;
    movingAverageQueryDuration.add(queryTime);
    requestCounter.add(1);

    const success = check(res, {
      'moving avg status 200 or 404': (r) => r.status === 200 || r.status === 404,
      'moving avg time < 250ms': (r) => r.timings.duration < 250,
    });

    querySuccessRate.add(success);
    errorRate.add(res.status >= 500);
  });

  sleep(randomIntBetween(1, 2));

  // -------------------------------------------------------------------------
  // Test 10: Percentile query
  // -------------------------------------------------------------------------
  group('TimescaleDB - Percentile Query', () => {
    const metric = randomItem(metricTypes);
    const { start, end } = getTimeRange('24h');
    const percentile = randomItem([50, 75, 90, 95, 99]);
    const queryStart = Date.now();

    const res = http.get(
      `${BASE_URL}/analytics/metrics/${metric}/percentile?start=${start}&end=${end}&p=${percentile}`,
      { headers, tags: { name: 'ts-percentile' } }
    );

    const queryTime = Date.now() - queryStart;
    percentileQueryDuration.add(queryTime);
    requestCounter.add(1);

    const success = check(res, {
      'percentile status 200 or 404': (r) => r.status === 200 || r.status === 404,
      'percentile time < 300ms': (r) => r.timings.duration < 300,
    });

    querySuccessRate.add(success);
    errorRate.add(res.status >= 500);
  });

  sleep(randomIntBetween(1, 2));

  // -------------------------------------------------------------------------
  // Test 11: High cardinality query (many series)
  // -------------------------------------------------------------------------
  group('TimescaleDB - High Cardinality Query', () => {
    const { start, end } = getTimeRange('1h');
    const queryStart = Date.now();

    const res = http.get(
      `${BASE_URL}/analytics/metrics?start=${start}&end=${end}&limit=1000&groupBy=entityId`,
      { headers, tags: { name: 'ts-high-cardinality' } }
    );

    const queryTime = Date.now() - queryStart;
    highCardinalityQueryDuration.add(queryTime);
    requestCounter.add(1);

    const success = check(res, {
      'high cardinality status 200 or 404': (r) => r.status === 200 || r.status === 404,
      'high cardinality time < 400ms': (r) => r.timings.duration < 400,
    });

    querySuccessRate.add(success);
    errorRate.add(res.status >= 500);
  });

  sleep(randomIntBetween(1, 2));

  // -------------------------------------------------------------------------
  // Test 12: Anomaly detection query
  // -------------------------------------------------------------------------
  group('TimescaleDB - Anomaly Detection', () => {
    const metric = randomItem(metricTypes);
    const { start, end } = getTimeRange('24h');
    const queryStart = Date.now();

    const res = http.get(
      `${BASE_URL}/analytics/metrics/${metric}/anomalies?start=${start}&end=${end}&threshold=2.5`,
      { headers, tags: { name: 'ts-anomaly-detection' } }
    );

    const queryTime = Date.now() - queryStart;
    anomalyDetectionDuration.add(queryTime);
    requestCounter.add(1);

    const success = check(res, {
      'anomaly detection status 200 or 404': (r) => r.status === 200 || r.status === 404,
      'anomaly detection time < 500ms': (r) => r.timings.duration < 500,
    });

    querySuccessRate.add(success);
    errorRate.add(res.status >= 500);
  });

  sleep(randomIntBetween(1, 2));

  // -------------------------------------------------------------------------
  // Test 13: Multi-metric dashboard query
  // -------------------------------------------------------------------------
  group('TimescaleDB - Dashboard Query', () => {
    const { start, end } = getTimeRange('1h');
    const queryStart = Date.now();

    const res = http.post(
      `${BASE_URL}/analytics/dashboard`,
      JSON.stringify({
        metrics: metricTypes.slice(0, 5),
        start: start,
        end: end,
        bucket: '5m',
        aggregates: ['avg', 'max', 'min'],
      }),
      { headers, tags: { name: 'ts-dashboard' } }
    );

    const queryTime = Date.now() - queryStart;
    aggregateQueryDuration.add(queryTime);
    requestCounter.add(1);

    const success = check(res, {
      'dashboard status 200 or 404': (r) => r.status === 200 || r.status === 404,
      'dashboard time < 500ms': (r) => r.timings.duration < 500,
    });

    querySuccessRate.add(success);
    errorRate.add(res.status >= 500);
  });

  activeQueries.add(-1);

  // Think time
  sleep(randomIntBetween(2, 4));
}

// ============================================================================
// TEARDOWN
// ============================================================================

export function teardown(data) {
  const duration = (Date.now() - data.startTime) / 1000;
  console.log(`TimescaleDB Performance Test completed - Duration: ${duration.toFixed(2)}s`);
  console.log(`Scenario: ${data.scenario}`);
}

// ============================================================================
// CUSTOM SUMMARY
// ============================================================================

export function handleSummary(data) {
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');

  return {
    [`testing/performance-tests/results/timescale-perf-${SCENARIO}-${timestamp}.json`]: JSON.stringify(data, null, 2),
    stdout: generateTextSummary(data),
  };
}

function generateTextSummary(data) {
  const metrics = data.metrics;

  return `
================================================================================
               APOLLO PLATFORM - TIMESCALEDB PERFORMANCE TEST RESULTS
================================================================================
Scenario: ${SCENARIO}
Timestamp: ${new Date().toISOString()}

TIME-SERIES QUERY METRICS:
--------------------------------------------------------------------------------
Latest Value Query:
  - p50: ${metrics.ts_latest_query_duration_ms?.values?.['p(50)']?.toFixed(2) || 'N/A'} ms
  - p95: ${metrics.ts_latest_query_duration_ms?.values?.['p(95)']?.toFixed(2) || 'N/A'} ms
  - p99: ${metrics.ts_latest_query_duration_ms?.values?.['p(99)']?.toFixed(2) || 'N/A'} ms

Time Range Query:
  - p50: ${metrics.ts_time_range_query_duration_ms?.values?.['p(50)']?.toFixed(2) || 'N/A'} ms
  - p95: ${metrics.ts_time_range_query_duration_ms?.values?.['p(95)']?.toFixed(2) || 'N/A'} ms
  - p99: ${metrics.ts_time_range_query_duration_ms?.values?.['p(99)']?.toFixed(2) || 'N/A'} ms

Aggregate Query:
  - p50: ${metrics.ts_aggregate_query_duration_ms?.values?.['p(50)']?.toFixed(2) || 'N/A'} ms
  - p95: ${metrics.ts_aggregate_query_duration_ms?.values?.['p(95)']?.toFixed(2) || 'N/A'} ms
  - p99: ${metrics.ts_aggregate_query_duration_ms?.values?.['p(99)']?.toFixed(2) || 'N/A'} ms

Continuous Aggregate:
  - p50: ${metrics.ts_continuous_agg_duration_ms?.values?.['p(50)']?.toFixed(2) || 'N/A'} ms
  - p95: ${metrics.ts_continuous_agg_duration_ms?.values?.['p(95)']?.toFixed(2) || 'N/A'} ms
  - p99: ${metrics.ts_continuous_agg_duration_ms?.values?.['p(99)']?.toFixed(2) || 'N/A'} ms

INGESTION METRICS:
--------------------------------------------------------------------------------
Single Insert (p95): ${metrics.ts_single_insert_duration_ms?.values?.['p(95)']?.toFixed(2) || 'N/A'} ms
Batch Insert (p95): ${metrics.ts_batch_insert_duration_ms?.values?.['p(95)']?.toFixed(2) || 'N/A'} ms

ANALYTICS METRICS:
--------------------------------------------------------------------------------
Moving Average (p95): ${metrics.ts_moving_avg_duration_ms?.values?.['p(95)']?.toFixed(2) || 'N/A'} ms
Percentile Query (p95): ${metrics.ts_percentile_duration_ms?.values?.['p(95)']?.toFixed(2) || 'N/A'} ms
Anomaly Detection (p95): ${metrics.ts_anomaly_detection_duration_ms?.values?.['p(95)']?.toFixed(2) || 'N/A'} ms
High Cardinality (p95): ${metrics.ts_high_cardinality_duration_ms?.values?.['p(95)']?.toFixed(2) || 'N/A'} ms

RELIABILITY:
--------------------------------------------------------------------------------
Total Requests: ${metrics.ts_total_requests?.values?.count || 'N/A'}
Data Points Processed: ${metrics.ts_data_points_processed?.values?.count || 'N/A'}
Query Success Rate: ${((metrics.ts_query_success_rate?.values?.rate || 0) * 100).toFixed(2)}%
Error Rate: ${((metrics.ts_errors?.values?.rate || 0) * 100).toFixed(2)}%
HTTP Failure Rate: ${((metrics.http_req_failed?.values?.rate || 0) * 100).toFixed(2)}%

================================================================================
`;
}
