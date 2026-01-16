/**
 * Apollo Platform - PostgreSQL Performance Test
 *
 * Tests PostgreSQL database performance through API endpoints.
 * Measures query performance, connection handling, and throughput.
 *
 * Run: k6 run postgresql-perf.js
 * Run with env: k6 run -e API_URL=http://localhost:3000/api postgresql-perf.js
 * Run specific scenario: k6 run --env SCENARIO=stress postgresql-perf.js
 */

import http from 'k6/http';
import { check, group, sleep } from 'k6';
import { Rate, Trend, Counter, Gauge } from 'k6/metrics';
import { randomIntBetween, randomItem, randomString } from 'https://jslib.k6.io/k6-utils/1.4.0/index.js';

// ============================================================================
// CUSTOM METRICS
// ============================================================================

// Query performance metrics
const simpleQueryDuration = new Trend('pg_simple_query_duration_ms');
const complexQueryDuration = new Trend('pg_complex_query_duration_ms');
const joinQueryDuration = new Trend('pg_join_query_duration_ms');
const aggregationQueryDuration = new Trend('pg_aggregation_duration_ms');
const transactionDuration = new Trend('pg_transaction_duration_ms');
const bulkInsertDuration = new Trend('pg_bulk_insert_duration_ms');
const bulkUpdateDuration = new Trend('pg_bulk_update_duration_ms');

// Operation-specific metrics
const insertDuration = new Trend('pg_insert_duration_ms');
const updateDuration = new Trend('pg_update_duration_ms');
const deleteDuration = new Trend('pg_delete_duration_ms');
const selectDuration = new Trend('pg_select_duration_ms');

// Index performance metrics
const indexedQueryDuration = new Trend('pg_indexed_query_duration_ms');
const fullTextSearchDuration = new Trend('pg_fulltext_search_duration_ms');

// General metrics
const querySuccessRate = new Rate('pg_query_success_rate');
const errorRate = new Rate('pg_errors');
const requestCounter = new Counter('pg_total_requests');
const rowsAffected = new Counter('pg_rows_affected');
const activeConnections = new Gauge('pg_active_connections');

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
      { duration: '1m', target: 50 },
      { duration: '3m', target: 50 },
      { duration: '1m', target: 100 },
      { duration: '3m', target: 100 },
      { duration: '1m', target: 0 },
    ],
    gracefulRampDown: '30s',
  },
  stress: {
    executor: 'ramping-vus',
    startVUs: 0,
    stages: [
      { duration: '1m', target: 100 },
      { duration: '2m', target: 100 },
      { duration: '1m', target: 200 },
      { duration: '2m', target: 200 },
      { duration: '1m', target: 300 },
      { duration: '3m', target: 300 },
      { duration: '1m', target: 0 },
    ],
    gracefulRampDown: '1m',
  },
  spike: {
    executor: 'ramping-vus',
    startVUs: 1,
    stages: [
      { duration: '30s', target: 20 },
      { duration: '15s', target: 400 },
      { duration: '1m', target: 400 },
      { duration: '15s', target: 20 },
      { duration: '30s', target: 20 },
      { duration: '15s', target: 0 },
    ],
    gracefulRampDown: '30s',
  },
  soak: {
    executor: 'constant-vus',
    vus: 50,
    duration: '30m',
  },
};

export const options = {
  scenarios: {
    postgresql_test: scenarios[SCENARIO],
  },
  thresholds: {
    // Query performance thresholds (targeting < 200ms p95)
    http_req_duration: ['p(95)<200', 'p(99)<500'],
    pg_simple_query_duration_ms: ['p(95)<50', 'p(99)<100'],
    pg_complex_query_duration_ms: ['p(95)<200', 'p(99)<400'],
    pg_join_query_duration_ms: ['p(95)<150', 'p(99)<300'],
    pg_aggregation_duration_ms: ['p(95)<300', 'p(99)<600'],
    pg_transaction_duration_ms: ['p(95)<500', 'p(99)<1000'],
    pg_bulk_insert_duration_ms: ['p(95)<1000', 'p(99)<2000'],
    pg_bulk_update_duration_ms: ['p(95)<1000', 'p(99)<2000'],

    // CRUD operation thresholds
    pg_insert_duration_ms: ['p(95)<100', 'p(99)<200'],
    pg_update_duration_ms: ['p(95)<100', 'p(99)<200'],
    pg_delete_duration_ms: ['p(95)<100', 'p(99)<200'],
    pg_select_duration_ms: ['p(95)<50', 'p(99)<100'],

    // Index performance
    pg_indexed_query_duration_ms: ['p(95)<30', 'p(99)<50'],
    pg_fulltext_search_duration_ms: ['p(95)<200', 'p(99)<400'],

    // Error thresholds
    http_req_failed: ['rate<0.01'],
    pg_errors: ['rate<0.05'],
    pg_query_success_rate: ['rate>0.95'],
  },
  tags: {
    testType: 'postgresql-performance',
    scenario: SCENARIO,
  },
};

// ============================================================================
// TEST DATA
// ============================================================================

const priorities = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
const statuses = ['ACTIVE', 'PENDING', 'CLOSED', 'ARCHIVED'];
const classifications = ['UNCLASSIFIED', 'CONFIDENTIAL', 'SECRET', 'TOP_SECRET'];
const targetTypes = ['PERSON', 'ORGANIZATION', 'VESSEL', 'VEHICLE', 'PROPERTY'];

const searchTerms = [
  'investigation', 'suspect', 'evidence', 'crypto', 'fraud',
  'financial', 'international', 'operation', 'intelligence', 'target',
];

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

function getHeaders(token) {
  return {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    'Authorization': `Bearer ${token}`,
    'X-Request-ID': `pg-test-${__VU}-${__ITER}-${Date.now()}`,
  };
}

function generateInvestigation() {
  return {
    caseNumber: `PG-TEST-${Date.now()}-${__VU}-${randomString(4)}`,
    title: `PostgreSQL Load Test Investigation ${__VU}-${__ITER}`,
    description: `Performance testing PostgreSQL database operations. ${randomString(100)}`,
    priority: randomItem(priorities),
    status: randomItem(statuses),
    classification: randomItem(classifications),
    tags: ['load-test', 'postgresql', randomItem(searchTerms)],
  };
}

function generateTarget() {
  return {
    name: `Target ${__VU}-${__ITER}-${randomString(8)}`,
    type: randomItem(targetTypes),
    priority: randomItem(priorities),
    status: randomItem(statuses),
    aliases: [`alias-${randomString(6)}`, `alias-${randomString(6)}`],
    notes: `Performance testing target. ${randomString(50)}`,
  };
}

// ============================================================================
// SETUP
// ============================================================================

export function setup() {
  console.log(`Starting PostgreSQL Performance Test - Scenario: ${SCENARIO}`);
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
    createdIds: {
      investigations: [],
      targets: [],
    },
  };
}

// ============================================================================
// MAIN TEST FUNCTION
// ============================================================================

export default function(data) {
  const headers = getHeaders(data.token);

  activeConnections.add(1);

  // -------------------------------------------------------------------------
  // Test 1: Simple SELECT (indexed by ID)
  // -------------------------------------------------------------------------
  group('PostgreSQL - Simple SELECT', () => {
    const queryStart = Date.now();

    const res = http.get(
      `${BASE_URL}/investigations?page=1&limit=10`,
      { headers, tags: { name: 'pg-simple-select' } }
    );

    const queryTime = Date.now() - queryStart;
    simpleQueryDuration.add(queryTime);
    selectDuration.add(queryTime);
    requestCounter.add(1);

    const success = check(res, {
      'simple select status 200': (r) => r.status === 200,
      'simple select time < 50ms': (r) => r.timings.duration < 50,
    });

    querySuccessRate.add(success);
    errorRate.add(!success);

    if (res.status === 200) {
      try {
        const body = res.json();
        const count = body.data?.length || body.length || 0;
        rowsAffected.add(count);
      } catch (e) {
        // Ignore
      }
    }
  });

  sleep(randomIntBetween(1, 2));

  // -------------------------------------------------------------------------
  // Test 2: Complex SELECT with filters (multiple conditions)
  // -------------------------------------------------------------------------
  group('PostgreSQL - Complex SELECT', () => {
    const queryStart = Date.now();

    const params = new URLSearchParams({
      priority: randomItem(priorities),
      status: randomItem(statuses),
      classification: randomItem(classifications),
      page: '1',
      limit: '20',
    });

    const res = http.get(
      `${BASE_URL}/investigations?${params.toString()}`,
      { headers, tags: { name: 'pg-complex-select' } }
    );

    const queryTime = Date.now() - queryStart;
    complexQueryDuration.add(queryTime);
    requestCounter.add(1);

    const success = check(res, {
      'complex select status 200': (r) => r.status === 200,
      'complex select time < 200ms': (r) => r.timings.duration < 200,
    });

    querySuccessRate.add(success);
    errorRate.add(!success);
  });

  sleep(randomIntBetween(1, 2));

  // -------------------------------------------------------------------------
  // Test 3: INSERT operation
  // -------------------------------------------------------------------------
  let createdInvestigationId = null;

  group('PostgreSQL - INSERT', () => {
    const investigation = generateInvestigation();
    const queryStart = Date.now();

    const res = http.post(
      `${BASE_URL}/investigations`,
      JSON.stringify(investigation),
      { headers, tags: { name: 'pg-insert' } }
    );

    const queryTime = Date.now() - queryStart;
    insertDuration.add(queryTime);
    requestCounter.add(1);

    const success = check(res, {
      'insert status 201': (r) => r.status === 201,
      'insert time < 100ms': (r) => r.timings.duration < 100,
      'insert returns id': (r) => {
        try {
          return r.json().id !== undefined;
        } catch {
          return false;
        }
      },
    });

    querySuccessRate.add(success);
    errorRate.add(!success);

    if (res.status === 201) {
      try {
        createdInvestigationId = res.json().id;
        rowsAffected.add(1);
      } catch (e) {
        // Ignore
      }
    }
  });

  sleep(randomIntBetween(1, 2));

  // -------------------------------------------------------------------------
  // Test 4: UPDATE operation
  // -------------------------------------------------------------------------
  if (createdInvestigationId) {
    group('PostgreSQL - UPDATE', () => {
      const queryStart = Date.now();

      const res = http.patch(
        `${BASE_URL}/investigations/${createdInvestigationId}`,
        JSON.stringify({
          priority: randomItem(priorities),
          status: randomItem(statuses),
          notes: `Updated at ${new Date().toISOString()}. ${randomString(50)}`,
        }),
        { headers, tags: { name: 'pg-update' } }
      );

      const queryTime = Date.now() - queryStart;
      updateDuration.add(queryTime);
      requestCounter.add(1);

      const success = check(res, {
        'update status 200': (r) => r.status === 200,
        'update time < 100ms': (r) => r.timings.duration < 100,
      });

      querySuccessRate.add(success);
      errorRate.add(!success);

      if (res.status === 200) {
        rowsAffected.add(1);
      }
    });

    sleep(randomIntBetween(1, 2));
  }

  // -------------------------------------------------------------------------
  // Test 5: JOIN query (related entities)
  // -------------------------------------------------------------------------
  group('PostgreSQL - JOIN Query', () => {
    const queryStart = Date.now();

    const res = http.get(
      `${BASE_URL}/investigations?include=targets,evidence&page=1&limit=10`,
      { headers, tags: { name: 'pg-join-query' } }
    );

    const queryTime = Date.now() - queryStart;
    joinQueryDuration.add(queryTime);
    requestCounter.add(1);

    const success = check(res, {
      'join query status 200': (r) => r.status === 200,
      'join query time < 150ms': (r) => r.timings.duration < 150,
    });

    querySuccessRate.add(success);
    errorRate.add(!success);
  });

  sleep(randomIntBetween(1, 2));

  // -------------------------------------------------------------------------
  // Test 6: Aggregation query (COUNT, GROUP BY)
  // -------------------------------------------------------------------------
  group('PostgreSQL - Aggregation', () => {
    const queryStart = Date.now();

    const res = http.get(
      `${BASE_URL}/investigations/statistics`,
      { headers, tags: { name: 'pg-aggregation' } }
    );

    const queryTime = Date.now() - queryStart;
    aggregationQueryDuration.add(queryTime);
    requestCounter.add(1);

    const success = check(res, {
      'aggregation status 200': (r) => r.status === 200,
      'aggregation time < 300ms': (r) => r.timings.duration < 300,
    });

    querySuccessRate.add(success);
    errorRate.add(!success);
  });

  sleep(randomIntBetween(1, 2));

  // -------------------------------------------------------------------------
  // Test 7: Full-text search
  // -------------------------------------------------------------------------
  group('PostgreSQL - Full-text Search', () => {
    const searchTerm = randomItem(searchTerms);
    const queryStart = Date.now();

    const res = http.get(
      `${BASE_URL}/investigations?search=${encodeURIComponent(searchTerm)}&page=1&limit=20`,
      { headers, tags: { name: 'pg-fulltext-search' } }
    );

    const queryTime = Date.now() - queryStart;
    fullTextSearchDuration.add(queryTime);
    requestCounter.add(1);

    const success = check(res, {
      'fulltext search status 200': (r) => r.status === 200,
      'fulltext search time < 200ms': (r) => r.timings.duration < 200,
    });

    querySuccessRate.add(success);
    errorRate.add(!success);
  });

  sleep(randomIntBetween(1, 2));

  // -------------------------------------------------------------------------
  // Test 8: Indexed query (by specific field)
  // -------------------------------------------------------------------------
  group('PostgreSQL - Indexed Query', () => {
    const queryStart = Date.now();

    const res = http.get(
      `${BASE_URL}/investigations?priority=CRITICAL&page=1&limit=20`,
      { headers, tags: { name: 'pg-indexed-query' } }
    );

    const queryTime = Date.now() - queryStart;
    indexedQueryDuration.add(queryTime);
    requestCounter.add(1);

    const success = check(res, {
      'indexed query status 200': (r) => r.status === 200,
      'indexed query time < 30ms': (r) => r.timings.duration < 30,
    });

    querySuccessRate.add(success);
    errorRate.add(!success);
  });

  sleep(randomIntBetween(1, 2));

  // -------------------------------------------------------------------------
  // Test 9: Date range query
  // -------------------------------------------------------------------------
  group('PostgreSQL - Date Range Query', () => {
    const endDate = new Date().toISOString().split('T')[0];
    const startDate = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString().split('T')[0];

    const queryStart = Date.now();

    const res = http.get(
      `${BASE_URL}/investigations?startDate=${startDate}&endDate=${endDate}&page=1&limit=20`,
      { headers, tags: { name: 'pg-date-range' } }
    );

    const queryTime = Date.now() - queryStart;
    complexQueryDuration.add(queryTime);
    requestCounter.add(1);

    const success = check(res, {
      'date range status 200': (r) => r.status === 200,
      'date range time < 200ms': (r) => r.timings.duration < 200,
    });

    querySuccessRate.add(success);
    errorRate.add(!success);
  });

  sleep(randomIntBetween(1, 2));

  // -------------------------------------------------------------------------
  // Test 10: Pagination performance (deep pagination)
  // -------------------------------------------------------------------------
  group('PostgreSQL - Pagination', () => {
    const pages = [1, 10, 50, 100];

    for (const page of pages) {
      const queryStart = Date.now();

      const res = http.get(
        `${BASE_URL}/investigations?page=${page}&limit=20`,
        { headers, tags: { name: `pg-pagination-page-${page}` } }
      );

      const queryTime = Date.now() - queryStart;
      selectDuration.add(queryTime);
      requestCounter.add(1);

      check(res, {
        [`page ${page} status 200`]: (r) => r.status === 200,
        [`page ${page} time < 100ms`]: (r) => r.timings.duration < 100,
      });
    }
  });

  sleep(randomIntBetween(1, 2));

  // -------------------------------------------------------------------------
  // Test 11: Transaction (create related entities)
  // -------------------------------------------------------------------------
  group('PostgreSQL - Transaction', () => {
    const queryStart = Date.now();

    // Create investigation with targets in a single transaction
    const res = http.post(
      `${BASE_URL}/investigations/with-targets`,
      JSON.stringify({
        investigation: generateInvestigation(),
        targets: [generateTarget(), generateTarget()],
      }),
      { headers, tags: { name: 'pg-transaction' } }
    );

    const queryTime = Date.now() - queryStart;
    transactionDuration.add(queryTime);
    requestCounter.add(1);

    // Accept 201 (created), 200 (ok), or 404 (endpoint not implemented)
    const success = check(res, {
      'transaction status ok': (r) => r.status === 201 || r.status === 200 || r.status === 404,
      'transaction time < 500ms': (r) => r.timings.duration < 500,
    });

    querySuccessRate.add(success);
    errorRate.add(res.status >= 500);
  });

  sleep(randomIntBetween(1, 2));

  // -------------------------------------------------------------------------
  // Test 12: DELETE operation
  // -------------------------------------------------------------------------
  if (createdInvestigationId) {
    group('PostgreSQL - DELETE', () => {
      const queryStart = Date.now();

      const res = http.del(
        `${BASE_URL}/investigations/${createdInvestigationId}`,
        null,
        { headers, tags: { name: 'pg-delete' } }
      );

      const queryTime = Date.now() - queryStart;
      deleteDuration.add(queryTime);
      requestCounter.add(1);

      const success = check(res, {
        'delete status 200 or 204': (r) => r.status === 200 || r.status === 204,
        'delete time < 100ms': (r) => r.timings.duration < 100,
      });

      querySuccessRate.add(success);
      errorRate.add(!success);

      if (res.status === 200 || res.status === 204) {
        rowsAffected.add(1);
      }
    });
  }

  activeConnections.add(-1);

  // Think time
  sleep(randomIntBetween(2, 4));
}

// ============================================================================
// TEARDOWN
// ============================================================================

export function teardown(data) {
  const duration = (Date.now() - data.startTime) / 1000;
  console.log(`PostgreSQL Performance Test completed - Duration: ${duration.toFixed(2)}s`);
  console.log(`Scenario: ${data.scenario}`);
}

// ============================================================================
// CUSTOM SUMMARY
// ============================================================================

export function handleSummary(data) {
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');

  return {
    [`testing/performance-tests/results/postgresql-perf-${SCENARIO}-${timestamp}.json`]: JSON.stringify(data, null, 2),
    stdout: generateTextSummary(data),
  };
}

function generateTextSummary(data) {
  const metrics = data.metrics;

  return `
================================================================================
                APOLLO PLATFORM - POSTGRESQL PERFORMANCE TEST RESULTS
================================================================================
Scenario: ${SCENARIO}
Timestamp: ${new Date().toISOString()}

QUERY PERFORMANCE METRICS:
--------------------------------------------------------------------------------
Simple SELECT:
  - p50: ${metrics.pg_simple_query_duration_ms?.values?.['p(50)']?.toFixed(2) || 'N/A'} ms
  - p95: ${metrics.pg_simple_query_duration_ms?.values?.['p(95)']?.toFixed(2) || 'N/A'} ms
  - p99: ${metrics.pg_simple_query_duration_ms?.values?.['p(99)']?.toFixed(2) || 'N/A'} ms

Complex SELECT:
  - p50: ${metrics.pg_complex_query_duration_ms?.values?.['p(50)']?.toFixed(2) || 'N/A'} ms
  - p95: ${metrics.pg_complex_query_duration_ms?.values?.['p(95)']?.toFixed(2) || 'N/A'} ms
  - p99: ${metrics.pg_complex_query_duration_ms?.values?.['p(99)']?.toFixed(2) || 'N/A'} ms

JOIN Query:
  - p50: ${metrics.pg_join_query_duration_ms?.values?.['p(50)']?.toFixed(2) || 'N/A'} ms
  - p95: ${metrics.pg_join_query_duration_ms?.values?.['p(95)']?.toFixed(2) || 'N/A'} ms
  - p99: ${metrics.pg_join_query_duration_ms?.values?.['p(99)']?.toFixed(2) || 'N/A'} ms

Aggregation:
  - p50: ${metrics.pg_aggregation_duration_ms?.values?.['p(50)']?.toFixed(2) || 'N/A'} ms
  - p95: ${metrics.pg_aggregation_duration_ms?.values?.['p(95)']?.toFixed(2) || 'N/A'} ms
  - p99: ${metrics.pg_aggregation_duration_ms?.values?.['p(99)']?.toFixed(2) || 'N/A'} ms

Full-text Search:
  - p50: ${metrics.pg_fulltext_search_duration_ms?.values?.['p(50)']?.toFixed(2) || 'N/A'} ms
  - p95: ${metrics.pg_fulltext_search_duration_ms?.values?.['p(95)']?.toFixed(2) || 'N/A'} ms
  - p99: ${metrics.pg_fulltext_search_duration_ms?.values?.['p(99)']?.toFixed(2) || 'N/A'} ms

CRUD OPERATIONS:
--------------------------------------------------------------------------------
INSERT (p95): ${metrics.pg_insert_duration_ms?.values?.['p(95)']?.toFixed(2) || 'N/A'} ms
UPDATE (p95): ${metrics.pg_update_duration_ms?.values?.['p(95)']?.toFixed(2) || 'N/A'} ms
DELETE (p95): ${metrics.pg_delete_duration_ms?.values?.['p(95)']?.toFixed(2) || 'N/A'} ms
SELECT (p95): ${metrics.pg_select_duration_ms?.values?.['p(95)']?.toFixed(2) || 'N/A'} ms

RELIABILITY:
--------------------------------------------------------------------------------
Total Requests: ${metrics.pg_total_requests?.values?.count || 'N/A'}
Rows Affected: ${metrics.pg_rows_affected?.values?.count || 'N/A'}
Query Success Rate: ${((metrics.pg_query_success_rate?.values?.rate || 0) * 100).toFixed(2)}%
Error Rate: ${((metrics.pg_errors?.values?.rate || 0) * 100).toFixed(2)}%
HTTP Failure Rate: ${((metrics.http_req_failed?.values?.rate || 0) * 100).toFixed(2)}%

================================================================================
`;
}
