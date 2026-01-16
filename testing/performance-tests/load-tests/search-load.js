/**
 * Apollo Platform - Search Performance Load Test
 *
 * Tests search functionality across all searchable entities.
 * Includes: investigations, targets, evidence, intelligence, operations
 *
 * Run: k6 run search-load.js
 * Run with env: k6 run -e API_URL=http://localhost:3000/api search-load.js
 * Run specific scenario: k6 run --env SCENARIO=stress search-load.js
 */

import http from 'k6/http';
import { check, group, sleep } from 'k6';
import { Rate, Trend, Counter, Gauge } from 'k6/metrics';
import { randomIntBetween, randomItem } from 'https://jslib.k6.io/k6-utils/1.4.0/index.js';

// ============================================================================
// CUSTOM METRICS
// ============================================================================

// Search-specific metrics
const simpleSearchDuration = new Trend('simple_search_duration_ms');
const complexSearchDuration = new Trend('complex_search_duration_ms');
const fullTextSearchDuration = new Trend('fulltext_search_duration_ms');
const facetedSearchDuration = new Trend('faceted_search_duration_ms');
const autocompleteSearchDuration = new Trend('autocomplete_duration_ms');
const aggregationQueryDuration = new Trend('aggregation_duration_ms');

// Entity-specific search metrics
const investigationSearchDuration = new Trend('investigation_search_duration_ms');
const targetSearchDuration = new Trend('target_search_duration_ms');
const evidenceSearchDuration = new Trend('evidence_search_duration_ms');
const intelligenceSearchDuration = new Trend('intelligence_search_duration_ms');

// General metrics
const searchSuccessRate = new Rate('search_success_rate');
const errorRate = new Rate('errors');
const requestCounter = new Counter('total_requests');
const resultsCounter = new Counter('total_results_returned');
const activeSearches = new Gauge('active_searches');

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
      { duration: '2m', target: 30 },   // Ramp up
      { duration: '5m', target: 30 },   // Steady state
      { duration: '2m', target: 60 },   // Increase
      { duration: '5m', target: 60 },   // Steady state
      { duration: '2m', target: 100 },  // Peak load
      { duration: '5m', target: 100 },  // Steady state
      { duration: '2m', target: 0 },    // Ramp down
    ],
    gracefulRampDown: '30s',
  },
  stress: {
    executor: 'ramping-vus',
    startVUs: 0,
    stages: [
      { duration: '2m', target: 100 },
      { duration: '3m', target: 100 },
      { duration: '2m', target: 200 },
      { duration: '3m', target: 200 },
      { duration: '2m', target: 300 },
      { duration: '5m', target: 300 },
      { duration: '2m', target: 0 },
    ],
    gracefulRampDown: '1m',
  },
  spike: {
    executor: 'ramping-vus',
    startVUs: 1,
    stages: [
      { duration: '1m', target: 20 },
      { duration: '30s', target: 400 },
      { duration: '2m', target: 400 },
      { duration: '30s', target: 20 },
      { duration: '1m', target: 20 },
      { duration: '30s', target: 0 },
    ],
    gracefulRampDown: '30s',
  },
  soak: {
    executor: 'constant-vus',
    vus: 50,
    duration: '1h',
  },
};

export const options = {
  scenarios: {
    search_test: scenarios[SCENARIO],
  },
  thresholds: {
    // Response time thresholds (p95 < 200ms target)
    http_req_duration: ['p(95)<200', 'p(99)<500'],
    simple_search_duration_ms: ['p(95)<150', 'p(99)<300'],
    complex_search_duration_ms: ['p(95)<300', 'p(99)<600'],
    fulltext_search_duration_ms: ['p(95)<300', 'p(99)<500'],
    faceted_search_duration_ms: ['p(95)<250', 'p(99)<500'],
    autocomplete_duration_ms: ['p(95)<100', 'p(99)<200'],
    aggregation_duration_ms: ['p(95)<500', 'p(99)<1000'],

    // Entity-specific thresholds
    investigation_search_duration_ms: ['p(95)<200', 'p(99)<400'],
    target_search_duration_ms: ['p(95)<200', 'p(99)<400'],
    evidence_search_duration_ms: ['p(95)<250', 'p(99)<500'],
    intelligence_search_duration_ms: ['p(95)<300', 'p(99)<600'],

    // Error rate thresholds
    http_req_failed: ['rate<0.01'],
    errors: ['rate<0.05'],
    search_success_rate: ['rate>0.95'],
  },
  tags: {
    testType: 'search-load',
    scenario: SCENARIO,
  },
};

// ============================================================================
// TEST DATA
// ============================================================================

// Search terms for different scenarios
const searchTerms = {
  simple: [
    'investigation',
    'target',
    'evidence',
    'report',
    'analysis',
    'operation',
    'intelligence',
    'suspect',
  ],
  complex: [
    'high priority investigation crypto',
    'target location united states',
    'evidence chain of custody verified',
    'active operation surveillance',
    'intelligence report classified',
    'financial fraud cryptocurrency',
    'money laundering scheme',
    'international wire transfer',
  ],
  names: [
    'John',
    'Smith',
    'Johnson',
    'Williams',
    'Brown',
    'Jones',
    'Garcia',
    'Miller',
    'Davis',
    'Rodriguez',
  ],
  locations: [
    'New York',
    'Los Angeles',
    'Chicago',
    'Houston',
    'Phoenix',
    'London',
    'Dubai',
    'Singapore',
  ],
  caseNumbers: [
    'CASE-2026-',
    'INV-2026-',
    'OP-2026-',
    'INTEL-2026-',
  ],
};

const priorities = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
const statuses = ['ACTIVE', 'PENDING', 'CLOSED', 'ARCHIVED'];
const classifications = ['UNCLASSIFIED', 'CONFIDENTIAL', 'SECRET', 'TOP_SECRET'];
const targetTypes = ['PERSON', 'ORGANIZATION', 'VESSEL', 'VEHICLE', 'PROPERTY'];
const evidenceTypes = ['DOCUMENT', 'IMAGE', 'VIDEO', 'AUDIO', 'DIGITAL', 'PHYSICAL'];

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

function getHeaders(token) {
  return {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    'Authorization': `Bearer ${token}`,
    'X-Request-ID': `search-test-${__VU}-${__ITER}-${Date.now()}`,
  };
}

function generateSearchQuery() {
  const queryTypes = ['simple', 'complex', 'name', 'location', 'caseNumber'];
  const type = randomItem(queryTypes);

  switch (type) {
    case 'simple':
      return randomItem(searchTerms.simple);
    case 'complex':
      return randomItem(searchTerms.complex);
    case 'name':
      return randomItem(searchTerms.names);
    case 'location':
      return randomItem(searchTerms.locations);
    case 'caseNumber':
      return randomItem(searchTerms.caseNumbers) + randomIntBetween(1000, 9999);
    default:
      return randomItem(searchTerms.simple);
  }
}

// ============================================================================
// SETUP
// ============================================================================

export function setup() {
  console.log(`Starting Search Load Test - Scenario: ${SCENARIO}`);
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

  activeSearches.add(1);

  // -------------------------------------------------------------------------
  // Test 1: Simple Search - Investigations
  // -------------------------------------------------------------------------
  group('Search - Simple Investigation Search', () => {
    const searchTerm = generateSearchQuery();
    const searchStart = Date.now();

    const res = http.get(
      `${BASE_URL}/investigations?search=${encodeURIComponent(searchTerm)}&page=1&limit=20`,
      { headers, tags: { name: 'investigation-simple-search' } }
    );

    const searchTime = Date.now() - searchStart;
    simpleSearchDuration.add(searchTime);
    investigationSearchDuration.add(searchTime);
    requestCounter.add(1);

    const success = check(res, {
      'investigation search status 200': (r) => r.status === 200,
      'investigation search time < 200ms': (r) => r.timings.duration < 200,
      'investigation search has results': (r) => {
        try {
          const body = r.json();
          return body.data !== undefined || Array.isArray(body);
        } catch {
          return false;
        }
      },
    });

    searchSuccessRate.add(success);
    errorRate.add(!success);

    if (res.status === 200) {
      try {
        const body = res.json();
        const count = body.data?.length || body.length || 0;
        resultsCounter.add(count);
      } catch (e) {
        // Ignore parsing errors
      }
    }
  });

  sleep(randomIntBetween(1, 2));

  // -------------------------------------------------------------------------
  // Test 2: Faceted Search - Investigations with Filters
  // -------------------------------------------------------------------------
  group('Search - Faceted Investigation Search', () => {
    const priority = randomItem(priorities);
    const status = randomItem(statuses);
    const searchStart = Date.now();

    const res = http.get(
      `${BASE_URL}/investigations?priority=${priority}&status=${status}&page=1&limit=20`,
      { headers, tags: { name: 'investigation-faceted-search' } }
    );

    const searchTime = Date.now() - searchStart;
    facetedSearchDuration.add(searchTime);
    requestCounter.add(1);

    const success = check(res, {
      'faceted search status 200': (r) => r.status === 200,
      'faceted search time < 250ms': (r) => r.timings.duration < 250,
    });

    searchSuccessRate.add(success);
    errorRate.add(!success);
  });

  sleep(randomIntBetween(1, 2));

  // -------------------------------------------------------------------------
  // Test 3: Target Search
  // -------------------------------------------------------------------------
  group('Search - Target Search', () => {
    const searchTerm = randomItem(searchTerms.names);
    const targetType = randomItem(targetTypes);
    const searchStart = Date.now();

    const res = http.get(
      `${BASE_URL}/targets?search=${encodeURIComponent(searchTerm)}&type=${targetType}&page=1&limit=20`,
      { headers, tags: { name: 'target-search' } }
    );

    const searchTime = Date.now() - searchStart;
    targetSearchDuration.add(searchTime);
    requestCounter.add(1);

    const success = check(res, {
      'target search status 200': (r) => r.status === 200,
      'target search time < 200ms': (r) => r.timings.duration < 200,
    });

    searchSuccessRate.add(success);
    errorRate.add(!success);
  });

  sleep(randomIntBetween(1, 2));

  // -------------------------------------------------------------------------
  // Test 4: Evidence Search
  // -------------------------------------------------------------------------
  group('Search - Evidence Search', () => {
    const evidenceType = randomItem(evidenceTypes);
    const searchStart = Date.now();

    const res = http.get(
      `${BASE_URL}/evidence?type=${evidenceType}&page=1&limit=20`,
      { headers, tags: { name: 'evidence-search' } }
    );

    const searchTime = Date.now() - searchStart;
    evidenceSearchDuration.add(searchTime);
    requestCounter.add(1);

    const success = check(res, {
      'evidence search status 200': (r) => r.status === 200,
      'evidence search time < 250ms': (r) => r.timings.duration < 250,
    });

    searchSuccessRate.add(success);
    errorRate.add(!success);
  });

  sleep(randomIntBetween(1, 2));

  // -------------------------------------------------------------------------
  // Test 5: Intelligence Search
  // -------------------------------------------------------------------------
  group('Search - Intelligence Search', () => {
    const searchTerm = randomItem(searchTerms.complex);
    const classification = randomItem(classifications);
    const searchStart = Date.now();

    const res = http.get(
      `${BASE_URL}/intelligence?search=${encodeURIComponent(searchTerm)}&classification=${classification}&page=1&limit=20`,
      { headers, tags: { name: 'intelligence-search' } }
    );

    const searchTime = Date.now() - searchStart;
    intelligenceSearchDuration.add(searchTime);
    requestCounter.add(1);

    const success = check(res, {
      'intelligence search status 200': (r) => r.status === 200,
      'intelligence search time < 300ms': (r) => r.timings.duration < 300,
    });

    searchSuccessRate.add(success);
    errorRate.add(!success);
  });

  sleep(randomIntBetween(1, 2));

  // -------------------------------------------------------------------------
  // Test 6: Global Search (Cross-entity)
  // -------------------------------------------------------------------------
  group('Search - Global Search', () => {
    const searchTerm = generateSearchQuery();
    const searchStart = Date.now();

    const res = http.get(
      `${BASE_URL}/search?q=${encodeURIComponent(searchTerm)}&limit=50`,
      { headers, tags: { name: 'global-search' } }
    );

    const searchTime = Date.now() - searchStart;
    fullTextSearchDuration.add(searchTime);
    requestCounter.add(1);

    const success = check(res, {
      'global search status 200 or 404': (r) => r.status === 200 || r.status === 404,
      'global search time < 300ms': (r) => r.timings.duration < 300,
    });

    searchSuccessRate.add(success);
    errorRate.add(res.status !== 200 && res.status !== 404);
  });

  sleep(randomIntBetween(1, 2));

  // -------------------------------------------------------------------------
  // Test 7: Complex Search with Multiple Filters
  // -------------------------------------------------------------------------
  group('Search - Complex Multi-filter Search', () => {
    const params = new URLSearchParams({
      search: randomItem(searchTerms.simple),
      priority: randomItem(priorities),
      status: randomItem(statuses),
      classification: randomItem(classifications),
      sortBy: randomItem(['createdAt', 'updatedAt', 'priority']),
      sortOrder: randomItem(['asc', 'desc']),
      page: '1',
      limit: '20',
    });

    const searchStart = Date.now();
    const res = http.get(
      `${BASE_URL}/investigations?${params.toString()}`,
      { headers, tags: { name: 'complex-search' } }
    );

    const searchTime = Date.now() - searchStart;
    complexSearchDuration.add(searchTime);
    requestCounter.add(1);

    const success = check(res, {
      'complex search status 200': (r) => r.status === 200,
      'complex search time < 300ms': (r) => r.timings.duration < 300,
    });

    searchSuccessRate.add(success);
    errorRate.add(!success);
  });

  sleep(randomIntBetween(1, 2));

  // -------------------------------------------------------------------------
  // Test 8: Autocomplete Search
  // -------------------------------------------------------------------------
  group('Search - Autocomplete', () => {
    const prefix = randomItem(searchTerms.names).substring(0, 3);
    const searchStart = Date.now();

    const res = http.get(
      `${BASE_URL}/search/autocomplete?q=${encodeURIComponent(prefix)}&limit=10`,
      { headers, tags: { name: 'autocomplete' } }
    );

    const searchTime = Date.now() - searchStart;
    autocompleteSearchDuration.add(searchTime);
    requestCounter.add(1);

    check(res, {
      'autocomplete status 200 or 404': (r) => r.status === 200 || r.status === 404,
      'autocomplete time < 100ms': (r) => r.timings.duration < 100,
    });
  });

  sleep(randomIntBetween(1, 2));

  // -------------------------------------------------------------------------
  // Test 9: Date Range Search
  // -------------------------------------------------------------------------
  group('Search - Date Range Search', () => {
    const endDate = new Date().toISOString().split('T')[0];
    const startDate = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString().split('T')[0];

    const searchStart = Date.now();
    const res = http.get(
      `${BASE_URL}/investigations?startDate=${startDate}&endDate=${endDate}&page=1&limit=20`,
      { headers, tags: { name: 'date-range-search' } }
    );

    const searchTime = Date.now() - searchStart;
    facetedSearchDuration.add(searchTime);
    requestCounter.add(1);

    const success = check(res, {
      'date range search status 200': (r) => r.status === 200,
      'date range search time < 250ms': (r) => r.timings.duration < 250,
    });

    searchSuccessRate.add(success);
    errorRate.add(!success);
  });

  sleep(randomIntBetween(1, 2));

  // -------------------------------------------------------------------------
  // Test 10: Aggregation Query
  // -------------------------------------------------------------------------
  group('Search - Aggregation Query', () => {
    const searchStart = Date.now();
    const res = http.get(
      `${BASE_URL}/investigations/statistics`,
      { headers, tags: { name: 'aggregation' } }
    );

    const searchTime = Date.now() - searchStart;
    aggregationQueryDuration.add(searchTime);
    requestCounter.add(1);

    check(res, {
      'aggregation status 200': (r) => r.status === 200,
      'aggregation time < 500ms': (r) => r.timings.duration < 500,
    });
  });

  sleep(randomIntBetween(1, 2));

  // -------------------------------------------------------------------------
  // Test 11: Pagination Performance
  // -------------------------------------------------------------------------
  group('Search - Pagination', () => {
    const pages = [1, 5, 10, 20]; // Test different page numbers

    for (const page of pages) {
      const res = http.get(
        `${BASE_URL}/investigations?page=${page}&limit=20`,
        { headers, tags: { name: `pagination-page-${page}` } }
      );

      requestCounter.add(1);

      check(res, {
        [`page ${page} status 200`]: (r) => r.status === 200,
        [`page ${page} time < 200ms`]: (r) => r.timings.duration < 200,
      });
    }
  });

  activeSearches.add(-1);

  // Think time
  sleep(randomIntBetween(2, 4));
}

// ============================================================================
// TEARDOWN
// ============================================================================

export function teardown(data) {
  const duration = (Date.now() - data.startTime) / 1000;
  console.log(`Search Load Test completed - Duration: ${duration.toFixed(2)}s`);
  console.log(`Scenario: ${data.scenario}`);
}

// ============================================================================
// CUSTOM SUMMARY
// ============================================================================

export function handleSummary(data) {
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');

  return {
    [`testing/performance-tests/results/search-load-${SCENARIO}-${timestamp}.json`]: JSON.stringify(data, null, 2),
    stdout: generateTextSummary(data),
  };
}

function generateTextSummary(data) {
  const metrics = data.metrics;

  return `
================================================================================
                    APOLLO PLATFORM - SEARCH LOAD TEST RESULTS
================================================================================
Scenario: ${SCENARIO}
Timestamp: ${new Date().toISOString()}

SEARCH PERFORMANCE METRICS:
--------------------------------------------------------------------------------
Simple Search:
  - p50: ${metrics.simple_search_duration_ms?.values?.['p(50)']?.toFixed(2) || 'N/A'} ms
  - p95: ${metrics.simple_search_duration_ms?.values?.['p(95)']?.toFixed(2) || 'N/A'} ms
  - p99: ${metrics.simple_search_duration_ms?.values?.['p(99)']?.toFixed(2) || 'N/A'} ms

Complex Search:
  - p50: ${metrics.complex_search_duration_ms?.values?.['p(50)']?.toFixed(2) || 'N/A'} ms
  - p95: ${metrics.complex_search_duration_ms?.values?.['p(95)']?.toFixed(2) || 'N/A'} ms
  - p99: ${metrics.complex_search_duration_ms?.values?.['p(99)']?.toFixed(2) || 'N/A'} ms

Full-text Search:
  - p50: ${metrics.fulltext_search_duration_ms?.values?.['p(50)']?.toFixed(2) || 'N/A'} ms
  - p95: ${metrics.fulltext_search_duration_ms?.values?.['p(95)']?.toFixed(2) || 'N/A'} ms
  - p99: ${metrics.fulltext_search_duration_ms?.values?.['p(99)']?.toFixed(2) || 'N/A'} ms

Autocomplete:
  - p50: ${metrics.autocomplete_duration_ms?.values?.['p(50)']?.toFixed(2) || 'N/A'} ms
  - p95: ${metrics.autocomplete_duration_ms?.values?.['p(95)']?.toFixed(2) || 'N/A'} ms
  - p99: ${metrics.autocomplete_duration_ms?.values?.['p(99)']?.toFixed(2) || 'N/A'} ms

ENTITY-SPECIFIC METRICS:
--------------------------------------------------------------------------------
Investigation Search (p95): ${metrics.investigation_search_duration_ms?.values?.['p(95)']?.toFixed(2) || 'N/A'} ms
Target Search (p95): ${metrics.target_search_duration_ms?.values?.['p(95)']?.toFixed(2) || 'N/A'} ms
Evidence Search (p95): ${metrics.evidence_search_duration_ms?.values?.['p(95)']?.toFixed(2) || 'N/A'} ms
Intelligence Search (p95): ${metrics.intelligence_search_duration_ms?.values?.['p(95)']?.toFixed(2) || 'N/A'} ms

RELIABILITY METRICS:
--------------------------------------------------------------------------------
Total Requests: ${metrics.total_requests?.values?.count || 'N/A'}
Total Results Returned: ${metrics.total_results_returned?.values?.count || 'N/A'}
Search Success Rate: ${((metrics.search_success_rate?.values?.rate || 0) * 100).toFixed(2)}%
Error Rate: ${((metrics.errors?.values?.rate || 0) * 100).toFixed(2)}%
HTTP Failure Rate: ${((metrics.http_req_failed?.values?.rate || 0) * 100).toFixed(2)}%

================================================================================
`;
}
