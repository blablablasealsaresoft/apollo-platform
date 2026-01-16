/**
 * Apollo Platform - Intelligence Service Load Test
 *
 * Tests intelligence gathering, analysis, and correlation endpoints.
 * Includes: OSINT queries, blockchain analysis, fusion engine, real-time alerts
 *
 * Run: k6 run intelligence-load.js
 * Run with env: k6 run -e API_URL=http://localhost:3000/api intelligence-load.js
 * Run specific scenario: k6 run --env SCENARIO=stress intelligence-load.js
 */

import http from 'k6/http';
import { check, group, sleep } from 'k6';
import { Rate, Trend, Counter, Gauge } from 'k6/metrics';
import { randomIntBetween, randomItem, randomString } from 'https://jslib.k6.io/k6-utils/1.4.0/index.js';

// ============================================================================
// CUSTOM METRICS
// ============================================================================

// Intelligence query metrics
const osintQueryDuration = new Trend('osint_query_duration_ms');
const blockchainQueryDuration = new Trend('blockchain_query_duration_ms');
const fusionQueryDuration = new Trend('fusion_query_duration_ms');
const correlationDuration = new Trend('correlation_duration_ms');
const threatAnalysisDuration = new Trend('threat_analysis_duration_ms');
const alertQueryDuration = new Trend('alert_query_duration_ms');
const reportGenerationDuration = new Trend('report_generation_duration_ms');

// Collection metrics
const intelCollectionDuration = new Trend('intel_collection_duration_ms');
const sourceQueryDuration = new Trend('source_query_duration_ms');
const entityResolutionDuration = new Trend('entity_resolution_duration_ms');

// General metrics
const querySuccessRate = new Rate('query_success_rate');
const errorRate = new Rate('errors');
const requestCounter = new Counter('total_requests');
const dataPointsCollected = new Counter('data_points_collected');
const activeQueries = new Gauge('active_queries');

// ============================================================================
// CONFIGURATION
// ============================================================================

const BASE_URL = __ENV.API_URL || 'http://localhost:3000/api';
const SCENARIO = __ENV.SCENARIO || 'load';

const scenarios = {
  smoke: {
    executor: 'constant-vus',
    vus: 3,
    duration: '2m',
  },
  load: {
    executor: 'ramping-vus',
    startVUs: 0,
    stages: [
      { duration: '2m', target: 25 },
      { duration: '5m', target: 25 },
      { duration: '2m', target: 50 },
      { duration: '5m', target: 50 },
      { duration: '2m', target: 75 },
      { duration: '5m', target: 75 },
      { duration: '2m', target: 0 },
    ],
    gracefulRampDown: '30s',
  },
  stress: {
    executor: 'ramping-vus',
    startVUs: 0,
    stages: [
      { duration: '2m', target: 75 },
      { duration: '3m', target: 75 },
      { duration: '2m', target: 150 },
      { duration: '3m', target: 150 },
      { duration: '2m', target: 250 },
      { duration: '5m', target: 250 },
      { duration: '2m', target: 0 },
    ],
    gracefulRampDown: '1m',
  },
  spike: {
    executor: 'ramping-vus',
    startVUs: 1,
    stages: [
      { duration: '1m', target: 15 },
      { duration: '30s', target: 300 },
      { duration: '2m', target: 300 },
      { duration: '30s', target: 15 },
      { duration: '1m', target: 15 },
      { duration: '30s', target: 0 },
    ],
    gracefulRampDown: '30s',
  },
  soak: {
    executor: 'constant-vus',
    vus: 40,
    duration: '1h',
  },
};

export const options = {
  scenarios: {
    intelligence_test: scenarios[SCENARIO],
  },
  thresholds: {
    // Response time thresholds
    http_req_duration: ['p(95)<500', 'p(99)<1000'],
    osint_query_duration_ms: ['p(95)<1000', 'p(99)<2000'],
    blockchain_query_duration_ms: ['p(95)<2000', 'p(99)<5000'],
    fusion_query_duration_ms: ['p(95)<1000', 'p(99)<2000'],
    correlation_duration_ms: ['p(95)<500', 'p(99)<1000'],
    threat_analysis_duration_ms: ['p(95)<1500', 'p(99)<3000'],
    alert_query_duration_ms: ['p(95)<300', 'p(99)<600'],
    report_generation_duration_ms: ['p(95)<3000', 'p(99)<5000'],

    // Collection thresholds
    intel_collection_duration_ms: ['p(95)<500', 'p(99)<1000'],
    source_query_duration_ms: ['p(95)<300', 'p(99)<600'],
    entity_resolution_duration_ms: ['p(95)<800', 'p(99)<1500'],

    // Error rate thresholds
    http_req_failed: ['rate<0.01'],
    errors: ['rate<0.05'],
    query_success_rate: ['rate>0.95'],
  },
  tags: {
    testType: 'intelligence-load',
    scenario: SCENARIO,
  },
};

// ============================================================================
// TEST DATA
// ============================================================================

// Sample wallet addresses for blockchain queries
const walletAddresses = {
  bitcoin: [
    '1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2',
    '3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy',
    'bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq',
    '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa',
    '385cR5DM96n1HvBDMzLHPYcw89fZAXULJP',
  ],
  ethereum: [
    '0x742d35Cc6634C0532925a3b844Bc9e7595f',
    '0x8ba1f109551bD432803012645Ac136ddd64DBA72',
    '0xdAC17F958D2ee523a2206206994597C13D831ec7',
    '0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599',
    '0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984',
  ],
};

// Sample entities for OSINT queries
const osintTargets = {
  emails: [
    'suspect1@example.com',
    'person.of.interest@testmail.com',
    'anonymous.user@protonmail.com',
  ],
  usernames: [
    'crypto_whale_2026',
    'shadow_trader',
    'anonymous_user_x',
    'digital_nomad_99',
  ],
  domains: [
    'suspicious-crypto.com',
    'offshore-holdings.io',
    'secure-transfers.net',
  ],
  ips: [
    '192.168.1.100',
    '10.0.0.50',
    '172.16.0.25',
  ],
};

// Intelligence sources
const intelligenceSources = [
  'OSINT',
  'SIGINT',
  'HUMINT',
  'FININT',
  'GEOINT',
  'BLOCKCHAIN',
  'DARKWEB',
  'SOCIAL_MEDIA',
];

const alertTypes = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
const intelTypes = ['RAW', 'PROCESSED', 'ANALYZED', 'VERIFIED'];

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

function getHeaders(token) {
  return {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    'Authorization': `Bearer ${token}`,
    'X-Request-ID': `intel-test-${__VU}-${__ITER}-${Date.now()}`,
  };
}

function generateIntelQuery() {
  const types = ['email', 'username', 'domain', 'ip', 'wallet'];
  const type = randomItem(types);

  switch (type) {
    case 'email':
      return { type: 'email', value: randomItem(osintTargets.emails) };
    case 'username':
      return { type: 'username', value: randomItem(osintTargets.usernames) };
    case 'domain':
      return { type: 'domain', value: randomItem(osintTargets.domains) };
    case 'ip':
      return { type: 'ip', value: randomItem(osintTargets.ips) };
    case 'wallet':
      const chain = randomItem(['bitcoin', 'ethereum']);
      return { type: 'wallet', value: randomItem(walletAddresses[chain]), chain };
    default:
      return { type: 'username', value: randomItem(osintTargets.usernames) };
  }
}

// ============================================================================
// SETUP
// ============================================================================

export function setup() {
  console.log(`Starting Intelligence Load Test - Scenario: ${SCENARIO}`);
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
  // Test 1: OSINT Query - Username Lookup
  // -------------------------------------------------------------------------
  group('Intelligence - OSINT Username Lookup', () => {
    const username = randomItem(osintTargets.usernames);
    const queryStart = Date.now();

    const res = http.post(
      `${BASE_URL}/intelligence/osint/username`,
      JSON.stringify({ username }),
      { headers, tags: { name: 'osint-username' } }
    );

    const queryTime = Date.now() - queryStart;
    osintQueryDuration.add(queryTime);
    requestCounter.add(1);

    const success = check(res, {
      'osint username status 200 or 202': (r) => r.status === 200 || r.status === 202,
      'osint username time < 1000ms': (r) => r.timings.duration < 1000,
    });

    querySuccessRate.add(success);
    errorRate.add(!success);

    if (res.status === 200) {
      try {
        const body = res.json();
        if (body.results && body.results.length) {
          dataPointsCollected.add(body.results.length);
        }
      } catch (e) {
        // Ignore
      }
    }
  });

  sleep(randomIntBetween(1, 3));

  // -------------------------------------------------------------------------
  // Test 2: OSINT Query - Email Intelligence
  // -------------------------------------------------------------------------
  group('Intelligence - OSINT Email Lookup', () => {
    const email = randomItem(osintTargets.emails);
    const queryStart = Date.now();

    const res = http.post(
      `${BASE_URL}/intelligence/osint/email`,
      JSON.stringify({ email }),
      { headers, tags: { name: 'osint-email' } }
    );

    const queryTime = Date.now() - queryStart;
    osintQueryDuration.add(queryTime);
    requestCounter.add(1);

    const success = check(res, {
      'osint email status 200 or 202': (r) => r.status === 200 || r.status === 202,
      'osint email time < 1000ms': (r) => r.timings.duration < 1000,
    });

    querySuccessRate.add(success);
    errorRate.add(!success);
  });

  sleep(randomIntBetween(1, 3));

  // -------------------------------------------------------------------------
  // Test 3: Blockchain Query - Wallet Analysis
  // -------------------------------------------------------------------------
  group('Intelligence - Blockchain Wallet Analysis', () => {
    const chain = randomItem(['bitcoin', 'ethereum']);
    const address = randomItem(walletAddresses[chain]);
    const queryStart = Date.now();

    const res = http.post(
      `${BASE_URL}/intelligence/blockchain/analyze`,
      JSON.stringify({
        address: address,
        chain: chain,
        depth: randomIntBetween(1, 3),
      }),
      { headers, tags: { name: 'blockchain-analysis' }, timeout: '30s' }
    );

    const queryTime = Date.now() - queryStart;
    blockchainQueryDuration.add(queryTime);
    requestCounter.add(1);

    const success = check(res, {
      'blockchain analysis status 200 or 202': (r) => r.status === 200 || r.status === 202,
      'blockchain analysis time < 2000ms': (r) => r.timings.duration < 2000,
    });

    querySuccessRate.add(success);
    errorRate.add(!success);
  });

  sleep(randomIntBetween(2, 4));

  // -------------------------------------------------------------------------
  // Test 4: Blockchain Transaction Trace
  // -------------------------------------------------------------------------
  group('Intelligence - Blockchain Transaction Trace', () => {
    const chain = randomItem(['bitcoin', 'ethereum']);
    const address = randomItem(walletAddresses[chain]);
    const queryStart = Date.now();

    const res = http.get(
      `${BASE_URL}/intelligence/blockchain/transactions?address=${address}&chain=${chain}&limit=50`,
      { headers, tags: { name: 'blockchain-transactions' }, timeout: '30s' }
    );

    const queryTime = Date.now() - queryStart;
    blockchainQueryDuration.add(queryTime);
    requestCounter.add(1);

    const success = check(res, {
      'blockchain tx status 200': (r) => r.status === 200,
      'blockchain tx time < 2000ms': (r) => r.timings.duration < 2000,
    });

    querySuccessRate.add(success);
    errorRate.add(!success);
  });

  sleep(randomIntBetween(2, 4));

  // -------------------------------------------------------------------------
  // Test 5: Intelligence Fusion Query
  // -------------------------------------------------------------------------
  group('Intelligence - Fusion Query', () => {
    const query = generateIntelQuery();
    const queryStart = Date.now();

    const res = http.post(
      `${BASE_URL}/intelligence/fusion/query`,
      JSON.stringify({
        queryType: query.type,
        value: query.value,
        sources: randomItem([
          ['OSINT', 'BLOCKCHAIN'],
          ['OSINT', 'SOCIAL_MEDIA'],
          ['BLOCKCHAIN', 'FININT'],
          intelligenceSources,
        ]),
        correlate: true,
      }),
      { headers, tags: { name: 'fusion-query' }, timeout: '30s' }
    );

    const queryTime = Date.now() - queryStart;
    fusionQueryDuration.add(queryTime);
    requestCounter.add(1);

    const success = check(res, {
      'fusion query status 200 or 202': (r) => r.status === 200 || r.status === 202,
      'fusion query time < 1000ms': (r) => r.timings.duration < 1000,
    });

    querySuccessRate.add(success);
    errorRate.add(!success);
  });

  sleep(randomIntBetween(2, 4));

  // -------------------------------------------------------------------------
  // Test 6: Entity Correlation
  // -------------------------------------------------------------------------
  group('Intelligence - Entity Correlation', () => {
    const queryStart = Date.now();

    const res = http.post(
      `${BASE_URL}/intelligence/correlate`,
      JSON.stringify({
        entities: [
          { type: 'email', value: randomItem(osintTargets.emails) },
          { type: 'username', value: randomItem(osintTargets.usernames) },
          { type: 'wallet', value: randomItem(walletAddresses.bitcoin) },
        ],
        threshold: 0.7,
      }),
      { headers, tags: { name: 'correlation' }, timeout: '30s' }
    );

    const queryTime = Date.now() - queryStart;
    correlationDuration.add(queryTime);
    requestCounter.add(1);

    const success = check(res, {
      'correlation status 200 or 202': (r) => r.status === 200 || r.status === 202,
      'correlation time < 500ms': (r) => r.timings.duration < 500,
    });

    querySuccessRate.add(success);
    errorRate.add(!success);
  });

  sleep(randomIntBetween(1, 3));

  // -------------------------------------------------------------------------
  // Test 7: Threat Analysis
  // -------------------------------------------------------------------------
  group('Intelligence - Threat Analysis', () => {
    const query = generateIntelQuery();
    const queryStart = Date.now();

    const res = http.post(
      `${BASE_URL}/intelligence/threat/analyze`,
      JSON.stringify({
        target: query.value,
        targetType: query.type,
        analysisDepth: randomItem(['basic', 'standard', 'deep']),
      }),
      { headers, tags: { name: 'threat-analysis' }, timeout: '30s' }
    );

    const queryTime = Date.now() - queryStart;
    threatAnalysisDuration.add(queryTime);
    requestCounter.add(1);

    const success = check(res, {
      'threat analysis status 200 or 202': (r) => r.status === 200 || r.status === 202,
      'threat analysis time < 1500ms': (r) => r.timings.duration < 1500,
    });

    querySuccessRate.add(success);
    errorRate.add(!success);
  });

  sleep(randomIntBetween(2, 4));

  // -------------------------------------------------------------------------
  // Test 8: Alert Queries
  // -------------------------------------------------------------------------
  group('Intelligence - Alert Queries', () => {
    const queryStart = Date.now();

    const res = http.get(
      `${BASE_URL}/intelligence/alerts?severity=${randomItem(alertTypes)}&page=1&limit=20`,
      { headers, tags: { name: 'alert-query' } }
    );

    const queryTime = Date.now() - queryStart;
    alertQueryDuration.add(queryTime);
    requestCounter.add(1);

    const success = check(res, {
      'alerts query status 200': (r) => r.status === 200,
      'alerts query time < 300ms': (r) => r.timings.duration < 300,
    });

    querySuccessRate.add(success);
    errorRate.add(!success);
  });

  sleep(randomIntBetween(1, 2));

  // -------------------------------------------------------------------------
  // Test 9: Intelligence Collection
  // -------------------------------------------------------------------------
  group('Intelligence - Collection Request', () => {
    const queryStart = Date.now();

    const res = http.post(
      `${BASE_URL}/intelligence/collect`,
      JSON.stringify({
        target: randomItem(osintTargets.usernames),
        sources: [randomItem(intelligenceSources), randomItem(intelligenceSources)],
        priority: randomItem(['LOW', 'MEDIUM', 'HIGH']),
        depth: randomIntBetween(1, 3),
      }),
      { headers, tags: { name: 'intel-collection' } }
    );

    const queryTime = Date.now() - queryStart;
    intelCollectionDuration.add(queryTime);
    requestCounter.add(1);

    const success = check(res, {
      'collection status 200 or 202': (r) => r.status === 200 || r.status === 202 || r.status === 201,
      'collection time < 500ms': (r) => r.timings.duration < 500,
    });

    querySuccessRate.add(success);
    errorRate.add(!success);
  });

  sleep(randomIntBetween(1, 2));

  // -------------------------------------------------------------------------
  // Test 10: Source Query
  // -------------------------------------------------------------------------
  group('Intelligence - Source Status', () => {
    const queryStart = Date.now();

    const res = http.get(
      `${BASE_URL}/intelligence/sources`,
      { headers, tags: { name: 'source-status' } }
    );

    const queryTime = Date.now() - queryStart;
    sourceQueryDuration.add(queryTime);
    requestCounter.add(1);

    check(res, {
      'sources status 200': (r) => r.status === 200,
      'sources time < 300ms': (r) => r.timings.duration < 300,
    });
  });

  sleep(randomIntBetween(1, 2));

  // -------------------------------------------------------------------------
  // Test 11: Entity Resolution
  // -------------------------------------------------------------------------
  group('Intelligence - Entity Resolution', () => {
    const queryStart = Date.now();

    const res = http.post(
      `${BASE_URL}/intelligence/entity/resolve`,
      JSON.stringify({
        entities: [
          { identifier: randomItem(osintTargets.emails), type: 'email' },
          { identifier: randomItem(osintTargets.usernames), type: 'username' },
        ],
        fuzzyMatch: true,
        threshold: 0.8,
      }),
      { headers, tags: { name: 'entity-resolution' } }
    );

    const queryTime = Date.now() - queryStart;
    entityResolutionDuration.add(queryTime);
    requestCounter.add(1);

    const success = check(res, {
      'entity resolution status 200': (r) => r.status === 200,
      'entity resolution time < 800ms': (r) => r.timings.duration < 800,
    });

    querySuccessRate.add(success);
    errorRate.add(!success);
  });

  sleep(randomIntBetween(1, 2));

  // -------------------------------------------------------------------------
  // Test 12: Report Generation (Async)
  // -------------------------------------------------------------------------
  group('Intelligence - Report Generation', () => {
    const queryStart = Date.now();

    const res = http.post(
      `${BASE_URL}/intelligence/reports/generate`,
      JSON.stringify({
        reportType: randomItem(['summary', 'detailed', 'executive']),
        target: randomItem(osintTargets.usernames),
        includeBlockchain: true,
        includeOSINT: true,
        format: randomItem(['pdf', 'json', 'html']),
      }),
      { headers, tags: { name: 'report-generation' }, timeout: '60s' }
    );

    const queryTime = Date.now() - queryStart;
    reportGenerationDuration.add(queryTime);
    requestCounter.add(1);

    const success = check(res, {
      'report generation status 200 or 202': (r) => r.status === 200 || r.status === 202 || r.status === 201,
      'report generation time < 3000ms': (r) => r.timings.duration < 3000,
    });

    querySuccessRate.add(success);
    errorRate.add(!success);
  });

  activeQueries.add(-1);

  // Think time
  sleep(randomIntBetween(3, 6));
}

// ============================================================================
// TEARDOWN
// ============================================================================

export function teardown(data) {
  const duration = (Date.now() - data.startTime) / 1000;
  console.log(`Intelligence Load Test completed - Duration: ${duration.toFixed(2)}s`);
  console.log(`Scenario: ${data.scenario}`);
}

// ============================================================================
// CUSTOM SUMMARY
// ============================================================================

export function handleSummary(data) {
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');

  return {
    [`testing/performance-tests/results/intelligence-load-${SCENARIO}-${timestamp}.json`]: JSON.stringify(data, null, 2),
    stdout: generateTextSummary(data),
  };
}

function generateTextSummary(data) {
  const metrics = data.metrics;

  return `
================================================================================
                 APOLLO PLATFORM - INTELLIGENCE LOAD TEST RESULTS
================================================================================
Scenario: ${SCENARIO}
Timestamp: ${new Date().toISOString()}

INTELLIGENCE QUERY METRICS:
--------------------------------------------------------------------------------
OSINT Query:
  - p50: ${metrics.osint_query_duration_ms?.values?.['p(50)']?.toFixed(2) || 'N/A'} ms
  - p95: ${metrics.osint_query_duration_ms?.values?.['p(95)']?.toFixed(2) || 'N/A'} ms
  - p99: ${metrics.osint_query_duration_ms?.values?.['p(99)']?.toFixed(2) || 'N/A'} ms

Blockchain Query:
  - p50: ${metrics.blockchain_query_duration_ms?.values?.['p(50)']?.toFixed(2) || 'N/A'} ms
  - p95: ${metrics.blockchain_query_duration_ms?.values?.['p(95)']?.toFixed(2) || 'N/A'} ms
  - p99: ${metrics.blockchain_query_duration_ms?.values?.['p(99)']?.toFixed(2) || 'N/A'} ms

Fusion Query:
  - p50: ${metrics.fusion_query_duration_ms?.values?.['p(50)']?.toFixed(2) || 'N/A'} ms
  - p95: ${metrics.fusion_query_duration_ms?.values?.['p(95)']?.toFixed(2) || 'N/A'} ms
  - p99: ${metrics.fusion_query_duration_ms?.values?.['p(99)']?.toFixed(2) || 'N/A'} ms

Correlation:
  - p50: ${metrics.correlation_duration_ms?.values?.['p(50)']?.toFixed(2) || 'N/A'} ms
  - p95: ${metrics.correlation_duration_ms?.values?.['p(95)']?.toFixed(2) || 'N/A'} ms
  - p99: ${metrics.correlation_duration_ms?.values?.['p(99)']?.toFixed(2) || 'N/A'} ms

Threat Analysis:
  - p50: ${metrics.threat_analysis_duration_ms?.values?.['p(50)']?.toFixed(2) || 'N/A'} ms
  - p95: ${metrics.threat_analysis_duration_ms?.values?.['p(95)']?.toFixed(2) || 'N/A'} ms
  - p99: ${metrics.threat_analysis_duration_ms?.values?.['p(99)']?.toFixed(2) || 'N/A'} ms

Report Generation:
  - p50: ${metrics.report_generation_duration_ms?.values?.['p(50)']?.toFixed(2) || 'N/A'} ms
  - p95: ${metrics.report_generation_duration_ms?.values?.['p(95)']?.toFixed(2) || 'N/A'} ms
  - p99: ${metrics.report_generation_duration_ms?.values?.['p(99)']?.toFixed(2) || 'N/A'} ms

RELIABILITY METRICS:
--------------------------------------------------------------------------------
Total Requests: ${metrics.total_requests?.values?.count || 'N/A'}
Data Points Collected: ${metrics.data_points_collected?.values?.count || 'N/A'}
Query Success Rate: ${((metrics.query_success_rate?.values?.rate || 0) * 100).toFixed(2)}%
Error Rate: ${((metrics.errors?.values?.rate || 0) * 100).toFixed(2)}%
HTTP Failure Rate: ${((metrics.http_req_failed?.values?.rate || 0) * 100).toFixed(2)}%

================================================================================
`;
}
