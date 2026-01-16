/**
 * Apollo Platform - Concurrent Users Stress Test
 *
 * Tests system behavior under high concurrent user load.
 * Simulates realistic user sessions with authentication, browsing, and operations.
 *
 * Run: k6 run concurrent-users.js
 * Run with env: k6 run -e API_URL=http://localhost:3000/api concurrent-users.js
 * Run specific scenario: k6 run --env SCENARIO=peak concurrent-users.js
 */

import http from 'k6/http';
import { check, group, sleep } from 'k6';
import { Rate, Trend, Counter, Gauge } from 'k6/metrics';
import { randomIntBetween, randomItem, randomString } from 'https://jslib.k6.io/k6-utils/1.4.0/index.js';

// ============================================================================
// CUSTOM METRICS
// ============================================================================

// User session metrics
const sessionDuration = new Trend('cu_session_duration_ms');
const loginDuration = new Trend('cu_login_duration_ms');
const pageLoadDuration = new Trend('cu_page_load_duration_ms');
const actionDuration = new Trend('cu_action_duration_ms');

// Concurrency metrics
const concurrentUsers = new Gauge('cu_concurrent_users');
const peakConcurrentUsers = new Gauge('cu_peak_concurrent_users');
const activeSessions = new Gauge('cu_active_sessions');

// Performance metrics
const requestsPerUser = new Trend('cu_requests_per_user');
const throughput = new Counter('cu_throughput');
const responseTime = new Trend('cu_response_time_ms');

// Success/Failure metrics
const loginSuccessRate = new Rate('cu_login_success_rate');
const sessionSuccessRate = new Rate('cu_session_success_rate');
const actionSuccessRate = new Rate('cu_action_success_rate');
const errorRate = new Rate('cu_error_rate');

// Resource contention metrics
const lockWaitTime = new Trend('cu_lock_wait_time_ms');
const queueTime = new Trend('cu_queue_time_ms');

// ============================================================================
// CONFIGURATION
// ============================================================================

const BASE_URL = __ENV.API_URL || 'http://localhost:3000/api';
const SCENARIO = __ENV.SCENARIO || 'standard';

const scenarios = {
  // Smoke test: Quick validation with few users
  smoke: {
    executor: 'constant-vus',
    vus: 5,
    duration: '2m',
  },
  // Standard load: 50-100 concurrent users
  standard: {
    executor: 'ramping-vus',
    startVUs: 0,
    stages: [
      { duration: '1m', target: 25 },    // Ramp up
      { duration: '3m', target: 50 },    // Normal load
      { duration: '2m', target: 75 },    // Increase
      { duration: '3m', target: 100 },   // Full load
      { duration: '2m', target: 100 },   // Sustain
      { duration: '2m', target: 50 },    // Decrease
      { duration: '1m', target: 0 },     // Ramp down
    ],
    gracefulRampDown: '30s',
  },
  // Peak load: 200+ concurrent users
  peak: {
    executor: 'ramping-vus',
    startVUs: 0,
    stages: [
      { duration: '1m', target: 50 },
      { duration: '2m', target: 100 },
      { duration: '2m', target: 150 },
      { duration: '2m', target: 200 },
      { duration: '3m', target: 250 },   // Peak
      { duration: '5m', target: 250 },   // Sustain peak
      { duration: '2m', target: 150 },
      { duration: '2m', target: 50 },
      { duration: '1m', target: 0 },
    ],
    gracefulRampDown: '1m',
  },
  // Burst: Sudden influx of users
  burst: {
    executor: 'ramping-vus',
    startVUs: 10,
    stages: [
      { duration: '1m', target: 20 },    // Normal operation
      { duration: '30s', target: 300 },  // Sudden burst
      { duration: '2m', target: 300 },   // Handle burst
      { duration: '30s', target: 50 },   // Users leave
      { duration: '1m', target: 50 },    // Recovery
      { duration: '30s', target: 200 },  // Second burst
      { duration: '2m', target: 200 },   // Handle
      { duration: '1m', target: 50 },    // Normal
      { duration: '30s', target: 0 },    // End
    ],
    gracefulRampDown: '30s',
  },
  // Sustained: Long duration with steady users
  sustained: {
    executor: 'constant-vus',
    vus: 100,
    duration: '30m',
  },
  // Gradual increase to find breaking point
  breaking: {
    executor: 'ramping-vus',
    startVUs: 0,
    stages: [
      { duration: '2m', target: 100 },
      { duration: '2m', target: 200 },
      { duration: '2m', target: 300 },
      { duration: '2m', target: 400 },
      { duration: '2m', target: 500 },
      { duration: '2m', target: 600 },
      { duration: '2m', target: 700 },
      { duration: '2m', target: 800 },
      { duration: '2m', target: 900 },
      { duration: '3m', target: 1000 },  // Target 1000 concurrent
      { duration: '2m', target: 500 },   // Recovery test
      { duration: '1m', target: 0 },
    ],
    gracefulRampDown: '2m',
  },
};

export const options = {
  scenarios: {
    concurrent_users: scenarios[SCENARIO],
  },
  thresholds: {
    // Response time targets
    http_req_duration: ['p(95)<500', 'p(99)<1000'],
    cu_response_time_ms: ['p(95)<300', 'p(99)<600'],
    cu_login_duration_ms: ['p(95)<500', 'p(99)<1000'],
    cu_page_load_duration_ms: ['p(95)<400', 'p(99)<800'],
    cu_action_duration_ms: ['p(95)<300', 'p(99)<600'],

    // Success rate targets
    http_req_failed: ['rate<0.01'],
    cu_login_success_rate: ['rate>0.95'],
    cu_session_success_rate: ['rate>0.95'],
    cu_action_success_rate: ['rate>0.95'],
    cu_error_rate: ['rate<0.05'],
  },
  tags: {
    testType: 'concurrent-users',
    scenario: SCENARIO,
  },
};

// ============================================================================
// TEST DATA
// ============================================================================

// User personas with different behavior patterns
const userPersonas = [
  {
    name: 'analyst',
    weight: 40,
    actions: ['view_dashboard', 'search', 'view_investigation', 'view_target', 'view_intelligence'],
    thinkTime: { min: 5, max: 15 },
    sessionLength: { min: 10, max: 30 }, // actions per session
  },
  {
    name: 'investigator',
    weight: 30,
    actions: ['view_dashboard', 'create_investigation', 'update_investigation', 'add_evidence', 'search', 'view_target'],
    thinkTime: { min: 3, max: 10 },
    sessionLength: { min: 15, max: 40 },
  },
  {
    name: 'manager',
    weight: 15,
    actions: ['view_dashboard', 'view_statistics', 'view_operations', 'search'],
    thinkTime: { min: 10, max: 30 },
    sessionLength: { min: 5, max: 15 },
  },
  {
    name: 'admin',
    weight: 10,
    actions: ['view_dashboard', 'view_users', 'view_audit_log', 'view_statistics'],
    thinkTime: { min: 5, max: 20 },
    sessionLength: { min: 5, max: 20 },
  },
  {
    name: 'api_client',
    weight: 5,
    actions: ['api_query', 'api_search', 'api_create'],
    thinkTime: { min: 1, max: 3 },
    sessionLength: { min: 20, max: 50 },
  },
];

// Test user pool
const testUsers = [];
for (let i = 1; i <= 100; i++) {
  testUsers.push({
    email: `loadtest${i}@apollo.com`,
    password: 'LoadTest123!',
  });
}

const priorities = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
const statuses = ['ACTIVE', 'PENDING', 'IN_PROGRESS', 'COMPLETED'];
const searchTerms = ['investigation', 'target', 'crypto', 'fraud', 'financial', 'international'];

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

function selectPersona() {
  const totalWeight = userPersonas.reduce((sum, p) => sum + p.weight, 0);
  let random = Math.random() * totalWeight;

  for (const persona of userPersonas) {
    random -= persona.weight;
    if (random <= 0) {
      return persona;
    }
  }
  return userPersonas[0];
}

function getRandomUser() {
  return testUsers[randomIntBetween(0, testUsers.length - 1)];
}

function getHeaders(token) {
  return {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    'Authorization': `Bearer ${token}`,
    'X-Request-ID': `cu-${__VU}-${__ITER}-${Date.now()}`,
    'X-User-Agent': 'Apollo-LoadTest/1.0',
  };
}

function executeAction(action, headers) {
  const actionStart = Date.now();
  let res;
  let success = false;

  switch (action) {
    case 'view_dashboard':
      res = http.get(`${BASE_URL}/dashboard`, { headers, tags: { name: 'dashboard' } });
      success = res.status === 200;
      break;

    case 'view_statistics':
      res = http.get(`${BASE_URL}/investigations/statistics`, { headers, tags: { name: 'statistics' } });
      success = res.status === 200;
      break;

    case 'search':
      const searchTerm = randomItem(searchTerms);
      res = http.get(`${BASE_URL}/search?q=${encodeURIComponent(searchTerm)}&limit=20`, { headers, tags: { name: 'search' } });
      success = res.status === 200 || res.status === 404;
      break;

    case 'view_investigation':
      res = http.get(`${BASE_URL}/investigations?page=1&limit=10`, { headers, tags: { name: 'investigations-list' } });
      success = res.status === 200;
      break;

    case 'view_target':
      res = http.get(`${BASE_URL}/targets?page=1&limit=10`, { headers, tags: { name: 'targets-list' } });
      success = res.status === 200;
      break;

    case 'view_intelligence':
      res = http.get(`${BASE_URL}/intelligence?page=1&limit=10`, { headers, tags: { name: 'intelligence-list' } });
      success = res.status === 200;
      break;

    case 'view_operations':
      res = http.get(`${BASE_URL}/operations?page=1&limit=10`, { headers, tags: { name: 'operations-list' } });
      success = res.status === 200;
      break;

    case 'view_users':
      res = http.get(`${BASE_URL}/users?page=1&limit=20`, { headers, tags: { name: 'users-list' } });
      success = res.status === 200 || res.status === 403;
      break;

    case 'view_audit_log':
      res = http.get(`${BASE_URL}/audit-log?page=1&limit=50`, { headers, tags: { name: 'audit-log' } });
      success = res.status === 200 || res.status === 403 || res.status === 404;
      break;

    case 'create_investigation':
      res = http.post(
        `${BASE_URL}/investigations`,
        JSON.stringify({
          caseNumber: `CU-${Date.now()}-${__VU}`,
          title: `Concurrent User Test ${__VU}`,
          description: `Test investigation created during concurrent user stress test. ${randomString(50)}`,
          priority: randomItem(priorities),
          status: randomItem(statuses),
        }),
        { headers, tags: { name: 'create-investigation' } }
      );
      success = res.status === 201;
      break;

    case 'update_investigation':
      // Get an investigation first
      const listRes = http.get(`${BASE_URL}/investigations?page=1&limit=5`, { headers, tags: { name: 'get-for-update' } });
      if (listRes.status === 200) {
        try {
          const data = listRes.json();
          const investigations = data.data || data;
          if (investigations && investigations.length > 0) {
            const inv = randomItem(investigations);
            res = http.patch(
              `${BASE_URL}/investigations/${inv.id}`,
              JSON.stringify({
                notes: `Updated at ${new Date().toISOString()} by VU ${__VU}`,
                priority: randomItem(priorities),
              }),
              { headers, tags: { name: 'update-investigation' } }
            );
            success = res.status === 200;
          }
        } catch (e) {
          success = true; // Consider success if no investigations to update
        }
      }
      break;

    case 'add_evidence':
      res = http.post(
        `${BASE_URL}/evidence`,
        JSON.stringify({
          type: randomItem(['DOCUMENT', 'IMAGE', 'DIGITAL']),
          title: `Evidence from VU ${__VU}`,
          description: `Evidence added during concurrent user test. ${randomString(30)}`,
        }),
        { headers, tags: { name: 'add-evidence' } }
      );
      success = res.status === 201 || res.status === 400 || res.status === 404;
      break;

    case 'api_query':
      res = http.get(`${BASE_URL}/investigations?page=${randomIntBetween(1, 10)}&limit=50`, { headers, tags: { name: 'api-query' } });
      success = res.status === 200;
      break;

    case 'api_search':
      const apiSearchTerm = randomItem(searchTerms);
      res = http.get(`${BASE_URL}/investigations?search=${encodeURIComponent(apiSearchTerm)}`, { headers, tags: { name: 'api-search' } });
      success = res.status === 200;
      break;

    case 'api_create':
      res = http.post(
        `${BASE_URL}/investigations`,
        JSON.stringify({
          caseNumber: `API-${Date.now()}-${__VU}`,
          title: `API Client Test ${__VU}`,
          priority: randomItem(priorities),
        }),
        { headers, tags: { name: 'api-create' } }
      );
      success = res.status === 201;
      break;

    default:
      res = http.get(`${BASE_URL}/health`, { headers, tags: { name: 'health' } });
      success = res.status === 200;
  }

  const actionTime = Date.now() - actionStart;
  actionDuration.add(actionTime);
  responseTime.add(res ? res.timings.duration : actionTime);
  actionSuccessRate.add(success);
  errorRate.add(!success);
  throughput.add(1);

  return { success, response: res, duration: actionTime };
}

// ============================================================================
// SETUP
// ============================================================================

export function setup() {
  console.log(`Starting Concurrent Users Test - Scenario: ${SCENARIO}`);
  console.log(`API URL: ${BASE_URL}`);

  // Health check
  const healthRes = http.get(`${BASE_URL}/health`, { timeout: '10s' });
  if (healthRes.status !== 200) {
    console.warn('API health check failed');
  }

  return {
    startTime: Date.now(),
    scenario: SCENARIO,
    peakUsers: 0,
  };
}

// ============================================================================
// MAIN TEST FUNCTION
// ============================================================================

export default function(data) {
  const sessionStart = Date.now();
  const persona = selectPersona();
  const user = getRandomUser();
  let token = null;
  let requestCount = 0;

  // Track concurrent users
  concurrentUsers.add(1);
  activeSessions.add(1);

  // -------------------------------------------------------------------------
  // Login Phase
  // -------------------------------------------------------------------------
  group(`${persona.name} - Login`, () => {
    const loginStart = Date.now();

    const loginRes = http.post(
      `${BASE_URL}/auth/login`,
      JSON.stringify({
        email: user.email,
        password: user.password,
      }),
      { headers: { 'Content-Type': 'application/json' }, tags: { name: 'login' } }
    );

    const loginTime = Date.now() - loginStart;
    loginDuration.add(loginTime);
    requestCount++;

    const loginSuccess = loginRes.status === 200;
    loginSuccessRate.add(loginSuccess);

    if (loginSuccess) {
      try {
        const body = loginRes.json();
        token = body.token || body.accessToken;
      } catch (e) {
        console.error(`VU ${__VU}: Failed to parse login response`);
      }
    }
  });

  // Skip session if login failed
  if (!token) {
    concurrentUsers.add(-1);
    activeSessions.add(-1);
    sessionSuccessRate.add(0);
    sleep(randomIntBetween(5, 10));
    return;
  }

  const headers = getHeaders(token);

  // Initial page load (dashboard)
  group(`${persona.name} - Initial Load`, () => {
    const loadStart = Date.now();
    const dashRes = http.get(`${BASE_URL}/dashboard`, { headers, tags: { name: 'initial-dashboard' } });
    pageLoadDuration.add(Date.now() - loadStart);
    requestCount++;
  });

  sleep(randomIntBetween(1, 3));

  // -------------------------------------------------------------------------
  // User Session - Execute Actions Based on Persona
  // -------------------------------------------------------------------------
  const actionsToPerform = randomIntBetween(persona.sessionLength.min, persona.sessionLength.max);
  let sessionSuccess = true;

  for (let i = 0; i < actionsToPerform; i++) {
    const action = randomItem(persona.actions);

    group(`${persona.name} - ${action}`, () => {
      const result = executeAction(action, headers);
      requestCount++;

      if (!result.success) {
        sessionSuccess = false;
      }
    });

    // Think time between actions (persona-specific)
    const thinkTime = randomIntBetween(persona.thinkTime.min, persona.thinkTime.max);
    sleep(thinkTime / 10); // Convert to seconds, scaled down for testing
  }

  // -------------------------------------------------------------------------
  // Logout Phase
  // -------------------------------------------------------------------------
  group(`${persona.name} - Logout`, () => {
    const logoutRes = http.post(
      `${BASE_URL}/auth/logout`,
      null,
      { headers, tags: { name: 'logout' } }
    );
    requestCount++;

    check(logoutRes, {
      'logout successful': (r) => r.status === 200 || r.status === 204,
    });
  });

  // Record session metrics
  const sessionTime = Date.now() - sessionStart;
  sessionDuration.add(sessionTime);
  requestsPerUser.add(requestCount);
  sessionSuccessRate.add(sessionSuccess);

  // Update concurrent users
  concurrentUsers.add(-1);
  activeSessions.add(-1);

  // Brief pause before next iteration
  sleep(randomIntBetween(1, 5));
}

// ============================================================================
// TEARDOWN
// ============================================================================

export function teardown(data) {
  const duration = (Date.now() - data.startTime) / 1000;
  console.log(`Concurrent Users Test completed - Duration: ${duration.toFixed(2)}s`);
  console.log(`Scenario: ${data.scenario}`);
}

// ============================================================================
// CUSTOM SUMMARY
// ============================================================================

export function handleSummary(data) {
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');

  return {
    [`testing/performance-tests/results/concurrent-users-${SCENARIO}-${timestamp}.json`]: JSON.stringify(data, null, 2),
    stdout: generateTextSummary(data),
  };
}

function generateTextSummary(data) {
  const metrics = data.metrics;

  return `
================================================================================
                APOLLO PLATFORM - CONCURRENT USERS TEST RESULTS
================================================================================
Scenario: ${SCENARIO}
Timestamp: ${new Date().toISOString()}

SESSION METRICS:
--------------------------------------------------------------------------------
Session Duration:
  - p50: ${metrics.cu_session_duration_ms?.values?.['p(50)']?.toFixed(2) || 'N/A'} ms
  - p95: ${metrics.cu_session_duration_ms?.values?.['p(95)']?.toFixed(2) || 'N/A'} ms
  - p99: ${metrics.cu_session_duration_ms?.values?.['p(99)']?.toFixed(2) || 'N/A'} ms

Login Duration:
  - p50: ${metrics.cu_login_duration_ms?.values?.['p(50)']?.toFixed(2) || 'N/A'} ms
  - p95: ${metrics.cu_login_duration_ms?.values?.['p(95)']?.toFixed(2) || 'N/A'} ms
  - p99: ${metrics.cu_login_duration_ms?.values?.['p(99)']?.toFixed(2) || 'N/A'} ms

Page Load Duration:
  - p50: ${metrics.cu_page_load_duration_ms?.values?.['p(50)']?.toFixed(2) || 'N/A'} ms
  - p95: ${metrics.cu_page_load_duration_ms?.values?.['p(95)']?.toFixed(2) || 'N/A'} ms
  - p99: ${metrics.cu_page_load_duration_ms?.values?.['p(99)']?.toFixed(2) || 'N/A'} ms

Action Duration:
  - p50: ${metrics.cu_action_duration_ms?.values?.['p(50)']?.toFixed(2) || 'N/A'} ms
  - p95: ${metrics.cu_action_duration_ms?.values?.['p(95)']?.toFixed(2) || 'N/A'} ms
  - p99: ${metrics.cu_action_duration_ms?.values?.['p(99)']?.toFixed(2) || 'N/A'} ms

THROUGHPUT METRICS:
--------------------------------------------------------------------------------
Total Throughput: ${metrics.cu_throughput?.values?.count || 'N/A'} requests
Requests Per User (avg): ${metrics.cu_requests_per_user?.values?.avg?.toFixed(2) || 'N/A'}
HTTP Requests: ${metrics.http_reqs?.values?.count || 'N/A'}
HTTP Request Rate: ${metrics.http_reqs?.values?.rate?.toFixed(2) || 'N/A'} req/s

SUCCESS RATES:
--------------------------------------------------------------------------------
Login Success Rate: ${((metrics.cu_login_success_rate?.values?.rate || 0) * 100).toFixed(2)}%
Session Success Rate: ${((metrics.cu_session_success_rate?.values?.rate || 0) * 100).toFixed(2)}%
Action Success Rate: ${((metrics.cu_action_success_rate?.values?.rate || 0) * 100).toFixed(2)}%
Error Rate: ${((metrics.cu_error_rate?.values?.rate || 0) * 100).toFixed(2)}%
HTTP Failure Rate: ${((metrics.http_req_failed?.values?.rate || 0) * 100).toFixed(2)}%

RESPONSE TIME:
--------------------------------------------------------------------------------
Overall Response Time:
  - p50: ${metrics.cu_response_time_ms?.values?.['p(50)']?.toFixed(2) || 'N/A'} ms
  - p95: ${metrics.cu_response_time_ms?.values?.['p(95)']?.toFixed(2) || 'N/A'} ms
  - p99: ${metrics.cu_response_time_ms?.values?.['p(99)']?.toFixed(2) || 'N/A'} ms

HTTP Request Duration:
  - p50: ${metrics.http_req_duration?.values?.['p(50)']?.toFixed(2) || 'N/A'} ms
  - p95: ${metrics.http_req_duration?.values?.['p(95)']?.toFixed(2) || 'N/A'} ms
  - p99: ${metrics.http_req_duration?.values?.['p(99)']?.toFixed(2) || 'N/A'} ms

CONCURRENCY ANALYSIS:
--------------------------------------------------------------------------------
${getConcurrencyAnalysis(metrics)}

================================================================================
`;
}

function getConcurrencyAnalysis(metrics) {
  const loginSuccessRate = metrics.cu_login_success_rate?.values?.rate || 0;
  const sessionSuccessRate = metrics.cu_session_success_rate?.values?.rate || 0;
  const actionSuccessRate = metrics.cu_action_success_rate?.values?.rate || 0;
  const p95ResponseTime = metrics.cu_response_time_ms?.values?.['p(95)'] || 0;
  const httpFailRate = metrics.http_req_failed?.values?.rate || 0;

  let analysis = [];

  // Login analysis
  if (loginSuccessRate >= 0.99) {
    analysis.push('Authentication system handles concurrent logins EXCELLENTLY');
  } else if (loginSuccessRate >= 0.95) {
    analysis.push('Authentication system handles concurrent logins WELL');
  } else if (loginSuccessRate >= 0.90) {
    analysis.push('Authentication system shows STRESS under concurrent logins');
  } else {
    analysis.push('Authentication system STRUGGLING with concurrent logins');
  }

  // Session analysis
  if (sessionSuccessRate >= 0.95) {
    analysis.push('User sessions complete successfully under load');
  } else if (sessionSuccessRate >= 0.85) {
    analysis.push('Some user sessions experiencing issues under load');
  } else {
    analysis.push('Significant session failures under load');
  }

  // Response time analysis
  if (p95ResponseTime < 300) {
    analysis.push('Response times EXCELLENT (p95 < 300ms)');
  } else if (p95ResponseTime < 500) {
    analysis.push('Response times GOOD (p95 < 500ms)');
  } else if (p95ResponseTime < 1000) {
    analysis.push('Response times ACCEPTABLE (p95 < 1s)');
  } else {
    analysis.push('Response times DEGRADED (p95 > 1s)');
  }

  // HTTP failure analysis
  if (httpFailRate > 0.05) {
    analysis.push('WARNING: High HTTP failure rate detected');
  }

  // Overall verdict
  if (loginSuccessRate >= 0.95 && sessionSuccessRate >= 0.95 && p95ResponseTime < 500) {
    analysis.push('\nVERDICT: System handles concurrent users EXCELLENTLY');
  } else if (loginSuccessRate >= 0.90 && sessionSuccessRate >= 0.90 && p95ResponseTime < 1000) {
    analysis.push('\nVERDICT: System handles concurrent users ADEQUATELY');
  } else {
    analysis.push('\nVERDICT: System shows DEGRADATION under concurrent user load');
  }

  return analysis.join('\n');
}
