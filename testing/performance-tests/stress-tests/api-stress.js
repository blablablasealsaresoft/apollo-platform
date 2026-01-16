/**
 * Apollo Platform - API Stress Test
 *
 * Pushes the API beyond normal operating capacity to find breaking points.
 * Identifies resource limits, failure modes, and recovery behavior.
 *
 * Run: k6 run api-stress.js
 * Run with env: k6 run -e API_URL=http://localhost:3000/api api-stress.js
 * Run specific intensity: k6 run --env INTENSITY=extreme api-stress.js
 */

import http from 'k6/http';
import { check, group, sleep, fail } from 'k6';
import { Rate, Trend, Counter, Gauge } from 'k6/metrics';
import { randomIntBetween, randomItem, randomString } from 'https://jslib.k6.io/k6-utils/1.4.0/index.js';

// ============================================================================
// CUSTOM METRICS
// ============================================================================

// Response time metrics
const apiResponseTime = new Trend('stress_api_response_time_ms');
const p99ResponseTime = new Trend('stress_p99_response_time_ms');
const timeToFirstByte = new Trend('stress_ttfb_ms');

// Throughput metrics
const requestsPerSecond = new Rate('stress_requests_per_second');
const successfulRequests = new Counter('stress_successful_requests');
const failedRequests = new Counter('stress_failed_requests');
const totalRequests = new Counter('stress_total_requests');

// Error metrics
const errorRate = new Rate('stress_error_rate');
const timeoutRate = new Rate('stress_timeout_rate');
const serverErrorRate = new Rate('stress_server_error_rate');
const clientErrorRate = new Rate('stress_client_error_rate');

// Resource metrics
const activeVUs = new Gauge('stress_active_vus');
const connectionErrors = new Counter('stress_connection_errors');

// Recovery metrics
const recoveryTime = new Trend('stress_recovery_time_ms');

// ============================================================================
// CONFIGURATION
// ============================================================================

const BASE_URL = __ENV.API_URL || 'http://localhost:3000/api';
const INTENSITY = __ENV.INTENSITY || 'high';

// Stress test intensity levels
const intensityLevels = {
  // Medium stress: 200 VUs peak
  medium: {
    executor: 'ramping-vus',
    startVUs: 0,
    stages: [
      { duration: '1m', target: 50 },    // Warm up
      { duration: '2m', target: 100 },   // Ramp to load
      { duration: '2m', target: 150 },   // Increase
      { duration: '3m', target: 200 },   // Stress level
      { duration: '2m', target: 200 },   // Hold stress
      { duration: '2m', target: 100 },   // Decrease
      { duration: '1m', target: 50 },    // Cool down
      { duration: '1m', target: 0 },     // Ramp down
    ],
    gracefulRampDown: '1m',
  },
  // High stress: 500 VUs peak
  high: {
    executor: 'ramping-vus',
    startVUs: 0,
    stages: [
      { duration: '1m', target: 100 },   // Warm up
      { duration: '2m', target: 200 },   // Ramp to load
      { duration: '2m', target: 300 },   // Increase
      { duration: '2m', target: 400 },   // Push harder
      { duration: '3m', target: 500 },   // Peak stress
      { duration: '3m', target: 500 },   // Hold peak
      { duration: '2m', target: 300 },   // Decrease
      { duration: '1m', target: 100 },   // Cool down
      { duration: '1m', target: 0 },     // Ramp down
    ],
    gracefulRampDown: '2m',
  },
  // Extreme stress: 1000 VUs peak
  extreme: {
    executor: 'ramping-vus',
    startVUs: 0,
    stages: [
      { duration: '1m', target: 200 },   // Warm up
      { duration: '2m', target: 400 },   // Ramp to load
      { duration: '2m', target: 600 },   // Increase
      { duration: '2m', target: 800 },   // Push harder
      { duration: '3m', target: 1000 },  // Peak stress
      { duration: '5m', target: 1000 },  // Hold peak
      { duration: '2m', target: 500 },   // Decrease
      { duration: '1m', target: 200 },   // Cool down
      { duration: '1m', target: 0 },     // Ramp down
    ],
    gracefulRampDown: '2m',
  },
  // Breaking point test: Find system limits
  breaking: {
    executor: 'ramping-arrival-rate',
    startRate: 10,
    timeUnit: '1s',
    preAllocatedVUs: 100,
    maxVUs: 2000,
    stages: [
      { duration: '1m', target: 50 },    // Start
      { duration: '2m', target: 100 },   // Increase
      { duration: '2m', target: 200 },   // More
      { duration: '2m', target: 400 },   // Pushing
      { duration: '2m', target: 600 },   // Hard
      { duration: '2m', target: 800 },   // Very hard
      { duration: '2m', target: 1000 },  // Extreme
      { duration: '3m', target: 1500 },  // Breaking point
      { duration: '2m', target: 500 },   // Recovery test
      { duration: '1m', target: 100 },   // Cool down
    ],
  },
};

export const options = {
  scenarios: {
    stress_test: intensityLevels[INTENSITY],
  },
  thresholds: {
    // Stress test thresholds are more lenient
    http_req_duration: ['p(95)<2000', 'p(99)<5000'],  // Allow slower responses
    stress_error_rate: ['rate<0.10'],                  // Allow up to 10% errors
    stress_server_error_rate: ['rate<0.05'],           // Max 5% server errors
    stress_timeout_rate: ['rate<0.05'],                // Max 5% timeouts
  },
  tags: {
    testType: 'api-stress',
    intensity: INTENSITY,
  },
};

// ============================================================================
// TEST DATA
// ============================================================================

const endpoints = [
  { method: 'GET', path: '/investigations', weight: 20 },
  { method: 'GET', path: '/investigations?page=1&limit=20', weight: 15 },
  { method: 'GET', path: '/targets', weight: 15 },
  { method: 'GET', path: '/targets?page=1&limit=20', weight: 10 },
  { method: 'GET', path: '/evidence', weight: 10 },
  { method: 'GET', path: '/intelligence', weight: 10 },
  { method: 'GET', path: '/operations', weight: 5 },
  { method: 'GET', path: '/search?q=test', weight: 5 },
  { method: 'GET', path: '/analytics/dashboard', weight: 5 },
  { method: 'POST', path: '/investigations', weight: 3 },
  { method: 'POST', path: '/targets', weight: 2 },
];

const priorities = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
const statuses = ['ACTIVE', 'PENDING', 'CLOSED', 'ARCHIVED'];

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

function getHeaders(token) {
  return {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    'Authorization': `Bearer ${token}`,
    'X-Request-ID': `stress-${__VU}-${__ITER}-${Date.now()}`,
  };
}

function selectEndpoint() {
  const totalWeight = endpoints.reduce((sum, e) => sum + e.weight, 0);
  let random = Math.random() * totalWeight;

  for (const endpoint of endpoints) {
    random -= endpoint.weight;
    if (random <= 0) {
      return endpoint;
    }
  }
  return endpoints[0];
}

function generatePayload(path) {
  if (path.includes('/investigations')) {
    return JSON.stringify({
      caseNumber: `STRESS-${Date.now()}-${__VU}`,
      title: `Stress Test Investigation ${__VU}`,
      description: `API stress testing. ${randomString(100)}`,
      priority: randomItem(priorities),
      status: randomItem(statuses),
    });
  }
  if (path.includes('/targets')) {
    return JSON.stringify({
      name: `Stress Target ${__VU}-${Date.now()}`,
      type: randomItem(['PERSON', 'ORGANIZATION']),
      priority: randomItem(priorities),
    });
  }
  return null;
}

// ============================================================================
// SETUP
// ============================================================================

export function setup() {
  console.log(`Starting API Stress Test - Intensity: ${INTENSITY}`);
  console.log(`API URL: ${BASE_URL}`);
  console.log(`VU limit based on intensity level`);

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
    intensity: INTENSITY,
  };
}

// ============================================================================
// MAIN TEST FUNCTION
// ============================================================================

export default function(data) {
  const headers = getHeaders(data.token);
  const endpoint = selectEndpoint();

  activeVUs.add(1);
  totalRequests.add(1);

  const requestStart = Date.now();
  let res;
  let isTimeout = false;
  let isConnectionError = false;

  try {
    if (endpoint.method === 'GET') {
      res = http.get(
        `${BASE_URL}${endpoint.path}`,
        {
          headers,
          timeout: '30s',
          tags: { name: `stress-${endpoint.method}-${endpoint.path.split('?')[0]}` }
        }
      );
    } else if (endpoint.method === 'POST') {
      const payload = generatePayload(endpoint.path);
      res = http.post(
        `${BASE_URL}${endpoint.path}`,
        payload,
        {
          headers,
          timeout: '30s',
          tags: { name: `stress-${endpoint.method}-${endpoint.path}` }
        }
      );
    }
  } catch (e) {
    // Connection error or timeout
    isConnectionError = true;
    connectionErrors.add(1);
    errorRate.add(1);
    failedRequests.add(1);
    activeVUs.add(-1);

    console.error(`VU ${__VU}: Connection error - ${e.message || e}`);
    sleep(randomIntBetween(1, 3));
    return;
  }

  const responseTime = Date.now() - requestStart;
  apiResponseTime.add(responseTime);

  // Record TTFB if available
  if (res && res.timings && res.timings.waiting) {
    timeToFirstByte.add(res.timings.waiting);
  }

  // Check for timeout
  if (res && res.timings && res.timings.duration > 29000) {
    isTimeout = true;
    timeoutRate.add(1);
  } else {
    timeoutRate.add(0);
  }

  // Categorize response
  if (res) {
    const status = res.status;

    if (status >= 200 && status < 300) {
      // Success
      successfulRequests.add(1);
      errorRate.add(0);
      serverErrorRate.add(0);
      clientErrorRate.add(0);
      requestsPerSecond.add(1);
    } else if (status >= 400 && status < 500) {
      // Client error
      failedRequests.add(1);
      errorRate.add(1);
      clientErrorRate.add(1);
      serverErrorRate.add(0);
    } else if (status >= 500) {
      // Server error
      failedRequests.add(1);
      errorRate.add(1);
      serverErrorRate.add(1);
      clientErrorRate.add(0);

      // Log server errors for investigation
      console.warn(`VU ${__VU}: Server error ${status} on ${endpoint.method} ${endpoint.path}`);
    }

    // Basic checks
    check(res, {
      'response received': (r) => r !== null,
      'not server error': (r) => r.status < 500,
      'not rate limited': (r) => r.status !== 429,
      'response time < 5s': (r) => r.timings.duration < 5000,
    });
  }

  // Track p99 response times separately
  if (responseTime > 0) {
    p99ResponseTime.add(responseTime);
  }

  activeVUs.add(-1);

  // Adaptive think time based on response time
  // If server is stressed (slow response), back off more
  let thinkTime = 0.1; // Base think time

  if (responseTime > 2000) {
    thinkTime = 2; // Back off significantly if slow
  } else if (responseTime > 1000) {
    thinkTime = 1;
  } else if (responseTime > 500) {
    thinkTime = 0.5;
  }

  sleep(thinkTime);
}

// ============================================================================
// TEARDOWN
// ============================================================================

export function teardown(data) {
  const duration = (Date.now() - data.startTime) / 1000;
  console.log(`API Stress Test completed - Duration: ${duration.toFixed(2)}s`);
  console.log(`Intensity: ${data.intensity}`);
}

// ============================================================================
// CUSTOM SUMMARY
// ============================================================================

export function handleSummary(data) {
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');

  return {
    [`testing/performance-tests/results/api-stress-${INTENSITY}-${timestamp}.json`]: JSON.stringify(data, null, 2),
    stdout: generateTextSummary(data),
  };
}

function generateTextSummary(data) {
  const metrics = data.metrics;

  const successCount = metrics.stress_successful_requests?.values?.count || 0;
  const failedCount = metrics.stress_failed_requests?.values?.count || 0;
  const totalCount = successCount + failedCount;
  const successRate = totalCount > 0 ? ((successCount / totalCount) * 100).toFixed(2) : 'N/A';

  return `
================================================================================
                    APOLLO PLATFORM - API STRESS TEST RESULTS
================================================================================
Intensity: ${INTENSITY}
Timestamp: ${new Date().toISOString()}

RESPONSE TIME METRICS:
--------------------------------------------------------------------------------
API Response Time:
  - p50: ${metrics.stress_api_response_time_ms?.values?.['p(50)']?.toFixed(2) || 'N/A'} ms
  - p90: ${metrics.stress_api_response_time_ms?.values?.['p(90)']?.toFixed(2) || 'N/A'} ms
  - p95: ${metrics.stress_api_response_time_ms?.values?.['p(95)']?.toFixed(2) || 'N/A'} ms
  - p99: ${metrics.stress_api_response_time_ms?.values?.['p(99)']?.toFixed(2) || 'N/A'} ms
  - max: ${metrics.stress_api_response_time_ms?.values?.max?.toFixed(2) || 'N/A'} ms

Time to First Byte:
  - p50: ${metrics.stress_ttfb_ms?.values?.['p(50)']?.toFixed(2) || 'N/A'} ms
  - p95: ${metrics.stress_ttfb_ms?.values?.['p(95)']?.toFixed(2) || 'N/A'} ms

THROUGHPUT METRICS:
--------------------------------------------------------------------------------
Total Requests: ${totalCount}
Successful Requests: ${successCount}
Failed Requests: ${failedCount}
Success Rate: ${successRate}%

ERROR METRICS:
--------------------------------------------------------------------------------
Overall Error Rate: ${((metrics.stress_error_rate?.values?.rate || 0) * 100).toFixed(2)}%
Server Error Rate (5xx): ${((metrics.stress_server_error_rate?.values?.rate || 0) * 100).toFixed(2)}%
Client Error Rate (4xx): ${((metrics.stress_client_error_rate?.values?.rate || 0) * 100).toFixed(2)}%
Timeout Rate: ${((metrics.stress_timeout_rate?.values?.rate || 0) * 100).toFixed(2)}%
Connection Errors: ${metrics.stress_connection_errors?.values?.count || 0}

HTTP STATUS BREAKDOWN:
--------------------------------------------------------------------------------
HTTP Failures: ${((metrics.http_req_failed?.values?.rate || 0) * 100).toFixed(2)}%
HTTP Request Duration (p95): ${metrics.http_req_duration?.values?.['p(95)']?.toFixed(2) || 'N/A'} ms
HTTP Request Duration (p99): ${metrics.http_req_duration?.values?.['p(99)']?.toFixed(2) || 'N/A'} ms

STRESS TEST ANALYSIS:
--------------------------------------------------------------------------------
${getStressAnalysis(metrics)}

================================================================================
`;
}

function getStressAnalysis(metrics) {
  const p95 = metrics.stress_api_response_time_ms?.values?.['p(95)'] || 0;
  const p99 = metrics.stress_api_response_time_ms?.values?.['p(99)'] || 0;
  const errorRate = metrics.stress_error_rate?.values?.rate || 0;
  const serverErrorRate = metrics.stress_server_error_rate?.values?.rate || 0;
  const timeoutRate = metrics.stress_timeout_rate?.values?.rate || 0;

  let analysis = [];

  // Response time analysis
  if (p95 < 500) {
    analysis.push('Response times are EXCELLENT under stress (p95 < 500ms)');
  } else if (p95 < 1000) {
    analysis.push('Response times are GOOD under stress (p95 < 1s)');
  } else if (p95 < 2000) {
    analysis.push('Response times are ACCEPTABLE under stress (p95 < 2s)');
  } else {
    analysis.push('Response times DEGRADED significantly under stress (p95 > 2s)');
  }

  // Error rate analysis
  if (errorRate < 0.01) {
    analysis.push('Error rate is EXCELLENT (< 1%)');
  } else if (errorRate < 0.05) {
    analysis.push('Error rate is ACCEPTABLE (< 5%)');
  } else if (errorRate < 0.10) {
    analysis.push('Error rate is ELEVATED (5-10%)');
  } else {
    analysis.push('Error rate is HIGH (> 10%) - System may be at capacity');
  }

  // Server error analysis
  if (serverErrorRate > 0.05) {
    analysis.push('WARNING: High server error rate indicates backend issues');
  }

  // Timeout analysis
  if (timeoutRate > 0.02) {
    analysis.push('WARNING: Timeouts detected - may need to increase resources');
  }

  // Overall verdict
  if (p95 < 1000 && errorRate < 0.05) {
    analysis.push('\nVERDICT: System PASSED stress test');
  } else if (p95 < 2000 && errorRate < 0.10) {
    analysis.push('\nVERDICT: System showed DEGRADATION under stress but remained functional');
  } else {
    analysis.push('\nVERDICT: System FAILED stress test - optimization needed');
  }

  return analysis.join('\n');
}
