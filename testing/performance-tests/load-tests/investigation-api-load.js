import http from 'k6/http';
import { check, group, sleep } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';

// Custom metrics
const errorRate = new Rate('errors');
const investigationCreationTrend = new Trend('investigation_creation_duration');
const searchTrend = new Trend('search_duration');
const requestCounter = new Counter('total_requests');

// Test configuration
export const options = {
  stages: [
    { duration: '2m', target: 100 },   // Ramp-up to 100 users
    { duration: '5m', target: 100 },   // Stay at 100 users
    { duration: '2m', target: 500 },   // Ramp-up to 500 users
    { duration: '5m', target: 500 },   // Stay at 500 users
    { duration: '2m', target: 1000 },  // Ramp-up to 1000 users
    { duration: '5m', target: 1000 },  // Stay at 1000 users
    { duration: '2m', target: 0 },     // Ramp-down to 0 users
  ],
  thresholds: {
    http_req_duration: ['p(95)<500', 'p(99)<1000'], // 95% of requests should be below 500ms
    http_req_failed: ['rate<0.01'],                  // Error rate should be less than 1%
    errors: ['rate<0.1'],                            // Custom error rate
    investigation_creation_duration: ['p(95)<1000'], // Investigation creation under 1s
    search_duration: ['p(95)<300'],                  // Search under 300ms
  },
};

const BASE_URL = __ENV.API_URL || 'http://localhost:3000/api';
let authToken = '';

export function setup() {
  // Login to get auth token
  const loginRes = http.post(`${BASE_URL}/auth/login`, JSON.stringify({
    email: 'loadtest@apollo.com',
    password: 'LoadTest123!',
  }), {
    headers: { 'Content-Type': 'application/json' },
  });

  check(loginRes, {
    'login successful': (r) => r.status === 200,
  });

  return { token: loginRes.json('token') };
}

export default function (data) {
  authToken = data.token;

  const headers = {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${authToken}`,
  };

  group('Investigation API Load Test', () => {
    // Test 1: List investigations
    group('List Investigations', () => {
      const res = http.get(`${BASE_URL}/investigations?page=1&limit=20`, { headers });

      check(res, {
        'status is 200': (r) => r.status === 200,
        'response time < 200ms': (r) => r.timings.duration < 200,
        'has data array': (r) => r.json('data') !== undefined,
      });

      errorRate.add(res.status !== 200);
      requestCounter.add(1);
    });

    sleep(1);

    // Test 2: Create investigation
    group('Create Investigation', () => {
      const payload = JSON.stringify({
        caseNumber: `LOAD-TEST-${Date.now()}-${__VU}`,
        title: `Load Test Investigation ${__VU}`,
        description: 'Load testing the Apollo platform',
        priority: 'HIGH',
        classification: 'CONFIDENTIAL',
      });

      const createStart = Date.now();
      const res = http.post(`${BASE_URL}/investigations`, payload, { headers });
      const createDuration = Date.now() - createStart;

      check(res, {
        'status is 201': (r) => r.status === 201,
        'response time < 1s': (r) => r.timings.duration < 1000,
        'has investigation id': (r) => r.json('id') !== undefined,
      });

      investigationCreationTrend.add(createDuration);
      errorRate.add(res.status !== 201);
      requestCounter.add(1);

      // Store investigation ID for later tests
      const investigationId = res.json('id');

      // Test 3: Get investigation details
      if (investigationId) {
        sleep(0.5);

        const detailRes = http.get(`${BASE_URL}/investigations/${investigationId}`, { headers });

        check(detailRes, {
          'detail status is 200': (r) => r.status === 200,
          'detail response time < 100ms': (r) => r.timings.duration < 100,
        });

        errorRate.add(detailRes.status !== 200);
        requestCounter.add(1);
      }
    });

    sleep(1);

    // Test 4: Search investigations
    group('Search Investigations', () => {
      const searchStart = Date.now();
      const res = http.get(`${BASE_URL}/investigations?search=Load Test`, { headers });
      const searchDuration = Date.now() - searchStart;

      check(res, {
        'search status is 200': (r) => r.status === 200,
        'search response time < 300ms': (r) => r.timings.duration < 300,
        'has search results': (r) => r.json('data').length >= 0,
      });

      searchTrend.add(searchDuration);
      errorRate.add(res.status !== 200);
      requestCounter.add(1);
    });

    sleep(1);

    // Test 5: Filter by priority
    group('Filter Investigations', () => {
      const res = http.get(`${BASE_URL}/investigations?priority=HIGH&page=1&limit=10`, { headers });

      check(res, {
        'filter status is 200': (r) => r.status === 200,
        'filter response time < 200ms': (r) => r.timings.duration < 200,
      });

      errorRate.add(res.status !== 200);
      requestCounter.add(1);
    });

    sleep(1);

    // Test 6: Get statistics
    group('Get Statistics', () => {
      const res = http.get(`${BASE_URL}/investigations/statistics`, { headers });

      check(res, {
        'stats status is 200': (r) => r.status === 200,
        'stats response time < 500ms': (r) => r.timings.duration < 500,
      });

      errorRate.add(res.status !== 200);
      requestCounter.add(1);
    });
  });

  sleep(2);
}

export function teardown(data) {
  // Cleanup test data if needed
  console.log('Load test completed');
}

export function handleSummary(data) {
  return {
    'testing/performance-tests/load-tests/summary.json': JSON.stringify(data, null, 2),
    'testing/performance-tests/load-tests/summary.html': htmlReport(data),
    stdout: textSummary(data, { indent: ' ', enableColors: true }),
  };
}

function htmlReport(data) {
  return `
<!DOCTYPE html>
<html>
<head>
  <title>K6 Load Test Report - Apollo Platform</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 20px; }
    h1 { color: #333; }
    .metric { margin: 10px 0; padding: 10px; background: #f5f5f5; border-radius: 4px; }
    .pass { color: green; }
    .fail { color: red; }
  </style>
</head>
<body>
  <h1>K6 Load Test Report - Apollo Platform</h1>
  <div class="metric">
    <strong>Total Requests:</strong> ${data.metrics.http_reqs.values.count}
  </div>
  <div class="metric">
    <strong>Request Duration (p95):</strong> ${data.metrics.http_req_duration.values['p(95)']} ms
  </div>
  <div class="metric">
    <strong>Request Duration (p99):</strong> ${data.metrics.http_req_duration.values['p(99)']} ms
  </div>
  <div class="metric">
    <strong>Error Rate:</strong> ${(data.metrics.http_req_failed.values.rate * 100).toFixed(2)}%
  </div>
</body>
</html>
  `;
}
