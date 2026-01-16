/**
 * Apollo Platform - Authentication Load Test
 *
 * Tests authentication endpoints under various load conditions.
 * Scenarios: Smoke, Load, Stress, Spike, Soak
 *
 * Run: k6 run auth-load.js
 * Run with env: k6 run -e API_URL=http://localhost:3000/api auth-load.js
 * Run specific scenario: k6 run --env SCENARIO=smoke auth-load.js
 */

import http from 'k6/http';
import { check, group, sleep, fail } from 'k6';
import { Rate, Trend, Counter, Gauge } from 'k6/metrics';
import { randomString, randomIntBetween } from 'https://jslib.k6.io/k6-utils/1.4.0/index.js';

// ============================================================================
// CUSTOM METRICS
// ============================================================================

const loginSuccessRate = new Rate('login_success_rate');
const loginDuration = new Trend('login_duration_ms');
const tokenRefreshDuration = new Trend('token_refresh_duration_ms');
const registrationDuration = new Trend('registration_duration_ms');
const mfaVerificationDuration = new Trend('mfa_verification_duration_ms');
const logoutDuration = new Trend('logout_duration_ms');
const errorRate = new Rate('errors');
const requestCounter = new Counter('total_requests');
const activeUsers = new Gauge('active_users');

// ============================================================================
// CONFIGURATION
// ============================================================================

const BASE_URL = __ENV.API_URL || 'http://localhost:3000/api';
const SCENARIO = __ENV.SCENARIO || 'load';

// Test scenarios configuration
const scenarios = {
  // Smoke test: Quick verification with minimal load
  smoke: {
    executor: 'constant-vus',
    vus: 3,
    duration: '1m',
  },
  // Load test: Normal expected load
  load: {
    executor: 'ramping-vus',
    startVUs: 0,
    stages: [
      { duration: '2m', target: 50 },   // Ramp up to 50 users
      { duration: '5m', target: 50 },   // Stay at 50 users
      { duration: '2m', target: 100 },  // Ramp up to 100 users
      { duration: '5m', target: 100 },  // Stay at 100 users
      { duration: '2m', target: 0 },    // Ramp down
    ],
    gracefulRampDown: '30s',
  },
  // Stress test: Push beyond normal capacity
  stress: {
    executor: 'ramping-vus',
    startVUs: 0,
    stages: [
      { duration: '2m', target: 100 },  // Ramp up
      { duration: '3m', target: 100 },  // Stay
      { duration: '2m', target: 200 },  // Push higher
      { duration: '3m', target: 200 },  // Stay
      { duration: '2m', target: 300 },  // Push to stress
      { duration: '3m', target: 300 },  // Stay at stress
      { duration: '2m', target: 0 },    // Ramp down
    ],
    gracefulRampDown: '1m',
  },
  // Spike test: Sudden traffic burst
  spike: {
    executor: 'ramping-vus',
    startVUs: 1,
    stages: [
      { duration: '1m', target: 10 },   // Normal load
      { duration: '30s', target: 500 }, // Spike!
      { duration: '1m', target: 500 },  // Stay at spike
      { duration: '30s', target: 10 },  // Back to normal
      { duration: '1m', target: 10 },   // Stay normal
      { duration: '30s', target: 0 },   // Ramp down
    ],
    gracefulRampDown: '30s',
  },
  // Soak test: Extended duration test
  soak: {
    executor: 'constant-vus',
    vus: 75,
    duration: '1h',
  },
};

export const options = {
  scenarios: {
    auth_test: scenarios[SCENARIO],
  },
  thresholds: {
    // Response time thresholds
    http_req_duration: ['p(95)<200', 'p(99)<500'],
    login_duration_ms: ['p(95)<300', 'p(99)<600'],
    token_refresh_duration_ms: ['p(95)<150', 'p(99)<300'],
    registration_duration_ms: ['p(95)<500', 'p(99)<1000'],
    mfa_verification_duration_ms: ['p(95)<200', 'p(99)<400'],
    logout_duration_ms: ['p(95)<100', 'p(99)<200'],

    // Error rate thresholds
    http_req_failed: ['rate<0.01'],  // Less than 1% failure
    errors: ['rate<0.05'],           // Less than 5% custom errors
    login_success_rate: ['rate>0.95'], // At least 95% login success
  },
  // Tag results for analysis
  tags: {
    testType: 'auth-load',
    scenario: SCENARIO,
  },
};

// ============================================================================
// TEST DATA
// ============================================================================

const testUsers = [
  { email: 'loadtest1@apollo.com', password: 'LoadTest123!' },
  { email: 'loadtest2@apollo.com', password: 'LoadTest123!' },
  { email: 'loadtest3@apollo.com', password: 'LoadTest123!' },
  { email: 'loadtest4@apollo.com', password: 'LoadTest123!' },
  { email: 'loadtest5@apollo.com', password: 'LoadTest123!' },
];

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

function getRandomUser() {
  return testUsers[randomIntBetween(0, testUsers.length - 1)];
}

function getHeaders(token = null) {
  const headers = {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    'X-Request-ID': `load-test-${__VU}-${__ITER}-${Date.now()}`,
  };
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  return headers;
}

// ============================================================================
// SETUP
// ============================================================================

export function setup() {
  console.log(`Starting Auth Load Test - Scenario: ${SCENARIO}`);
  console.log(`API URL: ${BASE_URL}`);

  // Verify API is reachable
  const healthCheck = http.get(`${BASE_URL}/health`, { timeout: '10s' });
  if (healthCheck.status !== 200) {
    console.warn('API health check failed, tests may not work correctly');
  }

  return {
    startTime: Date.now(),
    scenario: SCENARIO,
  };
}

// ============================================================================
// MAIN TEST FUNCTION
// ============================================================================

export default function(data) {
  const user = getRandomUser();
  let authToken = null;
  let refreshToken = null;

  activeUsers.add(1);

  // -------------------------------------------------------------------------
  // Test 1: Login
  // -------------------------------------------------------------------------
  group('Authentication - Login', () => {
    const loginPayload = JSON.stringify({
      email: user.email,
      password: user.password,
    });

    const loginStart = Date.now();
    const loginRes = http.post(
      `${BASE_URL}/auth/login`,
      loginPayload,
      { headers: getHeaders(), tags: { name: 'login' } }
    );
    const loginTime = Date.now() - loginStart;

    loginDuration.add(loginTime);
    requestCounter.add(1);

    const loginSuccess = check(loginRes, {
      'login status is 200': (r) => r.status === 200,
      'login response time < 200ms': (r) => r.timings.duration < 200,
      'login has token': (r) => {
        try {
          const body = r.json();
          return body.token !== undefined || body.accessToken !== undefined;
        } catch {
          return false;
        }
      },
      'login has refresh token': (r) => {
        try {
          const body = r.json();
          return body.refreshToken !== undefined;
        } catch {
          return false;
        }
      },
    });

    loginSuccessRate.add(loginSuccess);
    errorRate.add(!loginSuccess);

    if (loginRes.status === 200) {
      try {
        const body = loginRes.json();
        authToken = body.token || body.accessToken;
        refreshToken = body.refreshToken;
      } catch (e) {
        console.error('Failed to parse login response');
      }
    }
  });

  sleep(randomIntBetween(1, 3));

  // Skip remaining tests if login failed
  if (!authToken) {
    activeUsers.add(-1);
    return;
  }

  // -------------------------------------------------------------------------
  // Test 2: Validate Token
  // -------------------------------------------------------------------------
  group('Authentication - Validate Token', () => {
    const validateRes = http.get(
      `${BASE_URL}/auth/validate`,
      { headers: getHeaders(authToken), tags: { name: 'validate-token' } }
    );

    requestCounter.add(1);

    const validateSuccess = check(validateRes, {
      'validate status is 200': (r) => r.status === 200,
      'validate response time < 100ms': (r) => r.timings.duration < 100,
      'token is valid': (r) => {
        try {
          return r.json().valid === true || r.status === 200;
        } catch {
          return r.status === 200;
        }
      },
    });

    errorRate.add(!validateSuccess);
  });

  sleep(randomIntBetween(1, 2));

  // -------------------------------------------------------------------------
  // Test 3: Get Current User Profile
  // -------------------------------------------------------------------------
  group('Authentication - Get Profile', () => {
    const profileRes = http.get(
      `${BASE_URL}/auth/me`,
      { headers: getHeaders(authToken), tags: { name: 'get-profile' } }
    );

    requestCounter.add(1);

    const profileSuccess = check(profileRes, {
      'profile status is 200': (r) => r.status === 200,
      'profile response time < 150ms': (r) => r.timings.duration < 150,
      'profile has user data': (r) => {
        try {
          const body = r.json();
          return body.email !== undefined || body.user !== undefined;
        } catch {
          return false;
        }
      },
    });

    errorRate.add(!profileSuccess);
  });

  sleep(randomIntBetween(1, 2));

  // -------------------------------------------------------------------------
  // Test 4: Refresh Token
  // -------------------------------------------------------------------------
  if (refreshToken) {
    group('Authentication - Refresh Token', () => {
      const refreshPayload = JSON.stringify({
        refreshToken: refreshToken,
      });

      const refreshStart = Date.now();
      const refreshRes = http.post(
        `${BASE_URL}/auth/refresh`,
        refreshPayload,
        { headers: getHeaders(), tags: { name: 'refresh-token' } }
      );
      const refreshTime = Date.now() - refreshStart;

      tokenRefreshDuration.add(refreshTime);
      requestCounter.add(1);

      const refreshSuccess = check(refreshRes, {
        'refresh status is 200': (r) => r.status === 200,
        'refresh response time < 150ms': (r) => r.timings.duration < 150,
        'refresh has new token': (r) => {
          try {
            const body = r.json();
            return body.token !== undefined || body.accessToken !== undefined;
          } catch {
            return false;
          }
        },
      });

      errorRate.add(!refreshSuccess);

      // Update token if refresh succeeded
      if (refreshRes.status === 200) {
        try {
          const body = refreshRes.json();
          authToken = body.token || body.accessToken;
        } catch (e) {
          // Keep existing token
        }
      }
    });

    sleep(randomIntBetween(1, 2));
  }

  // -------------------------------------------------------------------------
  // Test 5: Invalid Login Attempt (Security Test)
  // -------------------------------------------------------------------------
  group('Authentication - Invalid Login', () => {
    const invalidPayload = JSON.stringify({
      email: 'invalid@test.com',
      password: 'wrongpassword123',
    });

    const invalidRes = http.post(
      `${BASE_URL}/auth/login`,
      invalidPayload,
      { headers: getHeaders(), tags: { name: 'invalid-login' } }
    );

    requestCounter.add(1);

    check(invalidRes, {
      'invalid login returns 401': (r) => r.status === 401 || r.status === 403,
      'invalid login response time < 200ms': (r) => r.timings.duration < 200,
      'invalid login has error message': (r) => {
        try {
          const body = r.json();
          return body.error !== undefined || body.message !== undefined;
        } catch {
          return false;
        }
      },
    });
  });

  sleep(randomIntBetween(1, 2));

  // -------------------------------------------------------------------------
  // Test 6: MFA Verification (if enabled)
  // -------------------------------------------------------------------------
  group('Authentication - MFA Check', () => {
    const mfaRes = http.get(
      `${BASE_URL}/auth/mfa/status`,
      { headers: getHeaders(authToken), tags: { name: 'mfa-status' } }
    );

    requestCounter.add(1);

    check(mfaRes, {
      'mfa status returns 200 or 404': (r) => r.status === 200 || r.status === 404,
      'mfa response time < 100ms': (r) => r.timings.duration < 100,
    });

    // If MFA is enabled, test verification endpoint
    if (mfaRes.status === 200) {
      try {
        const mfaData = mfaRes.json();
        if (mfaData.enabled || mfaData.mfaEnabled) {
          const verifyStart = Date.now();
          const verifyRes = http.post(
            `${BASE_URL}/auth/mfa/verify`,
            JSON.stringify({ code: '000000' }), // Test code
            { headers: getHeaders(authToken), tags: { name: 'mfa-verify' } }
          );
          const verifyTime = Date.now() - verifyStart;

          mfaVerificationDuration.add(verifyTime);
          requestCounter.add(1);

          check(verifyRes, {
            'mfa verify returns expected status': (r) =>
              r.status === 200 || r.status === 400 || r.status === 401,
            'mfa verify response time < 200ms': (r) => r.timings.duration < 200,
          });
        }
      } catch (e) {
        // MFA not configured
      }
    }
  });

  sleep(randomIntBetween(1, 2));

  // -------------------------------------------------------------------------
  // Test 7: Session Management
  // -------------------------------------------------------------------------
  group('Authentication - Sessions', () => {
    const sessionsRes = http.get(
      `${BASE_URL}/auth/sessions`,
      { headers: getHeaders(authToken), tags: { name: 'get-sessions' } }
    );

    requestCounter.add(1);

    check(sessionsRes, {
      'sessions status is 200 or 404': (r) => r.status === 200 || r.status === 404,
      'sessions response time < 150ms': (r) => r.timings.duration < 150,
    });
  });

  sleep(randomIntBetween(1, 2));

  // -------------------------------------------------------------------------
  // Test 8: Password Change Validation
  // -------------------------------------------------------------------------
  group('Authentication - Password Validation', () => {
    const passwordRes = http.post(
      `${BASE_URL}/auth/password/validate`,
      JSON.stringify({
        password: 'Test123!@#',
      }),
      { headers: getHeaders(authToken), tags: { name: 'password-validate' } }
    );

    requestCounter.add(1);

    check(passwordRes, {
      'password validate returns expected status': (r) =>
        r.status === 200 || r.status === 400 || r.status === 404,
      'password validate response time < 100ms': (r) => r.timings.duration < 100,
    });
  });

  sleep(randomIntBetween(1, 2));

  // -------------------------------------------------------------------------
  // Test 9: Logout
  // -------------------------------------------------------------------------
  group('Authentication - Logout', () => {
    const logoutStart = Date.now();
    const logoutRes = http.post(
      `${BASE_URL}/auth/logout`,
      null,
      { headers: getHeaders(authToken), tags: { name: 'logout' } }
    );
    const logoutTime = Date.now() - logoutStart;

    logoutDuration.add(logoutTime);
    requestCounter.add(1);

    const logoutSuccess = check(logoutRes, {
      'logout status is 200 or 204': (r) => r.status === 200 || r.status === 204,
      'logout response time < 100ms': (r) => r.timings.duration < 100,
    });

    errorRate.add(!logoutSuccess);
  });

  activeUsers.add(-1);

  // Think time before next iteration
  sleep(randomIntBetween(2, 5));
}

// ============================================================================
// TEARDOWN
// ============================================================================

export function teardown(data) {
  const duration = (Date.now() - data.startTime) / 1000;
  console.log(`Auth Load Test completed - Duration: ${duration.toFixed(2)}s`);
  console.log(`Scenario: ${data.scenario}`);
}

// ============================================================================
// CUSTOM SUMMARY
// ============================================================================

export function handleSummary(data) {
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');

  return {
    [`testing/performance-tests/results/auth-load-${SCENARIO}-${timestamp}.json`]: JSON.stringify(data, null, 2),
    stdout: generateTextSummary(data),
  };
}

function generateTextSummary(data) {
  const metrics = data.metrics;

  let summary = `
================================================================================
                    APOLLO PLATFORM - AUTH LOAD TEST RESULTS
================================================================================
Scenario: ${SCENARIO}
Timestamp: ${new Date().toISOString()}

PERFORMANCE METRICS:
--------------------------------------------------------------------------------
Login:
  - p50: ${metrics.login_duration_ms?.values?.['p(50)']?.toFixed(2) || 'N/A'} ms
  - p95: ${metrics.login_duration_ms?.values?.['p(95)']?.toFixed(2) || 'N/A'} ms
  - p99: ${metrics.login_duration_ms?.values?.['p(99)']?.toFixed(2) || 'N/A'} ms

Token Refresh:
  - p50: ${metrics.token_refresh_duration_ms?.values?.['p(50)']?.toFixed(2) || 'N/A'} ms
  - p95: ${metrics.token_refresh_duration_ms?.values?.['p(95)']?.toFixed(2) || 'N/A'} ms
  - p99: ${metrics.token_refresh_duration_ms?.values?.['p(99)']?.toFixed(2) || 'N/A'} ms

Logout:
  - p50: ${metrics.logout_duration_ms?.values?.['p(50)']?.toFixed(2) || 'N/A'} ms
  - p95: ${metrics.logout_duration_ms?.values?.['p(95)']?.toFixed(2) || 'N/A'} ms
  - p99: ${metrics.logout_duration_ms?.values?.['p(99)']?.toFixed(2) || 'N/A'} ms

RELIABILITY METRICS:
--------------------------------------------------------------------------------
Total Requests: ${metrics.total_requests?.values?.count || 'N/A'}
Login Success Rate: ${((metrics.login_success_rate?.values?.rate || 0) * 100).toFixed(2)}%
Error Rate: ${((metrics.errors?.values?.rate || 0) * 100).toFixed(2)}%
HTTP Failure Rate: ${((metrics.http_req_failed?.values?.rate || 0) * 100).toFixed(2)}%

THRESHOLD RESULTS:
--------------------------------------------------------------------------------
`;

  // Add threshold check results
  if (data.root_group?.checks) {
    for (const check of data.root_group.checks) {
      const status = check.passes === check.fails + check.passes ? 'PASS' : 'FAIL';
      summary += `${status}: ${check.name}\n`;
    }
  }

  summary += `
================================================================================
`;

  return summary;
}
