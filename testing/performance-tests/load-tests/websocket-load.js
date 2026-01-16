/**
 * Apollo Platform - WebSocket Load Test
 *
 * Tests WebSocket connections for real-time features:
 * - Connection establishment and stability
 * - Message throughput and latency
 * - Subscription performance
 * - Broadcast handling
 * - Reconnection scenarios
 *
 * Run: k6 run websocket-load.js
 * Run with env: k6 run -e WS_URL=ws://localhost:3000/ws websocket-load.js
 * Run specific scenario: k6 run --env SCENARIO=stress websocket-load.js
 */

import { check, sleep, group } from 'k6';
import ws from 'k6/ws';
import http from 'k6/http';
import { Rate, Trend, Counter, Gauge } from 'k6/metrics';
import { randomIntBetween, randomItem, randomString } from 'https://jslib.k6.io/k6-utils/1.4.0/index.js';

// ============================================================================
// CUSTOM METRICS
// ============================================================================

// Connection metrics
const connectionDuration = new Trend('ws_connection_duration_ms');
const connectionSuccessRate = new Rate('ws_connection_success_rate');
const activeConnections = new Gauge('ws_active_connections');

// Message metrics
const messageSendDuration = new Trend('ws_message_send_duration_ms');
const messageReceiveLatency = new Trend('ws_message_receive_latency_ms');
const messageCounter = new Counter('ws_total_messages');
const messagesReceived = new Counter('ws_messages_received');
const messagesSent = new Counter('ws_messages_sent');

// Subscription metrics
const subscriptionDuration = new Trend('ws_subscription_duration_ms');
const subscriptionSuccessRate = new Rate('ws_subscription_success_rate');
const activeSubscriptions = new Gauge('ws_active_subscriptions');

// Error metrics
const errorRate = new Rate('ws_errors');
const disconnectionCounter = new Counter('ws_disconnections');
const reconnectionCounter = new Counter('ws_reconnections');

// ============================================================================
// CONFIGURATION
// ============================================================================

const WS_URL = __ENV.WS_URL || 'ws://localhost:3000/ws';
const API_URL = __ENV.API_URL || 'http://localhost:3000/api';
const SCENARIO = __ENV.SCENARIO || 'load';

const scenarios = {
  // Smoke test: Quick verification with minimal connections
  smoke: {
    executor: 'constant-vus',
    vus: 5,
    duration: '2m',
  },
  // Load test: Normal expected WebSocket load
  load: {
    executor: 'ramping-vus',
    startVUs: 0,
    stages: [
      { duration: '1m', target: 25 },    // Ramp up
      { duration: '3m', target: 25 },    // Steady state
      { duration: '1m', target: 50 },    // Increase
      { duration: '3m', target: 50 },    // Steady state
      { duration: '1m', target: 100 },   // Peak
      { duration: '3m', target: 100 },   // Steady state
      { duration: '1m', target: 0 },     // Ramp down
    ],
    gracefulRampDown: '30s',
  },
  // Stress test: Push WebSocket beyond normal capacity
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
  // Spike test: Sudden connection burst
  spike: {
    executor: 'ramping-vus',
    startVUs: 1,
    stages: [
      { duration: '30s', target: 20 },
      { duration: '15s', target: 500 },   // Spike!
      { duration: '1m', target: 500 },    // Hold spike
      { duration: '15s', target: 20 },    // Drop
      { duration: '30s', target: 20 },
      { duration: '15s', target: 0 },
    ],
    gracefulRampDown: '30s',
  },
  // Soak test: Long duration connection stability
  soak: {
    executor: 'constant-vus',
    vus: 50,
    duration: '30m',
  },
};

export const options = {
  scenarios: {
    websocket_test: scenarios[SCENARIO],
  },
  thresholds: {
    // Connection thresholds
    ws_connection_duration_ms: ['p(95)<500', 'p(99)<1000'],
    ws_connection_success_rate: ['rate>0.95'],

    // Message latency thresholds
    ws_message_send_duration_ms: ['p(95)<100', 'p(99)<200'],
    ws_message_receive_latency_ms: ['p(95)<200', 'p(99)<500'],

    // Subscription thresholds
    ws_subscription_duration_ms: ['p(95)<300', 'p(99)<500'],
    ws_subscription_success_rate: ['rate>0.95'],

    // Error thresholds
    ws_errors: ['rate<0.05'],
  },
  tags: {
    testType: 'websocket-load',
    scenario: SCENARIO,
  },
};

// ============================================================================
// TEST DATA
// ============================================================================

// Channels to subscribe to
const channels = [
  'investigations',
  'targets',
  'alerts',
  'intelligence',
  'operations',
  'notifications',
  'system',
];

// Event types
const eventTypes = [
  'investigation.created',
  'investigation.updated',
  'target.updated',
  'alert.triggered',
  'intelligence.collected',
  'operation.status_changed',
  'notification.new',
];

// Message types
const messageTypes = {
  SUBSCRIBE: 'subscribe',
  UNSUBSCRIBE: 'unsubscribe',
  PING: 'ping',
  PONG: 'pong',
  MESSAGE: 'message',
  BROADCAST: 'broadcast',
  ACK: 'ack',
};

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

function generateSubscriptionMessage(channel) {
  return JSON.stringify({
    type: messageTypes.SUBSCRIBE,
    channel: channel,
    timestamp: Date.now(),
    requestId: `sub-${__VU}-${__ITER}-${Date.now()}`,
  });
}

function generateUnsubscribeMessage(channel) {
  return JSON.stringify({
    type: messageTypes.UNSUBSCRIBE,
    channel: channel,
    timestamp: Date.now(),
    requestId: `unsub-${__VU}-${__ITER}-${Date.now()}`,
  });
}

function generatePingMessage() {
  return JSON.stringify({
    type: messageTypes.PING,
    timestamp: Date.now(),
    requestId: `ping-${__VU}-${__ITER}-${Date.now()}`,
  });
}

function generateDataMessage(channel) {
  return JSON.stringify({
    type: messageTypes.MESSAGE,
    channel: channel,
    data: {
      eventType: randomItem(eventTypes),
      payload: {
        id: `${__VU}-${__ITER}-${Date.now()}`,
        value: randomString(50),
        timestamp: Date.now(),
      },
    },
    timestamp: Date.now(),
    requestId: `msg-${__VU}-${__ITER}-${Date.now()}`,
  });
}

// ============================================================================
// SETUP
// ============================================================================

export function setup() {
  console.log(`Starting WebSocket Load Test - Scenario: ${SCENARIO}`);
  console.log(`WebSocket URL: ${WS_URL}`);
  console.log(`API URL: ${API_URL}`);

  // Get auth token for WebSocket authentication
  const loginRes = http.post(
    `${API_URL}/auth/login`,
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

  // Verify WebSocket endpoint is reachable
  const healthCheck = http.get(`${API_URL}/health`);
  if (healthCheck.status !== 200) {
    console.warn('API health check failed, WebSocket tests may not work correctly');
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
  const wsUrl = data.token ? `${WS_URL}?token=${data.token}` : WS_URL;

  let connectionStart = Date.now();
  let isConnected = false;
  let subscriptions = [];
  let pendingMessages = new Map();

  const res = ws.connect(wsUrl, {
    tags: { name: 'websocket-connection' },
  }, function(socket) {
    isConnected = true;
    const connectionTime = Date.now() - connectionStart;
    connectionDuration.add(connectionTime);
    connectionSuccessRate.add(1);
    activeConnections.add(1);

    // -------------------------------------------------------------------------
    // Connection Established Handler
    // -------------------------------------------------------------------------
    socket.on('open', () => {
      console.log(`VU ${__VU}: WebSocket connected in ${connectionTime}ms`);

      // Test 1: Ping/Pong
      group('WebSocket - Ping/Pong', () => {
        const pingStart = Date.now();
        const pingMsg = generatePingMessage();
        const pingId = JSON.parse(pingMsg).requestId;

        pendingMessages.set(pingId, pingStart);
        socket.send(pingMsg);
        messagesSent.add(1);
        messageCounter.add(1);
      });

      sleep(1);

      // Test 2: Subscribe to channels
      group('WebSocket - Channel Subscriptions', () => {
        const channelsToSubscribe = channels.slice(0, randomIntBetween(2, 5));

        for (const channel of channelsToSubscribe) {
          const subStart = Date.now();
          const subMsg = generateSubscriptionMessage(channel);
          const subId = JSON.parse(subMsg).requestId;

          pendingMessages.set(subId, subStart);
          socket.send(subMsg);
          messagesSent.add(1);
          messageCounter.add(1);
          subscriptions.push(channel);

          sleep(0.2);
        }

        activeSubscriptions.add(subscriptions.length);
      });

      sleep(2);

      // Test 3: Send data messages
      group('WebSocket - Data Messages', () => {
        const messageCount = randomIntBetween(3, 10);

        for (let i = 0; i < messageCount; i++) {
          const channel = randomItem(subscriptions.length > 0 ? subscriptions : channels);
          const sendStart = Date.now();
          const dataMsg = generateDataMessage(channel);
          const msgId = JSON.parse(dataMsg).requestId;

          pendingMessages.set(msgId, sendStart);
          socket.send(dataMsg);

          const sendDuration = Date.now() - sendStart;
          messageSendDuration.add(sendDuration);
          messagesSent.add(1);
          messageCounter.add(1);

          sleep(randomIntBetween(1, 3) / 10);
        }
      });

      sleep(2);

      // Test 4: Unsubscribe from some channels
      group('WebSocket - Unsubscribe', () => {
        if (subscriptions.length > 1) {
          const channelToUnsub = subscriptions.pop();
          const unsubMsg = generateUnsubscribeMessage(channelToUnsub);

          socket.send(unsubMsg);
          messagesSent.add(1);
          messageCounter.add(1);
          activeSubscriptions.add(-1);
        }
      });

      sleep(2);

      // Test 5: Burst of messages
      group('WebSocket - Message Burst', () => {
        const burstSize = randomIntBetween(5, 15);
        const burstStart = Date.now();

        for (let i = 0; i < burstSize; i++) {
          const channel = randomItem(subscriptions.length > 0 ? subscriptions : channels);
          const dataMsg = generateDataMessage(channel);
          socket.send(dataMsg);
          messagesSent.add(1);
          messageCounter.add(1);
        }

        const burstDuration = Date.now() - burstStart;
        console.log(`VU ${__VU}: Sent ${burstSize} messages in ${burstDuration}ms`);
      });

      // Schedule close
      socket.setTimeout(() => {
        // Clean up subscriptions
        for (const channel of subscriptions) {
          socket.send(generateUnsubscribeMessage(channel));
          messagesSent.add(1);
        }

        socket.close();
      }, randomIntBetween(8000, 15000));
    });

    // -------------------------------------------------------------------------
    // Message Handler
    // -------------------------------------------------------------------------
    socket.on('message', (msg) => {
      messagesReceived.add(1);
      messageCounter.add(1);

      try {
        const data = JSON.parse(msg);

        // Handle pong response
        if (data.type === messageTypes.PONG || data.type === 'pong') {
          if (data.requestId && pendingMessages.has(data.requestId)) {
            const latency = Date.now() - pendingMessages.get(data.requestId);
            messageReceiveLatency.add(latency);
            pendingMessages.delete(data.requestId);
          }
        }

        // Handle subscription acknowledgment
        if (data.type === messageTypes.ACK || data.type === 'ack') {
          if (data.requestId && pendingMessages.has(data.requestId)) {
            const subTime = Date.now() - pendingMessages.get(data.requestId);
            subscriptionDuration.add(subTime);
            subscriptionSuccessRate.add(1);
            pendingMessages.delete(data.requestId);
          }
        }

        // Handle broadcast messages
        if (data.type === messageTypes.BROADCAST || data.type === 'broadcast') {
          // Measure latency if timestamp available
          if (data.timestamp) {
            const latency = Date.now() - data.timestamp;
            if (latency > 0 && latency < 60000) {
              messageReceiveLatency.add(latency);
            }
          }
        }

        // Handle regular messages
        if (data.type === messageTypes.MESSAGE || data.type === 'message') {
          if (data.requestId && pendingMessages.has(data.requestId)) {
            const latency = Date.now() - pendingMessages.get(data.requestId);
            messageReceiveLatency.add(latency);
            pendingMessages.delete(data.requestId);
          }
        }

      } catch (e) {
        // Non-JSON message or parse error
        console.log(`VU ${__VU}: Received non-JSON message`);
      }
    });

    // -------------------------------------------------------------------------
    // Error Handler
    // -------------------------------------------------------------------------
    socket.on('error', (e) => {
      console.error(`VU ${__VU}: WebSocket error: ${e.message || e}`);
      errorRate.add(1);
    });

    // -------------------------------------------------------------------------
    // Close Handler
    // -------------------------------------------------------------------------
    socket.on('close', () => {
      console.log(`VU ${__VU}: WebSocket closed`);
      activeConnections.add(-1);
      activeSubscriptions.add(-subscriptions.length);
      disconnectionCounter.add(1);
      isConnected = false;
    });
  });

  // Check connection result
  check(res, {
    'WebSocket connection established': (r) => r && r.status === 101,
  });

  if (!res || res.status !== 101) {
    connectionSuccessRate.add(0);
    errorRate.add(1);
  }

  // Think time before next iteration
  sleep(randomIntBetween(2, 5));
}

// ============================================================================
// TEARDOWN
// ============================================================================

export function teardown(data) {
  const duration = (Date.now() - data.startTime) / 1000;
  console.log(`WebSocket Load Test completed - Duration: ${duration.toFixed(2)}s`);
  console.log(`Scenario: ${data.scenario}`);
}

// ============================================================================
// CUSTOM SUMMARY
// ============================================================================

export function handleSummary(data) {
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');

  return {
    [`testing/performance-tests/results/websocket-load-${SCENARIO}-${timestamp}.json`]: JSON.stringify(data, null, 2),
    stdout: generateTextSummary(data),
  };
}

function generateTextSummary(data) {
  const metrics = data.metrics;

  return `
================================================================================
                  APOLLO PLATFORM - WEBSOCKET LOAD TEST RESULTS
================================================================================
Scenario: ${SCENARIO}
Timestamp: ${new Date().toISOString()}

CONNECTION METRICS:
--------------------------------------------------------------------------------
Connection Duration:
  - p50: ${metrics.ws_connection_duration_ms?.values?.['p(50)']?.toFixed(2) || 'N/A'} ms
  - p95: ${metrics.ws_connection_duration_ms?.values?.['p(95)']?.toFixed(2) || 'N/A'} ms
  - p99: ${metrics.ws_connection_duration_ms?.values?.['p(99)']?.toFixed(2) || 'N/A'} ms

Connection Success Rate: ${((metrics.ws_connection_success_rate?.values?.rate || 0) * 100).toFixed(2)}%

MESSAGE METRICS:
--------------------------------------------------------------------------------
Message Send Duration:
  - p50: ${metrics.ws_message_send_duration_ms?.values?.['p(50)']?.toFixed(2) || 'N/A'} ms
  - p95: ${metrics.ws_message_send_duration_ms?.values?.['p(95)']?.toFixed(2) || 'N/A'} ms
  - p99: ${metrics.ws_message_send_duration_ms?.values?.['p(99)']?.toFixed(2) || 'N/A'} ms

Message Receive Latency:
  - p50: ${metrics.ws_message_receive_latency_ms?.values?.['p(50)']?.toFixed(2) || 'N/A'} ms
  - p95: ${metrics.ws_message_receive_latency_ms?.values?.['p(95)']?.toFixed(2) || 'N/A'} ms
  - p99: ${metrics.ws_message_receive_latency_ms?.values?.['p(99)']?.toFixed(2) || 'N/A'} ms

SUBSCRIPTION METRICS:
--------------------------------------------------------------------------------
Subscription Duration:
  - p50: ${metrics.ws_subscription_duration_ms?.values?.['p(50)']?.toFixed(2) || 'N/A'} ms
  - p95: ${metrics.ws_subscription_duration_ms?.values?.['p(95)']?.toFixed(2) || 'N/A'} ms
  - p99: ${metrics.ws_subscription_duration_ms?.values?.['p(99)']?.toFixed(2) || 'N/A'} ms

Subscription Success Rate: ${((metrics.ws_subscription_success_rate?.values?.rate || 0) * 100).toFixed(2)}%

THROUGHPUT:
--------------------------------------------------------------------------------
Total Messages: ${metrics.ws_total_messages?.values?.count || 'N/A'}
Messages Sent: ${metrics.ws_messages_sent?.values?.count || 'N/A'}
Messages Received: ${metrics.ws_messages_received?.values?.count || 'N/A'}
Disconnections: ${metrics.ws_disconnections?.values?.count || 'N/A'}
Reconnections: ${metrics.ws_reconnections?.values?.count || 'N/A'}

RELIABILITY:
--------------------------------------------------------------------------------
Error Rate: ${((metrics.ws_errors?.values?.rate || 0) * 100).toFixed(2)}%

================================================================================
`;
}
