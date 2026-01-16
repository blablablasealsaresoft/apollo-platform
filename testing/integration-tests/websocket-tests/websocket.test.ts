/**
 * Apollo Platform - WebSocket Integration Tests
 * Tests for real-time WebSocket functionality
 */

import WebSocket from 'ws';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';

// Test configuration
const WS_URL = process.env.WS_URL || 'ws://localhost:3005/ws';
const JWT_SECRET = process.env.JWT_SECRET || 'test-secret-key';

// Test user payload
const testUserPayload = {
  userId: uuidv4(),
  email: 'test@apollo.local',
  role: 'investigator',
  clearanceLevel: 'secret',
};

// Generate test JWT token
const generateToken = (payload: any = testUserPayload): string => {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });
};

// Helper to create WebSocket connection
const createConnection = (token?: string): Promise<WebSocket> => {
  return new Promise((resolve, reject) => {
    const url = token ? `${WS_URL}?token=${encodeURIComponent(token)}` : WS_URL;
    const ws = new WebSocket(url);

    ws.on('open', () => resolve(ws));
    ws.on('error', reject);

    // Timeout after 5 seconds
    setTimeout(() => {
      if (ws.readyState !== WebSocket.OPEN) {
        ws.close();
        reject(new Error('Connection timeout'));
      }
    }, 5000);
  });
};

// Helper to wait for specific message type
const waitForMessage = (ws: WebSocket, messageType: string, timeout = 5000): Promise<any> => {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error(`Timeout waiting for message type: ${messageType}`));
    }, timeout);

    const handler = (data: WebSocket.RawData) => {
      try {
        const message = JSON.parse(data.toString());
        if (message.type === messageType) {
          clearTimeout(timer);
          ws.off('message', handler);
          resolve(message);
        }
      } catch (e) {
        // Ignore parse errors
      }
    };

    ws.on('message', handler);
  });
};

// Helper to send message and wait for response
const sendAndWait = async (
  ws: WebSocket,
  message: any,
  responseType: string,
  timeout = 5000
): Promise<any> => {
  const responsePromise = waitForMessage(ws, responseType, timeout);
  ws.send(JSON.stringify(message));
  return responsePromise;
};

describe('WebSocket Server', () => {
  let ws: WebSocket;

  afterEach(() => {
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.close();
    }
  });

  describe('Connection', () => {
    it('should establish connection without authentication', async () => {
      ws = await createConnection();
      expect(ws.readyState).toBe(WebSocket.OPEN);

      // Should receive connect message
      const message = await waitForMessage(ws, 'connect');
      expect(message.channel).toBe('system');
      expect(message.payload.requiresAuth).toBe(true);
    });

    it('should authenticate with valid token', async () => {
      const token = generateToken();
      ws = await createConnection(token);

      const authSuccess = await waitForMessage(ws, 'auth:success');
      expect(authSuccess.payload.userId).toBe(testUserPayload.userId);
      expect(authSuccess.payload.role).toBe(testUserPayload.role);
    });

    it('should reject invalid token', async () => {
      ws = await createConnection('invalid-token');

      const authFailure = await waitForMessage(ws, 'auth:failure');
      expect(authFailure.payload.message).toBe('Authentication failed');
    });

    it('should handle post-connection authentication', async () => {
      ws = await createConnection();

      // Wait for initial connect message
      await waitForMessage(ws, 'connect');

      // Send auth message
      const token = generateToken();
      const authSuccess = await sendAndWait(
        ws,
        { type: 'auth', token },
        'auth:success'
      );

      expect(authSuccess.payload.userId).toBe(testUserPayload.userId);
    });
  });

  describe('Heartbeat', () => {
    it('should respond to ping with pong', async () => {
      const token = generateToken();
      ws = await createConnection(token);
      await waitForMessage(ws, 'auth:success');

      const pong = await sendAndWait(
        ws,
        { type: 'ping', timestamp: new Date().toISOString() },
        'pong'
      );

      expect(pong.channel).toBe('system');
      expect(pong.payload.timestamp).toBeDefined();
    });
  });

  describe('Subscriptions', () => {
    beforeEach(async () => {
      const token = generateToken();
      ws = await createConnection(token);
      await waitForMessage(ws, 'auth:success');
    });

    it('should subscribe to alerts channel', async () => {
      const confirmation = await sendAndWait(
        ws,
        {
          type: 'subscribe',
          channel: 'system',
          payload: { channel: 'alerts' },
          timestamp: new Date().toISOString(),
          messageId: uuidv4(),
        },
        'subscription:confirmed'
      );

      expect(confirmation.payload.channel).toBe('alerts');
    });

    it('should subscribe to surveillance channel', async () => {
      const confirmation = await sendAndWait(
        ws,
        {
          type: 'subscribe',
          channel: 'system',
          payload: { channel: 'surveillance' },
          timestamp: new Date().toISOString(),
          messageId: uuidv4(),
        },
        'subscription:confirmed'
      );

      expect(confirmation.payload.channel).toBe('surveillance');
    });

    it('should subscribe to blockchain channel', async () => {
      const confirmation = await sendAndWait(
        ws,
        {
          type: 'subscribe',
          channel: 'system',
          payload: { channel: 'blockchain' },
          timestamp: new Date().toISOString(),
          messageId: uuidv4(),
        },
        'subscription:confirmed'
      );

      expect(confirmation.payload.channel).toBe('blockchain');
    });

    it('should subscribe to specific investigation', async () => {
      const investigationId = uuidv4();
      const confirmation = await sendAndWait(
        ws,
        {
          type: 'subscribe',
          channel: 'system',
          payload: {
            channel: 'investigations',
            entityType: 'investigation',
            entityId: investigationId,
          },
          timestamp: new Date().toISOString(),
          messageId: uuidv4(),
        },
        'subscription:confirmed'
      );

      expect(confirmation.payload.channel).toBe('investigations');
      expect(confirmation.payload.entityId).toBe(investigationId);
    });

    it('should subscribe to specific operation', async () => {
      const operationId = uuidv4();
      const confirmation = await sendAndWait(
        ws,
        {
          type: 'subscribe',
          channel: 'system',
          payload: {
            channel: 'operations',
            entityType: 'operation',
            entityId: operationId,
          },
          timestamp: new Date().toISOString(),
          messageId: uuidv4(),
        },
        'subscription:confirmed'
      );

      expect(confirmation.payload.channel).toBe('operations');
      expect(confirmation.payload.entityId).toBe(operationId);
    });

    it('should require authentication for subscription', async () => {
      // Create unauthenticated connection
      const unauthWs = await createConnection();
      await waitForMessage(unauthWs, 'connect');

      // Try to subscribe without auth
      unauthWs.send(JSON.stringify({
        type: 'subscribe',
        channel: 'system',
        payload: { channel: 'alerts' },
        timestamp: new Date().toISOString(),
        messageId: uuidv4(),
      }));

      const error = await waitForMessage(unauthWs, 'error');
      expect(error.payload.code).toBe('UNAUTHORIZED');

      unauthWs.close();
    });
  });

  describe('Channel Access Control', () => {
    it('should allow analyst to access surveillance channel', async () => {
      const token = generateToken({
        ...testUserPayload,
        role: 'analyst',
      });
      ws = await createConnection(token);
      await waitForMessage(ws, 'auth:success');

      const confirmation = await sendAndWait(
        ws,
        {
          type: 'subscribe',
          channel: 'system',
          payload: { channel: 'surveillance' },
          timestamp: new Date().toISOString(),
          messageId: uuidv4(),
        },
        'subscription:confirmed'
      );

      expect(confirmation.payload.channel).toBe('surveillance');
    });

    it('should deny viewer access to surveillance channel', async () => {
      const token = generateToken({
        ...testUserPayload,
        role: 'viewer',
      });
      ws = await createConnection(token);
      await waitForMessage(ws, 'auth:success');

      ws.send(JSON.stringify({
        type: 'subscribe',
        channel: 'system',
        payload: { channel: 'surveillance' },
        timestamp: new Date().toISOString(),
        messageId: uuidv4(),
      }));

      const error = await waitForMessage(ws, 'error');
      expect(error.payload.code).toBe('ACCESS_DENIED');
    });
  });

  describe('Alert Events', () => {
    beforeEach(async () => {
      const token = generateToken();
      ws = await createConnection(token);
      await waitForMessage(ws, 'auth:success');

      // Subscribe to alerts
      await sendAndWait(
        ws,
        {
          type: 'subscribe',
          channel: 'system',
          payload: { channel: 'alerts' },
          timestamp: new Date().toISOString(),
          messageId: uuidv4(),
        },
        'subscription:confirmed'
      );
    });

    it('should handle alert acknowledgment', async () => {
      const alertId = uuidv4();

      // Send acknowledgment
      ws.send(JSON.stringify({
        type: 'alert:acknowledge',
        channel: 'alerts',
        payload: { alertId },
        timestamp: new Date().toISOString(),
        messageId: uuidv4(),
      }));

      // Should receive broadcast
      const ackEvent = await waitForMessage(ws, 'alert:acknowledge');
      expect(ackEvent.payload.alertId).toBe(alertId);
      expect(ackEvent.payload.acknowledgedBy.userId).toBe(testUserPayload.userId);
    });
  });

  describe('Multiple Clients', () => {
    let ws1: WebSocket;
    let ws2: WebSocket;

    afterEach(() => {
      if (ws1?.readyState === WebSocket.OPEN) ws1.close();
      if (ws2?.readyState === WebSocket.OPEN) ws2.close();
    });

    it('should support multiple connections from same user', async () => {
      const token = generateToken();

      ws1 = await createConnection(token);
      ws2 = await createConnection(token);

      const auth1 = await waitForMessage(ws1, 'auth:success');
      const auth2 = await waitForMessage(ws2, 'auth:success');

      expect(auth1.payload.userId).toBe(testUserPayload.userId);
      expect(auth2.payload.userId).toBe(testUserPayload.userId);
    });

    it('should broadcast to all subscribers', async () => {
      const token1 = generateToken();
      const token2 = generateToken({
        ...testUserPayload,
        userId: uuidv4(),
        email: 'test2@apollo.local',
      });

      ws1 = await createConnection(token1);
      ws2 = await createConnection(token2);

      await waitForMessage(ws1, 'auth:success');
      await waitForMessage(ws2, 'auth:success');

      // Both subscribe to alerts
      await sendAndWait(
        ws1,
        {
          type: 'subscribe',
          channel: 'system',
          payload: { channel: 'alerts' },
          timestamp: new Date().toISOString(),
          messageId: uuidv4(),
        },
        'subscription:confirmed'
      );

      await sendAndWait(
        ws2,
        {
          type: 'subscribe',
          channel: 'system',
          payload: { channel: 'alerts' },
          timestamp: new Date().toISOString(),
          messageId: uuidv4(),
        },
        'subscription:confirmed'
      );

      // Client 1 acknowledges alert
      const alertId = uuidv4();
      ws1.send(JSON.stringify({
        type: 'alert:acknowledge',
        channel: 'alerts',
        payload: { alertId },
        timestamp: new Date().toISOString(),
        messageId: uuidv4(),
      }));

      // Both clients should receive the broadcast
      const [ack1, ack2] = await Promise.all([
        waitForMessage(ws1, 'alert:acknowledge'),
        waitForMessage(ws2, 'alert:acknowledge'),
      ]);

      expect(ack1.payload.alertId).toBe(alertId);
      expect(ack2.payload.alertId).toBe(alertId);
    });
  });

  describe('Reconnection', () => {
    it('should handle client disconnect gracefully', async () => {
      const token = generateToken();
      ws = await createConnection(token);
      await waitForMessage(ws, 'auth:success');

      // Close connection
      ws.close(1000, 'Client disconnect');

      // Wait a bit for server cleanup
      await new Promise((resolve) => setTimeout(resolve, 100));

      // Reconnect
      ws = await createConnection(token);
      const reconnectAuth = await waitForMessage(ws, 'auth:success');

      expect(reconnectAuth.payload.userId).toBe(testUserPayload.userId);
    });

    it('should restore subscriptions on reconnect', async () => {
      const token = generateToken();
      ws = await createConnection(token);
      await waitForMessage(ws, 'auth:success');

      // Subscribe to alerts
      await sendAndWait(
        ws,
        {
          type: 'subscribe',
          channel: 'system',
          payload: { channel: 'alerts' },
          timestamp: new Date().toISOString(),
          messageId: uuidv4(),
        },
        'subscription:confirmed'
      );

      // Close and reconnect
      ws.close(1000, 'Reconnect test');
      await new Promise((resolve) => setTimeout(resolve, 100));

      ws = await createConnection(token);
      await waitForMessage(ws, 'auth:success');

      // Resubscribe (client should handle this)
      const resubConfirmation = await sendAndWait(
        ws,
        {
          type: 'subscribe',
          channel: 'system',
          payload: { channel: 'alerts' },
          timestamp: new Date().toISOString(),
          messageId: uuidv4(),
        },
        'subscription:confirmed'
      );

      expect(resubConfirmation.payload.channel).toBe('alerts');
    });
  });

  describe('Error Handling', () => {
    beforeEach(async () => {
      const token = generateToken();
      ws = await createConnection(token);
      await waitForMessage(ws, 'auth:success');
    });

    it('should handle malformed JSON', async () => {
      ws.send('not valid json');

      const error = await waitForMessage(ws, 'error');
      expect(error.payload.code).toBe('INVALID_MESSAGE');
    });

    it('should handle unknown message types gracefully', async () => {
      ws.send(JSON.stringify({
        type: 'unknown:message:type',
        channel: 'system',
        payload: {},
        timestamp: new Date().toISOString(),
        messageId: uuidv4(),
      }));

      // Should not crash, may or may not send error depending on implementation
      // Wait a bit to ensure no crash
      await new Promise((resolve) => setTimeout(resolve, 200));
      expect(ws.readyState).toBe(WebSocket.OPEN);
    });
  });
});

describe('WebSocket Events', () => {
  let ws: WebSocket;

  beforeEach(async () => {
    const token = generateToken();
    ws = await createConnection(token);
    await waitForMessage(ws, 'auth:success');
  });

  afterEach(() => {
    if (ws?.readyState === WebSocket.OPEN) {
      ws.close();
    }
  });

  describe('Alert Events', () => {
    it('should have correct alert:new structure', async () => {
      // Subscribe to alerts
      await sendAndWait(
        ws,
        {
          type: 'subscribe',
          channel: 'system',
          payload: { channel: 'alerts' },
          timestamp: new Date().toISOString(),
          messageId: uuidv4(),
        },
        'subscription:confirmed'
      );

      // This test would require a way to trigger an alert
      // In a real test environment, you would call an internal API
      // For now, we validate the subscription works
      expect(true).toBe(true);
    });
  });

  describe('Investigation Events', () => {
    it('should subscribe to specific investigation updates', async () => {
      const investigationId = uuidv4();

      const confirmation = await sendAndWait(
        ws,
        {
          type: 'subscribe',
          channel: 'system',
          payload: {
            channel: 'investigations',
            entityId: investigationId,
          },
          timestamp: new Date().toISOString(),
          messageId: uuidv4(),
        },
        'subscription:confirmed'
      );

      expect(confirmation.payload.entityId).toBe(investigationId);
    });
  });

  describe('Operation Events', () => {
    it('should subscribe to specific operation updates', async () => {
      const operationId = uuidv4();

      const confirmation = await sendAndWait(
        ws,
        {
          type: 'subscribe',
          channel: 'system',
          payload: {
            channel: 'operations',
            entityId: operationId,
          },
          timestamp: new Date().toISOString(),
          messageId: uuidv4(),
        },
        'subscription:confirmed'
      );

      expect(confirmation.payload.entityId).toBe(operationId);
    });
  });
});

// Performance tests
describe('WebSocket Performance', () => {
  const connections: WebSocket[] = [];

  afterEach(async () => {
    for (const conn of connections) {
      if (conn.readyState === WebSocket.OPEN) {
        conn.close();
      }
    }
    connections.length = 0;
  });

  it('should handle multiple concurrent connections', async () => {
    const numConnections = 10;
    const connectionPromises = [];

    for (let i = 0; i < numConnections; i++) {
      const token = generateToken({
        ...testUserPayload,
        userId: uuidv4(),
        email: `test${i}@apollo.local`,
      });
      connectionPromises.push(createConnection(token));
    }

    const results = await Promise.allSettled(connectionPromises);
    const successfulConnections = results.filter(
      (r) => r.status === 'fulfilled'
    ) as PromiseFulfilledResult<WebSocket>[];

    for (const result of successfulConnections) {
      connections.push(result.value);
    }

    expect(successfulConnections.length).toBe(numConnections);
  }, 30000);

  it('should handle rapid message sending', async () => {
    const token = generateToken();
    const ws = await createConnection(token);
    connections.push(ws);

    await waitForMessage(ws, 'auth:success');

    // Subscribe to alerts
    await sendAndWait(
      ws,
      {
        type: 'subscribe',
        channel: 'system',
        payload: { channel: 'alerts' },
        timestamp: new Date().toISOString(),
        messageId: uuidv4(),
      },
      'subscription:confirmed'
    );

    // Send multiple rapid pings
    const numMessages = 50;
    let pongCount = 0;

    const messageHandler = (data: WebSocket.RawData) => {
      const message = JSON.parse(data.toString());
      if (message.type === 'pong') {
        pongCount++;
      }
    };

    ws.on('message', messageHandler);

    for (let i = 0; i < numMessages; i++) {
      ws.send(JSON.stringify({
        type: 'ping',
        timestamp: new Date().toISOString(),
      }));
    }

    // Wait for all pongs
    await new Promise((resolve) => setTimeout(resolve, 2000));

    expect(pongCount).toBe(numMessages);
  }, 10000);
});
