/**
 * Apollo Platform - WebSocket Server
 * Comprehensive real-time communication server with JWT authentication,
 * multiple channels/rooms, heartbeat management, and Redis pub/sub integration
 */

import { WebSocketServer as WSServer, WebSocket, RawData } from 'ws';
import { IncomingMessage, Server } from 'http';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import { config, logger, redis, JWTPayload } from '@apollo/shared';
import {
  WebSocketEventType,
  WebSocketChannel,
  WebSocketMessage,
  ConnectedClient,
  SubscriptionRequest,
  RedisPubSubMessage,
  HeartbeatMessage,
  ErrorPayload,
  AlertPayload,
  SurveillanceMatchPayload,
  BlockchainTransactionPayload,
  InvestigationUpdatePayload,
  OperationStatusPayload,
  WebSocketStats,
} from './types';

// Extended WebSocket with client info
interface ExtendedWebSocket extends WebSocket {
  clientId: string;
  userId?: string;
  username?: string;
  role?: string;
  clearanceLevel?: string;
  isAlive: boolean;
  connectedAt: Date;
  lastActivity: Date;
  subscriptions: Set<string>;
  ipAddress: string;
  userAgent: string;
  authenticated: boolean;
}

// Redis channels for pub/sub
const REDIS_CHANNELS = {
  ALERTS: 'ws:alerts',
  SURVEILLANCE: 'ws:surveillance',
  BLOCKCHAIN: 'ws:blockchain',
  INVESTIGATIONS: 'ws:investigations',
  OPERATIONS: 'ws:operations',
  NOTIFICATIONS: 'ws:notifications',
  BROADCAST: 'ws:broadcast',
};

export class ApolloWebSocketServer {
  private wss: WSServer;
  private clients: Map<string, ExtendedWebSocket> = new Map();
  private userConnections: Map<string, Set<string>> = new Map();
  private channelSubscriptions: Map<string, Set<string>> = new Map();
  private heartbeatInterval: NodeJS.Timeout | null = null;
  private statsInterval: NodeJS.Timeout | null = null;
  private stats: WebSocketStats;

  constructor(server: Server) {
    this.wss = new WSServer({
      server,
      path: '/ws',
      clientTracking: true,
      perMessageDeflate: {
        zlibDeflateOptions: {
          chunkSize: 1024,
          memLevel: 7,
          level: 3,
        },
        zlibInflateOptions: {
          chunkSize: 10 * 1024,
        },
        clientNoContextTakeover: true,
        serverNoContextTakeover: true,
        serverMaxWindowBits: 10,
        concurrencyLimit: 10,
        threshold: 1024,
      },
    });

    this.stats = {
      totalConnections: 0,
      authenticatedConnections: 0,
      activeSubscriptions: new Map(),
      messagesPerMinute: 0,
      peakConnections: 0,
      uptime: Date.now(),
    };

    this.initialize();
  }

  private async initialize(): Promise<void> {
    // Setup WebSocket connection handler
    this.wss.on('connection', this.handleConnection.bind(this));

    // Setup heartbeat interval (every 30 seconds)
    this.heartbeatInterval = setInterval(() => this.heartbeat(), 30000);

    // Setup stats collection (every minute)
    this.statsInterval = setInterval(() => this.collectStats(), 60000);

    // Subscribe to Redis pub/sub channels
    await this.subscribeToRedisChannels();

    logger.info('Apollo WebSocket Server initialized');
  }

  private handleConnection(ws: WebSocket, request: IncomingMessage): void {
    const extWs = ws as ExtendedWebSocket;
    const clientId = uuidv4();

    // Initialize client properties
    extWs.clientId = clientId;
    extWs.isAlive = true;
    extWs.connectedAt = new Date();
    extWs.lastActivity = new Date();
    extWs.subscriptions = new Set();
    extWs.authenticated = false;
    extWs.ipAddress = this.getClientIP(request);
    extWs.userAgent = request.headers['user-agent'] || 'unknown';

    // Store client
    this.clients.set(clientId, extWs);
    this.stats.totalConnections++;

    if (this.stats.totalConnections > this.stats.peakConnections) {
      this.stats.peakConnections = this.stats.totalConnections;
    }

    logger.info(`WebSocket client connected: ${clientId} from ${extWs.ipAddress}`);

    // Try to authenticate from URL token
    const url = new URL(request.url || '', `http://${request.headers.host}`);
    const token = url.searchParams.get('token');
    if (token) {
      this.authenticateClient(extWs, token);
    }

    // Setup event handlers
    extWs.on('message', (data: RawData) => this.handleMessage(extWs, data));
    extWs.on('close', () => this.handleClose(extWs));
    extWs.on('error', (error) => this.handleError(extWs, error));
    extWs.on('pong', () => {
      extWs.isAlive = true;
      extWs.lastActivity = new Date();
    });

    // Send connection acknowledgment
    this.sendToClient(extWs, {
      type: WebSocketEventType.CONNECT,
      channel: WebSocketChannel.SYSTEM,
      payload: {
        clientId,
        message: 'Connected to Apollo WebSocket Server',
        requiresAuth: true,
      },
      timestamp: new Date().toISOString(),
      messageId: uuidv4(),
    });
  }

  private async handleMessage(client: ExtendedWebSocket, rawData: RawData): Promise<void> {
    try {
      const message = JSON.parse(rawData.toString());
      client.lastActivity = new Date();

      // Handle authentication
      if (message.type === 'auth') {
        await this.authenticateClient(client, message.token);
        return;
      }

      // Handle heartbeat
      if (message.type === 'ping') {
        this.sendToClient(client, {
          type: WebSocketEventType.PONG,
          channel: WebSocketChannel.SYSTEM,
          payload: { timestamp: new Date().toISOString() },
          timestamp: new Date().toISOString(),
          messageId: uuidv4(),
        });
        return;
      }

      // Require authentication for other messages
      if (!client.authenticated) {
        this.sendError(client, 'UNAUTHORIZED', 'Authentication required');
        return;
      }

      // Handle subscriptions
      if (message.type === WebSocketEventType.SUBSCRIBE) {
        await this.handleSubscribe(client, message.payload);
        return;
      }

      if (message.type === WebSocketEventType.UNSUBSCRIBE) {
        await this.handleUnsubscribe(client, message.payload);
        return;
      }

      // Handle other message types
      await this.processMessage(client, message);

    } catch (error) {
      logger.error(`Error processing WebSocket message: ${error}`);
      this.sendError(client, 'INVALID_MESSAGE', 'Failed to process message');
    }
  }

  private async authenticateClient(client: ExtendedWebSocket, token: string): Promise<void> {
    try {
      const decoded = jwt.verify(token, config.jwt.secret) as JWTPayload;

      client.userId = decoded.userId;
      client.role = decoded.role;
      client.clearanceLevel = decoded.clearanceLevel;
      client.authenticated = true;

      // Track user connections
      if (!this.userConnections.has(decoded.userId)) {
        this.userConnections.set(decoded.userId, new Set());
      }
      this.userConnections.get(decoded.userId)!.add(client.clientId);

      this.stats.authenticatedConnections++;

      // Auto-subscribe to user channel
      await this.subscribeToChannel(client, WebSocketChannel.USER, decoded.userId);

      // Send auth success
      this.sendToClient(client, {
        type: WebSocketEventType.AUTH_SUCCESS,
        channel: WebSocketChannel.SYSTEM,
        payload: {
          userId: decoded.userId,
          role: decoded.role,
          clearanceLevel: decoded.clearanceLevel,
          message: 'Authentication successful',
        },
        timestamp: new Date().toISOString(),
        messageId: uuidv4(),
        userId: decoded.userId,
      });

      logger.info(`Client ${client.clientId} authenticated as user ${decoded.userId}`);

    } catch (error) {
      logger.warn(`Authentication failed for client ${client.clientId}: ${error}`);
      this.sendToClient(client, {
        type: WebSocketEventType.AUTH_FAILURE,
        channel: WebSocketChannel.SYSTEM,
        payload: {
          message: 'Authentication failed',
          error: 'Invalid or expired token',
        },
        timestamp: new Date().toISOString(),
        messageId: uuidv4(),
      });
    }
  }

  private async handleSubscribe(client: ExtendedWebSocket, request: SubscriptionRequest): Promise<void> {
    const { channel, entityType, entityId } = request;

    // Validate clearance level for certain channels
    if (!this.canAccessChannel(client, channel)) {
      this.sendError(client, 'ACCESS_DENIED', `Insufficient clearance for channel: ${channel}`);
      return;
    }

    await this.subscribeToChannel(client, channel, entityId);

    this.sendToClient(client, {
      type: WebSocketEventType.SUBSCRIPTION_CONFIRMED,
      channel: WebSocketChannel.SYSTEM,
      payload: {
        channel,
        entityType,
        entityId,
        message: 'Subscription confirmed',
      },
      timestamp: new Date().toISOString(),
      messageId: uuidv4(),
      userId: client.userId,
    });

    logger.info(`Client ${client.clientId} subscribed to ${channel}${entityId ? `:${entityId}` : ''}`);
  }

  private async handleUnsubscribe(client: ExtendedWebSocket, request: SubscriptionRequest): Promise<void> {
    const { channel, entityId } = request;
    const channelKey = entityId ? `${channel}:${entityId}` : channel;

    client.subscriptions.delete(channelKey);

    const subscribers = this.channelSubscriptions.get(channelKey);
    if (subscribers) {
      subscribers.delete(client.clientId);
      if (subscribers.size === 0) {
        this.channelSubscriptions.delete(channelKey);
      }
    }

    logger.info(`Client ${client.clientId} unsubscribed from ${channelKey}`);
  }

  private async subscribeToChannel(client: ExtendedWebSocket, channel: WebSocketChannel, entityId?: string): Promise<void> {
    const channelKey = entityId ? `${channel}:${entityId}` : channel;

    client.subscriptions.add(channelKey);

    if (!this.channelSubscriptions.has(channelKey)) {
      this.channelSubscriptions.set(channelKey, new Set());
    }
    this.channelSubscriptions.get(channelKey)!.add(client.clientId);

    // Update stats
    const currentCount = this.stats.activeSubscriptions.get(channel) || 0;
    this.stats.activeSubscriptions.set(channel, currentCount + 1);
  }

  private canAccessChannel(client: ExtendedWebSocket, channel: WebSocketChannel): boolean {
    // Implement clearance level checks
    const restrictedChannels = [WebSocketChannel.SURVEILLANCE, WebSocketChannel.OPERATIONS];
    if (restrictedChannels.includes(channel)) {
      const allowedRoles = ['admin', 'investigator', 'analyst'];
      return allowedRoles.includes(client.role || '');
    }
    return true;
  }

  private async processMessage(client: ExtendedWebSocket, message: any): Promise<void> {
    // Route messages to appropriate handlers
    switch (message.type) {
      case 'alert:acknowledge':
        await this.handleAlertAcknowledge(client, message.payload);
        break;
      case 'investigation:view':
        await this.handleInvestigationView(client, message.payload);
        break;
      default:
        logger.debug(`Unhandled message type: ${message.type}`);
    }
  }

  private async handleAlertAcknowledge(client: ExtendedWebSocket, payload: any): Promise<void> {
    // Broadcast acknowledgment to all subscribed clients
    await this.broadcastToChannel(WebSocketChannel.ALERTS, {
      type: WebSocketEventType.ALERT_ACKNOWLEDGE,
      channel: WebSocketChannel.ALERTS,
      payload: {
        alertId: payload.alertId,
        acknowledgedBy: {
          userId: client.userId,
          timestamp: new Date().toISOString(),
        },
      },
      timestamp: new Date().toISOString(),
      messageId: uuidv4(),
      userId: client.userId,
    });
  }

  private async handleInvestigationView(client: ExtendedWebSocket, payload: any): Promise<void> {
    // Track who is viewing an investigation
    const investigationId = payload.investigationId;
    // Could broadcast presence info to other viewers
  }

  private handleClose(client: ExtendedWebSocket): void {
    logger.info(`WebSocket client disconnected: ${client.clientId}`);

    // Remove from clients map
    this.clients.delete(client.clientId);

    // Remove from user connections
    if (client.userId) {
      const userClients = this.userConnections.get(client.userId);
      if (userClients) {
        userClients.delete(client.clientId);
        if (userClients.size === 0) {
          this.userConnections.delete(client.userId);
        }
      }
    }

    // Remove from all channel subscriptions
    for (const [channelKey, subscribers] of this.channelSubscriptions.entries()) {
      subscribers.delete(client.clientId);
      if (subscribers.size === 0) {
        this.channelSubscriptions.delete(channelKey);
      }
    }

    // Update stats
    this.stats.totalConnections--;
    if (client.authenticated) {
      this.stats.authenticatedConnections--;
    }
  }

  private handleError(client: ExtendedWebSocket, error: Error): void {
    logger.error(`WebSocket error for client ${client.clientId}: ${error.message}`);
  }

  private sendError(client: ExtendedWebSocket, code: string, message: string, details?: any): void {
    this.sendToClient(client, {
      type: WebSocketEventType.ERROR,
      channel: WebSocketChannel.SYSTEM,
      payload: {
        code,
        message,
        details,
        timestamp: new Date().toISOString(),
      } as ErrorPayload,
      timestamp: new Date().toISOString(),
      messageId: uuidv4(),
    });
  }

  private sendToClient(client: ExtendedWebSocket, message: WebSocketMessage): void {
    if (client.readyState === WebSocket.OPEN) {
      client.send(JSON.stringify(message));
    }
  }

  // Public methods for broadcasting events

  public async broadcastToChannel(channel: WebSocketChannel, message: WebSocketMessage, entityId?: string): Promise<void> {
    const channelKey = entityId ? `${channel}:${entityId}` : channel;
    const subscribers = this.channelSubscriptions.get(channelKey);

    if (subscribers) {
      for (const clientId of subscribers) {
        const client = this.clients.get(clientId);
        if (client && client.readyState === WebSocket.OPEN) {
          this.sendToClient(client, message);
        }
      }
    }
  }

  public async broadcastToUser(userId: string, message: WebSocketMessage): Promise<void> {
    const userClients = this.userConnections.get(userId);
    if (userClients) {
      for (const clientId of userClients) {
        const client = this.clients.get(clientId);
        if (client && client.readyState === WebSocket.OPEN) {
          this.sendToClient(client, message);
        }
      }
    }
  }

  public async broadcastToAll(message: WebSocketMessage, excludeUserIds?: string[]): Promise<void> {
    for (const [clientId, client] of this.clients) {
      if (client.authenticated && client.readyState === WebSocket.OPEN) {
        if (!excludeUserIds || !excludeUserIds.includes(client.userId!)) {
          this.sendToClient(client, message);
        }
      }
    }
  }

  // High-level event methods

  public async sendAlert(alert: AlertPayload, targetUserIds?: string[]): Promise<void> {
    const message: WebSocketMessage<AlertPayload> = {
      type: WebSocketEventType.ALERT_NEW,
      channel: WebSocketChannel.ALERTS,
      payload: alert,
      timestamp: new Date().toISOString(),
      messageId: uuidv4(),
    };

    if (targetUserIds && targetUserIds.length > 0) {
      for (const userId of targetUserIds) {
        await this.broadcastToUser(userId, message);
      }
    } else {
      await this.broadcastToChannel(WebSocketChannel.ALERTS, message);
    }

    // Publish to Redis for other instances
    await this.publishToRedis(REDIS_CHANNELS.ALERTS, {
      eventType: WebSocketEventType.ALERT_NEW,
      channel: WebSocketChannel.ALERTS,
      payload: alert,
      targetUserIds,
    });
  }

  public async sendSurveillanceMatch(match: SurveillanceMatchPayload): Promise<void> {
    const message: WebSocketMessage<SurveillanceMatchPayload> = {
      type: WebSocketEventType.TARGET_SIGHTED,
      channel: WebSocketChannel.SURVEILLANCE,
      payload: match,
      timestamp: new Date().toISOString(),
      messageId: uuidv4(),
    };

    await this.broadcastToChannel(WebSocketChannel.SURVEILLANCE, message);

    // Also publish to Redis
    await this.publishToRedis(REDIS_CHANNELS.SURVEILLANCE, {
      eventType: WebSocketEventType.TARGET_SIGHTED,
      channel: WebSocketChannel.SURVEILLANCE,
      payload: match,
    });
  }

  public async sendBlockchainTransaction(transaction: BlockchainTransactionPayload): Promise<void> {
    const message: WebSocketMessage<BlockchainTransactionPayload> = {
      type: WebSocketEventType.TRANSACTION_DETECTED,
      channel: WebSocketChannel.BLOCKCHAIN,
      payload: transaction,
      timestamp: new Date().toISOString(),
      messageId: uuidv4(),
    };

    await this.broadcastToChannel(WebSocketChannel.BLOCKCHAIN, message);

    // Publish to Redis
    await this.publishToRedis(REDIS_CHANNELS.BLOCKCHAIN, {
      eventType: WebSocketEventType.TRANSACTION_DETECTED,
      channel: WebSocketChannel.BLOCKCHAIN,
      payload: transaction,
    });
  }

  public async sendInvestigationUpdate(update: InvestigationUpdatePayload): Promise<void> {
    const message: WebSocketMessage<InvestigationUpdatePayload> = {
      type: WebSocketEventType.INVESTIGATION_UPDATE,
      channel: WebSocketChannel.INVESTIGATIONS,
      payload: update,
      timestamp: new Date().toISOString(),
      messageId: uuidv4(),
    };

    // Broadcast to specific investigation channel
    await this.broadcastToChannel(WebSocketChannel.INVESTIGATIONS, message, update.investigationId);

    // Publish to Redis
    await this.publishToRedis(REDIS_CHANNELS.INVESTIGATIONS, {
      eventType: WebSocketEventType.INVESTIGATION_UPDATE,
      channel: WebSocketChannel.INVESTIGATIONS,
      payload: update,
      targetChannels: [`investigations:${update.investigationId}`],
    });
  }

  public async sendOperationStatus(status: OperationStatusPayload): Promise<void> {
    const message: WebSocketMessage<OperationStatusPayload> = {
      type: WebSocketEventType.OPERATION_STATUS,
      channel: WebSocketChannel.OPERATIONS,
      payload: status,
      timestamp: new Date().toISOString(),
      messageId: uuidv4(),
    };

    await this.broadcastToChannel(WebSocketChannel.OPERATIONS, message, status.operationId);

    // Publish to Redis
    await this.publishToRedis(REDIS_CHANNELS.OPERATIONS, {
      eventType: WebSocketEventType.OPERATION_STATUS,
      channel: WebSocketChannel.OPERATIONS,
      payload: status,
      targetChannels: [`operations:${status.operationId}`],
    });
  }

  public async sendNotification(userId: string, notification: any): Promise<void> {
    const message: WebSocketMessage = {
      type: WebSocketEventType.NOTIFICATION,
      channel: WebSocketChannel.USER,
      payload: notification,
      timestamp: new Date().toISOString(),
      messageId: uuidv4(),
      userId,
    };

    await this.broadcastToUser(userId, message);

    // Publish to Redis
    await this.publishToRedis(REDIS_CHANNELS.NOTIFICATIONS, {
      eventType: WebSocketEventType.NOTIFICATION,
      channel: WebSocketChannel.USER,
      payload: notification,
      targetUserIds: [userId],
    });
  }

  // Redis pub/sub methods

  private async publishToRedis(channel: string, message: RedisPubSubMessage): Promise<void> {
    try {
      await redis.publish(channel, JSON.stringify(message));
    } catch (error) {
      logger.error(`Failed to publish to Redis channel ${channel}: ${error}`);
    }
  }

  private async subscribeToRedisChannels(): Promise<void> {
    const channels = Object.values(REDIS_CHANNELS);

    for (const channel of channels) {
      await redis.subscribe(channel, (message: string) => {
        this.handleRedisMessage(channel, message);
      });
    }

    logger.info(`Subscribed to Redis channels: ${channels.join(', ')}`);
  }

  private async handleRedisMessage(channel: string, rawMessage: string): Promise<void> {
    try {
      const message: RedisPubSubMessage = JSON.parse(rawMessage);

      // Don't re-broadcast messages from this instance
      // In production, add instance ID check

      const wsMessage: WebSocketMessage = {
        type: message.eventType,
        channel: message.channel,
        payload: message.payload,
        timestamp: new Date().toISOString(),
        messageId: uuidv4(),
        metadata: message.metadata,
      };

      if (message.targetUserIds && message.targetUserIds.length > 0) {
        for (const userId of message.targetUserIds) {
          await this.broadcastToUser(userId, wsMessage);
        }
      } else if (message.targetChannels && message.targetChannels.length > 0) {
        for (const targetChannel of message.targetChannels) {
          const [wsChannel, entityId] = targetChannel.split(':');
          await this.broadcastToChannel(wsChannel as WebSocketChannel, wsMessage, entityId);
        }
      } else {
        await this.broadcastToChannel(message.channel, wsMessage);
      }
    } catch (error) {
      logger.error(`Error handling Redis message from ${channel}: ${error}`);
    }
  }

  // Heartbeat management

  private heartbeat(): void {
    for (const [clientId, client] of this.clients) {
      if (!client.isAlive) {
        logger.info(`Terminating inactive client: ${clientId}`);
        client.terminate();
        this.handleClose(client);
        continue;
      }

      client.isAlive = false;
      client.ping();
    }
  }

  // Statistics

  private collectStats(): void {
    this.stats.messagesPerMinute = 0; // Reset per-minute counter
    logger.debug(`WebSocket stats - Connections: ${this.stats.totalConnections}, Auth: ${this.stats.authenticatedConnections}`);
  }

  public getStats(): WebSocketStats {
    return { ...this.stats };
  }

  public getConnectedUsers(): string[] {
    return Array.from(this.userConnections.keys());
  }

  public isUserOnline(userId: string): boolean {
    return this.userConnections.has(userId) && this.userConnections.get(userId)!.size > 0;
  }

  // Utility methods

  private getClientIP(request: IncomingMessage): string {
    const xForwardedFor = request.headers['x-forwarded-for'];
    if (xForwardedFor) {
      const ips = Array.isArray(xForwardedFor) ? xForwardedFor[0] : xForwardedFor.split(',')[0];
      return ips.trim();
    }
    return request.socket.remoteAddress || 'unknown';
  }

  // Cleanup

  public async shutdown(): Promise<void> {
    logger.info('Shutting down WebSocket server...');

    if (this.heartbeatInterval) {
      clearInterval(this.heartbeatInterval);
    }

    if (this.statsInterval) {
      clearInterval(this.statsInterval);
    }

    // Close all connections gracefully
    for (const [clientId, client] of this.clients) {
      this.sendToClient(client, {
        type: WebSocketEventType.DISCONNECT,
        channel: WebSocketChannel.SYSTEM,
        payload: { message: 'Server shutting down' },
        timestamp: new Date().toISOString(),
        messageId: uuidv4(),
      });
      client.close();
    }

    this.wss.close();
    logger.info('WebSocket server shut down complete');
  }
}

export default ApolloWebSocketServer;
