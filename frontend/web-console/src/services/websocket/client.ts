/**
 * Apollo Platform - WebSocket Client
 * Comprehensive real-time communication client with automatic reconnection,
 * JWT authentication, event handling, and Redux integration
 */

import {
  WebSocketEventType,
  WebSocketChannel,
  WebSocketMessage,
  ConnectionState,
  ConnectionInfo,
  EventHandler,
  WebSocketClientOptions,
  SubscriptionRequest,
  AlertPayload,
  SurveillanceMatchPayload,
  BlockchainTransactionPayload,
  InvestigationUpdatePayload,
  OperationStatusPayload,
  NotificationPayload,
} from './types';

const DEFAULT_OPTIONS: WebSocketClientOptions = {
  url: import.meta.env.VITE_WS_URL || 'ws://localhost:3005/ws',
  autoConnect: false,
  reconnect: true,
  reconnectInterval: 1000,
  reconnectAttempts: 10,
  heartbeatInterval: 30000,
  debug: import.meta.env.DEV,
};

class ApolloWebSocketClient {
  private socket: WebSocket | null = null;
  private options: WebSocketClientOptions;
  private connectionInfo: ConnectionInfo;
  private eventHandlers: Map<string, Set<EventHandler>> = new Map();
  private subscriptions: Set<string> = new Set();
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private heartbeatTimer: ReturnType<typeof setInterval> | null = null;
  private messageQueue: WebSocketMessage[] = [];
  private token: string | null = null;
  private pingStartTime: number = 0;

  constructor(options: Partial<WebSocketClientOptions> = {}) {
    this.options = { ...DEFAULT_OPTIONS, ...options };
    this.connectionInfo = {
      state: ConnectionState.DISCONNECTED,
      reconnectAttempts: 0,
      authenticated: false,
    };
  }

  /**
   * Connect to WebSocket server
   */
  connect(token?: string): void {
    if (token) {
      this.token = token;
    }

    if (!this.token) {
      this.log('warn', 'No authentication token provided');
    }

    if (this.socket?.readyState === WebSocket.OPEN) {
      this.log('info', 'Already connected');
      return;
    }

    this.updateConnectionState(ConnectionState.CONNECTING);

    try {
      // Build WebSocket URL with token for initial auth
      const wsUrl = this.token
        ? `${this.options.url}?token=${encodeURIComponent(this.token)}`
        : this.options.url;

      this.socket = new WebSocket(wsUrl);
      this.setupSocketHandlers();
    } catch (error) {
      this.log('error', 'Failed to create WebSocket connection', error);
      this.handleReconnect();
    }
  }

  /**
   * Disconnect from WebSocket server
   */
  disconnect(): void {
    this.log('info', 'Disconnecting...');

    this.clearTimers();
    this.subscriptions.clear();

    if (this.socket) {
      this.socket.close(1000, 'Client disconnect');
      this.socket = null;
    }

    this.updateConnectionState(ConnectionState.DISCONNECTED);
    this.connectionInfo.authenticated = false;
    this.connectionInfo.userId = undefined;
  }

  /**
   * Setup WebSocket event handlers
   */
  private setupSocketHandlers(): void {
    if (!this.socket) return;

    this.socket.onopen = () => {
      this.log('info', 'WebSocket connected');
      this.connectionInfo.connectedAt = new Date();
      this.connectionInfo.reconnectAttempts = 0;
      this.updateConnectionState(ConnectionState.CONNECTED);

      // Send authentication if token exists
      if (this.token) {
        this.authenticate(this.token);
      }

      // Start heartbeat
      this.startHeartbeat();

      // Process queued messages
      this.processMessageQueue();

      // Re-subscribe to previous subscriptions
      this.resubscribe();

      // Emit connect event
      this.emit('connection:open', { timestamp: new Date().toISOString() });
    };

    this.socket.onmessage = (event: MessageEvent) => {
      try {
        const message: WebSocketMessage = JSON.parse(event.data);
        this.handleMessage(message);
      } catch (error) {
        this.log('error', 'Failed to parse message', error);
      }
    };

    this.socket.onclose = (event: CloseEvent) => {
      this.log('info', `WebSocket closed: ${event.code} - ${event.reason}`);
      this.clearTimers();

      if (event.code !== 1000 && this.options.reconnect) {
        this.handleReconnect();
      } else {
        this.updateConnectionState(ConnectionState.DISCONNECTED);
      }

      this.emit('connection:close', { code: event.code, reason: event.reason });
    };

    this.socket.onerror = (error: Event) => {
      this.log('error', 'WebSocket error', error);
      this.emit('connection:error', { error });
    };
  }

  /**
   * Handle incoming messages
   */
  private handleMessage(message: WebSocketMessage): void {
    this.connectionInfo.lastActivity = new Date();
    this.log('debug', 'Received message', message);

    // Handle system messages
    switch (message.type) {
      case WebSocketEventType.CONNECT:
        this.emit('connection:established', message.payload);
        break;

      case WebSocketEventType.AUTH_SUCCESS:
        this.connectionInfo.authenticated = true;
        this.connectionInfo.userId = message.payload.userId;
        this.updateConnectionState(ConnectionState.AUTHENTICATED);
        this.emit('auth:success', message.payload);
        break;

      case WebSocketEventType.AUTH_FAILURE:
        this.connectionInfo.authenticated = false;
        this.emit('auth:failure', message.payload);
        break;

      case WebSocketEventType.PONG:
        // Calculate latency
        if (this.pingStartTime) {
          this.connectionInfo.latency = Date.now() - this.pingStartTime;
          this.pingStartTime = 0;
        }
        break;

      case WebSocketEventType.SUBSCRIPTION_CONFIRMED:
        this.emit('subscription:confirmed', message.payload);
        break;

      case WebSocketEventType.ERROR:
        this.emit('error', message.payload);
        break;

      default:
        // Route to appropriate handlers based on type and channel
        this.routeMessage(message);
    }
  }

  /**
   * Route message to registered handlers
   */
  private routeMessage(message: WebSocketMessage): void {
    const { type, channel, payload } = message;

    // Emit by exact type
    this.emit(type, payload, message);

    // Emit by channel
    this.emit(`channel:${channel}`, payload, message);

    // Emit combined type:channel
    this.emit(`${channel}:${type}`, payload, message);

    // Emit wildcard for all messages
    this.emit('*', payload, message);
  }

  /**
   * Authenticate with the server
   */
  authenticate(token: string): void {
    this.token = token;
    this.send({ type: 'auth', token });
  }

  /**
   * Subscribe to a channel
   */
  subscribe(channel: WebSocketChannel, entityId?: string): void {
    const subscriptionKey = entityId ? `${channel}:${entityId}` : channel;
    this.subscriptions.add(subscriptionKey);

    const request: SubscriptionRequest = {
      channel,
      entityId,
    };

    this.sendMessage({
      type: WebSocketEventType.SUBSCRIBE,
      channel: WebSocketChannel.SYSTEM,
      payload: request,
      timestamp: new Date().toISOString(),
      messageId: this.generateId(),
    });
  }

  /**
   * Unsubscribe from a channel
   */
  unsubscribe(channel: WebSocketChannel, entityId?: string): void {
    const subscriptionKey = entityId ? `${channel}:${entityId}` : channel;
    this.subscriptions.delete(subscriptionKey);

    const request: SubscriptionRequest = {
      channel,
      entityId,
    };

    this.sendMessage({
      type: WebSocketEventType.UNSUBSCRIBE,
      channel: WebSocketChannel.SYSTEM,
      payload: request,
      timestamp: new Date().toISOString(),
      messageId: this.generateId(),
    });
  }

  /**
   * Re-subscribe to all previous subscriptions after reconnect
   */
  private resubscribe(): void {
    for (const subscription of this.subscriptions) {
      const [channel, entityId] = subscription.split(':');
      this.subscribe(channel as WebSocketChannel, entityId);
    }
  }

  /**
   * Subscribe to specific entity updates
   */
  subscribeToInvestigation(investigationId: string): void {
    this.subscribe(WebSocketChannel.INVESTIGATIONS, investigationId);
  }

  unsubscribeFromInvestigation(investigationId: string): void {
    this.unsubscribe(WebSocketChannel.INVESTIGATIONS, investigationId);
  }

  subscribeToOperation(operationId: string): void {
    this.subscribe(WebSocketChannel.OPERATIONS, operationId);
  }

  unsubscribeFromOperation(operationId: string): void {
    this.unsubscribe(WebSocketChannel.OPERATIONS, operationId);
  }

  subscribeToAlerts(): void {
    this.subscribe(WebSocketChannel.ALERTS);
  }

  subscribeToSurveillance(): void {
    this.subscribe(WebSocketChannel.SURVEILLANCE);
  }

  subscribeToBlockchain(): void {
    this.subscribe(WebSocketChannel.BLOCKCHAIN);
  }

  /**
   * Register event handler
   */
  on<T = any>(event: string, handler: EventHandler<T>): () => void {
    if (!this.eventHandlers.has(event)) {
      this.eventHandlers.set(event, new Set());
    }
    this.eventHandlers.get(event)!.add(handler as EventHandler);

    // Return unsubscribe function
    return () => this.off(event, handler);
  }

  /**
   * Remove event handler
   */
  off<T = any>(event: string, handler: EventHandler<T>): void {
    const handlers = this.eventHandlers.get(event);
    if (handlers) {
      handlers.delete(handler as EventHandler);
      if (handlers.size === 0) {
        this.eventHandlers.delete(event);
      }
    }
  }

  /**
   * Register one-time event handler
   */
  once<T = any>(event: string, handler: EventHandler<T>): () => void {
    const onceHandler: EventHandler<T> = (data, message) => {
      this.off(event, onceHandler);
      handler(data, message as WebSocketMessage<T>);
    };
    return this.on(event, onceHandler);
  }

  /**
   * Emit event to all registered handlers
   */
  private emit<T = any>(event: string, data: T, message?: WebSocketMessage<T>): void {
    const handlers = this.eventHandlers.get(event);
    if (handlers) {
      handlers.forEach((handler) => {
        try {
          handler(data, message as WebSocketMessage);
        } catch (error) {
          this.log('error', `Error in event handler for ${event}`, error);
        }
      });
    }
  }

  /**
   * Send raw data to server
   */
  private send(data: any): void {
    if (this.socket?.readyState === WebSocket.OPEN) {
      this.socket.send(JSON.stringify(data));
    }
  }

  /**
   * Send WebSocket message
   */
  sendMessage(message: WebSocketMessage): void {
    if (this.socket?.readyState === WebSocket.OPEN) {
      this.socket.send(JSON.stringify(message));
    } else {
      // Queue message for later
      this.messageQueue.push(message);
    }
  }

  /**
   * Process queued messages after connection
   */
  private processMessageQueue(): void {
    while (this.messageQueue.length > 0) {
      const message = this.messageQueue.shift();
      if (message) {
        this.sendMessage(message);
      }
    }
  }

  /**
   * Start heartbeat to keep connection alive
   */
  private startHeartbeat(): void {
    this.clearHeartbeat();
    this.heartbeatTimer = setInterval(() => {
      if (this.socket?.readyState === WebSocket.OPEN) {
        this.pingStartTime = Date.now();
        this.send({ type: 'ping', timestamp: new Date().toISOString() });
      }
    }, this.options.heartbeatInterval);
  }

  /**
   * Handle reconnection logic
   */
  private handleReconnect(): void {
    if (!this.options.reconnect) return;

    if (this.connectionInfo.reconnectAttempts >= this.options.reconnectAttempts) {
      this.log('error', 'Max reconnection attempts reached');
      this.updateConnectionState(ConnectionState.FAILED);
      this.emit('connection:failed', {
        attempts: this.connectionInfo.reconnectAttempts,
      });
      return;
    }

    this.updateConnectionState(ConnectionState.RECONNECTING);
    this.connectionInfo.reconnectAttempts++;

    // Exponential backoff
    const delay = Math.min(
      this.options.reconnectInterval * Math.pow(2, this.connectionInfo.reconnectAttempts - 1),
      30000 // Max 30 seconds
    );

    this.log('info', `Reconnecting in ${delay}ms (attempt ${this.connectionInfo.reconnectAttempts})`);

    this.reconnectTimer = setTimeout(() => {
      this.connect();
    }, delay);

    this.emit('connection:reconnecting', {
      attempt: this.connectionInfo.reconnectAttempts,
      delay,
    });
  }

  /**
   * Update connection state and emit change event
   */
  private updateConnectionState(state: ConnectionState): void {
    const previousState = this.connectionInfo.state;
    this.connectionInfo.state = state;
    this.emit('connection:stateChange', { previousState, currentState: state });
  }

  /**
   * Clear all timers
   */
  private clearTimers(): void {
    this.clearReconnectTimer();
    this.clearHeartbeat();
  }

  /**
   * Clear reconnect timer
   */
  private clearReconnectTimer(): void {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
  }

  /**
   * Clear heartbeat timer
   */
  private clearHeartbeat(): void {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
  }

  /**
   * Generate unique message ID
   */
  private generateId(): string {
    return `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Log message if debug is enabled
   */
  private log(level: 'debug' | 'info' | 'warn' | 'error', message: string, data?: any): void {
    if (!this.options.debug && level === 'debug') return;

    const prefix = '[Apollo WS]';
    const formattedMessage = `${prefix} ${message}`;

    switch (level) {
      case 'debug':
        console.debug(formattedMessage, data || '');
        break;
      case 'info':
        console.info(formattedMessage, data || '');
        break;
      case 'warn':
        console.warn(formattedMessage, data || '');
        break;
      case 'error':
        console.error(formattedMessage, data || '');
        break;
    }
  }

  // Public getters

  get isConnected(): boolean {
    return this.socket?.readyState === WebSocket.OPEN;
  }

  get isAuthenticated(): boolean {
    return this.connectionInfo.authenticated;
  }

  get state(): ConnectionState {
    return this.connectionInfo.state;
  }

  get latency(): number | undefined {
    return this.connectionInfo.latency;
  }

  getConnectionInfo(): ConnectionInfo {
    return { ...this.connectionInfo };
  }

  getSubscriptions(): string[] {
    return Array.from(this.subscriptions);
  }
}

// Export singleton instance
export const wsClient = new ApolloWebSocketClient();

// Export class for custom instances
export { ApolloWebSocketClient };
export default wsClient;
