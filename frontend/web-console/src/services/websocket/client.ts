import { io, Socket } from 'socket.io-client';
import { WebSocketMessage, RealtimeUpdate } from '@types/index';

const WS_URL = import.meta.env.VITE_WS_URL || 'ws://localhost:8000';

type EventHandler = (data: any) => void;

class WebSocketClient {
  private socket: Socket | null = null;
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 5;
  private reconnectDelay = 1000;
  private eventHandlers: Map<string, Set<EventHandler>> = new Map();

  connect(token: string) {
    if (this.socket?.connected) {
      return;
    }

    this.socket = io(WS_URL, {
      auth: {
        token,
      },
      reconnection: true,
      reconnectionDelay: this.reconnectDelay,
      reconnectionAttempts: this.maxReconnectAttempts,
    });

    this.setupEventListeners();
  }

  private setupEventListeners() {
    if (!this.socket) return;

    this.socket.on('connect', () => {
      console.log('WebSocket connected');
      this.reconnectAttempts = 0;
    });

    this.socket.on('disconnect', (reason) => {
      console.log('WebSocket disconnected:', reason);
    });

    this.socket.on('error', (error) => {
      console.error('WebSocket error:', error);
    });

    this.socket.on('reconnect_attempt', (attempt) => {
      this.reconnectAttempts = attempt;
      console.log(`WebSocket reconnection attempt ${attempt}`);
    });

    this.socket.on('reconnect_failed', () => {
      console.error('WebSocket reconnection failed');
    });

    // Listen for real-time updates
    this.socket.on('update', (update: RealtimeUpdate) => {
      this.handleUpdate(update);
    });

    // Listen for alerts
    this.socket.on('alert', (alert: any) => {
      this.emit('alert', alert);
    });

    // Listen for notifications
    this.socket.on('notification', (notification: any) => {
      this.emit('notification', notification);
    });

    // Listen for investigation updates
    this.socket.on('investigation:update', (data: any) => {
      this.emit('investigation:update', data);
    });

    // Listen for target updates
    this.socket.on('target:update', (data: any) => {
      this.emit('target:update', data);
    });

    // Listen for operation updates
    this.socket.on('operation:update', (data: any) => {
      this.emit('operation:update', data);
    });

    // Listen for evidence updates
    this.socket.on('evidence:update', (data: any) => {
      this.emit('evidence:update', data);
    });

    // Listen for facial recognition matches
    this.socket.on('facial:match', (data: any) => {
      this.emit('facial:match', data);
    });

    // Listen for blockchain transactions
    this.socket.on('blockchain:transaction', (data: any) => {
      this.emit('blockchain:transaction', data);
    });
  }

  private handleUpdate(update: RealtimeUpdate) {
    const eventName = `${update.entity}:${update.action}`;
    this.emit(eventName, update.data);
    this.emit('update', update);
  }

  on(event: string, handler: EventHandler) {
    if (!this.eventHandlers.has(event)) {
      this.eventHandlers.set(event, new Set());
    }
    this.eventHandlers.get(event)?.add(handler);
  }

  off(event: string, handler: EventHandler) {
    this.eventHandlers.get(event)?.delete(handler);
  }

  private emit(event: string, data: any) {
    const handlers = this.eventHandlers.get(event);
    if (handlers) {
      handlers.forEach((handler) => handler(data));
    }
  }

  send(event: string, data: any) {
    if (this.socket?.connected) {
      this.socket.emit(event, data);
    }
  }

  // Subscribe to specific entities
  subscribe(entityType: string, entityId: string) {
    this.send('subscribe', { entityType, entityId });
  }

  unsubscribe(entityType: string, entityId: string) {
    this.send('unsubscribe', { entityType, entityId });
  }

  // Subscribe to investigation updates
  subscribeToInvestigation(investigationId: string) {
    this.subscribe('investigation', investigationId);
  }

  unsubscribeFromInvestigation(investigationId: string) {
    this.unsubscribe('investigation', investigationId);
  }

  // Subscribe to target updates
  subscribeToTarget(targetId: string) {
    this.subscribe('target', targetId);
  }

  unsubscribeFromTarget(targetId: string) {
    this.unsubscribe('target', targetId);
  }

  // Subscribe to operation updates
  subscribeToOperation(operationId: string) {
    this.subscribe('operation', operationId);
  }

  unsubscribeFromOperation(operationId: string) {
    this.unsubscribe('operation', operationId);
  }

  disconnect() {
    if (this.socket) {
      this.socket.disconnect();
      this.socket = null;
    }
    this.eventHandlers.clear();
  }

  isConnected(): boolean {
    return this.socket?.connected || false;
  }
}

export const wsClient = new WebSocketClient();
export default wsClient;
