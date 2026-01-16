/**
 * Apollo Platform - WebSocket Types
 * Comprehensive type definitions for real-time communication
 */

// WebSocket Event Types
export enum WebSocketEventType {
  // Connection Events
  CONNECT = 'connect',
  DISCONNECT = 'disconnect',
  RECONNECT = 'reconnect',
  AUTH_SUCCESS = 'auth:success',
  AUTH_FAILURE = 'auth:failure',
  HEARTBEAT = 'heartbeat',
  PONG = 'pong',

  // Alert Events
  ALERT_NEW = 'alert:new',
  ALERT_UPDATE = 'alert:update',
  ALERT_ACKNOWLEDGE = 'alert:acknowledge',
  ALERT_RESOLVE = 'alert:resolve',
  ALERT_DISMISS = 'alert:dismiss',

  // Surveillance Events
  TARGET_SIGHTED = 'surveillance:target_sighted',
  FACIAL_MATCH = 'surveillance:facial_match',
  CAMERA_ALERT = 'surveillance:camera_alert',
  LOCATION_UPDATE = 'surveillance:location_update',

  // Blockchain Events
  TRANSACTION_DETECTED = 'blockchain:transaction_detected',
  WALLET_ACTIVITY = 'blockchain:wallet_activity',
  SUSPICIOUS_TRANSFER = 'blockchain:suspicious_transfer',
  MIXER_DETECTED = 'blockchain:mixer_detected',

  // Investigation Events
  INVESTIGATION_UPDATE = 'investigation:update',
  INVESTIGATION_CREATED = 'investigation:created',
  INVESTIGATION_CLOSED = 'investigation:closed',
  EVIDENCE_ADDED = 'investigation:evidence_added',

  // Operation Events
  OPERATION_STATUS = 'operation:status',
  OPERATION_CREATED = 'operation:created',
  OPERATION_COMPLETED = 'operation:completed',
  FIELD_REPORT = 'operation:field_report',

  // User/Notification Events
  NOTIFICATION = 'notification',
  USER_MESSAGE = 'user:message',
  SYSTEM_MESSAGE = 'system:message',

  // Subscription Events
  SUBSCRIBE = 'subscribe',
  UNSUBSCRIBE = 'unsubscribe',
  SUBSCRIPTION_CONFIRMED = 'subscription:confirmed',
  SUBSCRIPTION_ERROR = 'subscription:error',

  // Error Events
  ERROR = 'error',
}

// WebSocket Channel Types
export enum WebSocketChannel {
  ALERTS = 'alerts',
  INVESTIGATIONS = 'investigations',
  SURVEILLANCE = 'surveillance',
  BLOCKCHAIN = 'blockchain',
  OPERATIONS = 'operations',
  USER = 'user',
  SYSTEM = 'system',
}

// Alert Severity Levels
export enum AlertSeverity {
  INFO = 'info',
  WARNING = 'warning',
  ERROR = 'error',
  CRITICAL = 'critical',
}

// WebSocket Message Interface
export interface WebSocketMessage<T = any> {
  type: WebSocketEventType;
  channel: WebSocketChannel;
  payload: T;
  timestamp: string;
  messageId: string;
  userId?: string;
  metadata?: Record<string, any>;
}

// Alert Payload
export interface AlertPayload {
  id: string;
  type: string;
  severity: AlertSeverity;
  title: string;
  message: string;
  source: string;
  relatedEntity?: {
    type: 'investigation' | 'target' | 'operation' | 'evidence' | 'wallet';
    id: string;
    name?: string;
  };
  actionRequired: boolean;
  assignedTo?: string;
  status: 'new' | 'acknowledged' | 'in_progress' | 'resolved' | 'dismissed';
  createdAt: string;
  location?: {
    latitude: number;
    longitude: number;
    address?: string;
  };
}

// Surveillance Match Payload
export interface SurveillanceMatchPayload {
  matchId: string;
  targetId: string;
  targetName: string;
  confidence: number;
  sourceType: 'camera' | 'upload' | 'database' | 'external';
  sourceId: string;
  sourceName: string;
  imageUrl?: string;
  timestamp: string;
  location?: {
    latitude: number;
    longitude: number;
    address?: string;
    venue?: string;
  };
  metadata?: {
    cameraId?: string;
    feedName?: string;
    ageEstimate?: number;
    disguiseDetected?: boolean;
  };
}

// Blockchain Transaction Payload
export interface BlockchainTransactionPayload {
  transactionHash: string;
  blockchain: 'bitcoin' | 'ethereum' | 'binance' | 'polygon' | 'other';
  fromAddress: string;
  toAddress: string;
  value: number;
  currency: string;
  usdValue?: number;
  timestamp: string;
  blockNumber: number;
  confirmations: number;
  flags: string[];
  riskScore: number;
  relatedTargetIds?: string[];
  mixerDetected?: boolean;
  exchangeDetected?: {
    name: string;
    type: 'cex' | 'dex';
  };
}

// Investigation Update Payload
export interface InvestigationUpdatePayload {
  investigationId: string;
  caseNumber: string;
  title: string;
  updateType: 'status' | 'evidence' | 'target' | 'note' | 'team' | 'priority';
  previousValue?: any;
  newValue?: any;
  updatedBy: {
    id: string;
    name: string;
  };
  timestamp: string;
  summary: string;
}

// Operation Status Payload
export interface OperationStatusPayload {
  operationId: string;
  operationName: string;
  codename?: string;
  status: 'planning' | 'approved' | 'in_progress' | 'completed' | 'cancelled';
  previousStatus?: string;
  updatedBy: {
    id: string;
    name: string;
  };
  timestamp: string;
  location?: {
    latitude: number;
    longitude: number;
    address?: string;
  };
  notes?: string;
}

// Field Report Payload
export interface FieldReportPayload {
  reportId: string;
  operationId: string;
  operationName: string;
  author: {
    id: string;
    name: string;
  };
  timestamp: string;
  location?: string;
  summary: string;
  priority: 'routine' | 'important' | 'urgent' | 'flash';
  attachmentsCount: number;
}

// Notification Payload
export interface NotificationPayload {
  id: string;
  type: 'alert' | 'message' | 'system' | 'assignment';
  title: string;
  message: string;
  actionUrl?: string;
  read: boolean;
  createdAt: string;
}

// Subscription Request
export interface SubscriptionRequest {
  channel: WebSocketChannel;
  entityType?: string;
  entityId?: string;
  filters?: Record<string, any>;
}

// Client Authentication Data
export interface WebSocketAuthData {
  token: string;
  userId: string;
  role: string;
  clearanceLevel: string;
}

// Connected Client Info
export interface ConnectedClient {
  id: string;
  userId: string;
  username: string;
  role: string;
  clearanceLevel: string;
  connectedAt: Date;
  lastActivity: Date;
  subscriptions: Set<string>;
  ipAddress: string;
  userAgent: string;
}

// Heartbeat Message
export interface HeartbeatMessage {
  type: 'ping' | 'pong';
  timestamp: string;
  clientId: string;
}

// Error Payload
export interface ErrorPayload {
  code: string;
  message: string;
  details?: any;
  timestamp: string;
}

// Redis Pub/Sub Message
export interface RedisPubSubMessage {
  eventType: WebSocketEventType;
  channel: WebSocketChannel;
  payload: any;
  targetUserIds?: string[];
  targetChannels?: string[];
  excludeUserIds?: string[];
  metadata?: Record<string, any>;
}

// Room/Channel Subscription
export interface ChannelSubscription {
  channel: WebSocketChannel;
  entityId?: string;
  subscribedAt: Date;
  userId: string;
}

// WebSocket Statistics
export interface WebSocketStats {
  totalConnections: number;
  authenticatedConnections: number;
  activeSubscriptions: Map<string, number>;
  messagesPerMinute: number;
  peakConnections: number;
  uptime: number;
}
