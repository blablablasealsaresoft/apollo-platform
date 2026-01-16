/**
 * Apollo Platform - WebSocket Services Index
 * Central export for WebSocket client and types
 */

// Client
export { wsClient, ApolloWebSocketClient } from './client';

// Types
export {
  WebSocketEventType,
  WebSocketChannel,
  AlertSeverity,
  ConnectionState,
  type WebSocketMessage,
  type WebSocketClientOptions,
  type EventHandler,
  type ConnectionInfo,
  type SubscriptionRequest,
  type AlertPayload,
  type SurveillanceMatchPayload,
  type BlockchainTransactionPayload,
  type InvestigationUpdatePayload,
  type OperationStatusPayload,
  type NotificationPayload,
} from './types';

// Default export
export { default } from './client';
