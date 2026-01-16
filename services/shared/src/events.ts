/**
 * Apollo Platform - Event Publisher SDK
 * Standardized event publishing for real-time WebSocket communication
 * Use this module to emit events from any microservice
 */

import { redis } from './redis';
import { logger } from './logger';
import { generateId } from './utils';

// Redis channels for event publishing
export const EVENT_CHANNELS = {
  ALERTS: 'events:alerts',
  SURVEILLANCE: 'events:surveillance',
  BLOCKCHAIN: 'events:blockchain',
  INVESTIGATIONS: 'events:investigations',
  OPERATIONS: 'events:operations',
  NOTIFICATIONS: 'events:notifications',
  BROADCAST: 'events:broadcast',
} as const;

// Event types matching frontend expectations
export enum EventType {
  // Alert Events
  ALERT_NEW = 'alert:new',
  ALERT_UPDATE = 'alert:update',
  ALERT_ACKNOWLEDGE = 'alert:acknowledge',
  ALERT_RESOLVE = 'alert:resolve',

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

  // User Events
  NOTIFICATION = 'notification',
  USER_MESSAGE = 'user:message',
  SYSTEM_MESSAGE = 'system:message',
}

// Alert severity levels
export enum AlertSeverity {
  INFO = 'info',
  WARNING = 'warning',
  ERROR = 'error',
  CRITICAL = 'critical',
}

// Event payload interfaces
export interface AlertEvent {
  id?: string;
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
  actionRequired?: boolean;
  assignedTo?: string;
  location?: {
    latitude: number;
    longitude: number;
    address?: string;
  };
  targetUserIds?: string[];
  emailRecipients?: string[];
  metadata?: Record<string, any>;
}

export interface SurveillanceEvent {
  matchId?: string;
  targetId: string;
  targetName: string;
  confidence: number;
  sourceType: 'camera' | 'upload' | 'database' | 'external';
  sourceId: string;
  sourceName: string;
  imageUrl?: string;
  timestamp?: string;
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

export interface BlockchainEvent {
  transactionHash: string;
  blockchain: 'bitcoin' | 'ethereum' | 'binance' | 'polygon' | 'other';
  fromAddress: string;
  toAddress: string;
  value: number;
  currency: string;
  usdValue?: number;
  timestamp?: string;
  blockNumber: number;
  confirmations?: number;
  flags?: string[];
  riskScore?: number;
  relatedTargetIds?: string[];
  mixerDetected?: boolean;
  exchangeDetected?: {
    name: string;
    type: 'cex' | 'dex';
  };
}

export interface InvestigationEvent {
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
  timestamp?: string;
  summary: string;
  teamMemberIds?: string[];
}

export interface OperationEvent {
  operationId: string;
  operationName: string;
  codename?: string;
  status: 'planning' | 'approved' | 'in_progress' | 'completed' | 'cancelled';
  previousStatus?: string;
  updatedBy: {
    id: string;
    name: string;
  };
  timestamp?: string;
  location?: {
    latitude: number;
    longitude: number;
    address?: string;
  };
  notes?: string;
  teamMemberIds?: string[];
}

export interface NotificationEvent {
  userId: string;
  type?: 'alert' | 'message' | 'system' | 'assignment';
  title: string;
  message: string;
  actionUrl?: string;
  metadata?: Record<string, any>;
}

/**
 * Event Publisher class for emitting real-time events
 */
class EventPublisher {
  private serviceName: string;

  constructor(serviceName: string = 'unknown') {
    this.serviceName = serviceName;
  }

  /**
   * Set the service name for event tracking
   */
  setServiceName(name: string): void {
    this.serviceName = name;
  }

  /**
   * Publish an alert event
   */
  async publishAlert(alert: AlertEvent): Promise<void> {
    const event = {
      ...alert,
      id: alert.id || generateId(),
      source: alert.source || this.serviceName,
      timestamp: new Date().toISOString(),
    };

    await this.publish(EVENT_CHANNELS.ALERTS, event);
    logger.info(`Alert published: ${event.id} - ${event.title}`);
  }

  /**
   * Publish a critical alert (convenience method)
   */
  async publishCriticalAlert(title: string, message: string, options: Partial<AlertEvent> = {}): Promise<void> {
    await this.publishAlert({
      type: options.type || 'critical',
      severity: AlertSeverity.CRITICAL,
      title,
      message,
      source: options.source || this.serviceName,
      actionRequired: true,
      ...options,
    });
  }

  /**
   * Publish a surveillance match event
   */
  async publishSurveillanceMatch(match: SurveillanceEvent): Promise<void> {
    const event = {
      ...match,
      matchId: match.matchId || generateId(),
      timestamp: match.timestamp || new Date().toISOString(),
    };

    await this.publish(EVENT_CHANNELS.SURVEILLANCE, event);
    logger.info(`Surveillance match published: ${event.matchId} - ${event.targetName} (${(event.confidence * 100).toFixed(1)}%)`);
  }

  /**
   * Publish a blockchain transaction event
   */
  async publishBlockchainTransaction(transaction: BlockchainEvent): Promise<void> {
    const event = {
      ...transaction,
      timestamp: transaction.timestamp || new Date().toISOString(),
      confirmations: transaction.confirmations || 0,
      flags: transaction.flags || [],
      riskScore: transaction.riskScore || 0,
    };

    await this.publish(EVENT_CHANNELS.BLOCKCHAIN, event);
    logger.info(`Blockchain transaction published: ${event.transactionHash} - ${event.value} ${event.currency}`);
  }

  /**
   * Publish a suspicious blockchain transaction
   */
  async publishSuspiciousTransaction(transaction: BlockchainEvent): Promise<void> {
    // Ensure high risk score for suspicious transactions
    const event = {
      ...transaction,
      riskScore: Math.max(transaction.riskScore || 0, 70),
      flags: [...(transaction.flags || []), 'suspicious'],
    };

    await this.publishBlockchainTransaction(event);
  }

  /**
   * Publish an investigation update event
   */
  async publishInvestigationUpdate(update: InvestigationEvent): Promise<void> {
    const event = {
      ...update,
      timestamp: update.timestamp || new Date().toISOString(),
    };

    await this.publish(EVENT_CHANNELS.INVESTIGATIONS, event);
    logger.info(`Investigation update published: ${event.caseNumber} - ${event.updateType}`);
  }

  /**
   * Publish an operation status event
   */
  async publishOperationStatus(status: OperationEvent): Promise<void> {
    const event = {
      ...status,
      timestamp: status.timestamp || new Date().toISOString(),
    };

    await this.publish(EVENT_CHANNELS.OPERATIONS, event);
    logger.info(`Operation status published: ${event.operationId} - ${event.status}`);
  }

  /**
   * Publish a user notification
   */
  async publishNotification(notification: NotificationEvent): Promise<void> {
    const event = {
      ...notification,
      type: notification.type || 'message',
      timestamp: new Date().toISOString(),
    };

    await this.publish(EVENT_CHANNELS.NOTIFICATIONS, event);
    logger.info(`Notification published for user: ${event.userId} - ${event.title}`);
  }

  /**
   * Publish a system-wide broadcast message
   */
  async publishBroadcast(title: string, message: string, severity: AlertSeverity = AlertSeverity.INFO): Promise<void> {
    const event = {
      id: generateId(),
      type: 'system',
      severity,
      title,
      message,
      source: this.serviceName,
      timestamp: new Date().toISOString(),
    };

    await this.publish(EVENT_CHANNELS.BROADCAST, event);
    logger.info(`Broadcast published: ${event.title}`);
  }

  /**
   * Generic publish method
   */
  private async publish(channel: string, event: any): Promise<void> {
    try {
      await redis.publish(channel, JSON.stringify(event));
    } catch (error) {
      logger.error(`Failed to publish event to ${channel}:`, error);
      throw error;
    }
  }
}

// Export singleton instance
export const eventPublisher = new EventPublisher();

// Export class for custom instances
export { EventPublisher };

/**
 * Convenience functions for quick event publishing
 */
export const publishAlert = (alert: AlertEvent) => eventPublisher.publishAlert(alert);
export const publishCriticalAlert = (title: string, message: string, options?: Partial<AlertEvent>) =>
  eventPublisher.publishCriticalAlert(title, message, options);
export const publishSurveillanceMatch = (match: SurveillanceEvent) => eventPublisher.publishSurveillanceMatch(match);
export const publishBlockchainTransaction = (tx: BlockchainEvent) => eventPublisher.publishBlockchainTransaction(tx);
export const publishSuspiciousTransaction = (tx: BlockchainEvent) => eventPublisher.publishSuspiciousTransaction(tx);
export const publishInvestigationUpdate = (update: InvestigationEvent) => eventPublisher.publishInvestigationUpdate(update);
export const publishOperationStatus = (status: OperationEvent) => eventPublisher.publishOperationStatus(status);
export const publishNotification = (notification: NotificationEvent) => eventPublisher.publishNotification(notification);
export const publishBroadcast = (title: string, message: string, severity?: AlertSeverity) =>
  eventPublisher.publishBroadcast(title, message, severity);

export default eventPublisher;
