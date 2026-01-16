/**
 * Apollo Platform - Notification Service
 * Handles notification creation, storage, and delivery via WebSocket
 */

import nodemailer from 'nodemailer';
import { database, redis, logger, generateId, config, Notification, NotificationType } from '@apollo/shared';
import { ApolloWebSocketServer } from '../websocket/WebSocketServer';
import {
  WebSocketEventType,
  WebSocketChannel,
  AlertSeverity,
  AlertPayload,
  SurveillanceMatchPayload,
  BlockchainTransactionPayload,
  InvestigationUpdatePayload,
  OperationStatusPayload,
  NotificationPayload,
} from '../websocket/types';

// Redis channels for subscribing
const REDIS_CHANNELS = {
  ALERTS: 'events:alerts',
  SURVEILLANCE: 'events:surveillance',
  BLOCKCHAIN: 'events:blockchain',
  INVESTIGATIONS: 'events:investigations',
  OPERATIONS: 'events:operations',
  NOTIFICATIONS: 'events:notifications',
};

export class NotificationService {
  private wsServer: ApolloWebSocketServer;
  private transporter: nodemailer.Transporter | null = null;

  constructor(wsServer: ApolloWebSocketServer) {
    this.wsServer = wsServer;

    // Setup email transporter if configured
    if (config.email?.smtp?.host) {
      this.transporter = nodemailer.createTransport({
        host: config.email.smtp.host,
        port: config.email.smtp.port,
        secure: config.email.smtp.port === 465,
        auth: {
          user: config.email.smtp.user,
          pass: config.email.smtp.password,
        },
      });
    }
  }

  async initialize(): Promise<void> {
    // Subscribe to Redis event channels from other services
    await this.subscribeToEventChannels();
    logger.info('NotificationService initialized and subscribed to event channels');
  }

  /**
   * Subscribe to Redis channels for cross-service event handling
   */
  private async subscribeToEventChannels(): Promise<void> {
    // Alert events from various services
    await redis.subscribe(REDIS_CHANNELS.ALERTS, async (message: string) => {
      try {
        const event = JSON.parse(message);
        await this.handleAlertEvent(event);
      } catch (error) {
        logger.error('Error handling alert event:', error);
      }
    });

    // Surveillance events
    await redis.subscribe(REDIS_CHANNELS.SURVEILLANCE, async (message: string) => {
      try {
        const event = JSON.parse(message);
        await this.handleSurveillanceEvent(event);
      } catch (error) {
        logger.error('Error handling surveillance event:', error);
      }
    });

    // Blockchain events
    await redis.subscribe(REDIS_CHANNELS.BLOCKCHAIN, async (message: string) => {
      try {
        const event = JSON.parse(message);
        await this.handleBlockchainEvent(event);
      } catch (error) {
        logger.error('Error handling blockchain event:', error);
      }
    });

    // Investigation events
    await redis.subscribe(REDIS_CHANNELS.INVESTIGATIONS, async (message: string) => {
      try {
        const event = JSON.parse(message);
        await this.handleInvestigationEvent(event);
      } catch (error) {
        logger.error('Error handling investigation event:', error);
      }
    });

    // Operation events
    await redis.subscribe(REDIS_CHANNELS.OPERATIONS, async (message: string) => {
      try {
        const event = JSON.parse(message);
        await this.handleOperationEvent(event);
      } catch (error) {
        logger.error('Error handling operation event:', error);
      }
    });

    // User notification events
    await redis.subscribe(REDIS_CHANNELS.NOTIFICATIONS, async (message: string) => {
      try {
        const event = JSON.parse(message);
        await this.handleNotificationEvent(event);
      } catch (error) {
        logger.error('Error handling notification event:', error);
      }
    });

    logger.info(`Subscribed to Redis channels: ${Object.values(REDIS_CHANNELS).join(', ')}`);
  }

  /**
   * Handle alert events from Redis
   */
  private async handleAlertEvent(event: any): Promise<void> {
    const alert: AlertPayload = {
      id: event.id || generateId(),
      type: event.type || 'system',
      severity: event.severity || AlertSeverity.INFO,
      title: event.title,
      message: event.message,
      source: event.source || 'system',
      relatedEntity: event.relatedEntity,
      actionRequired: event.actionRequired || false,
      assignedTo: event.assignedTo,
      status: 'new',
      createdAt: new Date().toISOString(),
      location: event.location,
    };

    // Store alert in database
    await this.storeAlert(alert);

    // Broadcast via WebSocket
    await this.wsServer.sendAlert(alert, event.targetUserIds);

    // Send email for critical alerts
    if (alert.severity === AlertSeverity.CRITICAL && event.emailRecipients) {
      await this.sendAlertEmail(alert, event.emailRecipients);
    }
  }

  /**
   * Handle surveillance events from Redis
   */
  private async handleSurveillanceEvent(event: any): Promise<void> {
    const match: SurveillanceMatchPayload = {
      matchId: event.matchId || generateId(),
      targetId: event.targetId,
      targetName: event.targetName,
      confidence: event.confidence,
      sourceType: event.sourceType || 'camera',
      sourceId: event.sourceId,
      sourceName: event.sourceName,
      imageUrl: event.imageUrl,
      timestamp: event.timestamp || new Date().toISOString(),
      location: event.location,
      metadata: event.metadata,
    };

    // Create alert for high-confidence matches
    if (match.confidence >= 0.85) {
      const alert: AlertPayload = {
        id: generateId(),
        type: 'facial_match',
        severity: match.confidence >= 0.95 ? AlertSeverity.CRITICAL : AlertSeverity.WARNING,
        title: `Target Sighted: ${match.targetName}`,
        message: `Facial recognition match (${(match.confidence * 100).toFixed(1)}% confidence) detected at ${match.sourceName}`,
        source: 'surveillance-system',
        relatedEntity: {
          type: 'target',
          id: match.targetId,
          name: match.targetName,
        },
        actionRequired: true,
        status: 'new',
        createdAt: new Date().toISOString(),
        location: match.location,
      };

      await this.storeAlert(alert);
      await this.wsServer.sendAlert(alert);
    }

    // Broadcast surveillance match
    await this.wsServer.sendSurveillanceMatch(match);
  }

  /**
   * Handle blockchain events from Redis
   */
  private async handleBlockchainEvent(event: any): Promise<void> {
    const transaction: BlockchainTransactionPayload = {
      transactionHash: event.hash || event.transactionHash,
      blockchain: event.blockchain,
      fromAddress: event.from || event.fromAddress,
      toAddress: event.to || event.toAddress,
      value: event.value,
      currency: event.currency,
      usdValue: event.usdValue,
      timestamp: event.timestamp || new Date().toISOString(),
      blockNumber: event.blockNumber,
      confirmations: event.confirmations || 0,
      flags: event.flags || [],
      riskScore: event.riskScore || 0,
      relatedTargetIds: event.relatedTargetIds,
      mixerDetected: event.mixerDetected,
      exchangeDetected: event.exchangeDetected,
    };

    // Create alert for high-risk transactions
    if (transaction.riskScore >= 70 || transaction.mixerDetected) {
      const alert: AlertPayload = {
        id: generateId(),
        type: 'transaction',
        severity: transaction.riskScore >= 90 ? AlertSeverity.CRITICAL : AlertSeverity.WARNING,
        title: `Suspicious Transaction Detected`,
        message: `${transaction.value} ${transaction.currency} transferred${transaction.mixerDetected ? ' via mixer service' : ''} (Risk Score: ${transaction.riskScore})`,
        source: 'blockchain-monitor',
        relatedEntity: transaction.relatedTargetIds?.length ? {
          type: 'wallet',
          id: transaction.fromAddress,
        } : undefined,
        actionRequired: transaction.riskScore >= 90,
        status: 'new',
        createdAt: new Date().toISOString(),
      };

      await this.storeAlert(alert);
      await this.wsServer.sendAlert(alert);
    }

    // Broadcast blockchain transaction
    await this.wsServer.sendBlockchainTransaction(transaction);
  }

  /**
   * Handle investigation events from Redis
   */
  private async handleInvestigationEvent(event: any): Promise<void> {
    const update: InvestigationUpdatePayload = {
      investigationId: event.investigationId,
      caseNumber: event.caseNumber,
      title: event.title,
      updateType: event.updateType,
      previousValue: event.previousValue,
      newValue: event.newValue,
      updatedBy: event.updatedBy,
      timestamp: event.timestamp || new Date().toISOString(),
      summary: event.summary,
    };

    // Create notifications for team members
    if (event.teamMemberIds && event.teamMemberIds.length > 0) {
      for (const userId of event.teamMemberIds) {
        await this.createNotification({
          userId,
          type: NotificationType.INFO,
          title: `Investigation Update: ${update.caseNumber}`,
          message: update.summary,
          metadata: {
            investigationId: update.investigationId,
            updateType: update.updateType,
          },
        });
      }
    }

    // Broadcast investigation update
    await this.wsServer.sendInvestigationUpdate(update);
  }

  /**
   * Handle operation events from Redis
   */
  private async handleOperationEvent(event: any): Promise<void> {
    const status: OperationStatusPayload = {
      operationId: event.operationId,
      operationName: event.operationName,
      codename: event.codename,
      status: event.status,
      previousStatus: event.previousStatus,
      updatedBy: event.updatedBy,
      timestamp: event.timestamp || new Date().toISOString(),
      location: event.location,
      notes: event.notes,
    };

    // Create notifications for operation team
    if (event.teamMemberIds && event.teamMemberIds.length > 0) {
      for (const userId of event.teamMemberIds) {
        await this.createNotification({
          userId,
          type: NotificationType.ALERT,
          title: `Operation ${status.codename || status.operationName}: ${status.status}`,
          message: status.notes || `Operation status changed to ${status.status}`,
          metadata: {
            operationId: status.operationId,
            status: status.status,
          },
        });
      }
    }

    // Broadcast operation status
    await this.wsServer.sendOperationStatus(status);
  }

  /**
   * Handle direct notification events
   */
  private async handleNotificationEvent(event: any): Promise<void> {
    const notification = await this.createNotification({
      userId: event.userId,
      type: event.type || NotificationType.INFO,
      title: event.title,
      message: event.message,
      metadata: event.metadata,
    });

    // Send via WebSocket
    await this.wsServer.sendNotification(event.userId, notification);
  }

  /**
   * Create and store a notification
   */
  async createNotification(data: {
    userId: string;
    type: NotificationType;
    title: string;
    message: string;
    metadata?: Record<string, any>;
  }): Promise<Notification> {
    const id = generateId();
    const result = await database.query<Notification>(
      `INSERT INTO notifications (id, user_id, type, title, message, metadata, is_read)
       VALUES ($1, $2, $3, $4, $5, $6, false)
       RETURNING *`,
      [id, data.userId, data.type, data.title, data.message, data.metadata ? JSON.stringify(data.metadata) : null]
    );

    const notification = result.rows[0]!;
    logger.info(`Notification created: ${id} for user ${data.userId}`);

    // Send real-time notification via WebSocket
    await this.wsServer.sendNotification(data.userId, {
      id: notification.id,
      type: data.type as string,
      title: data.title,
      message: data.message,
      read: false,
      actionUrl: data.metadata?.actionUrl,
      createdAt: notification.createdAt.toISOString(),
    });

    return notification;
  }

  /**
   * Store an alert in the database
   */
  private async storeAlert(alert: AlertPayload): Promise<void> {
    try {
      await database.query(
        `INSERT INTO alerts (
          id, type, severity, title, message, source,
          related_entity_type, related_entity_id,
          action_required, assigned_to, status, metadata
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
        [
          alert.id,
          alert.type,
          alert.severity,
          alert.title,
          alert.message,
          alert.source,
          alert.relatedEntity?.type || null,
          alert.relatedEntity?.id || null,
          alert.actionRequired,
          alert.assignedTo || null,
          alert.status,
          JSON.stringify({ location: alert.location }),
        ]
      );
      logger.info(`Alert stored: ${alert.id}`);
    } catch (error) {
      logger.error(`Failed to store alert: ${error}`);
    }
  }

  /**
   * Send email for critical alerts
   */
  private async sendAlertEmail(alert: AlertPayload, recipients: string[]): Promise<void> {
    if (!this.transporter) {
      logger.warn('Email transporter not configured, skipping email notification');
      return;
    }

    try {
      const html = this.generateAlertEmailHtml(alert);

      await this.transporter.sendMail({
        from: config.email.from,
        to: recipients.join(','),
        subject: `[APOLLO ALERT - ${alert.severity.toUpperCase()}] ${alert.title}`,
        html,
      });

      logger.info(`Alert email sent to: ${recipients.join(', ')}`);
    } catch (error) {
      logger.error(`Failed to send alert email: ${error}`);
    }
  }

  /**
   * Generate HTML content for alert emails
   */
  private generateAlertEmailHtml(alert: AlertPayload): string {
    const severityColors: Record<string, string> = {
      info: '#3498db',
      warning: '#f39c12',
      error: '#e74c3c',
      critical: '#c0392b',
    };

    return `
      <!DOCTYPE html>
      <html>
      <head>
        <style>
          body { font-family: Arial, sans-serif; background-color: #1a1a2e; color: #e0e0e0; padding: 20px; }
          .container { max-width: 600px; margin: 0 auto; background-color: #16213e; border-radius: 8px; overflow: hidden; }
          .header { background-color: ${severityColors[alert.severity] || severityColors.info}; padding: 20px; text-align: center; }
          .header h1 { margin: 0; color: white; font-size: 24px; }
          .content { padding: 20px; }
          .severity-badge { display: inline-block; padding: 5px 15px; background-color: ${severityColors[alert.severity]}; color: white; border-radius: 4px; text-transform: uppercase; font-weight: bold; margin-bottom: 15px; }
          .field { margin-bottom: 15px; }
          .field-label { font-weight: bold; color: #00d9ff; margin-bottom: 5px; }
          .field-value { color: #e0e0e0; }
          .footer { background-color: #0f0f23; padding: 15px; text-align: center; font-size: 12px; color: #888; }
          .action-btn { display: inline-block; padding: 12px 24px; background-color: #00d9ff; color: #1a1a2e; text-decoration: none; border-radius: 4px; font-weight: bold; margin-top: 15px; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>APOLLO PLATFORM ALERT</h1>
          </div>
          <div class="content">
            <div class="severity-badge">${alert.severity}</div>
            <h2 style="color: white; margin-top: 0;">${alert.title}</h2>

            <div class="field">
              <div class="field-label">Message</div>
              <div class="field-value">${alert.message}</div>
            </div>

            <div class="field">
              <div class="field-label">Source</div>
              <div class="field-value">${alert.source}</div>
            </div>

            <div class="field">
              <div class="field-label">Time</div>
              <div class="field-value">${new Date(alert.createdAt).toLocaleString()}</div>
            </div>

            ${alert.relatedEntity ? `
            <div class="field">
              <div class="field-label">Related ${alert.relatedEntity.type}</div>
              <div class="field-value">${alert.relatedEntity.name || alert.relatedEntity.id}</div>
            </div>
            ` : ''}

            ${alert.location ? `
            <div class="field">
              <div class="field-label">Location</div>
              <div class="field-value">${alert.location.address || `${alert.location.latitude}, ${alert.location.longitude}`}</div>
            </div>
            ` : ''}

            ${alert.actionRequired ? '<p style="color: #f39c12; font-weight: bold;">ACTION REQUIRED - Please review this alert immediately.</p>' : ''}

            <a href="${config.services.apiGateway}/alerts/${alert.id}" class="action-btn">View in Apollo Console</a>
          </div>
          <div class="footer">
            Apollo Platform - Secure Intelligence System<br>
            This is an automated alert. Do not reply to this email.
          </div>
        </div>
      </body>
      </html>
    `;
  }

  /**
   * Get user notifications
   */
  async getUserNotifications(userId: string, limit: number = 50, offset: number = 0): Promise<Notification[]> {
    const result = await database.query<Notification>(
      'SELECT * FROM notifications WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3',
      [userId, limit, offset]
    );
    return result.rows;
  }

  /**
   * Mark notification as read
   */
  async markAsRead(notificationId: string): Promise<void> {
    await database.query('UPDATE notifications SET is_read = true WHERE id = $1', [notificationId]);
    logger.info(`Notification marked as read: ${notificationId}`);
  }

  /**
   * Mark all notifications as read for a user
   */
  async markAllAsRead(userId: string): Promise<number> {
    const result = await database.query(
      'UPDATE notifications SET is_read = true WHERE user_id = $1 AND is_read = false',
      [userId]
    );
    logger.info(`Marked ${result.rowCount} notifications as read for user ${userId}`);
    return result.rowCount || 0;
  }

  /**
   * Get unread notification count
   */
  async getUnreadCount(userId: string): Promise<number> {
    const result = await database.query(
      'SELECT COUNT(*) as count FROM notifications WHERE user_id = $1 AND is_read = false',
      [userId]
    );
    return parseInt(result.rows[0].count);
  }

  /**
   * Delete old notifications
   */
  async deleteOldNotifications(olderThanDays: number = 30): Promise<number> {
    const result = await database.query(
      `DELETE FROM notifications
       WHERE is_read = true
       AND created_at < NOW() - INTERVAL '1 day' * $1`,
      [olderThanDays]
    );
    logger.info(`Deleted ${result.rowCount} old notifications`);
    return result.rowCount || 0;
  }
}

export default NotificationService;
