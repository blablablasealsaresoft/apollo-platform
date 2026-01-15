import { WebSocketServer, WebSocket } from 'ws';
import nodemailer from 'nodemailer';
import { database, redis, logger, generateId, config, Notification, NotificationType } from '@apollo/shared';

export class NotificationService {
  private clients: Map<string, WebSocket[]> = new Map();
  private transporter: nodemailer.Transporter | null = null;

  constructor(private wss: WebSocketServer) {
    if (config.email.smtp.host) {
      this.transporter = nodemailer.createTransport({
        host: config.email.smtp.host,
        port: config.email.smtp.port,
        auth: {
          user: config.email.smtp.user,
          pass: config.email.smtp.password,
        },
      });
    }
  }

  addClient(userId: string, ws: WebSocket): void {
    if (!this.clients.has(userId)) {
      this.clients.set(userId, []);
    }
    this.clients.get(userId)!.push(ws);
    logger.info(`Client added for user: ${userId}`);
  }

  removeClient(ws: WebSocket): void {
    for (const [userId, sockets] of this.clients.entries()) {
      const index = sockets.indexOf(ws);
      if (index !== -1) {
        sockets.splice(index, 1);
        if (sockets.length === 0) {
          this.clients.delete(userId);
        }
        logger.info(`Client removed for user: ${userId}`);
        break;
      }
    }
  }

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
      [id, data.userId, data.type, data.title, data.message, data.metadata ? JSON.stringify(data.metadata) : null],
    );

    const notification = result.rows[0]!;

    // Send real-time notification via WebSocket
    this.sendToUser(data.userId, notification);

    // Publish to Redis for other instances
    await redis.publish('notifications', JSON.stringify({ userId: data.userId, notification }));

    logger.info(`Notification created: ${id}`);
    return notification;
  }

  async sendToUser(userId: string, notification: Notification): void {
    const sockets = this.clients.get(userId);
    if (sockets) {
      const message = JSON.stringify({ type: 'notification', data: notification });
      sockets.forEach((ws) => {
        if (ws.readyState === WebSocket.OPEN) {
          ws.send(message);
        }
      });
    }
  }

  async subscribeToEvents(): Promise<void> {
    await redis.subscribe('notifications', (message) => {
      try {
        const { userId, notification } = JSON.parse(message);
        this.sendToUser(userId, notification);
      } catch (error) {
        logger.error('Error processing notification event:', error);
      }
    });
    logger.info('Subscribed to notification events');
  }

  async sendEmail(to: string, subject: string, html: string): Promise<void> {
    if (!this.transporter) {
      logger.warn('Email transporter not configured');
      return;
    }

    try {
      await this.transporter.sendMail({
        from: config.email.from,
        to,
        subject,
        html,
      });
      logger.info(`Email sent to: ${to}`);
    } catch (error) {
      logger.error(`Failed to send email: ${error}`);
    }
  }

  async markAsRead(notificationId: string): Promise<void> {
    await database.query('UPDATE notifications SET is_read = true WHERE id = $1', [notificationId]);
  }

  async getUserNotifications(userId: string, limit: number = 50): Promise<Notification[]> {
    const result = await database.query<Notification>(
      'SELECT * FROM notifications WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2',
      [userId, limit],
    );
    return result.rows;
  }
}
