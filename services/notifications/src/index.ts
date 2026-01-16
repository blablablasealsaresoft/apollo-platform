/**
 * Apollo Platform - Notifications Service
 * Real-time notification service with WebSocket support and Redis pub/sub
 */

import express from 'express';
import { createServer } from 'http';
import cors from 'cors';
import helmet from 'helmet';
import { config, logger, database, redis } from '@apollo/shared';
import notificationRoutes from './routes/notification.routes';
import alertRoutes from './routes/alert.routes';
import { NotificationService } from './services/notification.service';
import { ApolloWebSocketServer } from './websocket/WebSocketServer';
import {
  WebSocketEventType,
  WebSocketChannel,
  AlertSeverity,
} from './websocket/types';

const app = express();
const PORT = process.env.NOTIFICATIONS_SERVICE_PORT || 3005;

// Security middleware
app.use(helmet());
app.use(cors({
  origin: config.cors.origin,
  credentials: true,
}));
app.use(express.json());

// Health check endpoint
app.get('/health', async (req, res) => {
  try {
    const dbHealthy = await database.healthCheck();
    const redisHealthy = await redis.healthCheck();
    const wsStats = wsServer?.getStats();

    res.status(dbHealthy && redisHealthy ? 200 : 503).json({
      status: dbHealthy && redisHealthy ? 'healthy' : 'unhealthy',
      service: 'notifications',
      timestamp: new Date().toISOString(),
      components: {
        database: dbHealthy ? 'healthy' : 'unhealthy',
        redis: redisHealthy ? 'healthy' : 'unhealthy',
        websocket: {
          status: 'healthy',
          connections: wsStats?.totalConnections || 0,
          authenticated: wsStats?.authenticatedConnections || 0,
        },
      },
    });
  } catch (error) {
    res.status(503).json({
      status: 'unhealthy',
      service: 'notifications',
      error: error instanceof Error ? error.message : 'Unknown error',
    });
  }
});

// WebSocket stats endpoint
app.get('/ws/stats', (req, res) => {
  const stats = wsServer?.getStats();
  const connectedUsers = wsServer?.getConnectedUsers();

  res.json({
    success: true,
    data: {
      stats,
      connectedUsers,
      uptime: stats ? Date.now() - stats.uptime : 0,
    },
  });
});

// Check if user is online
app.get('/ws/users/:userId/online', (req, res) => {
  const isOnline = wsServer?.isUserOnline(req.params.userId) || false;
  res.json({
    success: true,
    data: { userId: req.params.userId, isOnline },
  });
});

// API routes
app.use('/api/notifications', notificationRoutes);
app.use('/api/alerts', alertRoutes);

// Event publishing endpoints (for internal service communication)
app.post('/internal/events/alert', async (req, res) => {
  try {
    const { alert, targetUserIds } = req.body;
    await wsServer?.sendAlert(alert, targetUserIds);
    res.json({ success: true, message: 'Alert broadcasted' });
  } catch (error) {
    logger.error('Failed to broadcast alert:', error);
    res.status(500).json({ success: false, error: 'Failed to broadcast alert' });
  }
});

app.post('/internal/events/surveillance', async (req, res) => {
  try {
    const { match } = req.body;
    await wsServer?.sendSurveillanceMatch(match);
    res.json({ success: true, message: 'Surveillance match broadcasted' });
  } catch (error) {
    logger.error('Failed to broadcast surveillance match:', error);
    res.status(500).json({ success: false, error: 'Failed to broadcast' });
  }
});

app.post('/internal/events/blockchain', async (req, res) => {
  try {
    const { transaction } = req.body;
    await wsServer?.sendBlockchainTransaction(transaction);
    res.json({ success: true, message: 'Blockchain transaction broadcasted' });
  } catch (error) {
    logger.error('Failed to broadcast blockchain transaction:', error);
    res.status(500).json({ success: false, error: 'Failed to broadcast' });
  }
});

app.post('/internal/events/investigation', async (req, res) => {
  try {
    const { update } = req.body;
    await wsServer?.sendInvestigationUpdate(update);
    res.json({ success: true, message: 'Investigation update broadcasted' });
  } catch (error) {
    logger.error('Failed to broadcast investigation update:', error);
    res.status(500).json({ success: false, error: 'Failed to broadcast' });
  }
});

app.post('/internal/events/operation', async (req, res) => {
  try {
    const { status } = req.body;
    await wsServer?.sendOperationStatus(status);
    res.json({ success: true, message: 'Operation status broadcasted' });
  } catch (error) {
    logger.error('Failed to broadcast operation status:', error);
    res.status(500).json({ success: false, error: 'Failed to broadcast' });
  }
});

app.post('/internal/events/notification', async (req, res) => {
  try {
    const { userId, notification } = req.body;
    await wsServer?.sendNotification(userId, notification);
    res.json({ success: true, message: 'Notification sent' });
  } catch (error) {
    logger.error('Failed to send notification:', error);
    res.status(500).json({ success: false, error: 'Failed to send notification' });
  }
});

// Error handler
app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
  logger.error(`Notifications service error: ${err.message}`);
  res.status(err.statusCode || 500).json({
    success: false,
    error: {
      code: err.code || 'INTERNAL_ERROR',
      message: err.message || 'An unexpected error occurred',
    },
  });
});

// Create HTTP server
const server = createServer(app);

// Initialize WebSocket server
let wsServer: ApolloWebSocketServer | null = null;
let notificationService: NotificationService | null = null;

const startServer = async () => {
  try {
    // Connect to Redis
    await redis.connect();
    logger.info('Redis connected');

    // Initialize WebSocket server
    wsServer = new ApolloWebSocketServer(server);
    logger.info('WebSocket server initialized');

    // Initialize notification service with WebSocket server
    notificationService = new NotificationService(wsServer);
    await notificationService.initialize();
    logger.info('Notification service initialized');

    // Start HTTP server
    server.listen(PORT, () => {
      logger.info(`Notifications service running on port ${PORT}`);
      logger.info(`WebSocket endpoint: ws://localhost:${PORT}/ws`);
    });

    // Graceful shutdown
    process.on('SIGTERM', async () => {
      logger.info('SIGTERM received, shutting down gracefully...');
      await wsServer?.shutdown();
      server.close(() => {
        logger.info('HTTP server closed');
        process.exit(0);
      });
    });

    process.on('SIGINT', async () => {
      logger.info('SIGINT received, shutting down gracefully...');
      await wsServer?.shutdown();
      server.close(() => {
        logger.info('HTTP server closed');
        process.exit(0);
      });
    });

  } catch (error) {
    logger.error('Failed to start notifications service:', error);
    process.exit(1);
  }
};

startServer();

export { app, wsServer, notificationService };
export default app;
