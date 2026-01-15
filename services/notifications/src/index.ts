import express from 'express';
import { WebSocketServer } from 'ws';
import { createServer } from 'http';
import cors from 'cors';
import helmet from 'helmet';
import { config, logger, database, redis } from '@apollo/shared';
import notificationRoutes from './routes/notification.routes';
import { NotificationService } from './services/notification.service';

const app = express();
const PORT = process.env.NOTIFICATIONS_SERVICE_PORT || 3005;

app.use(helmet());
app.use(cors({ origin: config.cors.origin }));
app.use(express.json());

app.get('/health', async (req, res) => {
  const healthy = await database.healthCheck();
  res.status(healthy ? 200 : 503).json({ status: healthy ? 'healthy' : 'unhealthy', service: 'notifications' });
});

app.use('/api/notifications', notificationRoutes);

const server = createServer(app);
const wss = new WebSocketServer({ server, path: '/ws' });

const notificationService = new NotificationService(wss);

wss.on('connection', (ws, req) => {
  logger.info('WebSocket client connected');
  ws.on('message', (message) => {
    try {
      const data = JSON.parse(message.toString());
      if (data.type === 'auth' && data.userId) {
        notificationService.addClient(data.userId, ws);
      }
    } catch (error) {
      logger.error('WebSocket message error:', error);
    }
  });

  ws.on('close', () => {
    logger.info('WebSocket client disconnected');
    notificationService.removeClient(ws);
  });
});

const startServer = async () => {
  await redis.connect();
  await notificationService.subscribeToEvents();
  server.listen(PORT, () => logger.info(`Notifications service on port ${PORT}`));
};

startServer();
export default app;
