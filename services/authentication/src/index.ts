import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { config, logger, database, redis } from '@apollo/shared';
import authRoutes from './routes/auth.routes';
import oauthRoutes from './routes/oauth.routes';
import mfaRoutes from './routes/mfa.routes';
import biometricRoutes from './routes/biometric.routes';
import sessionRoutes from './routes/session.routes';
import apiKeyRoutes from './routes/apikey.routes';
import { errorHandler } from './middleware/error.middleware';
import { requestLogger } from './middleware/logging.middleware';
import './config/passport';

const app = express();
const PORT = process.env.AUTH_SERVICE_PORT || 3001;

// Middleware
app.use(helmet());
app.use(cors({ origin: config.cors.origin, credentials: true }));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(requestLogger);

// Health check
app.get('/health', async (req, res) => {
  const dbHealthy = await database.healthCheck();
  const redisHealthy = await redis.healthCheck();

  const health = {
    status: dbHealthy && redisHealthy ? 'healthy' : 'unhealthy',
    service: 'authentication',
    timestamp: new Date().toISOString(),
    checks: {
      database: dbHealthy,
      redis: redisHealthy,
    },
  };

  res.status(health.status === 'healthy' ? 200 : 503).json(health);
});

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/oauth', oauthRoutes);
app.use('/api/mfa', mfaRoutes);
app.use('/api/biometric', biometricRoutes);
app.use('/api/sessions', sessionRoutes);
app.use('/api/api-keys', apiKeyRoutes);

// Error handling
app.use(errorHandler);

// Start server
const startServer = async () => {
  try {
    await redis.connect();
    logger.info('Authentication service starting...');

    app.listen(PORT, () => {
      logger.info(`Authentication service running on port ${PORT}`);
    });
  } catch (error) {
    logger.error(`Failed to start authentication service: ${error}`);
    process.exit(1);
  }
};

// Graceful shutdown
process.on('SIGTERM', async () => {
  logger.info('SIGTERM received, shutting down gracefully');
  await database.close();
  await redis.disconnect();
  process.exit(0);
});

process.on('SIGINT', async () => {
  logger.info('SIGINT received, shutting down gracefully');
  await database.close();
  await redis.disconnect();
  process.exit(0);
});

startServer();

export default app;
