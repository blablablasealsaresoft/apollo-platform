import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { config, logger, database } from '@apollo/shared';
import userRoutes from './routes/user.routes';
import { errorHandler } from './middleware/error.middleware';
import { requestLogger } from './middleware/logging.middleware';

const app = express();
const PORT = process.env.USER_SERVICE_PORT || 3002;

app.use(helmet());
app.use(cors({ origin: config.cors.origin, credentials: true }));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(requestLogger);

app.get('/health', async (req, res) => {
  const dbHealthy = await database.healthCheck();
  res.status(dbHealthy ? 200 : 503).json({
    status: dbHealthy ? 'healthy' : 'unhealthy',
    service: 'user-management',
    timestamp: new Date().toISOString(),
  });
});

app.use('/api/users', userRoutes);
app.use(errorHandler);

const startServer = async () => {
  try {
    logger.info('User Management service starting...');
    app.listen(PORT, () => {
      logger.info(`User Management service running on port ${PORT}`);
    });
  } catch (error) {
    logger.error(`Failed to start User Management service: ${error}`);
    process.exit(1);
  }
};

process.on('SIGTERM', async () => {
  await database.close();
  process.exit(0);
});

startServer();
export default app;
