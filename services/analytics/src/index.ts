import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { config, logger, database, createErrorResponse, AppError, wrapError } from '@apollo/shared';
import analyticsRoutes from './routes/analytics.routes';

const app = express();
const PORT = process.env.ANALYTICS_SERVICE_PORT || 3006;

app.use(helmet());
app.use(cors({ origin: config.cors.origin }));
app.use(express.json());

// Health check endpoint
app.get('/health', async (_req: Request, res: Response) => {
  try {
    const healthy = await database.healthCheck();
    res.status(healthy ? 200 : 503).json({
      status: healthy ? 'healthy' : 'unhealthy',
      service: 'analytics',
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    logger.error('Health check failed', { error });
    res.status(503).json({
      status: 'unhealthy',
      service: 'analytics',
      timestamp: new Date().toISOString(),
      error: 'Database connection failed',
    });
  }
});

// Readiness check
app.get('/ready', async (_req: Request, res: Response) => {
  try {
    const dbReady = await database.healthCheck();
    if (dbReady) {
      res.status(200).json({ ready: true, service: 'analytics' });
    } else {
      res.status(503).json({ ready: false, service: 'analytics', reason: 'Database not ready' });
    }
  } catch (error) {
    res.status(503).json({ ready: false, service: 'analytics', reason: 'Health check failed' });
  }
});

// API routes
app.use('/api/analytics', analyticsRoutes);

// 404 handler
app.use((_req: Request, res: Response) => {
  res.status(404).json(createErrorResponse('NOT_FOUND', 'Endpoint not found'));
});

// Global error handler
app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
  const appError = err instanceof AppError ? err : wrapError(err);

  logger.error('Request error', {
    message: appError.message,
    code: appError.code,
    statusCode: appError.statusCode,
    stack: appError.stack,
  });

  res.status(appError.statusCode).json(
    createErrorResponse(appError.code, appError.message)
  );
});

app.listen(PORT, () => logger.info(`Analytics service on port ${PORT}`));
export default app;
