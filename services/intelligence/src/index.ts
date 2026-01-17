import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { config, logger, database, createErrorResponse } from '@apollo/shared';
import { AppError } from '@apollo/shared';
import intelRoutes from './routes/intel.routes';
import correlationRoutes from './routes/correlation.routes';

const app = express();
const PORT = process.env.INTELLIGENCE_SERVICE_PORT || 3004;

app.use(helmet());
app.use(cors({ origin: config.cors.origin }));
app.use(express.json());

// Health check endpoint
app.get('/health', async (req, res) => {
  try {
    const healthy = await database.healthCheck();
    res.status(healthy ? 200 : 503).json({
      status: healthy ? 'healthy' : 'unhealthy',
      service: 'intelligence',
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(503).json({
      status: 'unhealthy',
      service: 'intelligence',
      timestamp: new Date().toISOString()
    });
  }
});

// Readiness check endpoint
app.get('/ready', async (req, res) => {
  try {
    const healthy = await database.healthCheck();
    if (healthy) {
      res.status(200).json({ ready: true, service: 'intelligence' });
    } else {
      res.status(503).json({ ready: false, service: 'intelligence', reason: 'database unavailable' });
    }
  } catch (error) {
    res.status(503).json({ ready: false, service: 'intelligence', reason: 'health check failed' });
  }
});

app.use('/api/intelligence', intelRoutes);
app.use('/api/correlation', correlationRoutes);

// 404 handler
app.use((req, res) => {
  res.status(404).json(createErrorResponse('NOT_FOUND', `Route ${req.method} ${req.path} not found`));
});

// Error handling middleware
app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
  logger.error(`Error handling request ${req.method} ${req.path}: ${err.message}`);

  if (err instanceof AppError) {
    return res.status(err.statusCode).json(
      createErrorResponse(err.code, err.message)
    );
  }

  // Default to 500 for unexpected errors
  res.status(500).json(
    createErrorResponse('INTERNAL_ERROR', 'An unexpected error occurred')
  );
});

app.listen(PORT, () => logger.info(`Intelligence service on port ${PORT}`));
export default app;
