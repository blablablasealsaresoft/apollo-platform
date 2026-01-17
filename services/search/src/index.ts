import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { config, logger, AppError, createErrorResponse } from '@apollo/shared';
import searchRoutes from './routes/search.routes';
import { searchService } from './services/search.service';

const app = express();
const PORT = process.env.SEARCH_SERVICE_PORT || 3007;

app.use(helmet());
app.use(cors({ origin: config.cors.origin }));
app.use(express.json());

app.get('/health', async (req, res) => {
  const healthStatus = await searchService.healthCheck();
  res.status(healthStatus.healthy ? 200 : 503).json({
    status: healthStatus.healthy ? 'healthy' : 'unhealthy',
    service: 'search',
    ...(healthStatus.details && { details: healthStatus.details })
  });
});

app.use('/api/search', searchRoutes);

// Error handling middleware
app.use((err: Error, req: Request, res: Response, _next: NextFunction) => {
  if (err instanceof AppError) {
    logger.warn(`AppError: ${err.message}`, { code: err.code, statusCode: err.statusCode });
    return res.status(err.statusCode).json(createErrorResponse(err.code, err.message));
  }
  logger.error('Unhandled error:', err);
  return res.status(500).json(createErrorResponse('INTERNAL_ERROR', 'An unexpected error occurred'));
});

const startServer = async () => {
  await searchService.initialize();
  app.listen(PORT, () => logger.info(`Search service on port ${PORT}`));
};

startServer();
export default app;
