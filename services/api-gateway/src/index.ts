import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { createProxyMiddleware } from 'http-proxy-middleware';
import rateLimit from 'express-rate-limit';
import { config, logger } from '@apollo/shared';
import { authenticate } from './middleware/auth.middleware';
import { requestLogger } from './middleware/logging.middleware';

const app = express();
const PORT = process.env.API_GATEWAY_PORT || 3000;

// Security middleware
app.use(helmet());
app.use(cors({
  origin: config.cors.origin,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: config.rateLimit.windowMs,
  max: config.rateLimit.maxRequests,
  message: 'Too many requests from this IP',
  standardHeaders: true,
  legacyHeaders: false,
});

app.use(limiter);
app.use(express.json({ limit: '10mb' }));
app.use(requestLogger);

// Health check
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: 'api-gateway',
    timestamp: new Date().toISOString(),
  });
});

// Public routes (no authentication)
app.use('/api/auth', createProxyMiddleware({
  target: config.services.auth,
  changeOrigin: true,
  pathRewrite: { '^/api/auth': '/api/auth' },
}));

// Protected routes (require authentication)
app.use('/api/users', authenticate, createProxyMiddleware({
  target: config.services.user,
  changeOrigin: true,
  pathRewrite: { '^/api/users': '/api/users' },
}));

app.use('/api/operations', authenticate, createProxyMiddleware({
  target: config.services.operations,
  changeOrigin: true,
  pathRewrite: { '^/api/operations': '/api/operations' },
}));

app.use('/api/intelligence', authenticate, createProxyMiddleware({
  target: config.services.intelligence,
  changeOrigin: true,
  pathRewrite: { '^/api/intelligence': '/api/intelligence' },
}));

app.use('/api/notifications', authenticate, createProxyMiddleware({
  target: config.services.notifications,
  changeOrigin: true,
  pathRewrite: { '^/api/notifications': '/api/notifications' },
}));

app.use('/api/analytics', authenticate, createProxyMiddleware({
  target: config.services.analytics,
  changeOrigin: true,
  pathRewrite: { '^/api/analytics': '/api/analytics' },
}));

app.use('/api/search', authenticate, createProxyMiddleware({
  target: config.services.search,
  changeOrigin: true,
  pathRewrite: { '^/api/search': '/api/search' },
}));

// WebSocket proxy for notifications
app.use('/ws', authenticate, createProxyMiddleware({
  target: config.services.notifications,
  changeOrigin: true,
  ws: true,
}));

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: {
      code: 'NOT_FOUND',
      message: 'Endpoint not found',
    },
  });
});

// Error handler
app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
  logger.error(`Gateway error: ${err.message}`);
  res.status(err.statusCode || 500).json({
    success: false,
    error: {
      code: err.code || 'INTERNAL_ERROR',
      message: err.message || 'An unexpected error occurred',
    },
  });
});

app.listen(PORT, () => {
  logger.info(`API Gateway running on port ${PORT}`);
  logger.info('Service routes configured:');
  logger.info(`  Authentication: ${config.services.auth}`);
  logger.info(`  User Management: ${config.services.user}`);
  logger.info(`  Operations: ${config.services.operations}`);
  logger.info(`  Intelligence: ${config.services.intelligence}`);
  logger.info(`  Notifications: ${config.services.notifications}`);
  logger.info(`  Analytics: ${config.services.analytics}`);
  logger.info(`  Search: ${config.services.search}`);
});

export default app;
