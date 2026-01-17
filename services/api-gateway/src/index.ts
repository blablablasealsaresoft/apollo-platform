import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { createProxyMiddleware, Options } from 'http-proxy-middleware';
import rateLimit from 'express-rate-limit';
import swaggerUi from 'swagger-ui-express';
import yaml from 'js-yaml';
import fs from 'fs';
import path from 'path';
import http from 'http';
import { config, logger } from '@apollo/shared';
import { authenticate } from './middleware/auth.middleware';
import { requestLogger } from './middleware/logging.middleware';
import { authLimiter, sensitiveLimiter } from './middleware/rate-limit.middleware';
import { securityHeaders, additionalSecurityHeaders, handlePreflight } from './middleware/security.middleware';

// Service health check interface
interface ServiceHealth {
  name: string;
  status: 'healthy' | 'unhealthy' | 'degraded';
  url: string;
  responseTime?: number;
  error?: string;
}

interface AggregatedHealth {
  status: 'healthy' | 'unhealthy' | 'degraded';
  service: string;
  timestamp: string;
  uptime: number;
  services: ServiceHealth[];
}

// Start time for uptime calculation
const startTime = Date.now();

// Check health of a single service
async function checkServiceHealth(name: string, url: string): Promise<ServiceHealth> {
  const startTime = Date.now();
  return new Promise((resolve) => {
    const healthUrl = `${url}/health`;
    const timeout = 5000; // 5 second timeout

    const req = http.get(healthUrl, { timeout }, (res) => {
      const responseTime = Date.now() - startTime;
      if (res.statusCode === 200) {
        resolve({ name, status: 'healthy', url, responseTime });
      } else {
        resolve({ name, status: 'degraded', url, responseTime, error: `HTTP ${res.statusCode}` });
      }
    });

    req.on('error', (err) => {
      resolve({
        name,
        status: 'unhealthy',
        url,
        responseTime: Date.now() - startTime,
        error: err.message,
      });
    });

    req.on('timeout', () => {
      req.destroy();
      resolve({
        name,
        status: 'unhealthy',
        url,
        responseTime: timeout,
        error: 'Connection timeout',
      });
    });
  });
}

// Load OpenAPI specification
let openApiSpec: any = null;
try {
  const specPath = path.join(__dirname, '../../API_DOCUMENTATION.yaml');
  const specContent = fs.readFileSync(specPath, 'utf8');
  openApiSpec = yaml.load(specContent);
  logger.info('OpenAPI specification loaded successfully');
} catch (err) {
  logger.warn('Failed to load OpenAPI spec, documentation will be unavailable:', err);
}

const app = express();
const PORT = process.env.API_GATEWAY_PORT || 3000;

// Security middleware
app.use(securityHeaders);
app.use(additionalSecurityHeaders);
app.use(cors({
  origin: config.cors.origin,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Request-ID', 'X-Correlation-ID'],
  exposedHeaders: ['X-Request-ID', 'X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-RateLimit-Reset'],
}));
app.use(handlePreflight);

// Rate limiting
const limiter = rateLimit({
  windowMs: config.rateLimit.windowMs,
  max: config.rateLimit.maxRequests,
  message: 'Too many requests from this IP',
  standardHeaders: true,
  legacyHeaders: false,
});

app.use(limiter);
// Don't parse JSON for proxied routes - the proxy needs the raw body
app.use((req, res, next) => {
  // Skip body parsing for proxied API routes
  if (req.path.startsWith('/api/auth') ||
      req.path.startsWith('/api/users') ||
      req.path.startsWith('/api/operations') ||
      req.path.startsWith('/api/intelligence') ||
      req.path.startsWith('/api/notifications') ||
      req.path.startsWith('/api/analytics') ||
      req.path.startsWith('/api/search') ||
      req.path.startsWith('/api/reports') ||
      req.path.startsWith('/api/alerts')) {
    return next();
  }
  express.json({ limit: '10mb' })(req, res, next);
});
app.use(requestLogger);

// Simple health check for load balancers
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: 'api-gateway',
    timestamp: new Date().toISOString(),
    uptime: Math.floor((Date.now() - startTime) / 1000),
  });
});

// Aggregated health check for all backend services
app.get('/health/all', async (req, res) => {
  const services = [
    { name: 'authentication', url: config.services.auth },
    { name: 'user-management', url: config.services.user },
    { name: 'operations', url: config.services.operations },
    { name: 'intelligence', url: config.services.intelligence },
    { name: 'notifications', url: config.services.notifications },
    { name: 'analytics', url: config.services.analytics },
    { name: 'search', url: config.services.search },
    { name: 'reporting', url: config.services.reporting },
  ];

  const healthChecks = await Promise.all(
    services.map((svc) => checkServiceHealth(svc.name, svc.url))
  );

  const unhealthyCount = healthChecks.filter((h) => h.status === 'unhealthy').length;
  const degradedCount = healthChecks.filter((h) => h.status === 'degraded').length;

  let overallStatus: 'healthy' | 'unhealthy' | 'degraded' = 'healthy';
  if (unhealthyCount > 0) {
    overallStatus = unhealthyCount === services.length ? 'unhealthy' : 'degraded';
  } else if (degradedCount > 0) {
    overallStatus = 'degraded';
  }

  const response: AggregatedHealth = {
    status: overallStatus,
    service: 'api-gateway',
    timestamp: new Date().toISOString(),
    uptime: Math.floor((Date.now() - startTime) / 1000),
    services: healthChecks,
  };

  const statusCode = overallStatus === 'healthy' ? 200 : overallStatus === 'degraded' ? 207 : 503;
  res.status(statusCode).json(response);
});

// Readiness probe for Kubernetes
app.get('/ready', async (req, res) => {
  // Check critical services only
  const criticalServices = [
    { name: 'authentication', url: config.services.auth },
    { name: 'user-management', url: config.services.user },
  ];

  const healthChecks = await Promise.all(
    criticalServices.map((svc) => checkServiceHealth(svc.name, svc.url))
  );

  const allHealthy = healthChecks.every((h) => h.status === 'healthy');

  if (allHealthy) {
    res.json({ ready: true, services: healthChecks });
  } else {
    res.status(503).json({ ready: false, services: healthChecks });
  }
});

// API Documentation - Swagger UI
if (openApiSpec) {
  // Swagger UI options
  const swaggerOptions: swaggerUi.SwaggerUiOptions = {
    customCss: `
      .swagger-ui .topbar { display: none }
      .swagger-ui .info .title { color: #1a365d }
      .swagger-ui .info .description { margin-bottom: 20px }
    `,
    customSiteTitle: 'Apollo Platform API Documentation',
    customfavIcon: '/favicon.ico',
    swaggerOptions: {
      persistAuthorization: true,
      displayRequestDuration: true,
      filter: true,
      showExtensions: true,
      showCommonExtensions: true,
      docExpansion: 'none',
      tagsSorter: 'alpha',
      operationsSorter: 'alpha',
    },
  };

  // Serve Swagger UI at /api/docs
  app.use('/api/docs', swaggerUi.serve, swaggerUi.setup(openApiSpec, swaggerOptions));

  // Serve OpenAPI spec as JSON
  app.get('/api/openapi.json', (req, res) => {
    res.json(openApiSpec);
  });

  // Serve OpenAPI spec as YAML
  app.get('/api/openapi.yaml', (req, res) => {
    const yamlContent = yaml.dump(openApiSpec);
    res.type('text/yaml').send(yamlContent);
  });

  // API documentation index/redirect
  app.get('/api', (req, res) => {
    res.json({
      message: 'Apollo Platform API',
      version: openApiSpec.info?.version || '2.0.0',
      documentation: {
        swagger_ui: '/api/docs',
        openapi_json: '/api/openapi.json',
        openapi_yaml: '/api/openapi.yaml',
      },
      endpoints: {
        authentication: '/api/auth',
        users: '/api/users',
        operations: '/api/operations',
        intelligence: '/api/intelligence',
        notifications: '/api/notifications',
        analytics: '/api/analytics',
        search: '/api/search',
        reporting: '/api/reports',
        alerts: '/api/alerts',
      },
    });
  });

  logger.info('API Documentation available at /api/docs');
}

// Public routes (no authentication)
// Apply stricter rate limiting to auth endpoints to prevent brute force
app.use('/api/auth/login', authLimiter);
app.use('/api/auth/register', authLimiter);
app.use('/api/auth/forgot-password', sensitiveLimiter);
app.use('/api/auth/reset-password', sensitiveLimiter);

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

// Reporting service routes
app.use('/api/reports', authenticate, createProxyMiddleware({
  target: config.services.reporting,
  changeOrigin: true,
  pathRewrite: { '^/api/reports': '/api/reports' },
}));

// Alerts are handled by the notifications service
app.use('/api/alerts', authenticate, createProxyMiddleware({
  target: config.services.notifications,
  changeOrigin: true,
  pathRewrite: { '^/api/alerts': '/api/alerts' },
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
  logger.info(`  Reporting: ${config.services.reporting}`);
});

export default app;
