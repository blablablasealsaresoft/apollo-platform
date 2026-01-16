/**
 * Apollo Reporting Service
 *
 * Microservice for generating professional reports in multiple formats.
 * Supports PDF, DOCX, XLSX, HTML, JSON, and Markdown exports.
 *
 * Features:
 * - Investigation summary reports
 * - Target profile dossiers
 * - Evidence chain of custody reports
 * - Intelligence analysis reports
 * - Operation after-action reports
 * - Threat assessments
 * - Financial analysis reports
 * - Network mapping reports
 * - Timeline reports
 * - Executive briefs
 *
 * Classification markings, watermarks, and encryption are supported.
 */

import express, { Express, Request, Response, NextFunction } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import { v4 as uuidv4 } from 'uuid';
import reportRoutes from './routes/report.routes';
import { reportService } from './services/report.service';

// Environment configuration
const PORT = process.env.PORT || 3008;
const NODE_ENV = process.env.NODE_ENV || 'development';
const SERVICE_NAME = 'apollo-reporting-service';

// Create Express app
const app: Express = express();

// Request ID middleware
app.use((req: Request, _res: Response, next: NextFunction) => {
  req.headers['x-request-id'] = req.headers['x-request-id'] || uuidv4();
  next();
});

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:', 'blob:'],
      scriptSrc: ["'self'"],
    },
  },
  crossOriginEmbedderPolicy: false,
}));

// CORS configuration
app.use(cors({
  origin: process.env.CORS_ORIGIN || '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Request-ID', 'X-User-ID'],
  exposedHeaders: ['X-Report-Classification', 'X-Report-ID', 'X-Report-Checksum', 'Content-Disposition'],
  credentials: true,
}));

// Compression
app.use(compression());

// Body parsing
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Request logging
app.use((req: Request, _res: Response, next: NextFunction) => {
  const timestamp = new Date().toISOString();
  const requestId = req.headers['x-request-id'];
  console.log(`[${timestamp}] ${req.method} ${req.path} - RequestID: ${requestId}`);
  next();
});

// Health check endpoint
app.get('/health', (_req: Request, res: Response) => {
  res.json({
    status: 'healthy',
    service: SERVICE_NAME,
    version: '1.0.0',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: NODE_ENV,
  });
});

// Readiness check endpoint
app.get('/ready', async (_req: Request, res: Response) => {
  try {
    // Check if service is ready to accept requests
    res.json({
      status: 'ready',
      service: SERVICE_NAME,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    res.status(503).json({
      status: 'not_ready',
      service: SERVICE_NAME,
      error: (error as Error).message,
    });
  }
});

// API routes
app.use('/api/v1/reports', reportRoutes);

// API documentation endpoint
app.get('/api/v1', (_req: Request, res: Response) => {
  res.json({
    service: SERVICE_NAME,
    version: '1.0.0',
    endpoints: {
      reports: {
        'POST /api/v1/reports/generate': 'Generate a new report',
        'GET /api/v1/reports': 'List all reports',
        'GET /api/v1/reports/:id': 'Get report details',
        'GET /api/v1/reports/:id/status': 'Get report generation status',
        'GET /api/v1/reports/:id/download': 'Download report file',
        'DELETE /api/v1/reports/:id': 'Delete a report',
        'GET /api/v1/reports/templates': 'Get available templates',
        'GET /api/v1/reports/templates/:type': 'Get templates by report type',
        'GET /api/v1/reports/types': 'Get available report types and parameters',
        'POST /api/v1/reports/schedules': 'Create report schedule',
      },
    },
    supportedFormats: ['pdf', 'docx', 'xlsx', 'html', 'json', 'markdown'],
    supportedReportTypes: [
      'investigation_summary',
      'target_profile',
      'evidence_chain',
      'intelligence_analysis',
      'operation_after_action',
      'threat_assessment',
      'financial_analysis',
      'network_mapping',
      'timeline',
      'executive_brief',
    ],
    classifications: [
      'TOP SECRET//SCI',
      'TOP SECRET',
      'SECRET',
      'CONFIDENTIAL',
      'RESTRICTED',
      'UNCLASSIFIED',
      'UNCLASSIFIED//FOUO',
    ],
  });
});

// 404 handler
app.use((_req: Request, res: Response) => {
  res.status(404).json({
    success: false,
    error: {
      code: 'NOT_FOUND',
      message: 'The requested resource was not found',
    },
  });
});

// Global error handler
app.use((err: Error, req: Request, res: Response, _next: NextFunction) => {
  const requestId = req.headers['x-request-id'];
  console.error(`[ERROR] RequestID: ${requestId}`, err);

  // Determine error type and status code
  let statusCode = 500;
  let errorCode = 'INTERNAL_SERVER_ERROR';
  let message = 'An internal server error occurred';

  if (err.name === 'NotFoundError') {
    statusCode = 404;
    errorCode = 'NOT_FOUND';
    message = err.message;
  } else if (err.name === 'BadRequestError' || err.name === 'ValidationError') {
    statusCode = 400;
    errorCode = 'BAD_REQUEST';
    message = err.message;
  } else if (err.name === 'UnauthorizedError') {
    statusCode = 401;
    errorCode = 'UNAUTHORIZED';
    message = 'Authentication required';
  } else if (err.name === 'ForbiddenError') {
    statusCode = 403;
    errorCode = 'FORBIDDEN';
    message = 'Access denied';
  }

  res.status(statusCode).json({
    success: false,
    error: {
      code: errorCode,
      message,
      requestId,
      ...(NODE_ENV === 'development' && { stack: err.stack }),
    },
  });
});

// Graceful shutdown handler
const shutdown = async () => {
  console.log('Received shutdown signal. Closing server...');

  // Allow existing connections to complete
  process.exit(0);
};

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

// Start server
const startServer = async () => {
  try {
    // Initialize report service
    await reportService.initialize();
    console.log('Report service initialized');

    app.listen(PORT, () => {
      console.log(`
========================================
  Apollo Reporting Service Started
========================================
  Port: ${PORT}
  Environment: ${NODE_ENV}
  Service: ${SERVICE_NAME}
  Timestamp: ${new Date().toISOString()}
========================================

Available endpoints:
  Health:     GET  /health
  Ready:      GET  /ready
  API Info:   GET  /api/v1
  Reports:    POST /api/v1/reports/generate
              GET  /api/v1/reports
              GET  /api/v1/reports/:id
              GET  /api/v1/reports/:id/download
              GET  /api/v1/reports/templates
              GET  /api/v1/reports/types

Supported formats: PDF, DOCX, XLSX, HTML, JSON, Markdown
========================================
      `);
    });
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
};

startServer();

// Export app for testing
export { app };
