/**
 * Intelligence Fusion Service
 * Main entry point for the intelligence fusion microservice
 *
 * This service provides:
 * - Multi-source intelligence data ingestion
 * - Entity resolution and deduplication
 * - Cross-source correlation analysis
 * - Graph-based network analysis (Neo4j integration)
 * - Timeline building and activity pattern detection
 * - Risk assessment and threat scoring
 */

import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';

// Import shared module with fallback for standalone operation
let config: any = null;
let logger: any = console;
let database: any = null;

try {
  const shared = require('@apollo/shared');
  config = shared.config;
  logger = shared.logger || console;
  database = shared.database;
} catch (error) {
  // Shared module not available or config validation failed - use standalone mode
  console.warn('Running in standalone mode - shared module not available:', (error as Error).message);
  logger = {
    info: (...args: any[]) => console.log('[INFO]', ...args),
    warn: (...args: any[]) => console.warn('[WARN]', ...args),
    error: (...args: any[]) => console.error('[ERROR]', ...args),
    debug: (...args: any[]) => console.debug('[DEBUG]', ...args)
  };
}

import fusionRoutes from './routes/fusion.routes';
import { notFoundHandler, errorHandler } from './middleware/error.middleware';
import { initializeNeo4j, closeNeo4j } from './services/graph.service';

// Create Express app
const app = express();
const PORT = process.env.FUSION_SERVICE_PORT || process.env.PORT || 3008;

// ============================================
// MIDDLEWARE CONFIGURATION
// ============================================

// Security middleware
app.use(helmet({
  contentSecurityPolicy: false // Disable for API service
}));

// CORS configuration
app.use(cors({
  origin: config?.cors?.origin || '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Request-ID']
}));

// Body parsing
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Compression
app.use(compression());

// Request logging
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - start;
    logger.info('Request completed', {
      method: req.method,
      path: req.path,
      statusCode: res.statusCode,
      duration
    });
  });
  next();
});

// ============================================
// HEALTH CHECK ENDPOINTS
// ============================================

// Basic health check
app.get('/health', async (req, res) => {
  try {
    const dbHealthy = database ? await database.healthCheck() : true;
    res.status(dbHealthy ? 200 : 503).json({
      status: dbHealthy ? 'healthy' : 'unhealthy',
      service: 'intelligence-fusion',
      version: '1.0.0',
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(503).json({
      status: 'unhealthy',
      service: 'intelligence-fusion',
      error: String(error)
    });
  }
});

// Readiness check
app.get('/ready', async (req, res) => {
  res.status(200).json({
    ready: true,
    service: 'intelligence-fusion'
  });
});

// Liveness check
app.get('/live', (req, res) => {
  res.status(200).json({
    live: true,
    service: 'intelligence-fusion'
  });
});

// ============================================
// API ROUTES
// ============================================

// Mount fusion routes
app.use('/api/v1/fusion', fusionRoutes);

// Legacy route support
app.use('/api/fusion', fusionRoutes);

// ============================================
// ERROR HANDLING
// ============================================

// 404 handler
app.use(notFoundHandler);

// Global error handler
app.use(errorHandler);

// ============================================
// SERVICE INITIALIZATION
// ============================================

async function initializeService() {
  logger.info('Initializing Intelligence Fusion Service...');

  // Initialize Neo4j connection (optional)
  const neo4jUri = process.env.NEO4J_URI || 'bolt://localhost:7687';
  const neo4jUser = process.env.NEO4J_USER || 'neo4j';
  const neo4jPassword = process.env.NEO4J_PASSWORD || 'password';

  try {
    const connected = await initializeNeo4j(neo4jUri, neo4jUser, neo4jPassword);
    if (connected) {
      logger.info('Neo4j graph database connected');
    } else {
      logger.info('Running with in-memory graph (Neo4j not available)');
    }
  } catch (error) {
    logger.warn('Neo4j initialization failed, using in-memory graph', { error: String(error) });
  }

  // Verify database connection (optional)
  if (database) {
    try {
      const healthy = await database.healthCheck();
      if (healthy) {
        logger.info('Database connection established');
      } else {
        logger.warn('Database health check failed, some features may be limited');
      }
    } catch (error) {
      logger.warn('Database connection failed, some features may be limited', { error: String(error) });
    }
  }

  logger.info('Intelligence Fusion Service initialized');
}

// ============================================
// GRACEFUL SHUTDOWN
// ============================================

async function gracefulShutdown(signal: string) {
  logger.info(`Received ${signal}, starting graceful shutdown...`);

  // Close Neo4j connection
  try {
    await closeNeo4j();
    logger.info('Neo4j connection closed');
  } catch (error) {
    logger.error('Error closing Neo4j', { error: String(error) });
  }

  // Close database connection
  if (database?.close) {
    try {
      await database.close();
      logger.info('Database connection closed');
    } catch (error) {
      logger.error('Error closing database', { error: String(error) });
    }
  }

  logger.info('Graceful shutdown complete');
  process.exit(0);
}

// Register shutdown handlers
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// ============================================
// START SERVER
// ============================================

async function startServer() {
  try {
    // Initialize service
    await initializeService();

    // Start listening
    app.listen(PORT, () => {
      logger.info(`Intelligence Fusion Service running on port ${PORT}`);
      logger.info('Available endpoints:');
      logger.info('  POST /api/v1/fusion/fuse          - Main fusion endpoint');
      logger.info('  POST /api/v1/fusion/correlate     - Run correlation analysis');
      logger.info('  POST /api/v1/fusion/resolve       - Resolve entity identity');
      logger.info('  GET  /api/v1/fusion/graph/:id     - Get entity network');
      logger.info('  GET  /api/v1/fusion/timeline/:id  - Get activity timeline');
      logger.info('  POST /api/v1/fusion/assess-risk   - Calculate risk score');
      logger.info('  POST /api/v1/fusion/analyze       - Deep analysis');
      logger.info('  GET  /health                      - Health check');
    });
  } catch (error) {
    logger.error('Failed to start server', { error: String(error) });
    process.exit(1);
  }
}

// Start the server
startServer();

export default app;
