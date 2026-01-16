/**
 * Intelligence Fusion Routes
 * API route definitions for fusion operations
 */

import { Router } from 'express';
import * as fusionController from '../controllers/fusion.controller';

const router = Router();

// ============================================
// MAIN FUSION ENDPOINTS
// ============================================

/**
 * POST /api/v1/fusion/fuse
 * Main fusion endpoint - correlate intelligence from multiple sources
 *
 * Body: {
 *   target: string,
 *   sources: IntelligenceSource[],
 *   options?: {
 *     deepAnalysis?: boolean,
 *     maxGraphDepth?: number,
 *     minCorrelationScore?: number,
 *     includeTimeline?: boolean,
 *     includeRiskAssessment?: boolean
 *   }
 * }
 */
router.post('/fuse', fusionController.fuse);

/**
 * POST /api/v1/fusion/analyze
 * Run comprehensive deep analysis on target
 */
router.post('/analyze', fusionController.runDeepAnalysis);

// ============================================
// CORRELATION ENDPOINTS
// ============================================

/**
 * POST /api/v1/fusion/correlate
 * Run correlation analysis on entities
 *
 * Body: {
 *   entities: string[],
 *   sources?: IntelligenceSource[],
 *   options?: {
 *     minCorrelationScore?: number
 *   }
 * }
 */
router.post('/correlate', fusionController.correlate);

// ============================================
// ENTITY RESOLUTION ENDPOINTS
// ============================================

/**
 * POST /api/v1/fusion/resolve
 * Resolve and deduplicate entity identities
 *
 * Body: {
 *   target: string,
 *   sources?: IntelligenceSource[],
 *   options?: {
 *     minCorrelationScore?: number
 *   }
 * }
 */
router.post('/resolve', fusionController.resolve);

// ============================================
// GRAPH ENDPOINTS
// ============================================

/**
 * GET /api/v1/fusion/graph/export
 * Export graph data for visualization
 */
router.get('/graph/export', fusionController.exportGraph);

/**
 * DELETE /api/v1/fusion/graph
 * Clear all graph data
 */
router.delete('/graph', fusionController.clearGraph);

/**
 * POST /api/v1/fusion/graph/hydrate
 * Hydrate graph with entity data
 *
 * Body: {
 *   nodes: GraphNode[],
 *   edges?: GraphEdge[]
 * }
 */
router.post('/graph/hydrate', fusionController.hydrateGraph);

/**
 * GET /api/v1/fusion/graph/:entityId
 * Get entity network graph
 *
 * Query params:
 *   maxDepth?: number (default: 2)
 */
router.get('/graph/:entityId', fusionController.getEntityGraph);

/**
 * GET /api/v1/fusion/graph/:entityId/path/:targetId
 * Find shortest path between two entities
 */
router.get('/graph/:entityId/path/:targetId', fusionController.findPath);

/**
 * GET /api/v1/fusion/graph/:entityId/predictions
 * Get predicted links for entity
 *
 * Query params:
 *   topN?: number (default: 5)
 */
router.get('/graph/:entityId/predictions', fusionController.getPredictions);

// ============================================
// TIMELINE ENDPOINTS
// ============================================

/**
 * POST /api/v1/fusion/timeline/build
 * Build timeline from sources
 *
 * Body: {
 *   target: string,
 *   sources?: IntelligenceSource[]
 * }
 */
router.post('/timeline/build', fusionController.buildTimelineFromSources);

/**
 * GET /api/v1/fusion/timeline/:targetId
 * Get activity timeline for target
 *
 * Query params:
 *   limit?: number (default: 100)
 *   offset?: number (default: 0)
 */
router.get('/timeline/:targetId', fusionController.getTimeline);

// ============================================
// RISK ASSESSMENT ENDPOINTS
// ============================================

/**
 * POST /api/v1/fusion/assess-risk
 * Calculate risk score for entity
 *
 * Body: {
 *   target?: string,
 *   sources?: IntelligenceSource[],
 *   profile?: EntityProfile
 * }
 */
router.post('/assess-risk', fusionController.assessEntityRisk);

// ============================================
// HEALTH CHECK
// ============================================

/**
 * GET /api/v1/fusion/health
 * Health check endpoint
 */
router.get('/health', fusionController.healthCheck);

export default router;
