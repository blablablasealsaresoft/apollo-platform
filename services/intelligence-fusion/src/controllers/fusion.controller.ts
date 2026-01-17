/**
 * Intelligence Fusion Controller
 * REST API endpoints for intelligence fusion operations
 */

import { Request, Response, NextFunction } from 'express';

// Import logger with fallback for standalone operation
let logger: any = console;
try {
  const shared = require('@apollo/shared');
  logger = shared.logger || console;
} catch {
  logger = {
    info: (...args: any[]) => console.log('[INFO]', ...args),
    warn: (...args: any[]) => console.warn('[WARN]', ...args),
    error: (...args: any[]) => console.error('[ERROR]', ...args),
    debug: (...args: any[]) => console.debug('[DEBUG]', ...args)
  };
}
import { ingestIntel, validatePayload, RawIntelPayload } from '../processors/ingest.processor';
import {
  runFusion,
  resolveEntities,
  correlateEntities,
  assessRisk,
  buildTimeline,
  analyzeGraph,
  buildEntityProfile,
  calculateConfidence,
  IntelligenceSource,
  EntityProfile
} from '../algorithms/fusion_engine';
import * as graphService from '../services/graph.service';

// ============================================
// MAIN FUSION ENDPOINT
// ============================================

/**
 * POST /api/v1/fusion/fuse
 * Main fusion endpoint - correlate intelligence from multiple sources
 */
export async function fuse(req: Request, res: Response, next: NextFunction) {
  try {
    const startTime = Date.now();

    // Validate payload
    const validation = validatePayload(req.body);
    if (!validation.valid) {
      return res.status(400).json({
        error: 'Invalid payload',
        details: validation.errors
      });
    }

    // Ingest and normalize
    const normalized = await ingestIntel(req.body);

    // Run fusion
    const result = runFusion(normalized);

    const duration = Date.now() - startTime;
    logger.info('Fusion completed', {
      target: normalized.target,
      sources: normalized.sources?.length || 0,
      duration,
      confidence: result.confidence
    });

    res.json({
      success: true,
      duration,
      result
    });
  } catch (error) {
    logger.error('Fusion error', { error: String(error) });
    next(error);
  }
}

// ============================================
// CORRELATION ENDPOINT
// ============================================

/**
 * POST /api/v1/fusion/correlate
 * Run correlation analysis on entities
 */
export async function correlate(req: Request, res: Response, next: NextFunction) {
  try {
    const { entities, sources, options = {} } = req.body;

    if (!entities || !Array.isArray(entities)) {
      return res.status(400).json({
        error: 'entities array is required'
      });
    }

    // Convert to IntelligenceSource format if raw data provided
    let normalizedSources: IntelligenceSource[] = sources || [];
    if (sources && sources.length > 0) {
      const normalized = await ingestIntel({ sources, target: '' });
      normalizedSources = normalized.sources || [];
    }

    // Resolve entities first
    const resolved = resolveEntities(normalizedSources, entities[0] || '');

    // Run correlation
    const correlations = correlateEntities(
      resolved,
      normalizedSources,
      options.minCorrelationScore || 0.6
    );

    res.json({
      success: true,
      correlations: {
        relationships: correlations.relationships,
        temporalCorrelations: correlations.correlations,
        clusters: correlations.clusters,
        sharedAttributes: correlations.sharedAttributes,
        crossSourceValidation: correlations.crossSourceValidation
      },
      statistics: {
        totalRelationships: correlations.relationships.length,
        totalClusters: correlations.clusters.length,
        corroborationScore: correlations.crossSourceValidation.corroborationScore
      }
    });
  } catch (error) {
    logger.error('Correlation error', { error: String(error) });
    next(error);
  }
}

// ============================================
// ENTITY RESOLUTION ENDPOINT
// ============================================

/**
 * POST /api/v1/fusion/resolve
 * Resolve and deduplicate entity identities
 */
export async function resolve(req: Request, res: Response, next: NextFunction) {
  try {
    const { target, sources, options = {} } = req.body;

    if (!target) {
      return res.status(400).json({
        error: 'target identifier is required'
      });
    }

    // Normalize sources
    const normalized = await ingestIntel({
      target,
      sources: sources || [],
      options
    });

    // Resolve entities
    const resolved = resolveEntities(normalized.sources || [], target);

    // Build profile
    const correlations = correlateEntities(resolved, normalized.sources || [], options.minCorrelationScore || 0.6);
    const profile = buildEntityProfile(target, resolved, correlations, normalized.sources || []);
    profile.confidenceScore = calculateConfidence(profile, normalized.sources || []);

    res.json({
      success: true,
      entity: {
        entityId: profile.entityId,
        primaryIdentifier: profile.primaryIdentifier,
        entityType: profile.entityType,
        confidenceScore: profile.confidenceScore,
        attributes: profile.attributes,
        aliases: profile.aliases,
        sourcesCount: profile.sources.length
      },
      resolvedEntities: resolved.map(e => ({
        entityId: e.entityId,
        type: e.type,
        identifier: e.primaryIdentifier,
        confidence: e.confidence,
        sourceId: e.sourceId
      })),
      mergeHistory: {
        originalCount: sources?.length || 0,
        resolvedCount: resolved.length,
        mergeRate: sources?.length ? 1 - (resolved.length / sources.length) : 0
      }
    });
  } catch (error) {
    logger.error('Resolution error', { error: String(error) });
    next(error);
  }
}

// ============================================
// GRAPH ENDPOINTS
// ============================================

/**
 * GET /api/v1/fusion/graph/:entityId
 * Get entity network graph
 */
export async function getEntityGraph(req: Request, res: Response, next: NextFunction) {
  try {
    const { entityId } = req.params;
    const maxDepth = parseInt(req.query.maxDepth as string) || 2;

    if (!entityId) {
      return res.status(400).json({
        error: 'entityId is required'
      });
    }

    // Get entity network
    const network = await graphService.getEntityNetwork(entityId, maxDepth);

    // Calculate centrality if node exists
    let centrality = null;
    if (network.nodes.length > 0) {
      centrality = await graphService.calculateCentrality(entityId);
    }

    // Detect communities
    const communities = await graphService.detectCommunities();

    // Get network metrics
    const metrics = await graphService.getNetworkMetrics();

    res.json({
      success: true,
      graph: {
        nodes: network.nodes.map(n => ({
          id: n.id,
          type: n.type,
          identifier: n.identifier,
          riskScore: n.riskScore,
          confidenceScore: n.confidenceScore
        })),
        edges: network.edges.map(e => ({
          id: e.id,
          source: e.sourceId,
          target: e.targetId,
          type: e.type,
          weight: e.weight
        }))
      },
      analysis: {
        centrality,
        communities: communities.filter(c => c.members.includes(entityId)),
        networkMetrics: metrics
      }
    });
  } catch (error) {
    logger.error('Graph error', { error: String(error) });
    next(error);
  }
}

/**
 * GET /api/v1/fusion/graph/:entityId/path/:targetId
 * Find shortest path between two entities
 */
export async function findPath(req: Request, res: Response, next: NextFunction) {
  try {
    const { entityId, targetId } = req.params;

    if (!entityId || !targetId) {
      return res.status(400).json({
        error: 'entityId and targetId are required'
      });
    }

    const path = await graphService.findShortestPath(entityId, targetId);

    if (!path) {
      return res.status(404).json({
        error: 'No path found between entities'
      });
    }

    res.json({
      success: true,
      path: {
        nodes: path.nodes,
        edges: path.edges,
        hops: path.hops,
        totalWeight: path.totalWeight
      }
    });
  } catch (error) {
    logger.error('Path finding error', { error: String(error) });
    next(error);
  }
}

/**
 * GET /api/v1/fusion/graph/:entityId/predictions
 * Get predicted links for entity
 */
export async function getPredictions(req: Request, res: Response, next: NextFunction) {
  try {
    const { entityId } = req.params;
    const topN = parseInt(req.query.topN as string) || 5;

    if (!entityId) {
      return res.status(400).json({
        error: 'entityId is required'
      });
    }

    const predictions = await graphService.predictLinks(entityId, topN);

    res.json({
      success: true,
      predictions: predictions.map(p => ({
        targetId: p.targetId,
        score: p.score,
        commonNeighbors: p.commonNeighbors,
        method: p.method
      }))
    });
  } catch (error) {
    logger.error('Prediction error', { error: String(error) });
    next(error);
  }
}

/**
 * POST /api/v1/fusion/graph/hydrate
 * Hydrate graph with entity data
 */
export async function hydrateGraph(req: Request, res: Response, next: NextFunction) {
  try {
    const { nodes, edges } = req.body;

    if (!nodes || !Array.isArray(nodes)) {
      return res.status(400).json({
        error: 'nodes array is required'
      });
    }

    // Hydrate nodes
    const graphNodes = nodes.map((n: any) => ({
      id: n.id || n.entityId,
      type: n.type || 'unknown',
      identifier: n.identifier || n.primaryIdentifier || n.id,
      attributes: n.attributes || {},
      riskScore: n.riskScore,
      confidenceScore: n.confidenceScore,
      createdAt: new Date(n.createdAt || Date.now()),
      updatedAt: new Date(n.updatedAt || Date.now())
    }));

    await graphService.hydrateGraph(graphNodes);

    // Add edges if provided
    if (edges && Array.isArray(edges)) {
      for (const e of edges) {
        await graphService.addEdge({
          id: e.id || `edge_${e.sourceId}_${e.targetId}`,
          sourceId: e.sourceId || e.source,
          targetId: e.targetId || e.target,
          type: e.type || 'related',
          weight: e.weight || 1.0,
          evidence: e.evidence || [],
          createdAt: new Date(e.createdAt || Date.now())
        });
      }
    }

    res.json({
      success: true,
      hydrated: {
        nodes: graphNodes.length,
        edges: edges?.length || 0
      }
    });
  } catch (error) {
    logger.error('Hydration error', { error: String(error) });
    next(error);
  }
}

// ============================================
// TIMELINE ENDPOINT
// ============================================

/**
 * GET /api/v1/fusion/timeline/:targetId
 * Get activity timeline for target
 */
export async function getTimeline(req: Request, res: Response, next: NextFunction) {
  try {
    const { targetId } = req.params;
    const limit = parseInt(req.query.limit as string) || 100;
    const offset = parseInt(req.query.offset as string) || 0;

    if (!targetId) {
      return res.status(400).json({
        error: 'targetId is required'
      });
    }

    // For now, return empty timeline - in production this would query database
    // In a full implementation, we'd retrieve stored profile and sources

    res.json({
      success: true,
      targetId,
      timeline: [],
      pagination: {
        limit,
        offset,
        total: 0
      },
      patterns: {
        activityBursts: [],
        gaps: [],
        trends: null
      }
    });
  } catch (error) {
    logger.error('Timeline error', { error: String(error) });
    next(error);
  }
}

/**
 * POST /api/v1/fusion/timeline/build
 * Build timeline from sources
 */
export async function buildTimelineFromSources(req: Request, res: Response, next: NextFunction) {
  try {
    const { target, sources } = req.body;

    if (!target) {
      return res.status(400).json({
        error: 'target is required'
      });
    }

    // Normalize sources
    const normalized = await ingestIntel({
      target,
      sources: sources || []
    });

    // Resolve and build profile
    const resolved = resolveEntities(normalized.sources || [], target);
    const correlations = correlateEntities(resolved, normalized.sources || [], 0.6);
    const profile = buildEntityProfile(target, resolved, correlations, normalized.sources || []);

    // Build timeline
    const timeline = buildTimeline(profile, normalized.sources || []);

    // Analyze patterns
    const gaps = timeline.filter(e => e.type === 'gap');
    const events = timeline.filter(e => !e.isMetadata);

    res.json({
      success: true,
      timeline: events,
      analysis: {
        totalEvents: events.length,
        gaps: gaps.map(g => ({
          timestamp: g.timestamp,
          description: g.description
        })),
        dateRange: events.length > 0 ? {
          start: events[0].timestamp,
          end: events[events.length - 1].timestamp
        } : null,
        eventTypes: events.reduce((acc, e) => {
          acc[e.type] = (acc[e.type] || 0) + 1;
          return acc;
        }, {} as Record<string, number>)
      }
    });
  } catch (error) {
    logger.error('Timeline build error', { error: String(error) });
    next(error);
  }
}

// ============================================
// RISK ASSESSMENT ENDPOINT
// ============================================

/**
 * POST /api/v1/fusion/assess-risk
 * Calculate risk score for entity
 */
export async function assessEntityRisk(req: Request, res: Response, next: NextFunction) {
  try {
    const { target, sources, profile: existingProfile } = req.body;

    if (!target && !existingProfile) {
      return res.status(400).json({
        error: 'target or profile is required'
      });
    }

    let profile: EntityProfile;
    let correlations;

    if (existingProfile) {
      // Use provided profile
      profile = existingProfile;
      correlations = {
        relationships: existingProfile.relationships || [],
        correlations: [],
        clusters: [],
        sharedAttributes: {},
        crossSourceValidation: {
          multiSourceEntities: [],
          singleSourceEntities: [],
          corroborationScore: 0
        }
      };
    } else {
      // Build profile from sources
      const normalized = await ingestIntel({
        target,
        sources: sources || []
      });

      const resolved = resolveEntities(normalized.sources || [], target);
      correlations = correlateEntities(resolved, normalized.sources || [], 0.6);
      profile = buildEntityProfile(target, resolved, correlations, normalized.sources || []);
      profile.confidenceScore = calculateConfidence(profile, normalized.sources || []);
    }

    // Assess risk
    const riskAssessment = assessRisk(profile, correlations);

    res.json({
      success: true,
      riskAssessment: {
        overallRisk: riskAssessment.overallRisk,
        riskCategory: riskAssessment.riskCategory,
        components: riskAssessment.components,
        threatIndicators: riskAssessment.threatIndicators,
        recommendations: riskAssessment.recommendations
      },
      entity: {
        entityId: profile.entityId,
        primaryIdentifier: profile.primaryIdentifier,
        confidenceScore: profile.confidenceScore
      }
    });
  } catch (error) {
    logger.error('Risk assessment error', { error: String(error) });
    next(error);
  }
}

// ============================================
// DEEP ANALYSIS ENDPOINT
// ============================================

/**
 * POST /api/v1/fusion/analyze
 * Run comprehensive analysis on target
 */
export async function runDeepAnalysis(req: Request, res: Response, next: NextFunction) {
  try {
    const startTime = Date.now();
    const { target, sources, options = {} } = req.body;

    if (!target) {
      return res.status(400).json({
        error: 'target is required'
      });
    }

    // Enable deep analysis
    const fusionOptions = {
      ...options,
      deepAnalysis: true,
      includeTimeline: true,
      includeRiskAssessment: true
    };

    // Ingest and normalize
    const normalized = await ingestIntel({
      target,
      sources: sources || [],
      options: fusionOptions
    });

    // Run full fusion
    const result = runFusion(normalized);

    // Additional graph analysis
    let graphData = null;
    if (result.entityProfile) {
      try {
        // Hydrate graph with profile data
        const graphNodes = [{
          id: result.entityProfile.entityId,
          type: result.entityProfile.entityType,
          identifier: result.entityProfile.primaryIdentifier,
          attributes: result.entityProfile.attributes,
          riskScore: result.entityProfile.riskScore,
          confidenceScore: result.entityProfile.confidenceScore,
          createdAt: new Date(),
          updatedAt: new Date()
        }];
        await graphService.hydrateGraph(graphNodes);

        // Get graph visualization data
        graphData = graphService.exportGraphData();
      } catch (graphError) {
        logger.warn('Graph analysis failed', { error: String(graphError) });
      }
    }

    const duration = Date.now() - startTime;

    res.json({
      success: true,
      duration,
      analysis: {
        profile: result.entityProfile,
        correlations: result.correlations,
        timeline: result.timeline,
        riskAssessment: result.riskAssessment,
        graphAnalysis: result.graphAnalysis,
        graphVisualization: graphData
      },
      summary: result.summary,
      confidence: result.confidence
    });
  } catch (error) {
    logger.error('Deep analysis error', { error: String(error) });
    next(error);
  }
}

// ============================================
// GRAPH MANAGEMENT
// ============================================

/**
 * DELETE /api/v1/fusion/graph
 * Clear graph data
 */
export async function clearGraph(req: Request, res: Response, next: NextFunction) {
  try {
    graphService.clearGraph();

    res.json({
      success: true,
      message: 'Graph cleared'
    });
  } catch (error) {
    logger.error('Clear graph error', { error: String(error) });
    next(error);
  }
}

/**
 * GET /api/v1/fusion/graph/export
 * Export graph data for visualization
 */
export async function exportGraph(req: Request, res: Response, next: NextFunction) {
  try {
    const format = req.query.format as string || 'json';

    const graphData = graphService.exportGraphData();
    const metrics = await graphService.getNetworkMetrics();
    const communities = await graphService.detectCommunities();

    res.json({
      success: true,
      format,
      graph: graphData,
      metrics,
      communities
    });
  } catch (error) {
    logger.error('Export error', { error: String(error) });
    next(error);
  }
}

// ============================================
// HEALTH CHECK
// ============================================

/**
 * GET /api/v1/fusion/health
 * Health check endpoint
 */
export async function healthCheck(req: Request, res: Response) {
  const metrics = await graphService.getNetworkMetrics();

  res.json({
    status: 'healthy',
    service: 'intelligence-fusion',
    version: '1.0.0',
    graphMetrics: {
      nodes: metrics.totalNodes,
      edges: metrics.totalEdges
    },
    timestamp: new Date().toISOString()
  });
}

export default {
  fuse,
  correlate,
  resolve,
  getEntityGraph,
  findPath,
  getPredictions,
  hydrateGraph,
  getTimeline,
  buildTimelineFromSources,
  assessEntityRisk,
  runDeepAnalysis,
  clearGraph,
  exportGraph,
  healthCheck
};
