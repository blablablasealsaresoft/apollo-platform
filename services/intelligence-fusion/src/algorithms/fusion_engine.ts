/**
 * Intelligence Fusion Engine - Core Algorithms
 * Multi-source data correlation, entity resolution, and risk assessment
 */

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

import * as crypto from 'crypto';

// ============================================
// TYPES AND INTERFACES
// ============================================

export interface FusionInput {
  investigations: string[];
  telemetry: Record<string, unknown>;
  sources?: IntelligenceSource[];
  target?: string;
  options?: FusionOptions;
}

export interface FusionOptions {
  deepAnalysis?: boolean;
  maxGraphDepth?: number;
  minCorrelationScore?: number;
  includeTimeline?: boolean;
  includeRiskAssessment?: boolean;
}

export interface FusionResult {
  confidence: number;
  summary: string;
  entityProfile?: EntityProfile;
  correlations?: CorrelationResult;
  timeline?: TimelineEvent[];
  riskAssessment?: RiskAssessment;
  graphAnalysis?: GraphAnalysis;
}

export interface IntelligenceSource {
  sourceId: string;
  sourceType: SourceType;
  reliability: number;
  timestamp: Date;
  data: Record<string, any>;
}

export type SourceType =
  | 'osint'
  | 'sigint'
  | 'geoint'
  | 'finint'
  | 'humint'
  | 'blockchain'
  | 'breach'
  | 'sherlock'
  | 'socmint'
  | 'unknown';

export interface EntityProfile {
  entityId: string;
  primaryIdentifier: string;
  entityType: EntityType;
  attributes: Record<string, any>;
  aliases: string[];
  relationships: Relationship[];
  timeline: TimelineEvent[];
  riskScore: number;
  confidenceScore: number;
  sources: string[];
  metadata: Record<string, any>;
}

export type EntityType =
  | 'person'
  | 'email'
  | 'phone'
  | 'wallet'
  | 'organization'
  | 'domain'
  | 'ip'
  | 'location'
  | 'unknown';

export interface Relationship {
  sourceEntity: string;
  targetEntity: string;
  type: RelationshipType;
  score: number;
  evidence: string[];
}

export type RelationshipType =
  | 'owns'
  | 'alias'
  | 'associates'
  | 'colleague'
  | 'related'
  | 'transacted'
  | 'communicated';

export interface CorrelationResult {
  relationships: Relationship[];
  correlations: TemporalCorrelation[];
  clusters: EntityCluster[];
  sharedAttributes: Record<string, string[]>;
  crossSourceValidation: CrossSourceValidation;
}

export interface TemporalCorrelation {
  source1: string;
  source2: string;
  type: 'temporal';
  timeDiffHours: number;
  score: number;
}

export interface EntityCluster {
  clusterId: string;
  entities: string[];
  size: number;
}

export interface CrossSourceValidation {
  multiSourceEntities: Array<{ entityId: string; sourceCount: number; identifier: string }>;
  singleSourceEntities: string[];
  corroborationScore: number;
}

export interface TimelineEvent {
  timestamp: string;
  type: string;
  description: string;
  source?: string;
  details?: Record<string, any>;
  severity?: 'low' | 'medium' | 'high' | 'critical';
  isMetadata?: boolean;
}

export interface RiskAssessment {
  overallRisk: number;
  riskCategory: 'MINIMAL' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  components: Record<string, { score: number; weight: number }>;
  threatIndicators: ThreatIndicator[];
  recommendations: string[];
}

export interface ThreatIndicator {
  type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
}

export interface GraphAnalysis {
  centrality: {
    degree: number;
    betweenness: number;
    closeness: number;
    eigenvector: number;
  };
  communities: Array<{ id: string; members: string[]; size: number }>;
  influenceScore: number;
  predictedLinks: Array<{ target: string; score: number; commonNeighbors: number }>;
  networkMetrics: {
    totalNodes: number;
    totalEdges: number;
    density: number;
    clusteringCoefficient: number;
  };
}

export interface ResolvedEntity {
  entityId: string;
  primaryIdentifier: string;
  type: EntityType;
  attributes: Record<string, any>;
  aliases: string[];
  sourceId: string;
  confidence: number;
}

// ============================================
// CONFIGURATION
// ============================================

const DEFAULT_CONFIG = {
  entityResolution: {
    fuzzyThreshold: 0.85,
    emailExactMatch: true,
    phoneNormalize: true
  },
  correlation: {
    minCorrelationScore: 0.6,
    timeWindowDays: 365,
    maxGraphDepth: 3
  },
  confidence: {
    sourceWeights: {
      blockchain: 0.95,
      breach: 0.85,
      sherlock: 0.80,
      socmint: 0.75,
      osint: 0.70,
      sigint: 0.90,
      geoint: 0.85,
      finint: 0.90,
      humint: 0.65,
      unknown: 0.50
    },
    freshnessDecayDays: 180,
    corroborationBonus: 0.15,
    conflictPenalty: 0.20
  },
  risk: {
    criticalThreshold: 90,
    highThreshold: 75,
    mediumThreshold: 50,
    lowThreshold: 25
  }
};

// ============================================
// MAIN FUSION FUNCTION
// ============================================

/**
 * Run intelligence fusion on provided input
 */
export function runFusion(input: FusionInput): FusionResult {
  const options = input.options || {};

  // Basic confidence calculation for backward compatibility
  const baseConfidence = Math.min(1, input.investigations.length * 0.1 + 0.5);

  // If no sources provided, return basic result
  if (!input.sources || input.sources.length === 0) {
    return {
      confidence: baseConfidence,
      summary: `Correlated ${input.investigations.join(', ')}`
    };
  }

  logger.info(`Running fusion on ${input.sources.length} sources for target: ${input.target}`);

  // Step 1: Entity Resolution
  const resolvedEntities = resolveEntities(input.sources, input.target || '');

  // Step 2: Correlation
  const correlations = correlateEntities(resolvedEntities, input.sources, options.minCorrelationScore);

  // Step 3: Build Entity Profile
  const entityProfile = buildEntityProfile(input.target || '', resolvedEntities, correlations, input.sources);

  // Step 4: Calculate Confidence
  entityProfile.confidenceScore = calculateConfidence(entityProfile, input.sources);

  // Step 5: Risk Assessment
  let riskAssessment: RiskAssessment | undefined;
  if (options.includeRiskAssessment !== false) {
    riskAssessment = assessRisk(entityProfile, correlations);
    entityProfile.riskScore = riskAssessment.overallRisk;
  }

  // Step 6: Timeline Generation
  let timeline: TimelineEvent[] | undefined;
  if (options.includeTimeline !== false) {
    timeline = buildTimeline(entityProfile, input.sources);
    entityProfile.timeline = timeline;
  }

  // Step 7: Graph Analysis
  let graphAnalysis: GraphAnalysis | undefined;
  if (options.deepAnalysis) {
    graphAnalysis = analyzeGraph(entityProfile, correlations);
  }

  // Build summary
  const summary = generateSummary(entityProfile, correlations, riskAssessment);

  return {
    confidence: entityProfile.confidenceScore / 100,
    summary,
    entityProfile,
    correlations,
    timeline,
    riskAssessment,
    graphAnalysis
  };
}

// ============================================
// ENTITY RESOLUTION
// ============================================

/**
 * Resolve and deduplicate entities from multiple sources
 */
export function resolveEntities(
  sources: IntelligenceSource[],
  target: string
): ResolvedEntity[] {
  const candidates: ResolvedEntity[] = [];

  // Extract entities from each source
  for (const source of sources) {
    const entities = extractEntities(source);
    candidates.push(...entities);
  }

  // Deduplicate and merge
  return deduplicateEntities(candidates, target);
}

function extractEntities(source: IntelligenceSource): ResolvedEntity[] {
  const entities: ResolvedEntity[] = [];
  const data = source.data;

  // Email-based entity
  if (data.email) {
    const email = String(data.email).toLowerCase().trim();
    if (isValidEmail(email)) {
      entities.push({
        entityId: generateEntityId('email', email),
        primaryIdentifier: email,
        type: 'email',
        attributes: extractAttributes(data, ['email', 'name', 'username', 'location', 'phone', 'organization']),
        aliases: extractAliases(data),
        sourceId: source.sourceId,
        confidence: 0.9
      });
    }
  }

  // Phone-based entity
  if (data.phone) {
    const phone = normalizePhone(String(data.phone));
    if (phone) {
      entities.push({
        entityId: generateEntityId('phone', phone),
        primaryIdentifier: phone,
        type: 'phone',
        attributes: extractAttributes(data, ['phone', 'name', 'email', 'location', 'carrier']),
        aliases: [],
        sourceId: source.sourceId,
        confidence: 0.85
      });
    }
  }

  // Name-based entity
  if (data.name && String(data.name).trim().length >= 2) {
    const name = String(data.name).trim();
    entities.push({
      entityId: generateEntityId('name', normalizeName(name)),
      primaryIdentifier: name,
      type: 'person',
      attributes: extractAttributes(data, ['name', 'email', 'phone', 'location', 'age', 'occupation']),
      aliases: extractAliases(data),
      sourceId: source.sourceId,
      confidence: 0.75
    });
  }

  // Wallet-based entity
  if (data.wallet || data.address) {
    const wallet = String(data.wallet || data.address).trim();
    if (wallet) {
      entities.push({
        entityId: generateEntityId('wallet', wallet),
        primaryIdentifier: wallet,
        type: 'wallet',
        attributes: {
          ...extractAttributes(data, ['wallet', 'address', 'owner_email', 'owner_name', 'balance', 'transactions']),
          blockchain: detectBlockchain(wallet)
        },
        aliases: [],
        sourceId: source.sourceId,
        confidence: 0.95
      });
    }
  }

  // Domain-based entity
  if (data.domain) {
    entities.push({
      entityId: generateEntityId('domain', String(data.domain).toLowerCase()),
      primaryIdentifier: String(data.domain).toLowerCase(),
      type: 'domain',
      attributes: extractAttributes(data, ['domain', 'registrant', 'dns', 'hosting']),
      aliases: [],
      sourceId: source.sourceId,
      confidence: 0.85
    });
  }

  // IP-based entity
  if (data.ip || data.ip_address) {
    const ip = String(data.ip || data.ip_address);
    entities.push({
      entityId: generateEntityId('ip', ip),
      primaryIdentifier: ip,
      type: 'ip',
      attributes: extractAttributes(data, ['ip', 'ip_address', 'location', 'asn', 'isp']),
      aliases: [],
      sourceId: source.sourceId,
      confidence: 0.90
    });
  }

  return entities;
}

function deduplicateEntities(entities: ResolvedEntity[], target: string): ResolvedEntity[] {
  if (entities.length === 0) return [];

  // Group by type
  const byType = new Map<EntityType, ResolvedEntity[]>();
  for (const entity of entities) {
    if (!byType.has(entity.type)) {
      byType.set(entity.type, []);
    }
    byType.get(entity.type)!.push(entity);
  }

  const deduplicated: ResolvedEntity[] = [];

  for (const [type, typeEntities] of byType) {
    let deduped: ResolvedEntity[];

    switch (type) {
      case 'email':
        deduped = deduplicateByExactMatch(typeEntities, 'email');
        break;
      case 'phone':
        deduped = deduplicateByExactMatch(typeEntities, 'phone');
        break;
      case 'person':
        deduped = deduplicateByFuzzyName(typeEntities);
        break;
      case 'wallet':
        deduped = deduplicateByExactMatch(typeEntities, 'wallet');
        break;
      default:
        deduped = typeEntities;
    }

    deduplicated.push(...deduped);
  }

  return deduplicated;
}

function deduplicateByExactMatch(entities: ResolvedEntity[], keyAttr: string): ResolvedEntity[] {
  const seen = new Map<string, ResolvedEntity>();

  for (const entity of entities) {
    const key = String(entity.attributes[keyAttr] || entity.primaryIdentifier).toLowerCase();

    if (!seen.has(key)) {
      seen.set(key, entity);
    } else {
      // Merge entities
      seen.set(key, mergeEntities(seen.get(key)!, entity));
    }
  }

  return Array.from(seen.values());
}

function deduplicateByFuzzyName(entities: ResolvedEntity[]): ResolvedEntity[] {
  const deduplicated: ResolvedEntity[] = [];

  for (const entity of entities) {
    const entityName = entity.attributes.name || entity.primaryIdentifier;
    let matched = false;

    for (let i = 0; i < deduplicated.length; i++) {
      const existingName = deduplicated[i].attributes.name || deduplicated[i].primaryIdentifier;

      if (namesMatch(entityName, existingName)) {
        deduplicated[i] = mergeEntities(deduplicated[i], entity);
        matched = true;
        break;
      }
    }

    if (!matched) {
      deduplicated.push(entity);
    }
  }

  return deduplicated;
}

function mergeEntities(primary: ResolvedEntity, secondary: ResolvedEntity): ResolvedEntity {
  // Merge attributes
  const mergedAttrs = { ...primary.attributes };
  for (const [key, value] of Object.entries(secondary.attributes)) {
    if (!(key in mergedAttrs)) {
      mergedAttrs[key] = value;
    } else if (Array.isArray(value)) {
      const existing = mergedAttrs[key];
      if (Array.isArray(existing)) {
        mergedAttrs[key] = [...new Set([...existing, ...value])];
      } else {
        mergedAttrs[key] = [...new Set([existing, ...value])];
      }
    }
  }

  // Merge aliases
  const mergedAliases = [...new Set([...primary.aliases, ...secondary.aliases])];

  // Average confidence with corroboration bonus
  const mergedConfidence = Math.min((primary.confidence + secondary.confidence) / 2 * 1.1, 1.0);

  return {
    ...primary,
    attributes: mergedAttrs,
    aliases: mergedAliases,
    sourceId: `${primary.sourceId}+${secondary.sourceId}`,
    confidence: mergedConfidence
  };
}

// ============================================
// CORRELATION ENGINE
// ============================================

/**
 * Correlate entities across sources
 */
export function correlateEntities(
  entities: ResolvedEntity[],
  sources: IntelligenceSource[],
  minScore: number = DEFAULT_CONFIG.correlation.minCorrelationScore
): CorrelationResult {
  const relationships: Relationship[] = [];
  const temporalCorrelations: TemporalCorrelation[] = [];

  // Entity-to-entity correlations
  for (let i = 0; i < entities.length; i++) {
    for (let j = i + 1; j < entities.length; j++) {
      const score = calculateEntityCorrelation(entities[i], entities[j]);

      if (score >= minScore) {
        relationships.push({
          sourceEntity: entities[i].entityId,
          targetEntity: entities[j].entityId,
          type: determineRelationshipType(entities[i], entities[j]),
          score,
          evidence: collectEvidence(entities[i], entities[j])
        });
      }
    }
  }

  // Temporal correlations
  const timeWindowMs = DEFAULT_CONFIG.correlation.timeWindowDays * 24 * 60 * 60 * 1000;
  for (let i = 0; i < sources.length; i++) {
    for (let j = i + 1; j < sources.length; j++) {
      const timeDiff = Math.abs(sources[i].timestamp.getTime() - sources[j].timestamp.getTime());

      if (timeDiff <= timeWindowMs) {
        const proximityScore = 1 - (timeDiff / timeWindowMs);
        temporalCorrelations.push({
          source1: sources[i].sourceId,
          source2: sources[j].sourceId,
          type: 'temporal',
          timeDiffHours: timeDiff / (1000 * 60 * 60),
          score: proximityScore * 0.6 // weight temporal proximity
        });
      }
    }
  }

  // Attribute-based correlations
  const sharedAttributes = findSharedAttributes(entities);

  // Cluster entities
  const clusters = clusterEntities(entities, relationships);

  // Cross-source validation
  const crossSourceValidation = validateCrossSources(entities, sources);

  return {
    relationships,
    correlations: temporalCorrelations,
    clusters,
    sharedAttributes,
    crossSourceValidation
  };
}

function calculateEntityCorrelation(e1: ResolvedEntity, e2: ResolvedEntity): number {
  let score = 0;
  const weights = {
    exactMatch: 1.0,
    fuzzyMatch: 0.8,
    attributeOverlap: 0.7,
    sharedSource: 0.5
  };

  const attrs1 = e1.attributes;
  const attrs2 = e2.attributes;

  // Shared email domain
  if (attrs1.email && attrs2.email) {
    const domain1 = String(attrs1.email).split('@')[1] || '';
    const domain2 = String(attrs2.email).split('@')[1] || '';
    if (domain1 && domain1 === domain2) {
      score += weights.exactMatch * 0.6;
    }
  }

  // Shared phone prefix
  if (attrs1.phone && attrs2.phone) {
    const phone1 = String(attrs1.phone).slice(0, 4);
    const phone2 = String(attrs2.phone).slice(0, 4);
    if (phone1 === phone2) {
      score += weights.fuzzyMatch * 0.5;
    }
  }

  // Location overlap
  const loc1 = String(attrs1.location || '').toLowerCase();
  const loc2 = String(attrs2.location || '').toLowerCase();
  if (loc1 && loc2) {
    if (loc1 === loc2) {
      score += weights.exactMatch * 0.7;
    } else if (loc1.includes(loc2) || loc2.includes(loc1)) {
      score += weights.fuzzyMatch * 0.5;
    }
  }

  // Name similarity
  const name1 = attrs1.name || '';
  const name2 = attrs2.name || '';
  if (name1 && name2) {
    const similarity = stringSimilarity(name1, name2);
    if (similarity > 0.8) {
      score += weights.fuzzyMatch * similarity;
    }
  }

  // Shared aliases
  const aliases1 = new Set(e1.aliases.map(a => a.toLowerCase()));
  const aliases2 = new Set(e2.aliases.map(a => a.toLowerCase()));
  const sharedAliases = [...aliases1].filter(a => aliases2.has(a));
  if (sharedAliases.length > 0) {
    score += weights.exactMatch * Math.min(sharedAliases.length * 0.3, 1.0);
  }

  // Attribute key overlap
  const keys1 = new Set(Object.keys(attrs1));
  const keys2 = new Set(Object.keys(attrs2));
  const sharedKeys = [...keys1].filter(k => keys2.has(k));
  if (sharedKeys.length > 0) {
    const overlapScore = sharedKeys.filter(k => attrs1[k] === attrs2[k]).length / sharedKeys.length;
    score += weights.attributeOverlap * overlapScore * 0.5;
  }

  // Normalize to 0-1
  return Math.min(score / 4.0, 1.0);
}

function determineRelationshipType(e1: ResolvedEntity, e2: ResolvedEntity): RelationshipType {
  // Same type = alias
  if (e1.type === e2.type && e1.type === 'person') {
    return 'alias';
  }

  // Email to wallet = owns
  if ((e1.type === 'email' && e2.type === 'wallet') || (e2.type === 'email' && e1.type === 'wallet')) {
    return 'owns';
  }

  // Same location
  if (e1.attributes.location && e1.attributes.location === e2.attributes.location) {
    return 'associates';
  }

  // Same organization
  if (e1.attributes.organization && e1.attributes.organization === e2.attributes.organization) {
    return 'colleague';
  }

  return 'related';
}

function collectEvidence(e1: ResolvedEntity, e2: ResolvedEntity): string[] {
  const evidence: string[] = [];
  const attrs1 = e1.attributes;
  const attrs2 = e2.attributes;

  for (const key of Object.keys(attrs1)) {
    if (key in attrs2 && attrs1[key] === attrs2[key]) {
      evidence.push(`Shared ${key}: ${attrs1[key]}`);
    }
  }

  const aliases1 = new Set(e1.aliases.map(a => a.toLowerCase()));
  const aliases2 = new Set(e2.aliases.map(a => a.toLowerCase()));
  const shared = [...aliases1].filter(a => aliases2.has(a));
  if (shared.length > 0) {
    evidence.push(`Shared aliases: ${shared.join(', ')}`);
  }

  return evidence;
}

function findSharedAttributes(entities: ResolvedEntity[]): Record<string, string[]> {
  const attrIndex = new Map<string, Set<string>>();

  for (const entity of entities) {
    for (const [key, value] of Object.entries(entity.attributes)) {
      if (value && key !== 'name') {
        const attrKey = `${key}:${value}`;
        if (!attrIndex.has(attrKey)) {
          attrIndex.set(attrKey, new Set());
        }
        attrIndex.get(attrKey)!.add(entity.entityId);
      }
    }
  }

  const shared: Record<string, string[]> = {};
  for (const [attr, entityIds] of attrIndex) {
    if (entityIds.size >= 2) {
      shared[attr] = Array.from(entityIds);
    }
  }

  return shared;
}

function clusterEntities(entities: ResolvedEntity[], relationships: Relationship[]): EntityCluster[] {
  // Build adjacency graph
  const graph = new Map<string, Set<string>>();

  for (const rel of relationships) {
    if (!graph.has(rel.sourceEntity)) graph.set(rel.sourceEntity, new Set());
    if (!graph.has(rel.targetEntity)) graph.set(rel.targetEntity, new Set());
    graph.get(rel.sourceEntity)!.add(rel.targetEntity);
    graph.get(rel.targetEntity)!.add(rel.sourceEntity);
  }

  // Find connected components
  const visited = new Set<string>();
  const clusters: EntityCluster[] = [];

  function dfs(node: string, cluster: Set<string>) {
    visited.add(node);
    cluster.add(node);
    for (const neighbor of graph.get(node) || []) {
      if (!visited.has(neighbor)) {
        dfs(neighbor, cluster);
      }
    }
  }

  for (const entity of entities) {
    if (!visited.has(entity.entityId)) {
      const cluster = new Set<string>();
      dfs(entity.entityId, cluster);
      if (cluster.size >= 2) {
        clusters.push({
          clusterId: crypto.createHash('md5').update(Array.from(cluster).sort().join(',')).digest('hex').slice(0, 8),
          entities: Array.from(cluster),
          size: cluster.size
        });
      }
    }
  }

  return clusters;
}

function validateCrossSources(entities: ResolvedEntity[], sources: IntelligenceSource[]): CrossSourceValidation {
  const multiSource: Array<{ entityId: string; sourceCount: number; identifier: string }> = [];
  const singleSource: string[] = [];

  for (const entity of entities) {
    const sourceCount = entity.sourceId.split('+').length;

    if (sourceCount >= 2) {
      multiSource.push({
        entityId: entity.entityId,
        sourceCount,
        identifier: entity.primaryIdentifier
      });
    } else {
      singleSource.push(entity.entityId);
    }
  }

  const corroborationScore = entities.length > 0 ? multiSource.length / entities.length : 0;

  return {
    multiSourceEntities: multiSource,
    singleSourceEntities: singleSource,
    corroborationScore
  };
}

// ============================================
// PROFILE BUILDING
// ============================================

/**
 * Build unified entity profile
 */
export function buildEntityProfile(
  target: string,
  entities: ResolvedEntity[],
  correlations: CorrelationResult,
  sources: IntelligenceSource[]
): EntityProfile {
  const allAttributes: Record<string, Set<any>> = {};
  const allAliases = new Set<string>();
  const sourceIds = new Set<string>();

  for (const entity of entities) {
    // Aggregate attributes
    for (const [key, value] of Object.entries(entity.attributes)) {
      if (!allAttributes[key]) allAttributes[key] = new Set();
      if (Array.isArray(value)) {
        value.forEach(v => allAttributes[key].add(v));
      } else {
        allAttributes[key].add(value);
      }
    }

    // Collect aliases
    entity.aliases.forEach(a => allAliases.add(a));

    // Track sources
    sourceIds.add(entity.sourceId);
  }

  // Convert sets to final values
  const attributes: Record<string, any> = {};
  for (const [key, values] of Object.entries(allAttributes)) {
    const arr = Array.from(values);
    attributes[key] = arr.length === 1 ? arr[0] : arr;
  }

  const entityType = determineEntityType(target, entities);

  return {
    entityId: `entity_${crypto.createHash('sha256').update(target).digest('hex').slice(0, 16)}_${Date.now()}`,
    primaryIdentifier: target,
    entityType,
    attributes,
    aliases: Array.from(allAliases),
    relationships: correlations.relationships,
    timeline: [],
    riskScore: 0,
    confidenceScore: 0,
    sources: Array.from(sourceIds),
    metadata: {
      totalSources: sources.length,
      sourceTypes: [...new Set(sources.map(s => s.sourceType))],
      firstSeen: Math.min(...sources.map(s => s.timestamp.getTime())),
      lastSeen: Math.max(...sources.map(s => s.timestamp.getTime())),
      correlationCount: correlations.correlations.length
    }
  };
}

function determineEntityType(identifier: string, entities: ResolvedEntity[]): EntityType {
  // Check identifier pattern
  if (identifier.includes('@')) return 'email';
  if (identifier.startsWith('0x') || identifier.startsWith('bc1')) return 'wallet';
  if (/^[+\d\s()-]+$/.test(identifier.replace(/\s/g, ''))) return 'phone';

  // Check entity types from resolved data
  const types = entities.map(e => e.type).filter(Boolean);
  if (types.length > 0) {
    const typeCounts = types.reduce((acc, t) => {
      acc[t] = (acc[t] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);
    return Object.entries(typeCounts).sort((a, b) => b[1] - a[1])[0][0] as EntityType;
  }

  return 'person';
}

// ============================================
// CONFIDENCE SCORING
// ============================================

/**
 * Calculate confidence score for entity profile
 */
export function calculateConfidence(
  profile: EntityProfile,
  sources: IntelligenceSource[]
): number {
  const weights = DEFAULT_CONFIG.confidence;
  let totalScore = 0;

  // 1. Source reliability (30%)
  const avgReliability = sources.reduce((sum, s) =>
    sum + (weights.sourceWeights[s.sourceType] || weights.sourceWeights.unknown), 0
  ) / sources.length;
  totalScore += avgReliability * 0.30;

  // 2. Data freshness (20%)
  const now = Date.now();
  const freshnessScores = sources.map(s => {
    const ageDays = (now - s.timestamp.getTime()) / (1000 * 60 * 60 * 24);
    return Math.exp(-ageDays / weights.freshnessDecayDays);
  });
  const avgFreshness = freshnessScores.reduce((a, b) => a + b, 0) / freshnessScores.length;
  totalScore += avgFreshness * 0.20;

  // 3. Corroboration (25%)
  const uniqueSourceTypes = new Set(sources.map(s => s.sourceType)).size;
  let corroborationScore = 0.4;
  if (uniqueSourceTypes >= 4) corroborationScore = 1.0;
  else if (uniqueSourceTypes >= 3) corroborationScore = 0.85;
  else if (uniqueSourceTypes >= 2) corroborationScore = 0.65;
  totalScore += corroborationScore * 0.25;

  // 4. Completeness (15%)
  const essentialAttrs = ['email', 'name', 'phone', 'location'];
  const presentEssential = essentialAttrs.filter(attr =>
    profile.attributes[attr] !== undefined
  ).length;
  const completenessScore = (presentEssential / essentialAttrs.length) * 0.6 +
    Math.min(Object.keys(profile.attributes).length / 10, 1) * 0.4;
  totalScore += completenessScore * 0.15;

  // 5. Conflict penalty (10%)
  // Simplified - would detect conflicting values in production
  totalScore += 1.0 * 0.10;

  // Multi-source bonus
  if (sources.length >= 3) {
    totalScore += weights.corroborationBonus;
  }

  return Math.min(totalScore * 100, 100);
}

// ============================================
// RISK ASSESSMENT
// ============================================

/**
 * Assess risk for entity profile
 */
export function assessRisk(
  profile: EntityProfile,
  correlations: CorrelationResult
): RiskAssessment {
  const config = DEFAULT_CONFIG.risk;
  const components: Record<string, { score: number; weight: number }> = {};
  let totalRisk = 0;

  // 1. Breach exposure (20%)
  const breachRisk = calculateBreachRisk(profile);
  components.breach_exposure = { score: breachRisk * 100, weight: 0.20 };
  totalRisk += breachRisk * 0.20;

  // 2. Behavioral patterns (25%)
  const behavioralRisk = calculateBehavioralRisk(profile);
  components.behavioral_patterns = { score: behavioralRisk * 100, weight: 0.25 };
  totalRisk += behavioralRisk * 0.25;

  // 3. Network risk (20%)
  const networkRisk = calculateNetworkRisk(profile, correlations);
  components.network_risk = { score: networkRisk * 100, weight: 0.20 };
  totalRisk += networkRisk * 0.20;

  // 4. Geographic risk (10%)
  const geoRisk = calculateGeographicRisk(profile);
  components.geographic_risk = { score: geoRisk * 100, weight: 0.10 };
  totalRisk += geoRisk * 0.10;

  // 5. Temporal patterns (15%)
  const temporalRisk = calculateTemporalRisk(profile);
  components.temporal_patterns = { score: temporalRisk * 100, weight: 0.15 };
  totalRisk += temporalRisk * 0.15;

  // 6. Known indicators (10%)
  const indicatorRisk = calculateIndicatorRisk(profile);
  components.known_indicators = { score: indicatorRisk * 100, weight: 0.10 };
  totalRisk += indicatorRisk * 0.10;

  // Calculate overall risk
  let overallRisk = totalRisk * 100;

  // Critical indicator multiplier
  if (hasCriticalIndicators(profile)) {
    overallRisk *= 1.25;
  }

  overallRisk = Math.min(overallRisk, 100);

  // Categorize
  let riskCategory: RiskAssessment['riskCategory'];
  if (overallRisk >= config.criticalThreshold) riskCategory = 'CRITICAL';
  else if (overallRisk >= config.highThreshold) riskCategory = 'HIGH';
  else if (overallRisk >= config.mediumThreshold) riskCategory = 'MEDIUM';
  else if (overallRisk >= config.lowThreshold) riskCategory = 'LOW';
  else riskCategory = 'MINIMAL';

  // Identify threat indicators
  const threatIndicators = identifyThreatIndicators(profile);

  // Generate recommendations
  const recommendations = generateRecommendations(overallRisk, components);

  return {
    overallRisk: Math.round(overallRisk * 100) / 100,
    riskCategory,
    components,
    threatIndicators,
    recommendations
  };
}

function calculateBreachRisk(profile: EntityProfile): number {
  const breachSources = profile.sources.filter(s => s.toLowerCase().includes('breach')).length;

  let risk = 0;
  if (breachSources >= 5) risk = 0.9;
  else if (breachSources >= 3) risk = 0.7;
  else if (breachSources >= 1) risk = 0.4;
  else risk = 0.1;

  if (profile.attributes.password || profile.attributes.password_hash) {
    risk += 0.1;
  }

  return Math.min(risk, 1.0);
}

function calculateBehavioralRisk(profile: EntityProfile): number {
  let risk = 0;

  // Multiple aliases
  if (profile.aliases.length >= 5) risk += 0.3;
  else if (profile.aliases.length >= 3) risk += 0.15;

  // Multiple wallets
  const wallets = profile.attributes.wallets;
  if (Array.isArray(wallets) && wallets.length >= 5) risk += 0.2;
  else if (Array.isArray(wallets) && wallets.length >= 2) risk += 0.1;

  // Anonymization indicators
  const attrsStr = JSON.stringify(profile.attributes).toLowerCase();
  if (attrsStr.includes('vpn') || attrsStr.includes('tor')) {
    risk += 0.15;
  }

  return Math.min(risk, 1.0);
}

function calculateNetworkRisk(profile: EntityProfile, correlations: CorrelationResult): number {
  let risk = 0;
  const rels = profile.relationships.length;

  if (rels >= 10) risk += 0.4;
  else if (rels >= 5) risk += 0.2;
  else if (rels >= 2) risk += 0.1;

  // Ownership relationships
  const ownsCount = profile.relationships.filter(r => r.type === 'owns').length;
  if (ownsCount >= 3) risk += 0.2;

  // Cluster membership
  for (const cluster of correlations.clusters) {
    if (cluster.entities.includes(profile.entityId) && cluster.size >= 5) {
      risk += 0.15;
      break;
    }
  }

  return Math.min(risk, 1.0);
}

function calculateGeographicRisk(profile: EntityProfile): number {
  let risk = 0;
  const locations = Array.isArray(profile.attributes.locations)
    ? profile.attributes.locations
    : [profile.attributes.location].filter(Boolean);

  const highRiskCountries = ['russia', 'iran', 'north korea', 'syria', 'venezuela', 'crimea', 'belarus', 'myanmar'];
  const taxHavens = ['cayman', 'panama', 'bermuda', 'bahamas', 'switzerland', 'malta'];

  for (const loc of locations) {
    const locLower = String(loc).toLowerCase();
    if (highRiskCountries.some(c => locLower.includes(c))) {
      risk += 0.3;
    }
    if (taxHavens.some(h => locLower.includes(h))) {
      risk += 0.15;
    }
  }

  if (locations.length >= 5) risk += 0.2;
  else if (locations.length >= 3) risk += 0.1;

  return Math.min(risk, 1.0);
}

function calculateTemporalRisk(profile: EntityProfile): number {
  let risk = 0;
  const timeline = profile.timeline;

  if (timeline.length >= 10) {
    const now = Date.now();
    const thirtyDaysAgo = now - 30 * 24 * 60 * 60 * 1000;
    const recentEvents = timeline.filter(e => new Date(e.timestamp).getTime() > thirtyDaysAgo).length;

    if (recentEvents >= 5) risk += 0.3;
  }

  return Math.min(risk, 1.0);
}

function calculateIndicatorRisk(profile: EntityProfile): number {
  let risk = 0;
  const attrsStr = JSON.stringify(profile.attributes).toLowerCase();

  const highRiskDomains = ['tempmail.com', 'guerrillamail.com', '10minutemail.com', 'throwaway.email', 'mailinator.com'];
  const highRiskKeywords = ['fraud', 'scam', 'hack', 'breach', 'ransom', 'darknet', 'phishing', 'laundering'];

  // Check email domain
  const email = profile.attributes.email;
  if (email && highRiskDomains.some(d => String(email).includes(d))) {
    risk += 0.4;
  }

  // Check keywords
  const keywordMatches = highRiskKeywords.filter(k => attrsStr.includes(k)).length;
  risk += Math.min(keywordMatches * 0.1, 0.4);

  // Cryptocurrency activity
  if (attrsStr.includes('wallet') || attrsStr.includes('cryptocurrency')) {
    risk += 0.15;
  }

  // Darknet indicators
  if (attrsStr.includes('onion') || attrsStr.includes('i2p')) {
    risk += 0.25;
  }

  return Math.min(risk, 1.0);
}

function hasCriticalIndicators(profile: EntityProfile): boolean {
  const criticalKeywords = ['ransomware', 'exploit', 'malware', 'botnet', 'terrorism', 'trafficking'];
  const attrsStr = JSON.stringify(profile.attributes).toLowerCase();
  return criticalKeywords.some(k => attrsStr.includes(k));
}

function identifyThreatIndicators(profile: EntityProfile): ThreatIndicator[] {
  const indicators: ThreatIndicator[] = [];
  const attrsStr = JSON.stringify(profile.attributes).toLowerCase();

  // Breach exposure
  const breachSources = profile.sources.filter(s => s.toLowerCase().includes('breach')).length;
  if (breachSources >= 3) {
    indicators.push({
      type: 'breach_exposure',
      severity: 'high',
      description: `Appeared in ${breachSources} data breaches`
    });
  }

  // Multiple aliases
  if (profile.aliases.length >= 3) {
    indicators.push({
      type: 'multiple_aliases',
      severity: 'medium',
      description: `Uses ${profile.aliases.length} different aliases`
    });
  }

  // Cryptocurrency
  if (attrsStr.includes('wallet')) {
    indicators.push({
      type: 'cryptocurrency',
      severity: 'medium',
      description: 'Cryptocurrency wallet activity detected'
    });
  }

  // Anonymization
  if (attrsStr.includes('tor') || attrsStr.includes('vpn')) {
    indicators.push({
      type: 'anonymization',
      severity: 'high',
      description: 'Use of anonymization tools detected'
    });
  }

  return indicators;
}

function generateRecommendations(riskScore: number, components: Record<string, { score: number; weight: number }>): string[] {
  const recommendations: string[] = [];

  if (riskScore >= 75) {
    recommendations.push('URGENT: Immediate investigation recommended');
    recommendations.push('Consider escalation to security team');
  }

  if ((components.breach_exposure?.score || 0) >= 70) {
    recommendations.push('Monitor for credential stuffing attacks');
    recommendations.push('Recommend password reset for associated accounts');
  }

  if ((components.network_risk?.score || 0) >= 60) {
    recommendations.push('Investigate network connections and associates');
  }

  if ((components.behavioral_patterns?.score || 0) >= 70) {
    recommendations.push('Flag for behavioral analysis and monitoring');
  }

  if (riskScore >= 50) {
    recommendations.push('Enhanced due diligence recommended');
  }

  return recommendations;
}

// ============================================
// TIMELINE BUILDING
// ============================================

/**
 * Build activity timeline from intelligence sources
 */
export function buildTimeline(
  profile: EntityProfile,
  sources: IntelligenceSource[]
): TimelineEvent[] {
  const events: TimelineEvent[] = [];

  for (const source of sources) {
    const sourceEvents = extractTimelineEvents(source);
    events.push(...sourceEvents);
  }

  // Sort chronologically
  events.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());

  // Deduplicate
  const seen = new Set<string>();
  const deduplicated = events.filter(e => {
    const sig = `${e.timestamp.slice(0, 10)}|${e.type}|${e.description.slice(0, 50)}`;
    if (seen.has(sig)) return false;
    seen.add(sig);
    return true;
  });

  // Identify gaps
  return addTimelineGaps(deduplicated);
}

function extractTimelineEvents(source: IntelligenceSource): TimelineEvent[] {
  const events: TimelineEvent[] = [];
  const timestamp = source.timestamp.toISOString();
  const data = source.data;

  switch (source.sourceType) {
    case 'breach':
      events.push({
        timestamp,
        type: 'breach',
        severity: 'high',
        description: `Credentials exposed in ${data.breach || data.source || 'Unknown Breach'}`,
        source: source.sourceId,
        details: {
          breach_name: data.breach || data.source,
          exposed_data: ['email', 'password', 'phone', 'name'].filter(k => k in data)
        }
      });
      break;

    case 'blockchain':
      if (data.wallet || data.address) {
        events.push({
          timestamp,
          type: 'blockchain',
          description: `Cryptocurrency wallet identified: ${String(data.wallet || data.address).slice(0, 10)}...`,
          source: source.sourceId,
          details: { wallet: data.wallet || data.address, blockchain: data.blockchain || 'Unknown' }
        });
      }
      if (data.transactions) {
        events.push({
          timestamp,
          type: 'blockchain',
          description: `${data.transactions} blockchain transactions recorded`,
          source: source.sourceId,
          details: { transaction_count: data.transactions, volume: data.total_volume }
        });
      }
      break;

    case 'socmint':
      if (data.joined_date || data.created_at) {
        events.push({
          timestamp: data.joined_date || data.created_at || timestamp,
          type: 'social_media',
          description: `Social media account created on ${data.platform || 'platform'}`,
          source: source.sourceId,
          details: { platform: data.platform, username: data.username }
        });
      }
      break;

    case 'sherlock':
      const platforms = data.platforms || [];
      for (const platform of platforms) {
        events.push({
          timestamp,
          type: 'platform_presence',
          description: `Account found on ${platform}`,
          source: source.sourceId,
          details: { platform, username: data.username }
        });
      }
      break;

    default:
      events.push({
        timestamp,
        type: source.sourceType,
        description: `Intelligence gathered from ${source.sourceType}`,
        source: source.sourceId
      });
  }

  return events;
}

function addTimelineGaps(events: TimelineEvent[]): TimelineEvent[] {
  if (events.length < 2) return events;

  const enhanced: TimelineEvent[] = [];
  const maxGapDays = 30;
  const maxGapMs = maxGapDays * 24 * 60 * 60 * 1000;

  for (let i = 0; i < events.length; i++) {
    enhanced.push(events[i]);

    if (i < events.length - 1) {
      const currentTime = new Date(events[i].timestamp).getTime();
      const nextTime = new Date(events[i + 1].timestamp).getTime();
      const gap = nextTime - currentTime;

      if (gap > maxGapMs) {
        const gapDays = Math.floor(gap / (24 * 60 * 60 * 1000));
        enhanced.push({
          timestamp: events[i].timestamp,
          type: 'gap',
          description: `Timeline gap: ${gapDays} days of no recorded activity`,
          isMetadata: true
        });
      }
    }
  }

  return enhanced;
}

// ============================================
// GRAPH ANALYSIS
// ============================================

/**
 * Analyze entity network graph
 */
export function analyzeGraph(
  profile: EntityProfile,
  correlations: CorrelationResult
): GraphAnalysis {
  // Build adjacency for analysis
  const adjacency = new Map<string, Set<string>>();
  const nodes = new Set<string>([profile.entityId]);

  for (const rel of profile.relationships) {
    nodes.add(rel.sourceEntity);
    nodes.add(rel.targetEntity);

    if (!adjacency.has(rel.sourceEntity)) adjacency.set(rel.sourceEntity, new Set());
    if (!adjacency.has(rel.targetEntity)) adjacency.set(rel.targetEntity, new Set());

    adjacency.get(rel.sourceEntity)!.add(rel.targetEntity);
    adjacency.get(rel.targetEntity)!.add(rel.sourceEntity);
  }

  const nodeCount = nodes.size;
  const edgeCount = profile.relationships.length;

  // Degree centrality
  const neighbors = adjacency.get(profile.entityId) || new Set();
  const degree = nodeCount > 1 ? neighbors.size / (nodeCount - 1) : 0;

  // Simplified centrality (full implementation in graph.service.ts)
  const centrality = {
    degree,
    betweenness: 0.5, // Would calculate with BFS
    closeness: nodeCount > 1 ? (nodeCount - 1) / (neighbors.size || 1) : 0,
    eigenvector: degree * 0.7
  };

  // Influence score
  const influenceScore = (centrality.degree * 0.3 + centrality.betweenness * 0.3 +
    centrality.closeness * 0.2 + centrality.eigenvector * 0.2) * 100;

  // Network metrics
  const maxEdges = nodeCount > 1 ? (nodeCount * (nodeCount - 1)) / 2 : 0;
  const density = maxEdges > 0 ? edgeCount / maxEdges : 0;

  // Predicted links (simplified)
  const predictedLinks: Array<{ target: string; score: number; commonNeighbors: number }> = [];

  return {
    centrality,
    communities: correlations.clusters.map(c => ({ id: c.clusterId, members: c.entities, size: c.size })),
    influenceScore: Math.round(influenceScore * 100) / 100,
    predictedLinks,
    networkMetrics: {
      totalNodes: nodeCount,
      totalEdges: edgeCount,
      density,
      clusteringCoefficient: 0 // Would calculate local clustering
    }
  };
}

// ============================================
// UTILITIES
// ============================================

function generateEntityId(type: string, identifier: string): string {
  return crypto.createHash('sha256').update(`${type}:${identifier}`).digest('hex').slice(0, 16);
}

function generateSummary(
  profile: EntityProfile,
  correlations: CorrelationResult,
  risk?: RiskAssessment
): string {
  const parts: string[] = [
    `Entity: ${profile.primaryIdentifier} (${profile.entityType})`,
    `Sources: ${profile.sources.length}`,
    `Confidence: ${profile.confidenceScore.toFixed(1)}%`
  ];

  if (risk) {
    parts.push(`Risk: ${risk.riskCategory} (${risk.overallRisk.toFixed(1)}%)`);
  }

  if (profile.relationships.length > 0) {
    parts.push(`Relationships: ${profile.relationships.length}`);
  }

  if (correlations.clusters.length > 0) {
    parts.push(`Clusters: ${correlations.clusters.length}`);
  }

  return parts.join(' | ');
}

function isValidEmail(email: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function normalizePhone(phone: string): string {
  const digits = phone.replace(/\D/g, '');
  return digits.length >= 7 ? `+${digits}` : '';
}

function normalizeName(name: string): string {
  return name.toLowerCase().replace(/[^\w\s]/g, '').replace(/\s+/g, ' ').trim();
}

function namesMatch(name1: string, name2: string): boolean {
  if (!name1 || !name2) return false;
  const n1 = normalizeName(name1);
  const n2 = normalizeName(name2);
  if (n1 === n2) return true;
  return stringSimilarity(n1, n2) >= DEFAULT_CONFIG.entityResolution.fuzzyThreshold;
}

function stringSimilarity(s1: string, s2: string): number {
  if (s1 === s2) return 1;
  if (s1.length === 0 || s2.length === 0) return 0;

  // Levenshtein-based similarity
  const longer = s1.length > s2.length ? s1 : s2;
  const shorter = s1.length > s2.length ? s2 : s1;
  const longerLength = longer.length;

  const costs: number[] = [];
  for (let i = 0; i <= shorter.length; i++) {
    let lastValue = i;
    for (let j = 0; j <= longer.length; j++) {
      if (i === 0) {
        costs[j] = j;
      } else if (j > 0) {
        let newValue = costs[j - 1];
        if (shorter.charAt(i - 1) !== longer.charAt(j - 1)) {
          newValue = Math.min(Math.min(newValue, lastValue), costs[j]) + 1;
        }
        costs[j - 1] = lastValue;
        lastValue = newValue;
      }
    }
    if (i > 0) costs[longer.length] = lastValue;
  }

  return (longerLength - costs[longer.length]) / longerLength;
}

function extractAttributes(data: Record<string, any>, keys: string[]): Record<string, any> {
  const attrs: Record<string, any> = {};
  for (const key of keys) {
    if (key in data && data[key] !== undefined && data[key] !== null && data[key] !== '') {
      attrs[key] = data[key];
    }
  }
  return attrs;
}

function extractAliases(data: Record<string, any>): string[] {
  const aliases: string[] = [];

  if (data.aliases) {
    if (Array.isArray(data.aliases)) {
      aliases.push(...data.aliases);
    } else {
      aliases.push(String(data.aliases));
    }
  }

  if (data.username) {
    aliases.push(String(data.username));
  }

  return aliases;
}

function detectBlockchain(wallet: string): string {
  if (wallet.startsWith('0x') && wallet.length === 42) return 'Ethereum';
  if (wallet.startsWith('bc1') || wallet.startsWith('1') || wallet.startsWith('3')) return 'Bitcoin';
  if (wallet.startsWith('X')) return 'Monero';
  if (wallet.startsWith('r')) return 'Ripple';
  return 'Unknown';
}

// ============================================
// Note: Functions are exported inline above
// ============================================
