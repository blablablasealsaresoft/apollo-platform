/**
 * Graph Service - Neo4j Integration for Intelligence Fusion
 * Network analysis, community detection, and entity relationship management
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

// Types for graph operations
export interface GraphNode {
  id: string;
  type: 'person' | 'email' | 'phone' | 'wallet' | 'organization' | 'location' | 'domain' | 'ip' | 'unknown';
  identifier: string;
  attributes: Record<string, any>;
  riskScore?: number;
  confidenceScore?: number;
  createdAt: Date;
  updatedAt: Date;
}

export interface GraphEdge {
  id: string;
  sourceId: string;
  targetId: string;
  type: 'owns' | 'alias' | 'associates' | 'colleague' | 'related' | 'transacted' | 'communicated';
  weight: number;
  evidence: string[];
  createdAt: Date;
}

export interface CentralityMetrics {
  degree: number;
  betweenness: number;
  closeness: number;
  eigenvector: number;
  influence: number;
}

export interface Community {
  id: string;
  members: string[];
  size: number;
  label?: string;
}

export interface ShortestPath {
  nodes: string[];
  edges: string[];
  totalWeight: number;
  hops: number;
}

export interface NetworkMetrics {
  totalNodes: number;
  totalEdges: number;
  density: number;
  avgDegree: number;
  clusteringCoefficient: number;
  diameter?: number;
}

export interface PredictedLink {
  targetId: string;
  score: number;
  commonNeighbors: number;
  method: 'common_neighbors' | 'jaccard' | 'adamic_adar';
}

// Neo4j Driver types (optional dependency)
let neo4jDriver: any = null;

/**
 * Initialize Neo4j connection with timeout
 */
export async function initializeNeo4j(
  uri: string,
  username: string,
  password: string
): Promise<boolean> {
  // Skip Neo4j connection in standalone mode (when env var is set or URI is default localhost)
  if (process.env.SKIP_NEO4J === 'true' || process.env.NEO4J_SKIP === 'true') {
    logger.info('Neo4j connection skipped (SKIP_NEO4J=true)');
    return false;
  }

  try {
    const neo4j = await import('neo4j-driver');

    // Create driver with connection timeout
    neo4jDriver = neo4j.default.driver(
      uri,
      neo4j.default.auth.basic(username, password),
      { connectionTimeout: 5000 } // 5 second timeout
    );

    // Test connection with timeout
    const testPromise = (async () => {
      const session = neo4jDriver.session();
      try {
        await session.run('RETURN 1');
        return true;
      } finally {
        await session.close();
      }
    })();

    const timeoutPromise = new Promise<boolean>((_, reject) => {
      setTimeout(() => reject(new Error('Connection timeout')), 5000);
    });

    await Promise.race([testPromise, timeoutPromise]);

    logger.info('Neo4j connection established');
    return true;
  } catch (error) {
    // Clean up driver if it was created
    if (neo4jDriver) {
      try {
        await neo4jDriver.close();
      } catch {
        // Ignore close errors
      }
      neo4jDriver = null;
    }
    logger.warn('Neo4j not available, using in-memory graph', { error: String(error) });
    return false;
  }
}

/**
 * Close Neo4j connection
 */
export async function closeNeo4j(): Promise<void> {
  if (neo4jDriver) {
    await neo4jDriver.close();
    neo4jDriver = null;
  }
}

// In-memory graph store for fallback
const inMemoryGraph = {
  nodes: new Map<string, GraphNode>(),
  edges: new Map<string, GraphEdge>(),
  adjacency: new Map<string, Set<string>>()
};

/**
 * Hydrate graph with entity nodes
 */
export async function hydrateGraph(nodes: GraphNode[]): Promise<void> {
  logger.info(`[fusion] hydrating ${nodes.length} nodes`);

  if (neo4jDriver) {
    await hydrateGraphNeo4j(nodes);
  } else {
    await hydrateGraphInMemory(nodes);
  }
}

async function hydrateGraphNeo4j(nodes: GraphNode[]): Promise<void> {
  const session = neo4jDriver.session();
  try {
    for (const node of nodes) {
      await session.run(
        `MERGE (n:Entity {id: $id})
         SET n.type = $type,
             n.identifier = $identifier,
             n.attributes = $attributes,
             n.riskScore = $riskScore,
             n.confidenceScore = $confidenceScore,
             n.createdAt = datetime($createdAt),
             n.updatedAt = datetime($updatedAt)
         RETURN n`,
        {
          id: node.id,
          type: node.type,
          identifier: node.identifier,
          attributes: JSON.stringify(node.attributes),
          riskScore: node.riskScore || 0,
          confidenceScore: node.confidenceScore || 0,
          createdAt: node.createdAt.toISOString(),
          updatedAt: node.updatedAt.toISOString()
        }
      );
    }
    logger.info(`Hydrated ${nodes.length} nodes in Neo4j`);
  } finally {
    await session.close();
  }
}

async function hydrateGraphInMemory(nodes: GraphNode[]): Promise<void> {
  for (const node of nodes) {
    inMemoryGraph.nodes.set(node.id, node);
    if (!inMemoryGraph.adjacency.has(node.id)) {
      inMemoryGraph.adjacency.set(node.id, new Set());
    }
  }
  logger.info(`Hydrated ${nodes.length} nodes in memory`);
}

/**
 * Add relationship edge to graph
 */
export async function addEdge(edge: GraphEdge): Promise<void> {
  if (neo4jDriver) {
    await addEdgeNeo4j(edge);
  } else {
    await addEdgeInMemory(edge);
  }
}

async function addEdgeNeo4j(edge: GraphEdge): Promise<void> {
  const session = neo4jDriver.session();
  try {
    await session.run(
      `MATCH (a:Entity {id: $sourceId}), (b:Entity {id: $targetId})
       MERGE (a)-[r:RELATIONSHIP {id: $edgeId}]->(b)
       SET r.type = $type,
           r.weight = $weight,
           r.evidence = $evidence,
           r.createdAt = datetime($createdAt)
       RETURN r`,
      {
        sourceId: edge.sourceId,
        targetId: edge.targetId,
        edgeId: edge.id,
        type: edge.type,
        weight: edge.weight,
        evidence: JSON.stringify(edge.evidence),
        createdAt: edge.createdAt.toISOString()
      }
    );
  } finally {
    await session.close();
  }
}

async function addEdgeInMemory(edge: GraphEdge): Promise<void> {
  inMemoryGraph.edges.set(edge.id, edge);

  // Update adjacency list (bidirectional)
  if (!inMemoryGraph.adjacency.has(edge.sourceId)) {
    inMemoryGraph.adjacency.set(edge.sourceId, new Set());
  }
  if (!inMemoryGraph.adjacency.has(edge.targetId)) {
    inMemoryGraph.adjacency.set(edge.targetId, new Set());
  }

  inMemoryGraph.adjacency.get(edge.sourceId)!.add(edge.targetId);
  inMemoryGraph.adjacency.get(edge.targetId)!.add(edge.sourceId);
}

/**
 * Get entity network (ego network) up to specified depth
 */
export async function getEntityNetwork(
  entityId: string,
  maxDepth: number = 2
): Promise<{ nodes: GraphNode[]; edges: GraphEdge[] }> {
  if (neo4jDriver) {
    return getEntityNetworkNeo4j(entityId, maxDepth);
  }
  return getEntityNetworkInMemory(entityId, maxDepth);
}

async function getEntityNetworkNeo4j(
  entityId: string,
  maxDepth: number
): Promise<{ nodes: GraphNode[]; edges: GraphEdge[] }> {
  const session = neo4jDriver.session();
  try {
    const result = await session.run(
      `MATCH path = (start:Entity {id: $entityId})-[*1..${maxDepth}]-(connected:Entity)
       WITH nodes(path) as pathNodes, relationships(path) as pathRels
       UNWIND pathNodes as n
       WITH COLLECT(DISTINCT n) as uniqueNodes, pathRels
       UNWIND pathRels as r
       WITH uniqueNodes, COLLECT(DISTINCT r) as uniqueRels
       RETURN uniqueNodes, uniqueRels`,
      { entityId }
    );

    const nodes: GraphNode[] = [];
    const edges: GraphEdge[] = [];

    if (result.records.length > 0) {
      const record = result.records[0];
      const rawNodes = record.get('uniqueNodes') || [];
      const rawRels = record.get('uniqueRels') || [];

      for (const n of rawNodes) {
        nodes.push({
          id: n.properties.id,
          type: n.properties.type || 'unknown',
          identifier: n.properties.identifier,
          attributes: JSON.parse(n.properties.attributes || '{}'),
          riskScore: n.properties.riskScore,
          confidenceScore: n.properties.confidenceScore,
          createdAt: new Date(n.properties.createdAt),
          updatedAt: new Date(n.properties.updatedAt)
        });
      }

      for (const r of rawRels) {
        edges.push({
          id: r.properties.id,
          sourceId: r.start.properties.id,
          targetId: r.end.properties.id,
          type: r.properties.type,
          weight: r.properties.weight,
          evidence: JSON.parse(r.properties.evidence || '[]'),
          createdAt: new Date(r.properties.createdAt)
        });
      }
    }

    return { nodes, edges };
  } finally {
    await session.close();
  }
}

function getEntityNetworkInMemory(
  entityId: string,
  maxDepth: number
): { nodes: GraphNode[]; edges: GraphEdge[] } {
  const visitedNodes = new Set<string>();
  const resultNodes: GraphNode[] = [];
  const resultEdges: GraphEdge[] = [];
  const edgeIds = new Set<string>();

  // BFS traversal
  const queue: { id: string; depth: number }[] = [{ id: entityId, depth: 0 }];

  while (queue.length > 0) {
    const { id, depth } = queue.shift()!;

    if (visitedNodes.has(id) || depth > maxDepth) {
      continue;
    }

    visitedNodes.add(id);

    const node = inMemoryGraph.nodes.get(id);
    if (node) {
      resultNodes.push(node);
    }

    // Get adjacent nodes
    const neighbors = inMemoryGraph.adjacency.get(id) || new Set();
    for (const neighborId of neighbors) {
      if (!visitedNodes.has(neighborId)) {
        queue.push({ id: neighborId, depth: depth + 1 });
      }
    }
  }

  // Collect edges between visited nodes
  for (const edge of inMemoryGraph.edges.values()) {
    if (
      visitedNodes.has(edge.sourceId) &&
      visitedNodes.has(edge.targetId) &&
      !edgeIds.has(edge.id)
    ) {
      resultEdges.push(edge);
      edgeIds.add(edge.id);
    }
  }

  return { nodes: resultNodes, edges: resultEdges };
}

/**
 * Calculate centrality metrics for an entity
 */
export async function calculateCentrality(entityId: string): Promise<CentralityMetrics> {
  if (neo4jDriver) {
    return calculateCentralityNeo4j(entityId);
  }
  return calculateCentralityInMemory(entityId);
}

async function calculateCentralityNeo4j(entityId: string): Promise<CentralityMetrics> {
  const session = neo4jDriver.session();
  try {
    // Degree centrality
    const degreeResult = await session.run(
      `MATCH (n:Entity {id: $entityId})-[r]-()
       RETURN count(r) as degree`,
      { entityId }
    );
    const degree = degreeResult.records[0]?.get('degree')?.toNumber() || 0;

    // Get total nodes for normalization
    const totalResult = await session.run('MATCH (n:Entity) RETURN count(n) as total');
    const totalNodes = totalResult.records[0]?.get('total')?.toNumber() || 1;
    const normalizedDegree = degree / (totalNodes - 1);

    // Simplified betweenness (would use GDS library in production)
    const betweenness = await calculateBetweennessSimple(entityId);

    // Closeness centrality approximation
    const closenessResult = await session.run(
      `MATCH (start:Entity {id: $entityId}), (end:Entity)
       WHERE start <> end
       MATCH path = shortestPath((start)-[*..5]-(end))
       RETURN avg(length(path)) as avgDistance`,
      { entityId }
    );
    const avgDistance = closenessResult.records[0]?.get('avgDistance') || 1;
    const closeness = avgDistance > 0 ? (totalNodes - 1) / avgDistance : 0;

    // Eigenvector approximation using degree-based heuristic
    const eigenvector = normalizedDegree * 0.7 + closeness * 0.3;

    // Composite influence score
    const influence = (normalizedDegree * 0.3 + betweenness * 0.3 + closeness * 0.2 + eigenvector * 0.2) * 100;

    return {
      degree: normalizedDegree,
      betweenness,
      closeness,
      eigenvector,
      influence
    };
  } finally {
    await session.close();
  }
}

async function calculateBetweennessSimple(entityId: string): Promise<number> {
  // Simplified betweenness calculation
  // In production, use Neo4j GDS library
  return 0.5; // Placeholder
}

function calculateCentralityInMemory(entityId: string): CentralityMetrics {
  const nodes = Array.from(inMemoryGraph.nodes.keys());
  const n = nodes.length;

  if (n <= 1 || !inMemoryGraph.adjacency.has(entityId)) {
    return { degree: 0, betweenness: 0, closeness: 0, eigenvector: 0, influence: 0 };
  }

  // Degree centrality
  const neighbors = inMemoryGraph.adjacency.get(entityId) || new Set();
  const degree = neighbors.size / (n - 1);

  // Betweenness centrality (simplified)
  let betweenness = 0;
  for (const source of nodes) {
    for (const target of nodes) {
      if (source !== target && source !== entityId && target !== entityId) {
        const paths = findAllShortestPaths(source, target);
        const pathsThroughEntity = paths.filter(p => p.includes(entityId));
        if (paths.length > 0) {
          betweenness += pathsThroughEntity.length / paths.length;
        }
      }
    }
  }
  if (n > 2) {
    betweenness /= (n - 1) * (n - 2);
  }

  // Closeness centrality
  const distances = calculateShortestDistances(entityId);
  const totalDistance = Array.from(distances.values()).reduce((a, b) => a + b, 0);
  const closeness = totalDistance > 0 ? (n - 1) / totalDistance : 0;

  // Eigenvector centrality (power iteration approximation)
  const eigenvector = calculateEigenvectorCentrality(entityId);

  // Influence score
  const influence = (degree * 0.3 + betweenness * 0.3 + closeness * 0.2 + eigenvector * 0.2) * 100;

  return { degree, betweenness, closeness, eigenvector, influence };
}

function findAllShortestPaths(source: string, target: string): string[][] {
  const paths: string[][] = [];
  const queue: { node: string; path: string[] }[] = [{ node: source, path: [source] }];
  const visited = new Map<string, number>();
  let minLength = Infinity;

  while (queue.length > 0) {
    const { node, path } = queue.shift()!;

    if (path.length > minLength) continue;

    if (node === target) {
      if (path.length < minLength) {
        minLength = path.length;
        paths.length = 0;
      }
      if (path.length === minLength) {
        paths.push(path);
      }
      continue;
    }

    const neighbors = inMemoryGraph.adjacency.get(node) || new Set();
    for (const neighbor of neighbors) {
      const prevLength = visited.get(neighbor);
      if (prevLength === undefined || prevLength === path.length + 1) {
        visited.set(neighbor, path.length + 1);
        queue.push({ node: neighbor, path: [...path, neighbor] });
      }
    }
  }

  return paths;
}

function calculateShortestDistances(source: string): Map<string, number> {
  const distances = new Map<string, number>();
  const queue: { node: string; dist: number }[] = [{ node: source, dist: 0 }];
  const visited = new Set<string>();

  while (queue.length > 0) {
    const { node, dist } = queue.shift()!;

    if (visited.has(node)) continue;
    visited.add(node);

    if (node !== source) {
      distances.set(node, dist);
    }

    const neighbors = inMemoryGraph.adjacency.get(node) || new Set();
    for (const neighbor of neighbors) {
      if (!visited.has(neighbor)) {
        queue.push({ node: neighbor, dist: dist + 1 });
      }
    }
  }

  return distances;
}

function calculateEigenvectorCentrality(targetId: string): number {
  const nodes = Array.from(inMemoryGraph.nodes.keys());
  const n = nodes.length;
  if (n === 0) return 0;

  // Power iteration
  let scores = new Map<string, number>();
  for (const node of nodes) {
    scores.set(node, 1 / n);
  }

  const MAX_ITERATIONS = 100;
  const TOLERANCE = 0.0001;

  for (let i = 0; i < MAX_ITERATIONS; i++) {
    const newScores = new Map<string, number>();
    let maxDiff = 0;

    for (const node of nodes) {
      const neighbors = inMemoryGraph.adjacency.get(node) || new Set();
      let score = 0;
      for (const neighbor of neighbors) {
        score += scores.get(neighbor) || 0;
      }
      newScores.set(node, score);
    }

    // Normalize
    const norm = Math.sqrt(Array.from(newScores.values()).reduce((a, b) => a + b * b, 0));
    if (norm > 0) {
      for (const [node, score] of newScores) {
        const normalizedScore = score / norm;
        maxDiff = Math.max(maxDiff, Math.abs(normalizedScore - (scores.get(node) || 0)));
        newScores.set(node, normalizedScore);
      }
    }

    scores = newScores;

    if (maxDiff < TOLERANCE) break;
  }

  return scores.get(targetId) || 0;
}

/**
 * Detect communities using label propagation
 */
export async function detectCommunities(): Promise<Community[]> {
  if (neo4jDriver) {
    return detectCommunitiesNeo4j();
  }
  return detectCommunitiesInMemory();
}

async function detectCommunitiesNeo4j(): Promise<Community[]> {
  const session = neo4jDriver.session();
  try {
    // Using Louvain algorithm from GDS (if available)
    // Fallback to simple label propagation via Cypher
    const result = await session.run(
      `MATCH (n:Entity)-[r]-(m:Entity)
       WITH n, collect(DISTINCT m.id) as neighbors
       RETURN n.id as nodeId, neighbors`
    );

    // Build community structure from connected components
    const visited = new Set<string>();
    const communities: Community[] = [];

    for (const record of result.records) {
      const nodeId = record.get('nodeId');
      if (visited.has(nodeId)) continue;

      // BFS to find connected component
      const component = new Set<string>();
      const queue = [nodeId];

      while (queue.length > 0) {
        const current = queue.shift()!;
        if (visited.has(current)) continue;

        visited.add(current);
        component.add(current);

        const neighbors = result.records
          .find((r: any) => r.get('nodeId') === current)
          ?.get('neighbors') || [];

        for (const neighbor of neighbors) {
          if (!visited.has(neighbor)) {
            queue.push(neighbor);
          }
        }
      }

      if (component.size >= 2) {
        communities.push({
          id: `community_${communities.length}`,
          members: Array.from(component),
          size: component.size
        });
      }
    }

    return communities;
  } finally {
    await session.close();
  }
}

function detectCommunitiesInMemory(): Community[] {
  const nodes = Array.from(inMemoryGraph.nodes.keys());
  const labels = new Map<string, number>();

  // Initialize labels
  nodes.forEach((node, i) => labels.set(node, i));

  const MAX_ITERATIONS = 100;

  for (let iter = 0; iter < MAX_ITERATIONS; iter++) {
    let changed = false;

    for (const node of nodes) {
      const neighbors = inMemoryGraph.adjacency.get(node) || new Set();
      if (neighbors.size === 0) continue;

      // Count neighbor labels
      const labelCounts = new Map<number, number>();
      for (const neighbor of neighbors) {
        const label = labels.get(neighbor)!;
        labelCounts.set(label, (labelCounts.get(label) || 0) + 1);
      }

      // Find most common label
      let maxCount = 0;
      let newLabel = labels.get(node)!;
      for (const [label, count] of labelCounts) {
        if (count > maxCount) {
          maxCount = count;
          newLabel = label;
        }
      }

      if (newLabel !== labels.get(node)) {
        labels.set(node, newLabel);
        changed = true;
      }
    }

    if (!changed) break;
  }

  // Group by label
  const communities = new Map<number, string[]>();
  for (const [node, label] of labels) {
    if (!communities.has(label)) {
      communities.set(label, []);
    }
    communities.get(label)!.push(node);
  }

  // Filter and format
  return Array.from(communities.entries())
    .filter(([_, members]) => members.length >= 2)
    .map(([label, members], i) => ({
      id: `community_${i}`,
      members,
      size: members.length
    }));
}

/**
 * Find shortest path between two entities
 */
export async function findShortestPath(
  sourceId: string,
  targetId: string
): Promise<ShortestPath | null> {
  if (neo4jDriver) {
    return findShortestPathNeo4j(sourceId, targetId);
  }
  return findShortestPathInMemory(sourceId, targetId);
}

async function findShortestPathNeo4j(
  sourceId: string,
  targetId: string
): Promise<ShortestPath | null> {
  const session = neo4jDriver.session();
  try {
    const result = await session.run(
      `MATCH path = shortestPath((start:Entity {id: $sourceId})-[*..10]-(end:Entity {id: $targetId}))
       RETURN nodes(path) as nodes, relationships(path) as rels`,
      { sourceId, targetId }
    );

    if (result.records.length === 0) return null;

    const record = result.records[0];
    const pathNodes = record.get('nodes').map((n: any) => n.properties.id);
    const pathEdges = record.get('rels').map((r: any) => r.properties.id);
    const totalWeight = record.get('rels').reduce((sum: number, r: any) => sum + (r.properties.weight || 1), 0);

    return {
      nodes: pathNodes,
      edges: pathEdges,
      totalWeight,
      hops: pathNodes.length - 1
    };
  } finally {
    await session.close();
  }
}

function findShortestPathInMemory(sourceId: string, targetId: string): ShortestPath | null {
  const paths = findAllShortestPaths(sourceId, targetId);
  if (paths.length === 0) return null;

  const path = paths[0];
  const edges: string[] = [];
  let totalWeight = 0;

  for (let i = 0; i < path.length - 1; i++) {
    const from = path[i];
    const to = path[i + 1];

    for (const edge of inMemoryGraph.edges.values()) {
      if (
        (edge.sourceId === from && edge.targetId === to) ||
        (edge.sourceId === to && edge.targetId === from)
      ) {
        edges.push(edge.id);
        totalWeight += edge.weight;
        break;
      }
    }
  }

  return {
    nodes: path,
    edges,
    totalWeight,
    hops: path.length - 1
  };
}

/**
 * Predict missing links for an entity
 */
export async function predictLinks(
  entityId: string,
  topN: number = 5
): Promise<PredictedLink[]> {
  const neighbors = inMemoryGraph.adjacency.get(entityId) || new Set();
  const predictions: PredictedLink[] = [];

  for (const [nodeId, node] of inMemoryGraph.nodes) {
    if (nodeId === entityId || neighbors.has(nodeId)) continue;

    const nodeNeighbors = inMemoryGraph.adjacency.get(nodeId) || new Set();

    // Common neighbors
    const common = new Set([...neighbors].filter(x => nodeNeighbors.has(x)));
    if (common.size === 0) continue;

    // Jaccard coefficient
    const union = new Set([...neighbors, ...nodeNeighbors]);
    const score = common.size / union.size;

    predictions.push({
      targetId: nodeId,
      score,
      commonNeighbors: common.size,
      method: 'jaccard'
    });
  }

  return predictions
    .sort((a, b) => b.score - a.score)
    .slice(0, topN);
}

/**
 * Calculate network metrics
 */
export async function getNetworkMetrics(): Promise<NetworkMetrics> {
  const nodes = inMemoryGraph.nodes.size;
  const edges = inMemoryGraph.edges.size;

  if (nodes <= 1) {
    return {
      totalNodes: nodes,
      totalEdges: edges,
      density: 0,
      avgDegree: 0,
      clusteringCoefficient: 0
    };
  }

  // Density
  const maxEdges = (nodes * (nodes - 1)) / 2;
  const density = edges / maxEdges;

  // Average degree
  let totalDegree = 0;
  for (const neighbors of inMemoryGraph.adjacency.values()) {
    totalDegree += neighbors.size;
  }
  const avgDegree = totalDegree / nodes;

  // Global clustering coefficient (average of local)
  let totalClustering = 0;
  let nodesWithNeighbors = 0;

  for (const [nodeId, neighbors] of inMemoryGraph.adjacency) {
    if (neighbors.size < 2) continue;
    nodesWithNeighbors++;

    const neighborArray = Array.from(neighbors);
    let edgesAmongNeighbors = 0;

    for (let i = 0; i < neighborArray.length; i++) {
      for (let j = i + 1; j < neighborArray.length; j++) {
        const n1Neighbors = inMemoryGraph.adjacency.get(neighborArray[i]) || new Set();
        if (n1Neighbors.has(neighborArray[j])) {
          edgesAmongNeighbors++;
        }
      }
    }

    const possibleEdges = (neighbors.size * (neighbors.size - 1)) / 2;
    if (possibleEdges > 0) {
      totalClustering += edgesAmongNeighbors / possibleEdges;
    }
  }

  const clusteringCoefficient = nodesWithNeighbors > 0 ? totalClustering / nodesWithNeighbors : 0;

  return {
    totalNodes: nodes,
    totalEdges: edges,
    density,
    avgDegree,
    clusteringCoefficient
  };
}

/**
 * Export graph data for visualization
 */
export function exportGraphData(): {
  nodes: Array<{ id: string; type: string; label: string; risk?: number }>;
  edges: Array<{ source: string; target: string; type: string; weight: number }>;
} {
  return {
    nodes: Array.from(inMemoryGraph.nodes.values()).map(n => ({
      id: n.id,
      type: n.type,
      label: n.identifier,
      risk: n.riskScore
    })),
    edges: Array.from(inMemoryGraph.edges.values()).map(e => ({
      source: e.sourceId,
      target: e.targetId,
      type: e.type,
      weight: e.weight
    }))
  };
}

/**
 * Clear all graph data
 */
export function clearGraph(): void {
  inMemoryGraph.nodes.clear();
  inMemoryGraph.edges.clear();
  inMemoryGraph.adjacency.clear();
}

/**
 * Get node by ID
 */
export function getNode(nodeId: string): GraphNode | undefined {
  return inMemoryGraph.nodes.get(nodeId);
}

/**
 * Get all edges for a node
 */
export function getNodeEdges(nodeId: string): GraphEdge[] {
  const edges: GraphEdge[] = [];
  for (const edge of inMemoryGraph.edges.values()) {
    if (edge.sourceId === nodeId || edge.targetId === nodeId) {
      edges.push(edge);
    }
  }
  return edges;
}
