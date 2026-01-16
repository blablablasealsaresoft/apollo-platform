/**
 * Apollo Network Formatter
 *
 * Formats network and relationship data for report generation.
 * Supports:
 * - Entity relationship networks
 * - Financial transaction networks
 * - Communication networks
 * - Organizational hierarchies
 */

import {
  ReportGenerationOptions,
  ClassificationMarking,
  ReportSection,
  ReportTable,
  ReportChart,
} from '../types';
import { generateId } from '@apollo/shared';

interface FormattedReportData {
  title: string;
  subtitle?: string;
  classification: ClassificationMarking;
  generatedDate: Date;
  author?: string;
  sections: ReportSection[];
  tables?: ReportTable[];
  charts?: ReportChart[];
  footer?: string;
  metadata?: Record<string, any>;
}

interface NetworkNode {
  id: string;
  label: string;
  type?: string;
  properties?: Record<string, any>;
  weight?: number;
  group?: string;
}

interface NetworkEdge {
  source_id: string;
  target_id: string;
  relationship_type?: string;
  weight?: number;
  properties?: Record<string, any>;
  direction?: 'directed' | 'undirected';
}

interface NetworkData {
  nodes: NetworkNode[];
  edges: NetworkEdge[];
  depth?: number;
  metadata?: Record<string, any>;
}

interface ClusterAnalysis {
  clusterId: string;
  nodeCount: number;
  nodes: string[];
  centralNode?: string;
  density: number;
}

export class NetworkFormatter {
  /**
   * Format network map data for report generation
   */
  formatNetworkMap(
    data: NetworkData,
    options: ReportGenerationOptions
  ): FormattedReportData {
    const sections: ReportSection[] = [];
    const tables: ReportTable[] = [];
    const charts: ReportChart[] = [];

    const { nodes, edges } = data;

    // Executive Summary
    sections.push({
      id: generateId(),
      title: 'Network Analysis Summary',
      content: this.generateNetworkSummary(nodes, edges, data.depth),
      order: 1,
    });

    // Network Statistics
    sections.push({
      id: generateId(),
      title: 'Network Statistics',
      content: this.generateNetworkStatistics(nodes, edges),
      order: 2,
    });

    // Network visualization chart
    charts.push({
      id: generateId(),
      type: 'network',
      title: 'Entity Relationship Network',
      data: {
        nodes: nodes.map((n) => ({ id: n.id, label: n.label })),
        edges: edges.map((e) => ({ from: e.source_id, to: e.target_id })),
      },
    });

    // Node type distribution
    const nodeTypeCounts = this.countByField(nodes, 'type');
    if (Object.keys(nodeTypeCounts).length > 0) {
      charts.push({
        id: generateId(),
        type: 'pie',
        title: 'Nodes by Type',
        data: {
          labels: Object.keys(nodeTypeCounts),
          values: Object.values(nodeTypeCounts),
        },
      });
    }

    // Relationship type distribution
    const relationshipTypeCounts = this.countByField(edges, 'relationship_type');
    if (Object.keys(relationshipTypeCounts).length > 0) {
      charts.push({
        id: generateId(),
        type: 'bar',
        title: 'Relationships by Type',
        data: {
          labels: Object.keys(relationshipTypeCounts),
          values: Object.values(relationshipTypeCounts),
        },
      });
    }

    // Node Inventory
    sections.push({
      id: generateId(),
      title: 'Entity Inventory',
      content: `${nodes.length} entities have been identified in this network.`,
      order: 3,
      pageBreakBefore: true,
    });

    tables.push({
      id: generateId(),
      title: 'Network Entities',
      headers: ['ID', 'Label', 'Type', 'Group', 'Connections', 'Centrality Score'],
      rows: nodes.map((node) => {
        const connections = this.countNodeConnections(node.id, edges);
        const centrality = this.calculateCentrality(node.id, nodes, edges);
        return [
          node.id.substring(0, 8),
          node.label,
          node.type || 'Unknown',
          node.group || 'N/A',
          connections.toString(),
          centrality.toFixed(3),
        ];
      }),
      striped: true,
      bordered: true,
    });

    // Relationship Inventory
    sections.push({
      id: generateId(),
      title: 'Relationship Inventory',
      content: `${edges.length} relationship(s) have been mapped.`,
      order: 4,
    });

    tables.push({
      id: generateId(),
      title: 'Network Relationships',
      headers: ['Source', 'Target', 'Relationship Type', 'Weight', 'Direction'],
      rows: edges.map((edge) => {
        const sourceNode = nodes.find((n) => n.id === edge.source_id);
        const targetNode = nodes.find((n) => n.id === edge.target_id);
        return [
          sourceNode?.label || edge.source_id.substring(0, 8),
          targetNode?.label || edge.target_id.substring(0, 8),
          edge.relationship_type || 'Unknown',
          edge.weight?.toString() || '1',
          edge.direction || 'undirected',
        ];
      }),
      striped: true,
      bordered: true,
    });

    // Central Entities Analysis
    const centralEntities = this.identifyCentralEntities(nodes, edges);
    sections.push({
      id: generateId(),
      title: 'Central Entities Analysis',
      content: this.formatCentralEntitiesAnalysis(centralEntities, nodes),
      order: 5,
      pageBreakBefore: true,
    });

    tables.push({
      id: generateId(),
      title: 'Most Connected Entities',
      headers: ['Rank', 'Entity', 'Type', 'Connections', 'Centrality', 'Betweenness'],
      rows: centralEntities.slice(0, 20).map((entity, index) => {
        const node = nodes.find((n) => n.id === entity.nodeId)!;
        return [
          (index + 1).toString(),
          node.label,
          node.type || 'Unknown',
          entity.connections.toString(),
          entity.centrality.toFixed(3),
          entity.betweenness.toFixed(3),
        ];
      }),
      striped: true,
      bordered: true,
    });

    // Cluster Analysis
    const clusters = this.performClusterAnalysis(nodes, edges);
    if (clusters.length > 1) {
      sections.push({
        id: generateId(),
        title: 'Cluster Analysis',
        content: this.formatClusterAnalysis(clusters, nodes),
        order: 6,
      });

      tables.push({
        id: generateId(),
        title: 'Network Clusters',
        headers: ['Cluster', 'Node Count', 'Central Node', 'Density', 'Key Members'],
        rows: clusters.map((cluster, index) => {
          const centralNode = nodes.find((n) => n.id === cluster.centralNode);
          const keyMembers = cluster.nodes
            .slice(0, 3)
            .map((id) => nodes.find((n) => n.id === id)?.label || id)
            .join(', ');
          return [
            `Cluster ${index + 1}`,
            cluster.nodeCount.toString(),
            centralNode?.label || 'N/A',
            cluster.density.toFixed(2),
            keyMembers + (cluster.nodes.length > 3 ? '...' : ''),
          ];
        }),
        striped: true,
        bordered: true,
      });
    }

    // Path Analysis
    const keyPaths = this.identifyKeyPaths(nodes, edges);
    if (keyPaths.length > 0) {
      sections.push({
        id: generateId(),
        title: 'Path Analysis',
        content: this.formatPathAnalysis(keyPaths, nodes),
        order: 7,
      });
    }

    // Relationship Patterns
    sections.push({
      id: generateId(),
      title: 'Relationship Patterns',
      content: this.analyzeRelationshipPatterns(edges, nodes),
      order: 8,
      pageBreakBefore: true,
    });

    // Node Type Details
    const nodeTypes = [...new Set(nodes.map((n) => n.type).filter(Boolean))];
    if (nodeTypes.length > 0) {
      sections.push({
        id: generateId(),
        title: 'Entity Type Breakdown',
        content: 'Analysis by entity type:',
        order: 9,
        subsections: nodeTypes.map((type, index) => {
          const typeNodes = nodes.filter((n) => n.type === type);
          return {
            id: generateId(),
            title: `${type || 'Unknown'} (${typeNodes.length})`,
            content: this.formatNodeTypeAnalysis(typeNodes, edges),
            order: index + 1,
          };
        }),
      });
    }

    // Risk Assessment
    const riskEntities = this.identifyHighRiskEntities(nodes, edges);
    if (riskEntities.length > 0) {
      sections.push({
        id: generateId(),
        title: 'Risk Assessment',
        content: this.formatRiskAssessment(riskEntities, nodes),
        order: 10,
      });
    }

    return {
      title: 'Network Mapping Report',
      subtitle: data.metadata?.title || undefined,
      classification: options.classification,
      generatedDate: new Date(),
      sections,
      tables,
      charts,
      footer: `Network analysis: ${nodes.length} nodes, ${edges.length} edges`,
      metadata: {
        reportId: generateId(),
        type: 'network_mapping',
        nodeCount: nodes.length,
        edgeCount: edges.length,
        depth: data.depth,
      },
    };
  }

  // Helper methods

  private generateNetworkSummary(nodes: NetworkNode[], edges: NetworkEdge[], depth?: number): string {
    const nodeTypes = [...new Set(nodes.map((n) => n.type).filter(Boolean))];
    const relationshipTypes = [...new Set(edges.map((e) => e.relationship_type).filter(Boolean))];

    const avgConnections = edges.length > 0 ? (edges.length * 2 / nodes.length).toFixed(2) : '0';
    const density = this.calculateNetworkDensity(nodes.length, edges.length);

    let content = `NETWORK OVERVIEW\n\n`;
    content += `This network analysis encompasses ${nodes.length} entities connected by ${edges.length} relationships.\n\n`;

    content += `KEY METRICS:\n`;
    content += `- Total Entities: ${nodes.length}\n`;
    content += `- Total Relationships: ${edges.length}\n`;
    content += `- Entity Types: ${nodeTypes.length} (${nodeTypes.slice(0, 5).join(', ')}${nodeTypes.length > 5 ? '...' : ''})\n`;
    content += `- Relationship Types: ${relationshipTypes.length} (${relationshipTypes.slice(0, 5).join(', ')}${relationshipTypes.length > 5 ? '...' : ''})\n`;
    content += `- Average Connections: ${avgConnections}\n`;
    content += `- Network Density: ${density.toFixed(4)}\n`;

    if (depth) {
      content += `- Analysis Depth: ${depth} degree(s)\n`;
    }

    return content;
  }

  private generateNetworkStatistics(nodes: NetworkNode[], edges: NetworkEdge[]): string {
    const connectionCounts = nodes.map((n) => this.countNodeConnections(n.id, edges));
    const maxConnections = Math.max(...connectionCounts);
    const minConnections = Math.min(...connectionCounts);
    const avgConnections = connectionCounts.reduce((a, b) => a + b, 0) / connectionCounts.length;

    const isolatedNodes = nodes.filter((n) => this.countNodeConnections(n.id, edges) === 0);
    const hubNodes = nodes.filter((n) => this.countNodeConnections(n.id, edges) >= avgConnections * 2);

    let content = 'STATISTICAL ANALYSIS\n\n';

    content += `Connection Distribution:\n`;
    content += `- Maximum connections: ${maxConnections}\n`;
    content += `- Minimum connections: ${minConnections}\n`;
    content += `- Average connections: ${avgConnections.toFixed(2)}\n`;
    content += `- Isolated nodes: ${isolatedNodes.length}\n`;
    content += `- Hub nodes (2x avg): ${hubNodes.length}\n\n`;

    content += `Network Structure:\n`;
    content += `- Density: ${this.calculateNetworkDensity(nodes.length, edges.length).toFixed(4)}\n`;
    content += `- Clustering coefficient: ${this.calculateClusteringCoefficient(nodes, edges).toFixed(4)}\n`;

    return content;
  }

  private countNodeConnections(nodeId: string, edges: NetworkEdge[]): number {
    return edges.filter(
      (e) => e.source_id === nodeId || e.target_id === nodeId
    ).length;
  }

  private calculateCentrality(nodeId: string, nodes: NetworkNode[], edges: NetworkEdge[]): number {
    const connections = this.countNodeConnections(nodeId, edges);
    const maxPossible = nodes.length - 1;
    return maxPossible > 0 ? connections / maxPossible : 0;
  }

  private calculateNetworkDensity(nodeCount: number, edgeCount: number): number {
    const maxEdges = (nodeCount * (nodeCount - 1)) / 2;
    return maxEdges > 0 ? edgeCount / maxEdges : 0;
  }

  private calculateClusteringCoefficient(nodes: NetworkNode[], edges: NetworkEdge[]): number {
    let totalCoefficient = 0;

    nodes.forEach((node) => {
      const neighbors = this.getNeighbors(node.id, edges);
      if (neighbors.length < 2) return;

      let triangles = 0;
      const possibleTriangles = (neighbors.length * (neighbors.length - 1)) / 2;

      for (let i = 0; i < neighbors.length; i++) {
        for (let j = i + 1; j < neighbors.length; j++) {
          if (this.areConnected(neighbors[i], neighbors[j], edges)) {
            triangles++;
          }
        }
      }

      totalCoefficient += possibleTriangles > 0 ? triangles / possibleTriangles : 0;
    });

    return nodes.length > 0 ? totalCoefficient / nodes.length : 0;
  }

  private getNeighbors(nodeId: string, edges: NetworkEdge[]): string[] {
    const neighbors = new Set<string>();

    edges.forEach((edge) => {
      if (edge.source_id === nodeId) {
        neighbors.add(edge.target_id);
      }
      if (edge.target_id === nodeId) {
        neighbors.add(edge.source_id);
      }
    });

    return Array.from(neighbors);
  }

  private areConnected(nodeA: string, nodeB: string, edges: NetworkEdge[]): boolean {
    return edges.some(
      (e) =>
        (e.source_id === nodeA && e.target_id === nodeB) ||
        (e.source_id === nodeB && e.target_id === nodeA)
    );
  }

  private identifyCentralEntities(
    nodes: NetworkNode[],
    edges: NetworkEdge[]
  ): { nodeId: string; connections: number; centrality: number; betweenness: number }[] {
    return nodes
      .map((node) => ({
        nodeId: node.id,
        connections: this.countNodeConnections(node.id, edges),
        centrality: this.calculateCentrality(node.id, nodes, edges),
        betweenness: this.calculateBetweenness(node.id, nodes, edges),
      }))
      .sort((a, b) => b.centrality - a.centrality);
  }

  private calculateBetweenness(nodeId: string, nodes: NetworkNode[], edges: NetworkEdge[]): number {
    // Simplified betweenness calculation
    const neighbors = this.getNeighbors(nodeId, edges);
    let pathsThrough = 0;

    neighbors.forEach((n1) => {
      neighbors.forEach((n2) => {
        if (n1 !== n2 && !this.areConnected(n1, n2, edges)) {
          pathsThrough++;
        }
      });
    });

    const totalPairs = nodes.length * (nodes.length - 1);
    return totalPairs > 0 ? pathsThrough / totalPairs : 0;
  }

  private formatCentralEntitiesAnalysis(
    centralEntities: { nodeId: string; connections: number; centrality: number }[],
    nodes: NetworkNode[]
  ): string {
    let content = `CENTRAL ENTITIES ANALYSIS\n\n`;

    const top5 = centralEntities.slice(0, 5);
    content += `The most central entities in this network are:\n\n`;

    top5.forEach((entity, index) => {
      const node = nodes.find((n) => n.id === entity.nodeId);
      content += `${index + 1}. ${node?.label || entity.nodeId}\n`;
      content += `   - Type: ${node?.type || 'Unknown'}\n`;
      content += `   - Connections: ${entity.connections}\n`;
      content += `   - Centrality Score: ${entity.centrality.toFixed(3)}\n\n`;
    });

    return content;
  }

  private performClusterAnalysis(nodes: NetworkNode[], edges: NetworkEdge[]): ClusterAnalysis[] {
    // Simple clustering based on connected components
    const visited = new Set<string>();
    const clusters: ClusterAnalysis[] = [];

    nodes.forEach((node) => {
      if (!visited.has(node.id)) {
        const cluster = this.findConnectedComponent(node.id, edges, visited);
        if (cluster.length > 0) {
          const centralNode = this.findClusterCenter(cluster, edges);
          const density = this.calculateClusterDensity(cluster, edges);

          clusters.push({
            clusterId: generateId(),
            nodeCount: cluster.length,
            nodes: cluster,
            centralNode,
            density,
          });
        }
      }
    });

    return clusters.sort((a, b) => b.nodeCount - a.nodeCount);
  }

  private findConnectedComponent(startId: string, edges: NetworkEdge[], visited: Set<string>): string[] {
    const component: string[] = [];
    const queue = [startId];

    while (queue.length > 0) {
      const nodeId = queue.shift()!;
      if (visited.has(nodeId)) continue;

      visited.add(nodeId);
      component.push(nodeId);

      const neighbors = this.getNeighbors(nodeId, edges);
      neighbors.forEach((n) => {
        if (!visited.has(n)) {
          queue.push(n);
        }
      });
    }

    return component;
  }

  private findClusterCenter(cluster: string[], edges: NetworkEdge[]): string {
    let maxConnections = 0;
    let center = cluster[0];

    cluster.forEach((nodeId) => {
      const connections = edges.filter(
        (e) =>
          (e.source_id === nodeId && cluster.includes(e.target_id)) ||
          (e.target_id === nodeId && cluster.includes(e.source_id))
      ).length;

      if (connections > maxConnections) {
        maxConnections = connections;
        center = nodeId;
      }
    });

    return center;
  }

  private calculateClusterDensity(cluster: string[], edges: NetworkEdge[]): number {
    const clusterEdges = edges.filter(
      (e) => cluster.includes(e.source_id) && cluster.includes(e.target_id)
    ).length;

    const maxEdges = (cluster.length * (cluster.length - 1)) / 2;
    return maxEdges > 0 ? clusterEdges / maxEdges : 0;
  }

  private formatClusterAnalysis(clusters: ClusterAnalysis[], nodes: NetworkNode[]): string {
    let content = `CLUSTER ANALYSIS\n\n`;
    content += `${clusters.length} distinct cluster(s) have been identified in this network.\n\n`;

    clusters.slice(0, 5).forEach((cluster, index) => {
      const centralNode = nodes.find((n) => n.id === cluster.centralNode);
      content += `Cluster ${index + 1}:\n`;
      content += `- Nodes: ${cluster.nodeCount}\n`;
      content += `- Central Entity: ${centralNode?.label || 'Unknown'}\n`;
      content += `- Density: ${cluster.density.toFixed(2)}\n\n`;
    });

    return content;
  }

  private identifyKeyPaths(
    nodes: NetworkNode[],
    edges: NetworkEdge[]
  ): { path: string[]; type: string }[] {
    // Identify notable paths in the network
    const paths: { path: string[]; type: string }[] = [];

    // Find bridge nodes (nodes whose removal disconnects the network)
    nodes.forEach((node) => {
      const neighbors = this.getNeighbors(node.id, edges);
      if (neighbors.length === 2) {
        if (!this.areConnected(neighbors[0], neighbors[1], edges)) {
          paths.push({
            path: [neighbors[0], node.id, neighbors[1]],
            type: 'bridge',
          });
        }
      }
    });

    return paths.slice(0, 10);
  }

  private formatPathAnalysis(
    paths: { path: string[]; type: string }[],
    nodes: NetworkNode[]
  ): string {
    let content = `PATH ANALYSIS\n\n`;
    content += `${paths.length} significant path(s) have been identified:\n\n`;

    paths.forEach((pathInfo, index) => {
      const pathLabels = pathInfo.path.map(
        (id) => nodes.find((n) => n.id === id)?.label || id
      );
      content += `${index + 1}. ${pathInfo.type.toUpperCase()} PATH\n`;
      content += `   ${pathLabels.join(' -> ')}\n\n`;
    });

    return content;
  }

  private analyzeRelationshipPatterns(edges: NetworkEdge[], nodes: NetworkNode[]): string {
    const relationshipCounts = this.countByField(edges, 'relationship_type');
    const directedCount = edges.filter((e) => e.direction === 'directed').length;
    const weightedCount = edges.filter((e) => e.weight && e.weight > 1).length;

    let content = `RELATIONSHIP PATTERN ANALYSIS\n\n`;

    content += `Relationship Type Distribution:\n`;
    Object.entries(relationshipCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .forEach(([type, count]) => {
        const percentage = ((count / edges.length) * 100).toFixed(1);
        content += `- ${type || 'Unknown'}: ${count} (${percentage}%)\n`;
      });

    content += `\nRelationship Characteristics:\n`;
    content += `- Directed relationships: ${directedCount} (${((directedCount / edges.length) * 100).toFixed(1)}%)\n`;
    content += `- Weighted relationships: ${weightedCount} (${((weightedCount / edges.length) * 100).toFixed(1)}%)\n`;

    return content;
  }

  private formatNodeTypeAnalysis(typeNodes: NetworkNode[], edges: NetworkEdge[]): string {
    const totalConnections = typeNodes.reduce(
      (sum, n) => sum + this.countNodeConnections(n.id, edges),
      0
    );

    let content = `Total entities: ${typeNodes.length}\n`;
    content += `Total connections: ${totalConnections}\n`;
    content += `Average connections: ${(totalConnections / typeNodes.length).toFixed(2)}\n`;

    return content;
  }

  private identifyHighRiskEntities(
    nodes: NetworkNode[],
    edges: NetworkEdge[]
  ): { nodeId: string; riskScore: number; factors: string[] }[] {
    const riskEntities: { nodeId: string; riskScore: number; factors: string[] }[] = [];

    nodes.forEach((node) => {
      const factors: string[] = [];
      let riskScore = 0;

      // High connectivity
      const connections = this.countNodeConnections(node.id, edges);
      if (connections > 10) {
        factors.push(`High connectivity (${connections})`);
        riskScore += connections / 10;
      }

      // Bridge position
      const neighbors = this.getNeighbors(node.id, edges);
      if (neighbors.length >= 2) {
        const disconnected = neighbors.filter((n1, i) =>
          neighbors.slice(i + 1).some((n2) => !this.areConnected(n1, n2, edges))
        );
        if (disconnected.length > 0) {
          factors.push('Bridge position');
          riskScore += 2;
        }
      }

      // Multiple relationship types
      const nodeEdges = edges.filter((e) => e.source_id === node.id || e.target_id === node.id);
      const relationshipTypes = new Set(nodeEdges.map((e) => e.relationship_type));
      if (relationshipTypes.size > 3) {
        factors.push(`Multiple relationship types (${relationshipTypes.size})`);
        riskScore += 1;
      }

      if (factors.length > 0) {
        riskEntities.push({ nodeId: node.id, riskScore, factors });
      }
    });

    return riskEntities.sort((a, b) => b.riskScore - a.riskScore).slice(0, 10);
  }

  private formatRiskAssessment(
    riskEntities: { nodeId: string; riskScore: number; factors: string[] }[],
    nodes: NetworkNode[]
  ): string {
    let content = `NETWORK RISK ASSESSMENT\n\n`;
    content += `${riskEntities.length} high-interest entities have been identified based on network position:\n\n`;

    riskEntities.slice(0, 5).forEach((entity, index) => {
      const node = nodes.find((n) => n.id === entity.nodeId);
      content += `${index + 1}. ${node?.label || entity.nodeId}\n`;
      content += `   Risk Score: ${entity.riskScore.toFixed(2)}\n`;
      content += `   Factors: ${entity.factors.join(', ')}\n\n`;
    });

    return content;
  }

  private countByField(items: any[], field: string): Record<string, number> {
    return items.reduce(
      (acc, item) => {
        const value = item[field];
        if (value) {
          acc[value] = (acc[value] || 0) + 1;
        }
        return acc;
      },
      {} as Record<string, number>
    );
  }
}

export const networkFormatter = new NetworkFormatter();
