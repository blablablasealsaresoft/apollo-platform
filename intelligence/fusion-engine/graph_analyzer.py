"""
Graph Analysis System
Network analysis with Neo4j integration and centrality calculations
"""

import os
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict, deque
import hashlib


class GraphAnalyzer:
    """
    Graph Analysis Engine
    Analyzes entity relationship networks using graph theory
    """

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize Graph Analyzer

        Args:
            config: Configuration dictionary

        Raises:
            ValueError: If Neo4j is enabled but credentials are not provided
        """
        self.neo4j_uri = config.get('neo4j_uri', 'bolt://localhost:7687')
        self.neo4j_user = config.get('neo4j_user', 'neo4j')
        # No default password - must be provided via config or environment
        self.neo4j_password = config.get('neo4j_password') or os.environ.get('NEO4J_PASSWORD')

        # Validate credentials if Neo4j is explicitly enabled
        if config.get('neo4j_enabled', False) and not self.neo4j_password:
            raise ValueError(
                "NEO4J_PASSWORD is required when neo4j_enabled is True. "
                "Set it via config['neo4j_password'] or NEO4J_PASSWORD environment variable."
            )

        self.neo4j_enabled = config.get('neo4j_enabled', False)
        self.neo4j_driver = None

        # In-memory graph representation
        self.graph = defaultdict(list)
        self.nodes = {}
        self.edges = []

    def initialize_neo4j(self):
        """Initialize Neo4j connection"""
        try:
            from neo4j import GraphDatabase
            self.neo4j_driver = GraphDatabase.driver(
                self.neo4j_uri,
                auth=(self.neo4j_user, self.neo4j_password)
            )
            self.neo4j_enabled = True
            print("Neo4j connection established")
        except ImportError:
            print("Warning: neo4j package not installed. Using in-memory graph only.")
            self.neo4j_enabled = False
        except Exception as e:
            print(f"Warning: Could not connect to Neo4j: {e}. Using in-memory graph only.")
            self.neo4j_enabled = False

    def analyze_network(self, profile: Any, correlations: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform comprehensive network analysis

        Args:
            profile: EntityProfile object
            correlations: Correlation results

        Returns:
            Graph analysis results
        """
        # Build graph from profile and correlations
        self._build_graph(profile, correlations)

        analysis = {
            'centrality': {},
            'communities': [],
            'shortest_paths': {},
            'influence_score': 0.0,
            'network_metrics': {}
        }

        # Calculate centrality measures
        analysis['centrality'] = self._calculate_centrality(profile.entity_id)

        # Community detection
        analysis['communities'] = self._detect_communities()

        # Network metrics
        analysis['network_metrics'] = self._calculate_network_metrics(profile.entity_id)

        # Influence scoring
        analysis['influence_score'] = self._calculate_influence(profile.entity_id)

        # Link prediction (potential hidden connections)
        analysis['predicted_links'] = self._predict_links(profile.entity_id)

        return analysis

    def _build_graph(self, profile: Any, correlations: Dict[str, Any]):
        """Build graph representation from profile and correlations"""
        # Clear existing graph
        self.graph.clear()
        self.nodes.clear()
        self.edges.clear()

        # Add primary entity as node
        self.nodes[profile.entity_id] = {
            'id': profile.entity_id,
            'type': profile.entity_type,
            'identifier': profile.primary_identifier,
            'risk_score': profile.risk_score,
            'confidence_score': profile.confidence_score
        }

        # Add relationships
        for rel in profile.relationships:
            source = rel.get('source_entity', profile.entity_id)
            target = rel.get('target_entity')
            rel_type = rel.get('type', 'related')
            score = rel.get('score', 0.5)

            if target:
                # Add edge
                self.graph[source].append({
                    'target': target,
                    'type': rel_type,
                    'weight': score
                })

                # Bidirectional for undirected graph
                self.graph[target].append({
                    'target': source,
                    'type': rel_type,
                    'weight': score
                })

                # Store edge
                self.edges.append({
                    'source': source,
                    'target': target,
                    'type': rel_type,
                    'weight': score
                })

                # Add target node if not exists
                if target not in self.nodes:
                    self.nodes[target] = {
                        'id': target,
                        'type': 'unknown',
                        'identifier': target
                    }

    def _calculate_centrality(self, entity_id: str) -> Dict[str, float]:
        """Calculate various centrality measures"""
        centrality = {
            'degree': 0.0,
            'betweenness': 0.0,
            'closeness': 0.0,
            'eigenvector': 0.0
        }

        # Degree centrality (number of connections)
        centrality['degree'] = self._degree_centrality(entity_id)

        # Betweenness centrality (importance in paths)
        centrality['betweenness'] = self._betweenness_centrality(entity_id)

        # Closeness centrality (average distance to others)
        centrality['closeness'] = self._closeness_centrality(entity_id)

        # Eigenvector centrality (connected to important nodes)
        centrality['eigenvector'] = self._eigenvector_centrality(entity_id)

        return centrality

    def _degree_centrality(self, entity_id: str) -> float:
        """Calculate degree centrality"""
        if entity_id not in self.graph:
            return 0.0

        degree = len(self.graph[entity_id])
        max_possible = len(self.nodes) - 1

        if max_possible == 0:
            return 0.0

        return degree / max_possible

    def _betweenness_centrality(self, entity_id: str) -> float:
        """Calculate betweenness centrality using BFS"""
        if len(self.nodes) < 3:
            return 0.0

        betweenness = 0.0
        node_list = list(self.nodes.keys())

        # For each pair of nodes
        for source in node_list:
            for target in node_list:
                if source != target and source != entity_id and target != entity_id:
                    # Find all shortest paths
                    paths = self._find_all_shortest_paths(source, target)

                    if paths:
                        # Count how many pass through entity_id
                        paths_through = sum(1 for path in paths if entity_id in path)
                        betweenness += paths_through / len(paths)

        # Normalize
        n = len(self.nodes)
        if n > 2:
            betweenness /= ((n - 1) * (n - 2))

        return betweenness

    def _closeness_centrality(self, entity_id: str) -> float:
        """Calculate closeness centrality"""
        if entity_id not in self.graph:
            return 0.0

        # Calculate shortest path lengths to all other nodes
        distances = self._shortest_path_lengths(entity_id)

        if not distances:
            return 0.0

        total_distance = sum(distances.values())
        if total_distance == 0:
            return 0.0

        # Closeness is inverse of average distance
        n = len(self.nodes)
        return (n - 1) / total_distance

    def _eigenvector_centrality(self, entity_id: str, max_iter: int = 100) -> float:
        """Calculate eigenvector centrality using power iteration"""
        if not self.nodes:
            return 0.0

        # Initialize all nodes with equal centrality
        centrality = {node: 1.0 for node in self.nodes}

        # Power iteration
        for _ in range(max_iter):
            new_centrality = {}

            for node in self.nodes:
                # Sum of neighbor centralities (weighted)
                score = 0.0
                for edge in self.graph[node]:
                    neighbor = edge['target']
                    weight = edge.get('weight', 1.0)
                    score += centrality.get(neighbor, 0.0) * weight

                new_centrality[node] = score

            # Normalize
            norm = sum(new_centrality.values())
            if norm > 0:
                centrality = {node: score / norm for node, score in new_centrality.items()}

        return centrality.get(entity_id, 0.0)

    def _find_all_shortest_paths(self, source: str, target: str) -> List[List[str]]:
        """Find all shortest paths between two nodes"""
        if source not in self.graph or target not in self.graph:
            return []

        # BFS to find shortest path length
        queue = deque([(source, [source])])
        visited = {source: 0}
        paths = []
        min_length = float('inf')

        while queue:
            node, path = queue.popleft()

            if node == target:
                if len(path) < min_length:
                    min_length = len(path)
                    paths = [path]
                elif len(path) == min_length:
                    paths.append(path)
                continue

            if len(path) > min_length:
                continue

            for edge in self.graph[node]:
                neighbor = edge['target']
                new_path = path + [neighbor]

                if neighbor not in visited or visited[neighbor] == len(new_path):
                    visited[neighbor] = len(new_path)
                    queue.append((neighbor, new_path))

        return paths

    def _shortest_path_lengths(self, source: str) -> Dict[str, int]:
        """Calculate shortest path lengths from source to all nodes"""
        if source not in self.graph:
            return {}

        distances = {source: 0}
        queue = deque([source])

        while queue:
            node = queue.popleft()
            current_dist = distances[node]

            for edge in self.graph[node]:
                neighbor = edge['target']
                if neighbor not in distances:
                    distances[neighbor] = current_dist + 1
                    queue.append(neighbor)

        return {k: v for k, v in distances.items() if k != source}

    def _detect_communities(self) -> List[Dict[str, Any]]:
        """Detect communities using label propagation"""
        if not self.nodes:
            return []

        # Initialize each node with unique label
        labels = {node: i for i, node in enumerate(self.nodes)}

        # Iterate until convergence
        max_iter = 100
        for iteration in range(max_iter):
            changed = False

            for node in self.nodes:
                if node not in self.graph:
                    continue

                # Count neighbor labels
                neighbor_labels = defaultdict(float)
                for edge in self.graph[node]:
                    neighbor = edge['target']
                    weight = edge.get('weight', 1.0)
                    neighbor_labels[labels[neighbor]] += weight

                # Adopt most common label
                if neighbor_labels:
                    new_label = max(neighbor_labels.items(), key=lambda x: x[1])[0]
                    if new_label != labels[node]:
                        labels[node] = new_label
                        changed = True

            if not changed:
                break

        # Group nodes by label
        communities = defaultdict(list)
        for node, label in labels.items():
            communities[label].append(node)

        # Convert to list format
        community_list = [
            {
                'community_id': label,
                'members': members,
                'size': len(members)
            }
            for label, members in communities.items()
            if len(members) > 1  # Only communities with 2+ members
        ]

        return community_list

    def _calculate_network_metrics(self, entity_id: str) -> Dict[str, Any]:
        """Calculate overall network metrics"""
        metrics = {
            'total_nodes': len(self.nodes),
            'total_edges': len(self.edges),
            'density': 0.0,
            'clustering_coefficient': 0.0,
            'average_degree': 0.0
        }

        n = len(self.nodes)

        if n > 1:
            # Network density
            max_edges = n * (n - 1) / 2
            metrics['density'] = len(self.edges) / max_edges if max_edges > 0 else 0.0

            # Average degree
            total_degree = sum(len(neighbors) for neighbors in self.graph.values())
            metrics['average_degree'] = total_degree / n

            # Clustering coefficient
            metrics['clustering_coefficient'] = self._clustering_coefficient(entity_id)

        return metrics

    def _clustering_coefficient(self, entity_id: str) -> float:
        """Calculate local clustering coefficient"""
        if entity_id not in self.graph:
            return 0.0

        neighbors = [edge['target'] for edge in self.graph[entity_id]]
        k = len(neighbors)

        if k < 2:
            return 0.0

        # Count edges among neighbors
        edges_among_neighbors = 0
        for i, n1 in enumerate(neighbors):
            for n2 in neighbors[i + 1:]:
                if any(edge['target'] == n2 for edge in self.graph.get(n1, [])):
                    edges_among_neighbors += 1

        # Clustering coefficient
        max_edges = k * (k - 1) / 2
        return edges_among_neighbors / max_edges if max_edges > 0 else 0.0

    def _calculate_influence(self, entity_id: str) -> float:
        """Calculate influence score based on network position"""
        if entity_id not in self.nodes:
            return 0.0

        centrality = self._calculate_centrality(entity_id)

        # Weighted combination of centrality measures
        influence = (
            centrality['degree'] * 0.3 +
            centrality['betweenness'] * 0.3 +
            centrality['closeness'] * 0.2 +
            centrality['eigenvector'] * 0.2
        )

        return round(influence * 100, 2)

    def _predict_links(self, entity_id: str, top_n: int = 5) -> List[Dict[str, Any]]:
        """Predict potential missing links using common neighbors"""
        if entity_id not in self.graph:
            return []

        # Get direct neighbors
        direct_neighbors = set(edge['target'] for edge in self.graph[entity_id])

        # Calculate common neighbors with non-connected nodes
        predictions = []

        for node in self.nodes:
            if node == entity_id or node in direct_neighbors:
                continue

            # Count common neighbors
            node_neighbors = set(edge['target'] for edge in self.graph.get(node, []))
            common = direct_neighbors.intersection(node_neighbors)

            if common:
                # Jaccard coefficient
                union = direct_neighbors.union(node_neighbors)
                score = len(common) / len(union) if union else 0.0

                predictions.append({
                    'target': node,
                    'score': score,
                    'common_neighbors': len(common),
                    'method': 'common_neighbors'
                })

        # Sort by score and return top N
        predictions.sort(key=lambda x: x['score'], reverse=True)
        return predictions[:top_n]

    def find_connections(self, entity: Any, max_depth: int = 2) -> List[Dict[str, Any]]:
        """Find all connections up to max_depth"""
        connections = []
        visited = set()
        queue = deque([(entity.entity_id, 0)])

        while queue:
            node_id, depth = queue.popleft()

            if node_id in visited or depth > max_depth:
                continue

            visited.add(node_id)

            if node_id != entity.entity_id:
                connections.append({
                    'entity_id': node_id,
                    'depth': depth
                })

            # Add neighbors to queue
            if node_id in self.graph:
                for edge in self.graph[node_id]:
                    neighbor = edge['target']
                    if neighbor not in visited:
                        queue.append((neighbor, depth + 1))

        return connections

    def export_graph(self, profile: Any, output_path: str, format: str = 'gexf'):
        """
        Export graph to file

        Args:
            profile: EntityProfile
            output_path: Output file path
            format: Export format (gexf, graphml, json)
        """
        if format == 'gexf':
            self._export_gexf(output_path)
        elif format == 'graphml':
            self._export_graphml(output_path)
        elif format == 'json':
            self._export_json(output_path)
        else:
            raise ValueError(f"Unsupported format: {format}")

    def _export_gexf(self, output_path: str):
        """Export graph as GEXF format"""
        import xml.etree.ElementTree as ET

        gexf = ET.Element('gexf', xmlns='http://www.gexf.net/1.2draft', version='1.2')
        graph = ET.SubElement(gexf, 'graph', mode='static', defaultedgetype='undirected')

        # Nodes
        nodes = ET.SubElement(graph, 'nodes')
        for node_id, node_data in self.nodes.items():
            node_elem = ET.SubElement(nodes, 'node', id=node_id, label=node_data.get('identifier', node_id))

        # Edges
        edges = ET.SubElement(graph, 'edges')
        for i, edge in enumerate(self.edges):
            ET.SubElement(edges, 'edge',
                         id=str(i),
                         source=edge['source'],
                         target=edge['target'],
                         weight=str(edge.get('weight', 1.0)))

        tree = ET.ElementTree(gexf)
        tree.write(output_path, encoding='utf-8', xml_declaration=True)

    def _export_graphml(self, output_path: str):
        """Export graph as GraphML format"""
        import xml.etree.ElementTree as ET

        graphml = ET.Element('graphml', xmlns='http://graphml.graphdrawing.org/xmlns')
        graph = ET.SubElement(graphml, 'graph', id='G', edgedefault='undirected')

        # Nodes
        for node_id, node_data in self.nodes.items():
            ET.SubElement(graph, 'node', id=node_id)

        # Edges
        for i, edge in enumerate(self.edges):
            ET.SubElement(graph, 'edge',
                         id=str(i),
                         source=edge['source'],
                         target=edge['target'])

        tree = ET.ElementTree(graphml)
        tree.write(output_path, encoding='utf-8', xml_declaration=True)

    def _export_json(self, output_path: str):
        """Export graph as JSON"""
        import json

        graph_data = {
            'nodes': [
                {'id': node_id, **node_data}
                for node_id, node_data in self.nodes.items()
            ],
            'edges': self.edges
        }

        with open(output_path, 'w') as f:
            json.dump(graph_data, f, indent=2)

    def close(self):
        """Close Neo4j connection"""
        if self.neo4j_driver:
            self.neo4j_driver.close()
