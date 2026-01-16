"""
Wallet Cluster Visualization System
Creates visual representations of wallet clusters and transaction flows
"""

import logging
from typing import Dict, List, Optional, Any, Set, Tuple
from datetime import datetime
import json

try:
    import networkx as nx
    NETWORKX_AVAILABLE = True
except ImportError:
    NETWORKX_AVAILABLE = False
    logging.warning("NetworkX not available - graph functionality limited")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ClusterVisualizer:
    """
    Creates visual representations of wallet clusters using:
    - NetworkX graph structures
    - Transaction flow diagrams
    - Interactive graph exports
    - Cluster hierarchies
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize cluster visualizer

        Args:
            config: Configuration dictionary
        """
        self.config = config or {}

        # Visualization parameters
        self.max_nodes = self.config.get('max_nodes', 1000)
        self.show_values = self.config.get('show_values', True)
        self.color_by_risk = self.config.get('color_by_risk', True)

        logger.info("Cluster visualizer initialized")

    def visualize_cluster(self, cluster, links: List) -> Dict[str, Any]:
        """
        Create visualization of a wallet cluster

        Args:
            cluster: AddressCluster object
            links: List of ClusterLink objects

        Returns:
            Visualization data
        """
        logger.info(f"Visualizing cluster {cluster.cluster_id} with {len(cluster.addresses)} addresses")

        if not NETWORKX_AVAILABLE:
            logger.warning("NetworkX not available - returning basic visualization")
            return self._create_basic_visualization(cluster, links)

        # Build graph
        G = self._build_graph(cluster, links)

        # Calculate layout
        layout = self._calculate_layout(G)

        # Generate visualization data
        viz_data = {
            'cluster_id': cluster.cluster_id,
            'graph_stats': self._get_graph_statistics(G),
            'nodes': self._serialize_nodes(G, layout, cluster),
            'edges': self._serialize_edges(G, links),
            'layout': layout,
            'metadata': {
                'entity_type': cluster.entity_type,
                'entity_name': cluster.entity_name,
                'risk_score': cluster.risk_score,
                'total_addresses': len(cluster.addresses),
                'total_links': len(links)
            }
        }

        return viz_data

    def create_transaction_flow_diagram(self, transactions: List[Dict],
                                       focus_address: Optional[str] = None) -> Dict[str, Any]:
        """
        Create transaction flow diagram

        Args:
            transactions: List of transaction dictionaries
            focus_address: Optional address to highlight

        Returns:
            Flow diagram data
        """
        logger.info(f"Creating transaction flow diagram for {len(transactions)} transactions")

        if not NETWORKX_AVAILABLE:
            return self._create_basic_flow_diagram(transactions)

        # Build directed graph
        G = nx.DiGraph()

        # Add nodes and edges from transactions
        for tx in transactions:
            tx_node = f"tx_{tx['hash'][:8]}"
            G.add_node(tx_node, node_type='transaction', **tx)

            # Add input edges
            for input_addr in tx.get('inputs', []):
                G.add_node(input_addr, node_type='address')
                G.add_edge(input_addr, tx_node, edge_type='input')

            # Add output edges
            for output in tx.get('outputs', []):
                output_addr = output['address']
                G.add_node(output_addr, node_type='address')
                G.add_edge(tx_node, output_addr,
                          edge_type='output',
                          value=output.get('value', 0))

        # Calculate layout
        try:
            layout = nx.spring_layout(G, k=2, iterations=50)
        except:
            layout = {node: (i % 10, i // 10) for i, node in enumerate(G.nodes())}

        # Create flow data
        flow_data = {
            'total_transactions': len(transactions),
            'total_addresses': sum(1 for n, d in G.nodes(data=True)
                                  if d.get('node_type') == 'address'),
            'focus_address': focus_address,
            'nodes': [
                {
                    'id': node,
                    'type': G.nodes[node].get('node_type', 'unknown'),
                    'position': {'x': layout[node][0], 'y': layout[node][1]},
                    'is_focus': node == focus_address
                }
                for node in G.nodes()
            ],
            'edges': [
                {
                    'source': u,
                    'target': v,
                    'type': d.get('edge_type', 'unknown'),
                    'value': d.get('value', 0)
                }
                for u, v, d in G.edges(data=True)
            ]
        }

        return flow_data

    def create_hierarchical_view(self, cluster, subcluster_data: List[Dict]) -> Dict[str, Any]:
        """
        Create hierarchical view of cluster and subclusters

        Args:
            cluster: Main cluster
            subcluster_data: List of subcluster information

        Returns:
            Hierarchical view data
        """
        logger.info(f"Creating hierarchical view for cluster {cluster.cluster_id}")

        # Build hierarchy tree
        hierarchy = {
            'id': cluster.cluster_id,
            'type': 'main_cluster',
            'name': cluster.entity_name or 'Unknown',
            'size': len(cluster.addresses),
            'risk_score': cluster.risk_score,
            'children': []
        }

        # Add subclusters
        for subcluster in subcluster_data:
            hierarchy['children'].append({
                'id': subcluster.get('id'),
                'type': 'subcluster',
                'name': subcluster.get('name', 'Subcluster'),
                'size': subcluster.get('size', 0),
                'risk_score': subcluster.get('risk_score', 0)
            })

        return hierarchy

    def export_to_graphml(self, cluster, links: List, output_file: str):
        """
        Export cluster to GraphML format for external visualization

        Args:
            cluster: AddressCluster object
            links: List of links
            output_file: Output file path
        """
        if not NETWORKX_AVAILABLE:
            logger.error("NetworkX required for GraphML export")
            return

        logger.info(f"Exporting cluster to GraphML: {output_file}")

        G = self._build_graph(cluster, links)

        # Add node attributes
        for node in G.nodes():
            G.nodes[node]['cluster_id'] = cluster.cluster_id
            G.nodes[node]['entity_type'] = cluster.entity_type or 'unknown'
            G.nodes[node]['risk_score'] = cluster.risk_score

        # Write GraphML
        nx.write_graphml(G, output_file)
        logger.info(f"Exported {len(G.nodes())} nodes and {len(G.edges())} edges to {output_file}")

    def export_to_json(self, cluster, links: List, output_file: str):
        """
        Export cluster visualization to JSON format

        Args:
            cluster: AddressCluster object
            links: List of links
            output_file: Output file path
        """
        logger.info(f"Exporting cluster to JSON: {output_file}")

        viz_data = self.visualize_cluster(cluster, links)

        with open(output_file, 'w') as f:
            json.dump(viz_data, f, indent=2)

        logger.info(f"Exported visualization to {output_file}")

    def export_to_d3(self, cluster, links: List, output_file: str):
        """
        Export cluster to D3.js compatible format

        Args:
            cluster: AddressCluster object
            links: List of links
            output_file: Output file path
        """
        logger.info(f"Exporting cluster to D3 format: {output_file}")

        # Create D3-compatible format
        nodes = []
        edges = []

        # Add nodes
        for idx, address in enumerate(cluster.addresses):
            nodes.append({
                'id': address,
                'name': f"Addr {idx}",
                'group': 1,
                'risk': cluster.risk_score,
                'entity': cluster.entity_name or 'Unknown'
            })

        # Add edges
        for link in links:
            edges.append({
                'source': link.source,
                'target': link.target,
                'type': link.link_type,
                'confidence': link.confidence
            })

        d3_data = {
            'nodes': nodes,
            'links': edges,
            'metadata': {
                'cluster_id': cluster.cluster_id,
                'entity_type': cluster.entity_type,
                'risk_score': cluster.risk_score
            }
        }

        with open(output_file, 'w') as f:
            json.dump(d3_data, f, indent=2)

        logger.info(f"Exported D3 visualization to {output_file}")

    def create_risk_heatmap(self, clusters: List) -> Dict[str, Any]:
        """
        Create risk heatmap across multiple clusters

        Args:
            clusters: List of cluster objects

        Returns:
            Heatmap data
        """
        logger.info(f"Creating risk heatmap for {len(clusters)} clusters")

        heatmap_data = {
            'clusters': [],
            'risk_distribution': {
                'LOW': 0,
                'MEDIUM': 0,
                'HIGH': 0,
                'CRITICAL': 0
            }
        }

        for cluster in clusters:
            risk_level = self._get_risk_level(cluster.risk_score)
            heatmap_data['risk_distribution'][risk_level] += 1

            heatmap_data['clusters'].append({
                'id': cluster.cluster_id,
                'name': cluster.entity_name or 'Unknown',
                'risk_score': cluster.risk_score,
                'risk_level': risk_level,
                'size': len(cluster.addresses),
                'entity_type': cluster.entity_type
            })

        # Sort by risk score
        heatmap_data['clusters'].sort(key=lambda x: x['risk_score'], reverse=True)

        return heatmap_data

    def _build_graph(self, cluster, links: List):
        """Build NetworkX graph from cluster and links"""
        G = nx.Graph()

        # Add nodes
        for address in cluster.addresses:
            G.add_node(address, cluster_id=cluster.cluster_id)

        # Add edges
        for link in links:
            if link.source in cluster.addresses and link.target in cluster.addresses:
                G.add_edge(
                    link.source,
                    link.target,
                    link_type=link.link_type,
                    confidence=link.confidence
                )

        return G

    def _calculate_layout(self, G) -> Dict[str, Tuple[float, float]]:
        """Calculate node layout positions"""
        try:
            # Try spring layout first
            layout = nx.spring_layout(G, k=1, iterations=50)
        except:
            try:
                # Fallback to circular layout
                layout = nx.circular_layout(G)
            except:
                # Final fallback to simple grid
                layout = {node: (i % 10, i // 10) for i, node in enumerate(G.nodes())}

        return layout

    def _get_graph_statistics(self, G) -> Dict[str, Any]:
        """Calculate graph statistics"""
        stats = {
            'num_nodes': G.number_of_nodes(),
            'num_edges': G.number_of_edges(),
            'density': nx.density(G) if G.number_of_nodes() > 0 else 0
        }

        try:
            if nx.is_connected(G):
                stats['diameter'] = nx.diameter(G)
                stats['avg_clustering'] = nx.average_clustering(G)
        except:
            pass

        try:
            stats['num_components'] = nx.number_connected_components(G)
        except:
            pass

        return stats

    def _serialize_nodes(self, G, layout: Dict, cluster) -> List[Dict[str, Any]]:
        """Serialize nodes for visualization"""
        nodes = []

        for node in G.nodes():
            pos = layout.get(node, (0, 0))

            node_data = {
                'id': node,
                'label': node[:8] + '...' if len(node) > 10 else node,
                'position': {'x': float(pos[0]), 'y': float(pos[1])},
                'degree': G.degree(node),
                'risk_score': cluster.risk_score,
                'color': self._get_node_color(cluster.risk_score)
            }

            nodes.append(node_data)

        return nodes

    def _serialize_edges(self, G, links: List) -> List[Dict[str, Any]]:
        """Serialize edges for visualization"""
        edges = []

        for link in links:
            if G.has_edge(link.source, link.target):
                edge_data = {
                    'source': link.source,
                    'target': link.target,
                    'type': link.link_type,
                    'confidence': link.confidence,
                    'color': self._get_edge_color(link.link_type),
                    'width': 1 + link.confidence * 2
                }
                edges.append(edge_data)

        return edges

    def _get_node_color(self, risk_score: float) -> str:
        """Get color for node based on risk score"""
        if risk_score < 0.2:
            return '#90EE90'  # Light green
        elif risk_score < 0.4:
            return '#FFFF00'  # Yellow
        elif risk_score < 0.6:
            return '#FFA500'  # Orange
        else:
            return '#FF0000'  # Red

    def _get_edge_color(self, link_type: str) -> str:
        """Get color for edge based on link type"""
        colors = {
            'common_input': '#4169E1',  # Royal blue
            'change_address': '#32CD32',  # Lime green
            'peel_chain': '#FF8C00',  # Dark orange
            'default': '#808080'  # Gray
        }
        return colors.get(link_type, colors['default'])

    def _get_risk_level(self, score: float) -> str:
        """Convert risk score to level"""
        if score < 0.2:
            return 'LOW'
        elif score < 0.4:
            return 'MEDIUM'
        elif score < 0.6:
            return 'HIGH'
        else:
            return 'CRITICAL'

    def _create_basic_visualization(self, cluster, links: List) -> Dict[str, Any]:
        """Create basic visualization without NetworkX"""
        return {
            'cluster_id': cluster.cluster_id,
            'visualization_type': 'basic',
            'addresses': list(cluster.addresses)[:100],  # Limit to 100
            'links': [
                {
                    'source': link.source,
                    'target': link.target,
                    'type': link.link_type
                }
                for link in links[:200]  # Limit to 200
            ],
            'metadata': {
                'total_addresses': len(cluster.addresses),
                'total_links': len(links),
                'risk_score': cluster.risk_score
            }
        }

    def _create_basic_flow_diagram(self, transactions: List[Dict]) -> Dict[str, Any]:
        """Create basic flow diagram without NetworkX"""
        return {
            'visualization_type': 'basic_flow',
            'transactions': [
                {
                    'hash': tx['hash'],
                    'inputs': tx.get('inputs', []),
                    'outputs': [o['address'] for o in tx.get('outputs', [])]
                }
                for tx in transactions[:50]  # Limit to 50
            ]
        }
