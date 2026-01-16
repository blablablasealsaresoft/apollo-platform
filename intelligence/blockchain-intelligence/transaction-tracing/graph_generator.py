"""
Graph Generator for Transaction Visualization
Generate interactive visualizations of transaction flows
"""

import logging
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
import networkx as nx
from collections import defaultdict
import json


class GraphGenerator:
    """
    Transaction graph visualization generator

    Features:
    - Transaction graph generation
    - Sankey diagrams for flow visualization
    - Interactive flow charts
    - Export to Gephi/Cytoscape formats
    - Hierarchical layouts
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize graph generator

        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.logger = logging.getLogger(__name__)

        # Visualization settings
        self.settings = {
            'node_size_scale': self.config.get('node_size_scale', 100),
            'edge_width_scale': self.config.get('edge_width_scale', 5),
            'color_scheme': self.config.get('color_scheme', 'default'),
            'layout': self.config.get('layout', 'hierarchical')
        }

    def generate_transaction_graph(
        self,
        graph: nx.DiGraph,
        title: str = "Transaction Graph",
        include_metadata: bool = True
    ) -> Dict[str, Any]:
        """
        Generate transaction graph visualization data

        Args:
            graph: NetworkX transaction graph
            title: Graph title
            include_metadata: Include metadata in nodes/edges

        Returns:
            Visualization data dictionary
        """
        self.logger.info(f"Generating transaction graph: {title}")

        # Calculate node positions
        pos = self._calculate_layout(graph)

        # Prepare nodes
        nodes = []
        for node in graph.nodes():
            node_data = graph.nodes[node]

            # Determine node size based on degree
            degree = graph.degree(node)
            size = self.settings['node_size_scale'] * (1 + degree / 10)

            # Determine node color
            color = self._get_node_color(node_data)

            node_viz = {
                'id': node,
                'label': node[:8] + '...' if len(node) > 8 else node,
                'x': pos[node][0],
                'y': pos[node][1],
                'size': size,
                'color': color,
                'degree': degree
            }

            if include_metadata:
                node_viz['metadata'] = node_data

            nodes.append(node_viz)

        # Prepare edges
        edges = []
        for source, target, data in graph.edges(data=True):
            # Edge width based on amount
            amount = data.get('amount', 1.0)
            width = self.settings['edge_width_scale'] * (amount / 10)

            # Edge color based on properties
            color = self._get_edge_color(data)

            edge_viz = {
                'source': source,
                'target': target,
                'width': min(width, 20),  # Cap width
                'color': color,
                'amount': amount
            }

            if include_metadata:
                edge_viz['metadata'] = data

            edges.append(edge_viz)

        return {
            'title': title,
            'nodes': nodes,
            'edges': edges,
            'layout': self.settings['layout'],
            'statistics': {
                'node_count': len(nodes),
                'edge_count': len(edges),
                'density': nx.density(graph),
                'avg_degree': sum(dict(graph.degree()).values()) / len(graph.nodes()) if graph.nodes() else 0
            }
        }

    def generate_sankey_diagram(
        self,
        graph: nx.DiGraph,
        source_address: str,
        max_depth: int = 3
    ) -> Dict[str, Any]:
        """
        Generate Sankey diagram for fund flow

        Args:
            graph: Transaction graph
            source_address: Starting address
            max_depth: Maximum depth to visualize

        Returns:
            Sankey diagram data
        """
        self.logger.info(f"Generating Sankey diagram from {source_address}")

        # BFS to build flow layers
        layers = []
        current_layer = {source_address}
        visited = {source_address}

        for depth in range(max_depth):
            next_layer = set()
            layer_flows = []

            for node in current_layer:
                for successor in graph.successors(node):
                    if successor not in visited:
                        edge_data = graph.get_edge_data(node, successor)
                        amount = edge_data.get('amount', 0)

                        layer_flows.append({
                            'source': node,
                            'target': successor,
                            'value': amount
                        })

                        next_layer.add(successor)
                        visited.add(successor)

            if layer_flows:
                layers.append(layer_flows)

            current_layer = next_layer
            if not current_layer:
                break

        # Build Sankey data structure
        nodes = []
        links = []
        node_index = {}
        index_counter = 0

        # Add all unique nodes
        for layer in layers:
            for flow in layer:
                if flow['source'] not in node_index:
                    nodes.append({'name': flow['source']})
                    node_index[flow['source']] = index_counter
                    index_counter += 1

                if flow['target'] not in node_index:
                    nodes.append({'name': flow['target']})
                    node_index[flow['target']] = index_counter
                    index_counter += 1

        # Add links
        for layer in layers:
            for flow in layer:
                links.append({
                    'source': node_index[flow['source']],
                    'target': node_index[flow['target']],
                    'value': flow['value']
                })

        return {
            'type': 'sankey',
            'nodes': nodes,
            'links': links,
            'depth': len(layers)
        }

    def generate_flow_timeline(
        self,
        graph: nx.DiGraph,
        time_intervals: int = 10
    ) -> Dict[str, Any]:
        """
        Generate timeline visualization of fund flow

        Args:
            graph: Transaction graph
            time_intervals: Number of time intervals

        Returns:
            Timeline data
        """
        # Extract timestamps
        timestamps = []
        for _, _, data in graph.edges(data=True):
            if 'timestamp' in data:
                timestamps.append(data['timestamp'])

        if not timestamps:
            return {'error': 'No timestamp data available'}

        # Create time buckets
        min_time = min(timestamps)
        max_time = max(timestamps)
        time_range = (max_time - min_time).total_seconds()
        interval_size = time_range / time_intervals

        buckets = [[] for _ in range(time_intervals)]

        for _, _, data in graph.edges(data=True):
            if 'timestamp' in data:
                ts = data['timestamp']
                bucket_idx = int((ts - min_time).total_seconds() / interval_size)
                bucket_idx = min(bucket_idx, time_intervals - 1)

                buckets[bucket_idx].append({
                    'amount': data.get('amount', 0),
                    'timestamp': ts
                })

        # Aggregate buckets
        timeline = []
        for i, bucket in enumerate(buckets):
            bucket_time = min_time + (i * interval_size)
            timeline.append({
                'time': bucket_time.isoformat(),
                'transaction_count': len(bucket),
                'total_volume': sum(tx['amount'] for tx in bucket),
                'avg_amount': sum(tx['amount'] for tx in bucket) / len(bucket) if bucket else 0
            })

        return {
            'type': 'timeline',
            'intervals': timeline,
            'start_time': min_time.isoformat(),
            'end_time': max_time.isoformat(),
            'total_transactions': len(timestamps)
        }

    def export_to_gephi(
        self,
        graph: nx.DiGraph,
        output_path: str
    ) -> str:
        """
        Export graph to Gephi GEXF format

        Args:
            graph: NetworkX graph
            output_path: Output file path

        Returns:
            Path to exported file
        """
        self.logger.info(f"Exporting to Gephi format: {output_path}")

        # Write GEXF
        nx.write_gexf(graph, output_path)

        return output_path

    def export_to_cytoscape(
        self,
        graph: nx.DiGraph,
        output_path: str
    ) -> str:
        """
        Export graph to Cytoscape JSON format

        Args:
            graph: NetworkX graph
            output_path: Output file path

        Returns:
            Path to exported file
        """
        self.logger.info(f"Exporting to Cytoscape format: {output_path}")

        # Convert to Cytoscape format
        cyto_data = {
            'elements': {
                'nodes': [],
                'edges': []
            }
        }

        # Add nodes
        for node in graph.nodes():
            node_data = graph.nodes[node]
            cyto_data['elements']['nodes'].append({
                'data': {
                    'id': node,
                    **node_data
                }
            })

        # Add edges
        for source, target, data in graph.edges(data=True):
            cyto_data['elements']['edges'].append({
                'data': {
                    'source': source,
                    'target': target,
                    'id': f"{source}_{target}",
                    **data
                }
            })

        # Write JSON
        with open(output_path, 'w') as f:
            json.dump(cyto_data, f, indent=2, default=str)

        return output_path

    def export_to_d3(
        self,
        graph: nx.DiGraph,
        output_path: str
    ) -> str:
        """
        Export graph to D3.js JSON format

        Args:
            graph: NetworkX graph
            output_path: Output file path

        Returns:
            Path to exported file
        """
        self.logger.info(f"Exporting to D3 format: {output_path}")

        # Build node index
        node_index = {node: i for i, node in enumerate(graph.nodes())}

        # Convert to D3 format
        d3_data = {
            'nodes': [],
            'links': []
        }

        # Add nodes
        for node in graph.nodes():
            node_data = graph.nodes[node]
            d3_data['nodes'].append({
                'id': node,
                'group': node_data.get('type', 'default'),
                **node_data
            })

        # Add links
        for source, target, data in graph.edges(data=True):
            d3_data['links'].append({
                'source': node_index[source],
                'target': node_index[target],
                'value': data.get('amount', 1),
                **data
            })

        # Write JSON
        with open(output_path, 'w') as f:
            json.dump(d3_data, f, indent=2, default=str)

        return output_path

    def generate_html_visualization(
        self,
        graph: nx.DiGraph,
        output_path: str,
        title: str = "Transaction Flow"
    ) -> str:
        """
        Generate interactive HTML visualization

        Args:
            graph: Transaction graph
            output_path: Output HTML file path
            title: Visualization title

        Returns:
            Path to HTML file
        """
        self.logger.info(f"Generating HTML visualization: {output_path}")

        # Export graph data
        graph_data = self.generate_transaction_graph(graph, title)

        # Generate HTML
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>{title}</title>
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        #graph {{
            width: 100%;
            height: 800px;
            background-color: white;
            border: 1px solid #ddd;
            border-radius: 4px;
        }}
        .node {{
            stroke: #fff;
            stroke-width: 2px;
            cursor: pointer;
        }}
        .link {{
            stroke: #999;
            stroke-opacity: 0.6;
        }}
        .node-label {{
            font-size: 10px;
            pointer-events: none;
        }}
        #info {{
            margin-top: 20px;
            padding: 15px;
            background-color: white;
            border-radius: 4px;
            border: 1px solid #ddd;
        }}
        h1 {{
            margin-top: 0;
        }}
    </style>
</head>
<body>
    <h1>{title}</h1>
    <div id="info">
        <p><strong>Nodes:</strong> {graph_data['statistics']['node_count']}</p>
        <p><strong>Edges:</strong> {graph_data['statistics']['edge_count']}</p>
        <p><strong>Density:</strong> {graph_data['statistics']['density']:.4f}</p>
    </div>
    <div id="graph"></div>

    <script>
        const graphData = {json.dumps(graph_data, default=str)};

        const width = document.getElementById('graph').clientWidth;
        const height = 800;

        const svg = d3.select('#graph')
            .append('svg')
            .attr('width', width)
            .attr('height', height);

        const simulation = d3.forceSimulation(graphData.nodes)
            .force('link', d3.forceLink(graphData.edges)
                .id(d => d.id)
                .distance(100))
            .force('charge', d3.forceManyBody().strength(-300))
            .force('center', d3.forceCenter(width / 2, height / 2));

        const link = svg.append('g')
            .selectAll('line')
            .data(graphData.edges)
            .enter()
            .append('line')
            .attr('class', 'link')
            .attr('stroke-width', d => d.width);

        const node = svg.append('g')
            .selectAll('circle')
            .data(graphData.nodes)
            .enter()
            .append('circle')
            .attr('class', 'node')
            .attr('r', d => Math.sqrt(d.size))
            .attr('fill', d => d.color)
            .call(d3.drag()
                .on('start', dragstarted)
                .on('drag', dragged)
                .on('end', dragended));

        const label = svg.append('g')
            .selectAll('text')
            .data(graphData.nodes)
            .enter()
            .append('text')
            .attr('class', 'node-label')
            .text(d => d.label);

        node.append('title')
            .text(d => `${{d.id}}\\nDegree: ${{d.degree}}`);

        simulation.on('tick', () => {{
            link
                .attr('x1', d => d.source.x)
                .attr('y1', d => d.source.y)
                .attr('x2', d => d.target.x)
                .attr('y2', d => d.target.y);

            node
                .attr('cx', d => d.x)
                .attr('cy', d => d.y);

            label
                .attr('x', d => d.x + 10)
                .attr('y', d => d.y);
        }});

        function dragstarted(event, d) {{
            if (!event.active) simulation.alphaTarget(0.3).restart();
            d.fx = d.x;
            d.fy = d.y;
        }}

        function dragged(event, d) {{
            d.fx = event.x;
            d.fy = event.y;
        }}

        function dragended(event, d) {{
            if (!event.active) simulation.alphaTarget(0);
            d.fx = null;
            d.fy = null;
        }}
    </script>
</body>
</html>
"""

        # Write HTML file
        with open(output_path, 'w') as f:
            f.write(html_content)

        return output_path

    def _calculate_layout(self, graph: nx.DiGraph) -> Dict[str, Tuple[float, float]]:
        """Calculate node positions based on layout algorithm"""
        layout_type = self.settings['layout']

        if layout_type == 'hierarchical':
            # Use hierarchical layout if graph is DAG
            if nx.is_directed_acyclic_graph(graph):
                pos = nx.spring_layout(graph, k=1, iterations=50)
            else:
                pos = nx.spring_layout(graph)
        elif layout_type == 'circular':
            pos = nx.circular_layout(graph)
        elif layout_type == 'kamada_kawai':
            pos = nx.kamada_kawai_layout(graph)
        else:  # spring layout
            pos = nx.spring_layout(graph)

        # Scale positions
        scale = 1000
        return {node: (x * scale, y * scale) for node, (x, y) in pos.items()}

    def _get_node_color(self, node_data: Dict[str, Any]) -> str:
        """Get node color based on type"""
        node_type = node_data.get('type', 'default')

        color_map = {
            'address': '#4CAF50',
            'contract': '#2196F3',
            'mixer': '#F44336',
            'exchange': '#FF9800',
            'transaction': '#9E9E9E',
            'internal': '#00BCD4',
            'token_transfer': '#9C27B0',
            'default': '#607D8B'
        }

        return color_map.get(node_type, color_map['default'])

    def _get_edge_color(self, edge_data: Dict[str, Any]) -> str:
        """Get edge color based on properties"""
        if edge_data.get('cross_chain', False):
            return '#FF5722'
        elif edge_data.get('is_tainted', False):
            return '#F44336'
        else:
            return '#999999'


# Example usage
def main():
    """Example usage of GraphGenerator"""
    generator = GraphGenerator()

    # Create sample graph
    graph = nx.DiGraph()
    graph.add_edge('A', 'B', amount=10.0)
    graph.add_edge('B', 'C', amount=5.0)
    graph.add_edge('B', 'D', amount=5.0)
    graph.add_edge('C', 'E', amount=3.0)

    graph.nodes['A']['type'] = 'address'
    graph.nodes['B']['type'] = 'exchange'
    graph.nodes['C']['type'] = 'address'
    graph.nodes['D']['type'] = 'mixer'
    graph.nodes['E']['type'] = 'address'

    # Generate visualization data
    viz_data = generator.generate_transaction_graph(graph, "Sample Transaction Flow")
    print(f"Generated graph with {len(viz_data['nodes'])} nodes")

    # Generate Sankey
    sankey = generator.generate_sankey_diagram(graph, 'A', max_depth=3)
    print(f"Sankey diagram with {len(sankey['nodes'])} nodes and {len(sankey['links'])} links")

    # Export to various formats
    generator.export_to_gephi(graph, 'transaction_graph.gexf')
    generator.export_to_cytoscape(graph, 'transaction_graph_cytoscape.json')
    generator.export_to_d3(graph, 'transaction_graph_d3.json')
    generator.generate_html_visualization(graph, 'transaction_graph.html')

    print("Exports completed!")


if __name__ == "__main__":
    main()
