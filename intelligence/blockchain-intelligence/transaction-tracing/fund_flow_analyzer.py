"""
Fund Flow Analyzer
Advanced analysis of fund movement patterns and flows
"""

import asyncio
import logging
from typing import Dict, List, Set, Optional, Tuple, Any
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict, deque
import networkx as nx
from enum import Enum
import statistics


class FlowPattern(Enum):
    """Types of fund flow patterns"""
    LAYERING = "layering"
    PEELING = "peeling"
    MIXING = "mixing"
    CONSOLIDATION = "consolidation"
    DISTRIBUTION = "distribution"
    CIRCULAR = "circular"
    INTEGRATION = "integration"
    PLACEMENT = "placement"


class EntityType(Enum):
    """Types of entities in fund flow"""
    INDIVIDUAL = "individual"
    EXCHANGE = "exchange"
    MIXER = "mixer"
    MERCHANT = "merchant"
    GAMBLING = "gambling"
    DARKNET = "darknet"
    MINING_POOL = "mining_pool"
    ICO = "ico"
    DEFI = "defi"
    BRIDGE = "bridge"
    UNKNOWN = "unknown"


@dataclass
class FlowNode:
    """Node in fund flow graph"""
    address: str
    blockchain: str
    entity_type: EntityType
    total_inflow: float
    total_outflow: float
    transaction_count: int
    first_seen: datetime
    last_seen: datetime
    risk_score: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FlowEdge:
    """Edge in fund flow graph"""
    source: str
    destination: str
    total_amount: float
    transaction_count: int
    first_tx: datetime
    last_tx: datetime
    avg_amount: float
    frequency: float  # transactions per day
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FlowAnalysis:
    """Complete fund flow analysis"""
    source_address: str
    total_value_flow: float
    num_hops: int
    num_unique_addresses: int
    patterns_detected: List[Dict[str, Any]]
    endpoints: List[Dict[str, Any]]
    intermediaries: List[Dict[str, Any]]
    risk_assessment: Dict[str, Any]
    flow_graph: nx.DiGraph
    timeline: List[Dict[str, Any]]


class FundFlowAnalyzer:
    """
    Advanced fund flow analyzer

    Features:
    - Source/destination identification
    - Intermediate hop analysis
    - Layering detection
    - Integration point identification
    - Pattern recognition
    - Temporal analysis
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize fund flow analyzer

        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.logger = logging.getLogger(__name__)

        # Known entity mappings
        self.entity_map: Dict[str, EntityType] = {}

        # Flow patterns database
        self.known_patterns: Dict[str, FlowPattern] = {}

        # Statistics
        self.stats = {
            'analyses_performed': 0,
            'patterns_detected': defaultdict(int),
            'endpoints_identified': 0
        }

    async def analyze_flow(
        self,
        transaction_graph: nx.DiGraph,
        source_address: str,
        min_amount: float = 0.0
    ) -> FlowAnalysis:
        """
        Analyze fund flow from transaction graph

        Args:
            transaction_graph: NetworkX transaction graph
            source_address: Source address
            min_amount: Minimum transaction amount

        Returns:
            Complete flow analysis
        """
        self.logger.info(f"Analyzing fund flow from {source_address}")
        self.stats['analyses_performed'] += 1

        # Build flow graph with aggregated edges
        flow_graph = await self._build_flow_graph(transaction_graph, min_amount)

        # Identify nodes
        nodes = await self._analyze_nodes(flow_graph)

        # Detect patterns
        patterns = await self._detect_patterns(flow_graph, source_address)

        # Identify endpoints
        endpoints = await self._identify_endpoints(flow_graph, nodes)

        # Identify intermediaries
        intermediaries = await self._identify_intermediaries(flow_graph, nodes)

        # Calculate flow metrics
        total_value = sum(
            data.get('total_amount', 0)
            for _, _, data in flow_graph.edges(data=True)
        )

        # Build timeline
        timeline = await self._build_timeline(transaction_graph)

        # Risk assessment
        risk = await self._assess_risk(flow_graph, patterns, endpoints)

        # Calculate hops
        try:
            max_hops = max(
                nx.shortest_path_length(flow_graph, source_address, node)
                for node in flow_graph.nodes()
                if node != source_address and nx.has_path(flow_graph, source_address, node)
            ) if flow_graph.number_of_nodes() > 1 else 0
        except:
            max_hops = 0

        return FlowAnalysis(
            source_address=source_address,
            total_value_flow=total_value,
            num_hops=max_hops,
            num_unique_addresses=flow_graph.number_of_nodes(),
            patterns_detected=patterns,
            endpoints=endpoints,
            intermediaries=intermediaries,
            risk_assessment=risk,
            flow_graph=flow_graph,
            timeline=timeline
        )

    async def identify_source(
        self,
        transaction_graph: nx.DiGraph,
        target_address: str
    ) -> List[Dict[str, Any]]:
        """
        Identify sources of funds for target address

        Args:
            transaction_graph: Transaction graph
            target_address: Target address

        Returns:
            List of identified sources with confidence scores
        """
        sources = []

        # Find all nodes with paths to target
        for node in transaction_graph.nodes():
            if node != target_address:
                try:
                    if nx.has_path(transaction_graph, node, target_address):
                        paths = list(nx.all_simple_paths(
                            transaction_graph,
                            node,
                            target_address,
                            cutoff=10
                        ))

                        if paths:
                            # Calculate total flow from this source
                            total_flow = 0.0
                            for path in paths:
                                path_flow = self._calculate_path_flow(
                                    transaction_graph,
                                    path
                                )
                                total_flow += path_flow

                            # Check if this is a primary source (no incoming edges)
                            in_degree = transaction_graph.in_degree(node)

                            sources.append({
                                'address': node,
                                'total_flow': total_flow,
                                'num_paths': len(paths),
                                'shortest_path_length': len(min(paths, key=len)),
                                'is_primary_source': in_degree == 0,
                                'confidence': self._calculate_source_confidence(
                                    transaction_graph,
                                    node,
                                    target_address,
                                    paths
                                )
                            })
                except nx.NetworkXNoPath:
                    continue

        # Sort by confidence
        sources.sort(key=lambda x: x['confidence'], reverse=True)

        return sources

    async def identify_destination(
        self,
        transaction_graph: nx.DiGraph,
        source_address: str
    ) -> List[Dict[str, Any]]:
        """
        Identify destinations of funds from source

        Args:
            transaction_graph: Transaction graph
            source_address: Source address

        Returns:
            List of destinations with analysis
        """
        destinations = []

        # Find all reachable nodes
        for node in transaction_graph.nodes():
            if node != source_address:
                try:
                    if nx.has_path(transaction_graph, source_address, node):
                        paths = list(nx.all_simple_paths(
                            transaction_graph,
                            source_address,
                            node,
                            cutoff=10
                        ))

                        if paths:
                            # Calculate total flow to destination
                            total_flow = 0.0
                            for path in paths:
                                path_flow = self._calculate_path_flow(
                                    transaction_graph,
                                    path
                                )
                                total_flow += path_flow

                            # Check if terminal (no outgoing edges)
                            out_degree = transaction_graph.out_degree(node)

                            # Get entity type
                            entity_type = self.entity_map.get(node, EntityType.UNKNOWN)

                            destinations.append({
                                'address': node,
                                'total_flow': total_flow,
                                'num_paths': len(paths),
                                'shortest_path_length': len(min(paths, key=len)),
                                'is_terminal': out_degree == 0,
                                'entity_type': entity_type.value,
                                'risk_level': self._calculate_destination_risk(
                                    entity_type,
                                    total_flow,
                                    out_degree
                                )
                            })
                except nx.NetworkXNoPath:
                    continue

        # Sort by flow amount
        destinations.sort(key=lambda x: x['total_flow'], reverse=True)

        return destinations

    async def detect_layering(
        self,
        transaction_graph: nx.DiGraph,
        min_layers: int = 3
    ) -> List[Dict[str, Any]]:
        """
        Detect layering patterns (multiple hops to obscure origin)

        Args:
            transaction_graph: Transaction graph
            min_layers: Minimum number of layers to consider

        Returns:
            List of detected layering patterns
        """
        layering_patterns = []

        # Find all simple paths
        for source in transaction_graph.nodes():
            for target in transaction_graph.nodes():
                if source != target:
                    try:
                        paths = list(nx.all_simple_paths(
                            transaction_graph,
                            source,
                            target,
                            cutoff=15
                        ))

                        for path in paths:
                            if len(path) >= min_layers:
                                # Analyze path characteristics
                                is_layering = await self._is_layering_pattern(
                                    transaction_graph,
                                    path
                                )

                                if is_layering:
                                    layering_patterns.append({
                                        'source': source,
                                        'destination': target,
                                        'path': path,
                                        'num_layers': len(path) - 1,
                                        'total_flow': self._calculate_path_flow(
                                            transaction_graph,
                                            path
                                        ),
                                        'pattern_type': FlowPattern.LAYERING.value,
                                        'confidence': 0.8
                                    })

                                    self.stats['patterns_detected']['layering'] += 1

                    except nx.NetworkXNoPath:
                        continue

        return layering_patterns

    async def detect_peeling_chain(
        self,
        transaction_graph: nx.DiGraph,
        min_peels: int = 3
    ) -> List[Dict[str, Any]]:
        """
        Detect peeling chain patterns (sequential small sends)

        Args:
            transaction_graph: Transaction graph
            min_peels: Minimum number of peels

        Returns:
            List of peeling chains
        """
        peeling_chains = []

        # Find linear chains
        for node in transaction_graph.nodes():
            if transaction_graph.out_degree(node) == 2:
                # Potential peel (1 change, 1 payment)
                chain = [node]
                current = node

                while True:
                    successors = list(transaction_graph.successors(current))
                    if len(successors) != 2:
                        break

                    # Identify change output (larger amount)
                    amounts = []
                    for successor in successors:
                        edge_data = transaction_graph.get_edge_data(current, successor)
                        amounts.append((successor, edge_data.get('amount', 0)))

                    amounts.sort(key=lambda x: x[1], reverse=True)
                    change_addr = amounts[0][0]

                    chain.append(change_addr)
                    current = change_addr

                    if transaction_graph.out_degree(current) != 2:
                        break

                if len(chain) >= min_peels:
                    peeling_chains.append({
                        'chain': chain,
                        'length': len(chain),
                        'pattern_type': FlowPattern.PEELING.value,
                        'confidence': 0.9
                    })

                    self.stats['patterns_detected']['peeling'] += 1

        return peeling_chains

    async def detect_mixing(
        self,
        transaction_graph: nx.DiGraph
    ) -> List[Dict[str, Any]]:
        """
        Detect mixing patterns (many-to-many)

        Args:
            transaction_graph: Transaction graph

        Returns:
            List of mixing patterns
        """
        mixing_patterns = []

        for node in transaction_graph.nodes():
            in_degree = transaction_graph.in_degree(node)
            out_degree = transaction_graph.out_degree(node)

            # Mixing typically has many inputs and many outputs
            if in_degree >= 5 and out_degree >= 5:
                # Check for equal output amounts (CoinJoin pattern)
                out_amounts = []
                for successor in transaction_graph.successors(node):
                    edge_data = transaction_graph.get_edge_data(node, successor)
                    out_amounts.append(edge_data.get('amount', 0))

                # Count equal amounts
                if out_amounts:
                    amount_counts = defaultdict(int)
                    for amount in out_amounts:
                        amount_counts[amount] += 1

                    max_equal = max(amount_counts.values())

                    if max_equal >= out_degree * 0.5:
                        # Likely mixer
                        mixing_patterns.append({
                            'mixer_address': node,
                            'num_inputs': in_degree,
                            'num_outputs': out_degree,
                            'equal_outputs': max_equal,
                            'pattern_type': FlowPattern.MIXING.value,
                            'entity_type': EntityType.MIXER.value,
                            'confidence': 0.85
                        })

                        self.stats['patterns_detected']['mixing'] += 1

        return mixing_patterns

    async def detect_circular_flow(
        self,
        transaction_graph: nx.DiGraph
    ) -> List[Dict[str, Any]]:
        """
        Detect circular fund flows

        Args:
            transaction_graph: Transaction graph

        Returns:
            List of circular flows
        """
        circular_flows = []

        # Find all cycles
        try:
            cycles = list(nx.simple_cycles(transaction_graph))

            for cycle in cycles:
                if len(cycle) >= 3:
                    # Calculate flow around cycle
                    total_flow = 0.0
                    for i in range(len(cycle)):
                        source = cycle[i]
                        dest = cycle[(i + 1) % len(cycle)]
                        edge_data = transaction_graph.get_edge_data(source, dest)
                        if edge_data:
                            total_flow += edge_data.get('amount', 0)

                    circular_flows.append({
                        'cycle': cycle,
                        'length': len(cycle),
                        'total_flow': total_flow,
                        'pattern_type': FlowPattern.CIRCULAR.value,
                        'confidence': 0.7
                    })

                    self.stats['patterns_detected']['circular'] += 1

        except nx.NetworkXNoCycle:
            pass

        return circular_flows

    async def _build_flow_graph(
        self,
        transaction_graph: nx.DiGraph,
        min_amount: float
    ) -> nx.DiGraph:
        """Build aggregated flow graph"""
        flow_graph = nx.DiGraph()

        # Aggregate transactions between same address pairs
        edge_aggregation = defaultdict(lambda: {
            'total_amount': 0.0,
            'count': 0,
            'timestamps': []
        })

        for source, dest, data in transaction_graph.edges(data=True):
            amount = data.get('amount', 0)
            if amount >= min_amount:
                key = (source, dest)
                edge_aggregation[key]['total_amount'] += amount
                edge_aggregation[key]['count'] += 1
                if 'timestamp' in data:
                    edge_aggregation[key]['timestamps'].append(data['timestamp'])

        # Build graph
        for (source, dest), agg_data in edge_aggregation.items():
            timestamps = agg_data['timestamps']
            flow_graph.add_edge(
                source,
                dest,
                total_amount=agg_data['total_amount'],
                transaction_count=agg_data['count'],
                avg_amount=agg_data['total_amount'] / agg_data['count'],
                first_tx=min(timestamps) if timestamps else None,
                last_tx=max(timestamps) if timestamps else None
            )

        return flow_graph

    async def _analyze_nodes(
        self,
        flow_graph: nx.DiGraph
    ) -> Dict[str, FlowNode]:
        """Analyze all nodes in flow graph"""
        nodes = {}

        for node in flow_graph.nodes():
            # Calculate inflow/outflow
            inflow = sum(
                data.get('total_amount', 0)
                for _, _, data in flow_graph.in_edges(node, data=True)
            )
            outflow = sum(
                data.get('total_amount', 0)
                for _, _, data in flow_graph.out_edges(node, data=True)
            )

            # Get timestamps
            all_timestamps = []
            for _, _, data in flow_graph.in_edges(node, data=True):
                if data.get('first_tx'):
                    all_timestamps.append(data['first_tx'])
                if data.get('last_tx'):
                    all_timestamps.append(data['last_tx'])

            for _, _, data in flow_graph.out_edges(node, data=True):
                if data.get('first_tx'):
                    all_timestamps.append(data['first_tx'])
                if data.get('last_tx'):
                    all_timestamps.append(data['last_tx'])

            nodes[node] = FlowNode(
                address=node,
                blockchain='',  # Would be set from graph data
                entity_type=self.entity_map.get(node, EntityType.UNKNOWN),
                total_inflow=inflow,
                total_outflow=outflow,
                transaction_count=flow_graph.in_degree(node) + flow_graph.out_degree(node),
                first_seen=min(all_timestamps) if all_timestamps else datetime.now(),
                last_seen=max(all_timestamps) if all_timestamps else datetime.now()
            )

        return nodes

    async def _detect_patterns(
        self,
        flow_graph: nx.DiGraph,
        source_address: str
    ) -> List[Dict[str, Any]]:
        """Detect all flow patterns"""
        patterns = []

        # Detect layering
        layering = await self.detect_layering(flow_graph)
        patterns.extend(layering)

        # Detect peeling
        peeling = await self.detect_peeling_chain(flow_graph)
        patterns.extend(peeling)

        # Detect mixing
        mixing = await self.detect_mixing(flow_graph)
        patterns.extend(mixing)

        # Detect circular
        circular = await self.detect_circular_flow(flow_graph)
        patterns.extend(circular)

        return patterns

    async def _identify_endpoints(
        self,
        flow_graph: nx.DiGraph,
        nodes: Dict[str, FlowNode]
    ) -> List[Dict[str, Any]]:
        """Identify endpoint addresses"""
        endpoints = []

        for node_addr, node_data in nodes.items():
            # Terminal nodes (no outflow)
            if flow_graph.out_degree(node_addr) == 0 and node_data.total_inflow > 0:
                endpoints.append({
                    'address': node_addr,
                    'entity_type': node_data.entity_type.value,
                    'total_received': node_data.total_inflow,
                    'is_terminal': True
                })
                self.stats['endpoints_identified'] += 1

        return endpoints

    async def _identify_intermediaries(
        self,
        flow_graph: nx.DiGraph,
        nodes: Dict[str, FlowNode]
    ) -> List[Dict[str, Any]]:
        """Identify intermediary addresses"""
        intermediaries = []

        for node_addr, node_data in nodes.items():
            # Intermediaries have both inflow and outflow
            if (flow_graph.in_degree(node_addr) > 0 and
                flow_graph.out_degree(node_addr) > 0):

                # Calculate flow-through ratio
                flow_through = min(node_data.total_inflow, node_data.total_outflow)
                retention = abs(node_data.total_inflow - node_data.total_outflow)

                intermediaries.append({
                    'address': node_addr,
                    'entity_type': node_data.entity_type.value,
                    'total_inflow': node_data.total_inflow,
                    'total_outflow': node_data.total_outflow,
                    'flow_through': flow_through,
                    'retention': retention,
                    'in_degree': flow_graph.in_degree(node_addr),
                    'out_degree': flow_graph.out_degree(node_addr)
                })

        return intermediaries

    async def _build_timeline(
        self,
        transaction_graph: nx.DiGraph
    ) -> List[Dict[str, Any]]:
        """Build transaction timeline"""
        timeline = []

        for source, dest, data in transaction_graph.edges(data=True):
            if 'timestamp' in data:
                timeline.append({
                    'timestamp': data['timestamp'],
                    'from': source,
                    'to': dest,
                    'amount': data.get('amount', 0)
                })

        timeline.sort(key=lambda x: x['timestamp'])

        return timeline

    async def _assess_risk(
        self,
        flow_graph: nx.DiGraph,
        patterns: List[Dict[str, Any]],
        endpoints: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Assess overall risk of fund flow"""
        risk = {
            'overall_score': 0.0,
            'factors': []
        }

        # Pattern-based risk
        high_risk_patterns = [FlowPattern.MIXING, FlowPattern.LAYERING]
        pattern_risk = sum(
            1 for p in patterns
            if FlowPattern(p.get('pattern_type', '')) in high_risk_patterns
        )
        if pattern_risk > 0:
            risk['factors'].append({
                'factor': 'high_risk_patterns',
                'score': min(pattern_risk * 0.2, 0.4)
            })

        # Endpoint-based risk
        high_risk_entities = [EntityType.MIXER, EntityType.DARKNET, EntityType.GAMBLING]
        endpoint_risk = sum(
            1 for e in endpoints
            if EntityType(e.get('entity_type', 'unknown')) in high_risk_entities
        )
        if endpoint_risk > 0:
            risk['factors'].append({
                'factor': 'high_risk_endpoints',
                'score': min(endpoint_risk * 0.3, 0.5)
            })

        # Calculate overall score
        risk['overall_score'] = min(
            sum(f['score'] for f in risk['factors']),
            1.0
        )

        return risk

    def _calculate_path_flow(
        self,
        graph: nx.DiGraph,
        path: List[str]
    ) -> float:
        """Calculate total flow along path"""
        total = 0.0
        for i in range(len(path) - 1):
            edge_data = graph.get_edge_data(path[i], path[i + 1])
            if edge_data:
                total += edge_data.get('amount', 0)
        return total

    def _calculate_source_confidence(
        self,
        graph: nx.DiGraph,
        source: str,
        target: str,
        paths: List[List[str]]
    ) -> float:
        """Calculate confidence that this is a true source"""
        confidence = 0.5

        # Primary source (no incoming)
        if graph.in_degree(source) == 0:
            confidence += 0.3

        # Multiple paths
        if len(paths) > 1:
            confidence += 0.1

        # Short paths
        avg_path_length = sum(len(p) for p in paths) / len(paths)
        if avg_path_length <= 3:
            confidence += 0.1

        return min(confidence, 1.0)

    def _calculate_destination_risk(
        self,
        entity_type: EntityType,
        flow_amount: float,
        out_degree: int
    ) -> str:
        """Calculate risk level for destination"""
        high_risk = [EntityType.MIXER, EntityType.DARKNET, EntityType.GAMBLING]
        medium_risk = [EntityType.EXCHANGE, EntityType.UNKNOWN]

        if entity_type in high_risk:
            return 'high'
        elif entity_type in medium_risk and flow_amount > 10:
            return 'medium'
        else:
            return 'low'

    async def _is_layering_pattern(
        self,
        graph: nx.DiGraph,
        path: List[str]
    ) -> bool:
        """Check if path represents layering"""
        # Rapid transactions through multiple hops
        # Small variations in amounts
        # Short time windows

        if len(path) < 3:
            return False

        # Check for consistent flow
        amounts = []
        for i in range(len(path) - 1):
            edge_data = graph.get_edge_data(path[i], path[i + 1])
            if edge_data:
                amounts.append(edge_data.get('amount', 0))

        if not amounts:
            return False

        # Similar amounts indicate layering
        avg_amount = sum(amounts) / len(amounts)
        variations = [abs(a - avg_amount) / avg_amount for a in amounts if avg_amount > 0]

        if variations and statistics.mean(variations) < 0.2:
            return True

        return False

    def get_statistics(self) -> Dict[str, Any]:
        """Get analyzer statistics"""
        return {
            'analyses_performed': self.stats['analyses_performed'],
            'patterns_detected': dict(self.stats['patterns_detected']),
            'endpoints_identified': self.stats['endpoints_identified']
        }


# Example usage
async def main():
    """Example usage of FundFlowAnalyzer"""
    analyzer = FundFlowAnalyzer()

    # Create sample graph
    graph = nx.DiGraph()
    graph.add_edge('A', 'B', amount=10.0, timestamp=datetime.now())
    graph.add_edge('B', 'C', amount=9.5, timestamp=datetime.now())
    graph.add_edge('C', 'D', amount=9.0, timestamp=datetime.now())

    # Analyze flow
    analysis = await analyzer.analyze_flow(graph, 'A')

    print(f"Flow Analysis:")
    print(f"  Total value: {analysis.total_value_flow}")
    print(f"  Hops: {analysis.num_hops}")
    print(f"  Patterns: {len(analysis.patterns_detected)}")
    print(f"  Endpoints: {len(analysis.endpoints)}")


if __name__ == "__main__":
    asyncio.run(main())
