"""
Multi-Chain Transaction Tracing Engine
Comprehensive transaction tracking across multiple blockchains
"""

import asyncio
import logging
from typing import Dict, List, Set, Optional, Tuple, Any
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import networkx as nx
from collections import defaultdict, deque
import json


class BlockchainType(Enum):
    """Supported blockchain types"""
    BITCOIN = "bitcoin"
    ETHEREUM = "ethereum"
    LITECOIN = "litecoin"
    MONERO = "monero"
    RIPPLE = "ripple"
    CARDANO = "cardano"
    POLYGON = "polygon"
    BSC = "bsc"
    AVALANCHE = "avalanche"


class TransactionType(Enum):
    """Transaction types"""
    STANDARD = "standard"
    BRIDGE = "bridge"
    SWAP = "swap"
    MIXER = "mixer"
    EXCHANGE = "exchange"
    CONTRACT = "contract"
    TOKEN_TRANSFER = "token_transfer"


@dataclass
class Transaction:
    """Transaction data structure"""
    tx_hash: str
    blockchain: BlockchainType
    timestamp: datetime
    inputs: List[Dict[str, Any]]
    outputs: List[Dict[str, Any]]
    amount: float
    fee: float
    tx_type: TransactionType = TransactionType.STANDARD
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __hash__(self):
        return hash(self.tx_hash)


@dataclass
class TraceResult:
    """Transaction trace result"""
    source_address: str
    blockchain: BlockchainType
    total_hops: int
    total_amount: float
    transaction_graph: nx.DiGraph
    endpoints: List[Dict[str, Any]]
    intermediate_hops: List[List[Transaction]]
    risk_score: float
    taint_score: float
    metadata: Dict[str, Any] = field(default_factory=dict)


class TransactionTracer:
    """
    Main multi-chain transaction tracing engine

    Features:
    - Multi-hop transaction tracking
    - Cross-chain tracing
    - Fund flow visualization
    - Endpoint identification
    - Taint analysis
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize transaction tracer

        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        self.graph = nx.DiGraph()

        # Tracer components
        self.bitcoin_tracer = None
        self.ethereum_tracer = None
        self.cross_chain_tracer = None
        self.taint_analyzer = None
        self.endpoint_identifier = None

        # Cache for transactions
        self.tx_cache: Dict[str, Transaction] = {}
        self.address_cache: Dict[str, List[Transaction]] = defaultdict(list)

        # Tracing statistics
        self.stats = {
            'total_traces': 0,
            'total_transactions': 0,
            'total_hops': 0,
            'endpoints_found': 0,
            'cross_chain_hops': 0
        }

        # API endpoints for different blockchains
        self.api_endpoints = self._load_api_endpoints()

    def _load_api_endpoints(self) -> Dict[BlockchainType, str]:
        """Load API endpoints for blockchain queries"""
        return {
            BlockchainType.BITCOIN: self.config.get('bitcoin_api', 'https://blockchain.info'),
            BlockchainType.ETHEREUM: self.config.get('ethereum_api', 'https://api.etherscan.io'),
            BlockchainType.LITECOIN: self.config.get('litecoin_api', 'https://litecoin.info'),
            BlockchainType.POLYGON: self.config.get('polygon_api', 'https://api.polygonscan.com'),
            BlockchainType.BSC: self.config.get('bsc_api', 'https://api.bscscan.com'),
        }

    async def trace_funds(
        self,
        address: str,
        blockchain: str,
        max_hops: int = 5,
        min_amount: float = 0.0,
        direction: str = 'both',
        include_taint: bool = True,
        follow_cross_chain: bool = True
    ) -> TraceResult:
        """
        Trace funds from a given address

        Args:
            address: Starting address
            blockchain: Blockchain type
            max_hops: Maximum number of hops to trace
            min_amount: Minimum transaction amount to follow
            direction: 'forward', 'backward', or 'both'
            include_taint: Include taint analysis
            follow_cross_chain: Follow cross-chain transactions

        Returns:
            TraceResult object with complete trace data
        """
        self.logger.info(f"Starting trace for {address} on {blockchain}")
        self.stats['total_traces'] += 1

        blockchain_type = BlockchainType(blockchain.lower())

        # Initialize graph
        trace_graph = nx.DiGraph()
        trace_graph.add_node(address, blockchain=blockchain, is_source=True)

        # Track visited addresses and transactions
        visited_addresses: Set[str] = set()
        visited_transactions: Set[str] = set()

        # BFS queue: (address, blockchain, current_hop, path)
        queue = deque([(address, blockchain_type, 0, [address])])

        # Store all hops
        all_hops: List[List[Transaction]] = [[] for _ in range(max_hops + 1)]
        endpoints: List[Dict[str, Any]] = []

        total_amount = 0.0

        while queue:
            current_addr, current_chain, hop, path = queue.popleft()

            if hop >= max_hops:
                continue

            if current_addr in visited_addresses:
                continue

            visited_addresses.add(current_addr)

            # Get transactions for current address
            transactions = await self._get_transactions(current_addr, current_chain)

            for tx in transactions:
                if tx.tx_hash in visited_transactions:
                    continue

                if tx.amount < min_amount:
                    continue

                visited_transactions.add(tx.tx_hash)
                self.stats['total_transactions'] += 1

                # Add to hops
                all_hops[hop].append(tx)
                total_amount += tx.amount

                # Process based on direction
                next_addresses = []

                if direction in ['forward', 'both']:
                    # Follow outputs
                    for output in tx.outputs:
                        next_addr = output.get('address')
                        if next_addr and next_addr not in visited_addresses:
                            next_addresses.append(next_addr)
                            trace_graph.add_edge(
                                current_addr,
                                next_addr,
                                tx_hash=tx.tx_hash,
                                amount=output.get('value', 0),
                                timestamp=tx.timestamp,
                                blockchain=current_chain.value
                            )

                if direction in ['backward', 'both']:
                    # Follow inputs
                    for input_data in tx.inputs:
                        prev_addr = input_data.get('address')
                        if prev_addr and prev_addr not in visited_addresses:
                            next_addresses.append(prev_addr)
                            trace_graph.add_edge(
                                prev_addr,
                                current_addr,
                                tx_hash=tx.tx_hash,
                                amount=input_data.get('value', 0),
                                timestamp=tx.timestamp,
                                blockchain=current_chain.value
                            )

                # Check for cross-chain transactions
                if follow_cross_chain and tx.tx_type in [TransactionType.BRIDGE, TransactionType.SWAP]:
                    cross_chain_info = await self._detect_cross_chain(tx)
                    if cross_chain_info:
                        self.stats['cross_chain_hops'] += 1
                        next_addr = cross_chain_info['destination_address']
                        next_chain = cross_chain_info['destination_chain']
                        next_addresses.append(next_addr)
                        trace_graph.add_edge(
                            current_addr,
                            next_addr,
                            tx_hash=tx.tx_hash,
                            amount=cross_chain_info['amount'],
                            timestamp=tx.timestamp,
                            blockchain=next_chain.value,
                            cross_chain=True
                        )

                # Add next addresses to queue
                for next_addr in next_addresses:
                    new_path = path + [next_addr]
                    queue.append((next_addr, current_chain, hop + 1, new_path))

                # Check if this is an endpoint
                endpoint_info = await self._identify_endpoint(next_addr if next_addresses else current_addr, current_chain)
                if endpoint_info:
                    endpoints.append({
                        'address': next_addr if next_addresses else current_addr,
                        'type': endpoint_info['type'],
                        'blockchain': current_chain.value,
                        'amount': tx.amount,
                        'hop': hop,
                        'path': path,
                        'metadata': endpoint_info
                    })
                    self.stats['endpoints_found'] += 1

        # Calculate risk and taint scores
        risk_score = self._calculate_risk_score(trace_graph, endpoints)
        taint_score = 0.0

        if include_taint and self.taint_analyzer:
            taint_score = await self.taint_analyzer.analyze(address, trace_graph)

        # Update statistics
        self.stats['total_hops'] += max([i for i, hop in enumerate(all_hops) if hop])

        return TraceResult(
            source_address=address,
            blockchain=blockchain_type,
            total_hops=len([hop for hop in all_hops if hop]),
            total_amount=total_amount,
            transaction_graph=trace_graph,
            endpoints=endpoints,
            intermediate_hops=[hop for hop in all_hops if hop],
            risk_score=risk_score,
            taint_score=taint_score,
            metadata={
                'visited_addresses': len(visited_addresses),
                'visited_transactions': len(visited_transactions),
                'direction': direction,
                'max_hops': max_hops
            }
        )

    async def trace_transaction(
        self,
        tx_hash: str,
        blockchain: str,
        trace_inputs: bool = True,
        trace_outputs: bool = True,
        max_depth: int = 3
    ) -> Dict[str, Any]:
        """
        Trace a specific transaction

        Args:
            tx_hash: Transaction hash
            blockchain: Blockchain type
            trace_inputs: Trace input sources
            trace_outputs: Trace output destinations
            max_depth: Maximum depth for recursive tracing

        Returns:
            Complete transaction trace
        """
        blockchain_type = BlockchainType(blockchain.lower())

        # Get transaction details
        tx = await self._get_transaction(tx_hash, blockchain_type)
        if not tx:
            return {'error': 'Transaction not found'}

        trace_data = {
            'transaction': tx,
            'input_traces': [],
            'output_traces': []
        }

        # Trace inputs
        if trace_inputs and max_depth > 0:
            for input_data in tx.inputs:
                prev_tx_hash = input_data.get('prev_tx_hash')
                if prev_tx_hash:
                    input_trace = await self.trace_transaction(
                        prev_tx_hash,
                        blockchain,
                        trace_inputs=True,
                        trace_outputs=False,
                        max_depth=max_depth - 1
                    )
                    trace_data['input_traces'].append(input_trace)

        # Trace outputs
        if trace_outputs and max_depth > 0:
            # Get transactions spending this transaction's outputs
            for i, output in enumerate(tx.outputs):
                spending_txs = await self._get_spending_transactions(tx_hash, i, blockchain_type)
                for spending_tx_hash in spending_txs:
                    output_trace = await self.trace_transaction(
                        spending_tx_hash,
                        blockchain,
                        trace_inputs=False,
                        trace_outputs=True,
                        max_depth=max_depth - 1
                    )
                    trace_data['output_traces'].append(output_trace)

        return trace_data

    async def find_path(
        self,
        source: str,
        destination: str,
        blockchain: str,
        max_hops: int = 10
    ) -> List[List[Transaction]]:
        """
        Find all paths between two addresses

        Args:
            source: Source address
            destination: Destination address
            blockchain: Blockchain type
            max_hops: Maximum path length

        Returns:
            List of transaction paths
        """
        blockchain_type = BlockchainType(blockchain.lower())

        # Build graph with BFS
        graph = nx.DiGraph()
        visited = set()
        queue = deque([(source, 0)])

        while queue:
            addr, depth = queue.popleft()

            if depth >= max_hops:
                continue

            if addr in visited:
                continue

            visited.add(addr)

            # Get transactions
            transactions = await self._get_transactions(addr, blockchain_type)

            for tx in transactions:
                for output in tx.outputs:
                    next_addr = output.get('address')
                    if next_addr:
                        graph.add_edge(addr, next_addr, transaction=tx)
                        if next_addr not in visited:
                            queue.append((next_addr, depth + 1))

        # Find all paths
        try:
            all_paths = list(nx.all_simple_paths(graph, source, destination, cutoff=max_hops))
        except nx.NetworkXNoPath:
            return []

        # Convert paths to transaction sequences
        transaction_paths = []
        for path in all_paths:
            tx_sequence = []
            for i in range(len(path) - 1):
                edge_data = graph.get_edge_data(path[i], path[i + 1])
                if edge_data:
                    tx_sequence.append(edge_data['transaction'])
            transaction_paths.append(tx_sequence)

        return transaction_paths

    async def _get_transactions(
        self,
        address: str,
        blockchain: BlockchainType
    ) -> List[Transaction]:
        """Get all transactions for an address"""
        # Check cache first
        cache_key = f"{blockchain.value}:{address}"
        if cache_key in self.address_cache:
            return self.address_cache[cache_key]

        # Simulate API call (in production, use actual blockchain APIs)
        transactions = []

        # This would be replaced with actual API calls
        if blockchain == BlockchainType.BITCOIN:
            if self.bitcoin_tracer:
                transactions = await self.bitcoin_tracer.get_address_transactions(address)
        elif blockchain == BlockchainType.ETHEREUM:
            if self.ethereum_tracer:
                transactions = await self.ethereum_tracer.get_address_transactions(address)

        # Cache results
        self.address_cache[cache_key] = transactions

        return transactions

    async def _get_transaction(
        self,
        tx_hash: str,
        blockchain: BlockchainType
    ) -> Optional[Transaction]:
        """Get transaction by hash"""
        # Check cache
        if tx_hash in self.tx_cache:
            return self.tx_cache[tx_hash]

        # Simulate API call
        transaction = None

        if blockchain == BlockchainType.BITCOIN:
            if self.bitcoin_tracer:
                transaction = await self.bitcoin_tracer.get_transaction(tx_hash)
        elif blockchain == BlockchainType.ETHEREUM:
            if self.ethereum_tracer:
                transaction = await self.ethereum_tracer.get_transaction(tx_hash)

        if transaction:
            self.tx_cache[tx_hash] = transaction

        return transaction

    async def _get_spending_transactions(
        self,
        tx_hash: str,
        output_index: int,
        blockchain: BlockchainType
    ) -> List[str]:
        """Get transactions that spend a specific output"""
        # This would query the blockchain for spending transactions
        return []

    async def _detect_cross_chain(
        self,
        transaction: Transaction
    ) -> Optional[Dict[str, Any]]:
        """Detect if transaction is cross-chain"""
        if self.cross_chain_tracer:
            return await self.cross_chain_tracer.detect_bridge_transaction(transaction)
        return None

    async def _identify_endpoint(
        self,
        address: str,
        blockchain: BlockchainType
    ) -> Optional[Dict[str, Any]]:
        """Identify if address is an endpoint"""
        if self.endpoint_identifier:
            return await self.endpoint_identifier.identify(address, blockchain)
        return None

    def _calculate_risk_score(
        self,
        graph: nx.DiGraph,
        endpoints: List[Dict[str, Any]]
    ) -> float:
        """
        Calculate risk score based on transaction patterns

        Factors:
        - Number of hops (more hops = higher risk)
        - Mixer usage
        - Cross-chain transfers
        - Endpoint types
        """
        risk_score = 0.0

        # Graph complexity
        num_nodes = graph.number_of_nodes()
        num_edges = graph.number_of_edges()

        if num_nodes > 0:
            # More complex graphs indicate obfuscation
            complexity_score = min(num_edges / num_nodes, 5.0) / 5.0
            risk_score += complexity_score * 0.3

        # Cross-chain hops (indicates sophistication)
        cross_chain_edges = sum(1 for _, _, data in graph.edges(data=True) if data.get('cross_chain', False))
        if num_edges > 0:
            cross_chain_ratio = cross_chain_edges / num_edges
            risk_score += cross_chain_ratio * 0.3

        # Endpoint analysis
        high_risk_endpoints = ['mixer', 'darknet', 'sanctioned']
        for endpoint in endpoints:
            if endpoint.get('type') in high_risk_endpoints:
                risk_score += 0.2

        return min(risk_score, 1.0)

    def get_statistics(self) -> Dict[str, Any]:
        """Get tracing statistics"""
        return self.stats.copy()

    def export_graph(
        self,
        trace_result: TraceResult,
        format: str = 'gexf'
    ) -> str:
        """
        Export transaction graph

        Args:
            trace_result: Trace result to export
            format: Export format (gexf, graphml, json)

        Returns:
            Serialized graph data
        """
        if format == 'gexf':
            from io import BytesIO
            buffer = BytesIO()
            nx.write_gexf(trace_result.transaction_graph, buffer)
            return buffer.getvalue().decode('utf-8')
        elif format == 'graphml':
            from io import BytesIO
            buffer = BytesIO()
            nx.write_graphml(trace_result.transaction_graph, buffer)
            return buffer.getvalue().decode('utf-8')
        elif format == 'json':
            from networkx.readwrite import json_graph
            data = json_graph.node_link_data(trace_result.transaction_graph)
            return json.dumps(data, indent=2)
        else:
            raise ValueError(f"Unsupported format: {format}")


# Example usage
async def main():
    """Example usage of TransactionTracer"""
    # Initialize tracer
    config = {
        'bitcoin_api': 'https://blockchain.info',
        'ethereum_api': 'https://api.etherscan.io'
    }

    tracer = TransactionTracer(config)

    # Trace funds from an address
    result = await tracer.trace_funds(
        address="1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
        blockchain="bitcoin",
        max_hops=5,
        min_amount=0.1,
        direction='both',
        follow_cross_chain=True
    )

    print(f"Trace completed:")
    print(f"  Total hops: {result.total_hops}")
    print(f"  Total amount: {result.total_amount}")
    print(f"  Endpoints found: {len(result.endpoints)}")
    print(f"  Risk score: {result.risk_score:.2f}")
    print(f"  Taint score: {result.taint_score:.2f}")

    # Find path between addresses
    paths = await tracer.find_path(
        source="1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
        destination="1dice8EMZmqKvrGE4Qc9bUFf9PX3xaYDp",
        blockchain="bitcoin",
        max_hops=10
    )

    print(f"\nFound {len(paths)} paths")

    # Export graph
    graph_data = tracer.export_graph(result, format='json')
    print(f"\nGraph exported: {len(graph_data)} bytes")


if __name__ == "__main__":
    asyncio.run(main())
