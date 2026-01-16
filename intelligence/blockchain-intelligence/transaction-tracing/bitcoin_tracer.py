"""
Bitcoin-Specific Transaction Tracer
UTXO-based transaction graph traversal and analysis
"""

import asyncio
import logging
from typing import Dict, List, Set, Optional, Tuple, Any
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict, deque
import networkx as nx


@dataclass
class UTXO:
    """Unspent Transaction Output"""
    tx_hash: str
    output_index: int
    address: str
    value: float  # in BTC
    script_type: str
    confirmations: int
    spent: bool = False
    spending_tx: Optional[str] = None

    def __hash__(self):
        return hash(f"{self.tx_hash}:{self.output_index}")


@dataclass
class BitcoinTransaction:
    """Bitcoin transaction structure"""
    tx_hash: str
    version: int
    locktime: int
    size: int
    vsize: int
    weight: int
    fee: float
    timestamp: datetime
    block_height: int
    confirmations: int
    inputs: List[Dict[str, Any]]
    outputs: List[Dict[str, Any]]
    is_coinbase: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class UTXOGraph:
    """UTXO transaction graph"""
    graph: nx.DiGraph
    utxos: Dict[str, UTXO]
    transactions: Dict[str, BitcoinTransaction]
    addresses: Set[str]


class BitcoinTracer:
    """
    Bitcoin-specific transaction tracer

    Features:
    - UTXO graph traversal
    - Input/output analysis
    - Multi-hop tracking (up to 10 hops)
    - Taint analysis
    - Change detection
    - Clustering analysis
    """

    def __init__(self, api_key: Optional[str] = None, network: str = 'mainnet'):
        """
        Initialize Bitcoin tracer

        Args:
            api_key: API key for blockchain data provider
            network: Bitcoin network (mainnet, testnet)
        """
        self.api_key = api_key
        self.network = network
        self.logger = logging.getLogger(__name__)

        # Caches
        self.tx_cache: Dict[str, BitcoinTransaction] = {}
        self.utxo_cache: Dict[str, UTXO] = {}
        self.address_cache: Dict[str, List[str]] = defaultdict(list)

        # Graph for current trace
        self.graph: Optional[nx.DiGraph] = None

        # Statistics
        self.stats = {
            'transactions_analyzed': 0,
            'utxos_tracked': 0,
            'hops_traversed': 0,
            'addresses_discovered': 0
        }

    async def get_transaction(self, tx_hash: str) -> Optional[BitcoinTransaction]:
        """
        Get transaction by hash

        Args:
            tx_hash: Transaction hash

        Returns:
            BitcoinTransaction object
        """
        # Check cache
        if tx_hash in self.tx_cache:
            return self.tx_cache[tx_hash]

        # Simulate API call to blockchain.info or similar
        # In production, replace with actual API calls
        tx = await self._fetch_transaction_from_api(tx_hash)

        if tx:
            self.tx_cache[tx_hash] = tx
            self.stats['transactions_analyzed'] += 1

        return tx

    async def get_address_transactions(
        self,
        address: str,
        limit: int = 100
    ) -> List[BitcoinTransaction]:
        """
        Get all transactions for an address

        Args:
            address: Bitcoin address
            limit: Maximum number of transactions

        Returns:
            List of transactions
        """
        # Check cache
        if address in self.address_cache:
            tx_hashes = self.address_cache[address][:limit]
            transactions = []
            for tx_hash in tx_hashes:
                tx = await self.get_transaction(tx_hash)
                if tx:
                    transactions.append(tx)
            return transactions

        # Fetch from API
        transactions = await self._fetch_address_transactions_from_api(address, limit)

        # Update cache
        self.address_cache[address] = [tx.tx_hash for tx in transactions]
        self.stats['addresses_discovered'] += 1

        return transactions

    async def trace_utxo_chain(
        self,
        tx_hash: str,
        output_index: int,
        max_hops: int = 10,
        min_amount: float = 0.0
    ) -> UTXOGraph:
        """
        Trace UTXO chain forward

        Args:
            tx_hash: Starting transaction hash
            output_index: Output index to trace
            max_hops: Maximum number of hops
            min_amount: Minimum amount to trace (in BTC)

        Returns:
            UTXOGraph with complete trace
        """
        self.logger.info(f"Tracing UTXO chain from {tx_hash}:{output_index}")

        # Initialize graph
        graph = nx.DiGraph()
        utxos: Dict[str, UTXO] = {}
        transactions: Dict[str, BitcoinTransaction] = {}
        addresses: Set[str] = set()

        # BFS queue: (tx_hash, output_index, hop)
        queue = deque([(tx_hash, output_index, 0)])
        visited: Set[Tuple[str, int]] = set()

        while queue:
            current_tx_hash, current_output_idx, hop = queue.popleft()

            if hop >= max_hops:
                continue

            utxo_key = (current_tx_hash, current_output_idx)
            if utxo_key in visited:
                continue

            visited.add(utxo_key)
            self.stats['hops_traversed'] += 1

            # Get transaction
            tx = await self.get_transaction(current_tx_hash)
            if not tx or current_output_idx >= len(tx.outputs):
                continue

            transactions[current_tx_hash] = tx

            # Get output details
            output = tx.outputs[current_output_idx]
            output_address = output.get('address', '')
            output_value = output.get('value', 0.0)

            if output_value < min_amount:
                continue

            # Create UTXO
            utxo = UTXO(
                tx_hash=current_tx_hash,
                output_index=current_output_idx,
                address=output_address,
                value=output_value,
                script_type=output.get('script_type', 'unknown'),
                confirmations=tx.confirmations,
                spent=False
            )

            utxos[f"{current_tx_hash}:{current_output_idx}"] = utxo
            addresses.add(output_address)
            self.stats['utxos_tracked'] += 1

            # Add to graph
            graph.add_node(
                f"{current_tx_hash}:{current_output_idx}",
                type='utxo',
                address=output_address,
                value=output_value,
                tx_hash=current_tx_hash
            )

            # Find spending transaction
            spending_tx_hash = await self._find_spending_transaction(
                current_tx_hash,
                current_output_idx
            )

            if spending_tx_hash:
                utxo.spent = True
                utxo.spending_tx = spending_tx_hash

                # Get spending transaction
                spending_tx = await self.get_transaction(spending_tx_hash)
                if spending_tx:
                    transactions[spending_tx_hash] = spending_tx

                    # Find which outputs to follow
                    for i, next_output in enumerate(spending_tx.outputs):
                        next_value = next_output.get('value', 0.0)
                        if next_value >= min_amount:
                            # Add edge
                            graph.add_edge(
                                f"{current_tx_hash}:{current_output_idx}",
                                f"{spending_tx_hash}:{i}",
                                tx_hash=spending_tx_hash,
                                value=next_value,
                                hop=hop
                            )

                            # Add to queue
                            queue.append((spending_tx_hash, i, hop + 1))

        return UTXOGraph(
            graph=graph,
            utxos=utxos,
            transactions=transactions,
            addresses=addresses
        )

    async def trace_backward(
        self,
        tx_hash: str,
        max_depth: int = 5
    ) -> Dict[str, Any]:
        """
        Trace transaction inputs backward

        Args:
            tx_hash: Transaction hash to trace
            max_depth: Maximum depth to trace

        Returns:
            Tree of input transactions
        """
        tx = await self.get_transaction(tx_hash)
        if not tx:
            return {'error': 'Transaction not found'}

        if tx.is_coinbase:
            return {'type': 'coinbase', 'transaction': tx}

        trace_tree = {
            'transaction': tx,
            'inputs': []
        }

        if max_depth > 0:
            for input_data in tx.inputs:
                prev_tx_hash = input_data.get('prev_tx_hash')
                if prev_tx_hash:
                    input_trace = await self.trace_backward(prev_tx_hash, max_depth - 1)
                    trace_tree['inputs'].append(input_trace)

        return trace_tree

    async def analyze_transaction_pattern(
        self,
        tx_hash: str
    ) -> Dict[str, Any]:
        """
        Analyze transaction pattern

        Detects:
        - Change outputs
        - Mixing patterns
        - CoinJoin
        - Peeling chains
        - Payment batching
        """
        tx = await self.get_transaction(tx_hash)
        if not tx:
            return {'error': 'Transaction not found'}

        analysis = {
            'tx_hash': tx_hash,
            'num_inputs': len(tx.inputs),
            'num_outputs': len(tx.outputs),
            'patterns': []
        }

        # Detect CoinJoin
        if len(tx.inputs) > 10 and len(tx.outputs) > 10:
            # Check for equal outputs (classic CoinJoin pattern)
            output_values = [out.get('value', 0) for out in tx.outputs]
            value_counts = {}
            for val in output_values:
                value_counts[val] = value_counts.get(val, 0) + 1

            max_equal_outputs = max(value_counts.values())
            if max_equal_outputs >= len(tx.outputs) * 0.5:
                analysis['patterns'].append({
                    'type': 'coinjoin',
                    'confidence': 0.8,
                    'equal_outputs': max_equal_outputs
                })

        # Detect change output
        if len(tx.outputs) == 2:
            # Likely one payment, one change
            values = sorted([out.get('value', 0) for out in tx.outputs])
            if values[1] > values[0] * 2:  # One output significantly larger
                analysis['patterns'].append({
                    'type': 'change_output',
                    'confidence': 0.7,
                    'likely_change_index': 1 if tx.outputs[1].get('value') > tx.outputs[0].get('value') else 0
                })

        # Detect payment batching
        if len(tx.inputs) < 5 and len(tx.outputs) > 20:
            analysis['patterns'].append({
                'type': 'payment_batching',
                'confidence': 0.9,
                'num_recipients': len(tx.outputs)
            })

        # Detect peeling chain (one input, two outputs, repeated)
        if len(tx.inputs) == 1 and len(tx.outputs) == 2:
            values = [out.get('value', 0) for out in tx.outputs]
            if abs(values[0] - values[1]) > min(values) * 10:
                analysis['patterns'].append({
                    'type': 'peeling_chain',
                    'confidence': 0.6
                })

        return analysis

    async def cluster_addresses(
        self,
        seed_address: str,
        max_transactions: int = 1000
    ) -> Set[str]:
        """
        Cluster addresses likely controlled by same entity

        Uses heuristics:
        - Multi-input transactions (inputs likely same owner)
        - Change address detection
        - Temporal patterns

        Args:
            seed_address: Starting address
            max_transactions: Maximum transactions to analyze

        Returns:
            Set of clustered addresses
        """
        cluster: Set[str] = {seed_address}
        queue = deque([seed_address])
        visited_tx: Set[str] = set()
        tx_count = 0

        while queue and tx_count < max_transactions:
            address = queue.popleft()

            # Get transactions for address
            transactions = await self.get_address_transactions(address, limit=50)

            for tx in transactions:
                if tx.tx_hash in visited_tx:
                    continue

                visited_tx.add(tx.tx_hash)
                tx_count += 1

                # Multi-input heuristic
                if len(tx.inputs) > 1:
                    for input_data in tx.inputs:
                        input_address = input_data.get('address')
                        if input_address and input_address not in cluster:
                            cluster.add(input_address)
                            queue.append(input_address)

                # Change detection heuristic
                if len(tx.outputs) == 2:
                    # Check if address is in inputs
                    input_addresses = {inp.get('address') for inp in tx.inputs}
                    if address in input_addresses:
                        # One output is likely change
                        for output in tx.outputs:
                            output_addr = output.get('address')
                            if output_addr and output_addr not in input_addresses:
                                # This might be the payment
                                pass
                            elif output_addr and output_addr not in cluster:
                                # This might be change (back to sender)
                                cluster.add(output_addr)
                                queue.append(output_addr)

        return cluster

    async def calculate_taint(
        self,
        source_tx: str,
        source_output: int,
        target_tx: str,
        target_input: int,
        method: str = 'poison'
    ) -> float:
        """
        Calculate taint between two UTXOs

        Args:
            source_tx: Source transaction hash
            source_output: Source output index
            target_tx: Target transaction hash
            target_input: Target input index
            method: Taint calculation method ('poison' or 'haircut')

        Returns:
            Taint score (0.0 to 1.0)
        """
        # Build path between source and target
        path = await self._find_utxo_path(
            (source_tx, source_output),
            (target_tx, target_input)
        )

        if not path:
            return 0.0

        if method == 'poison':
            # Poison taint: if any tainted input, all outputs are fully tainted
            return 1.0 if path else 0.0

        elif method == 'haircut':
            # Haircut taint: proportional to value
            taint = 1.0

            for i in range(len(path) - 1):
                current_tx_hash, current_output = path[i]
                next_tx_hash, next_input = path[i + 1]

                # Get transactions
                current_tx = await self.get_transaction(current_tx_hash)
                next_tx = await self.get_transaction(next_tx_hash)

                if current_tx and next_tx:
                    # Calculate proportion
                    output_value = current_tx.outputs[current_output].get('value', 0)
                    total_input = sum(inp.get('value', 0) for inp in next_tx.inputs)

                    if total_input > 0:
                        taint *= (output_value / total_input)

            return taint

        return 0.0

    async def _fetch_transaction_from_api(self, tx_hash: str) -> Optional[BitcoinTransaction]:
        """Fetch transaction from blockchain API"""
        # Simulate API call
        # In production, implement actual API calls to blockchain.info, blockcypher, etc.
        await asyncio.sleep(0.01)  # Simulate network delay

        # Return mock data for demonstration
        return None

    async def _fetch_address_transactions_from_api(
        self,
        address: str,
        limit: int
    ) -> List[BitcoinTransaction]:
        """Fetch address transactions from API"""
        await asyncio.sleep(0.01)
        return []

    async def _find_spending_transaction(
        self,
        tx_hash: str,
        output_index: int
    ) -> Optional[str]:
        """Find transaction that spends a specific output"""
        # Query blockchain for spending transaction
        await asyncio.sleep(0.01)
        return None

    async def _find_utxo_path(
        self,
        source: Tuple[str, int],
        target: Tuple[str, int]
    ) -> Optional[List[Tuple[str, int]]]:
        """Find path between two UTXOs"""
        # BFS to find path
        queue = deque([(source, [source])])
        visited = {source}

        while queue:
            current, path = queue.popleft()

            if current == target:
                return path

            # Find spending transaction
            spending_tx = await self._find_spending_transaction(current[0], current[1])
            if spending_tx:
                tx = await self.get_transaction(spending_tx)
                if tx:
                    for i in range(len(tx.outputs)):
                        next_utxo = (spending_tx, i)
                        if next_utxo not in visited:
                            visited.add(next_utxo)
                            queue.append((next_utxo, path + [next_utxo]))

        return None

    def get_statistics(self) -> Dict[str, Any]:
        """Get tracer statistics"""
        return self.stats.copy()


# Example usage
async def main():
    """Example usage of BitcoinTracer"""
    tracer = BitcoinTracer(network='mainnet')

    # Trace UTXO chain
    utxo_graph = await tracer.trace_utxo_chain(
        tx_hash="a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d",
        output_index=0,
        max_hops=5,
        min_amount=0.01
    )

    print(f"UTXO Graph:")
    print(f"  Nodes: {utxo_graph.graph.number_of_nodes()}")
    print(f"  Edges: {utxo_graph.graph.number_of_edges()}")
    print(f"  Addresses: {len(utxo_graph.addresses)}")

    # Cluster addresses
    cluster = await tracer.cluster_addresses("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
    print(f"\nClustered {len(cluster)} addresses")


if __name__ == "__main__":
    asyncio.run(main())
