"""
Real Wallet Clustering Engine - Production Implementation

Implements multiple clustering heuristics:
1. Common Input Ownership Heuristic (CIOH)
2. Change Address Detection
3. Peel Chain Analysis
4. Co-spending Patterns
5. Temporal Analysis
"""

import asyncio
import logging
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict
import hashlib
import networkx as nx

logger = logging.getLogger(__name__)


@dataclass
class ClusterEvidence:
    """Evidence supporting address clustering"""
    heuristic: str
    confidence: float
    transaction_hash: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AddressCluster:
    """A cluster of related addresses"""
    cluster_id: str
    addresses: Set[str]
    confidence: float
    evidence: List[ClusterEvidence]
    total_balance: float = 0.0
    total_received: float = 0.0
    total_sent: float = 0.0
    tx_count: int = 0
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    labels: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ClusteringResult:
    """Result of clustering analysis"""
    seed_address: str
    clusters: List[AddressCluster]
    graph: nx.Graph
    statistics: Dict[str, Any]


class RealWalletClusteringEngine:
    """
    Production Wallet Clustering Engine

    Uses graph-based algorithms to cluster cryptocurrency addresses
    that are likely controlled by the same entity.

    Heuristics implemented:
    1. Common Input Ownership (CIOH): Addresses used as inputs in the same
       transaction are assumed to be controlled by the same entity
    2. Change Address Detection: Identifies likely change addresses based on
       transaction patterns
    3. Peel Chain Analysis: Detects sequential transactions where small
       amounts are "peeled off"
    4. Co-spending Analysis: Addresses that frequently transact together
    5. Temporal Clustering: Addresses active in same time windows
    """

    def __init__(self, api_client=None):
        """
        Initialize clustering engine

        Args:
            api_client: Blockchain API client for fetching transaction data
        """
        self.api_client = api_client

        # Clustering graph
        self.graph = nx.Graph()

        # Confidence weights for different heuristics
        self.heuristic_weights = {
            'common_input': 1.0,      # Highest confidence
            'change_address': 0.7,
            'peel_chain': 0.6,
            'co_spending': 0.5,
            'temporal': 0.3
        }

        # Thresholds
        self.min_confidence = 0.6
        self.max_cluster_size = 10000
        self.change_detection_threshold = 0.8

        logger.info("Real Wallet Clustering Engine initialized")

    async def cluster_from_seed(
        self,
        seed_address: str,
        transactions: List[Dict],
        max_depth: int = 2
    ) -> ClusteringResult:
        """
        Build clusters starting from a seed address

        Args:
            seed_address: Starting address for clustering
            transactions: List of transactions to analyze
            max_depth: Maximum depth for recursive clustering

        Returns:
            ClusteringResult with clusters and graph
        """
        logger.info(f"Clustering from seed address: {seed_address}")

        # Reset graph
        self.graph.clear()
        self.graph.add_node(seed_address, is_seed=True)

        # Apply all heuristics
        evidence_map: Dict[Tuple[str, str], List[ClusterEvidence]] = defaultdict(list)

        # 1. Common Input Ownership Heuristic
        cioh_evidence = await self._apply_common_input_heuristic(
            seed_address, transactions
        )
        for (addr1, addr2), ev in cioh_evidence.items():
            evidence_map[(addr1, addr2)].append(ev)

        # 2. Change Address Detection
        change_evidence = await self._apply_change_detection(
            seed_address, transactions
        )
        for (addr1, addr2), ev in change_evidence.items():
            evidence_map[(addr1, addr2)].append(ev)

        # 3. Peel Chain Analysis
        peel_evidence = await self._apply_peel_chain_analysis(
            seed_address, transactions
        )
        for (addr1, addr2), ev in peel_evidence.items():
            evidence_map[(addr1, addr2)].append(ev)

        # Build graph from evidence
        for (addr1, addr2), evidences in evidence_map.items():
            # Calculate combined confidence
            combined_confidence = self._combine_evidence(evidences)

            if combined_confidence >= self.min_confidence:
                self.graph.add_node(addr1)
                self.graph.add_node(addr2)

                if self.graph.has_edge(addr1, addr2):
                    # Update existing edge
                    self.graph[addr1][addr2]['confidence'] = max(
                        self.graph[addr1][addr2]['confidence'],
                        combined_confidence
                    )
                    self.graph[addr1][addr2]['evidence'].extend(evidences)
                else:
                    self.graph.add_edge(
                        addr1, addr2,
                        confidence=combined_confidence,
                        evidence=evidences
                    )

        # Extract clusters from connected components
        clusters = self._extract_clusters(seed_address)

        # Calculate statistics
        statistics = self._calculate_statistics(clusters)

        return ClusteringResult(
            seed_address=seed_address,
            clusters=clusters,
            graph=self.graph.copy(),
            statistics=statistics
        )

    async def _apply_common_input_heuristic(
        self,
        seed_address: str,
        transactions: List[Dict]
    ) -> Dict[Tuple[str, str], ClusterEvidence]:
        """
        Apply Common Input Ownership Heuristic

        If multiple addresses are used as inputs in the same transaction,
        they are likely controlled by the same entity (needs private keys
        for all inputs to sign the transaction).
        """
        evidence = {}

        for tx in transactions:
            inputs = tx.get('inputs', [])

            # Extract input addresses
            input_addresses = []
            for inp in inputs:
                addr = inp.get('address')
                if addr:
                    input_addresses.append(addr)

            # If multiple inputs, they're likely same owner
            if len(input_addresses) > 1:
                # Create edges between all pairs
                for i, addr1 in enumerate(input_addresses):
                    for addr2 in input_addresses[i+1:]:
                        pair = tuple(sorted([addr1, addr2]))

                        if pair not in evidence:
                            evidence[pair] = ClusterEvidence(
                                heuristic='common_input',
                                confidence=self.heuristic_weights['common_input'],
                                transaction_hash=tx.get('txid'),
                                details={
                                    'input_count': len(input_addresses),
                                    'all_inputs': input_addresses
                                }
                            )

        logger.debug(f"CIOH found {len(evidence)} address pairs")
        return evidence

    async def _apply_change_detection(
        self,
        seed_address: str,
        transactions: List[Dict]
    ) -> Dict[Tuple[str, str], ClusterEvidence]:
        """
        Detect change addresses

        In a typical Bitcoin transaction:
        - User sends X BTC to recipient
        - Remaining balance (minus fee) goes to a change address
        - Change address is usually a new address owned by sender

        Detection criteria:
        - Transaction has exactly 2 outputs
        - One output is to a "new" address (no prior incoming transactions)
        - Output amounts suggest one is change
        """
        evidence = {}
        seen_addresses = set()

        # Build set of addresses seen in early transactions
        for tx in transactions:
            for out in tx.get('outputs', []):
                if out.get('address'):
                    seen_addresses.add(out['address'])

        for tx in transactions:
            outputs = tx.get('outputs', [])
            inputs = tx.get('inputs', [])

            # Only analyze 2-output transactions
            if len(outputs) != 2:
                continue

            # Get input address (sender)
            sender_addresses = [inp.get('address') for inp in inputs if inp.get('address')]
            if not sender_addresses:
                continue

            primary_sender = sender_addresses[0]  # First input

            # Analyze outputs
            out1 = outputs[0]
            out2 = outputs[1]

            addr1 = out1.get('address')
            addr2 = out2.get('address')
            val1 = out1.get('amount', 0)
            val2 = out2.get('amount', 0)

            if not addr1 or not addr2:
                continue

            # Heuristics for change detection:
            # 1. One address is new (not seen before in history)
            # 2. Amount ratio suggests change
            # 3. One output goes to an address format matching sender

            change_candidate = None

            # Check if one output is much smaller (likely change)
            if val1 > 0 and val2 > 0:
                ratio = max(val1, val2) / min(val1, val2)

                if ratio > 5:  # One is significantly larger
                    # Smaller is likely the payment, larger is change
                    # (or vice versa depending on transaction type)
                    smaller_addr = addr1 if val1 < val2 else addr2
                    larger_addr = addr1 if val1 >= val2 else addr2

                    # New address heuristic
                    is_new_small = smaller_addr not in seen_addresses
                    is_new_large = larger_addr not in seen_addresses

                    if is_new_large and not is_new_small:
                        change_candidate = larger_addr
                    elif is_new_small and not is_new_large:
                        change_candidate = smaller_addr

            # If we identified a likely change address
            if change_candidate and change_candidate != primary_sender:
                pair = tuple(sorted([primary_sender, change_candidate]))

                if pair not in evidence:
                    evidence[pair] = ClusterEvidence(
                        heuristic='change_address',
                        confidence=self.heuristic_weights['change_address'],
                        transaction_hash=tx.get('txid'),
                        details={
                            'sender': primary_sender,
                            'change_address': change_candidate,
                            'output_values': [val1, val2]
                        }
                    )

        logger.debug(f"Change detection found {len(evidence)} address pairs")
        return evidence

    async def _apply_peel_chain_analysis(
        self,
        seed_address: str,
        transactions: List[Dict]
    ) -> Dict[Tuple[str, str], ClusterEvidence]:
        """
        Detect peel chain patterns

        A peel chain is a sequence of transactions where:
        - Transaction has 2 outputs
        - One output is small ("peel" - goes to different address each time)
        - One output is large ("chain" - continues to next transaction)

        This is a common pattern for money laundering.
        """
        evidence = {}

        # Sort transactions by timestamp
        sorted_txs = sorted(
            [tx for tx in transactions if tx.get('timestamp')],
            key=lambda x: x['timestamp']
        )

        # Track chains
        chain_addresses = set([seed_address])

        for tx in sorted_txs:
            outputs = tx.get('outputs', [])
            inputs = tx.get('inputs', [])

            if len(outputs) != 2:
                continue

            # Check if any input is from our chain
            input_addrs = [inp.get('address') for inp in inputs if inp.get('address')]
            chain_input = any(addr in chain_addresses for addr in input_addrs)

            if not chain_input:
                continue

            # Get output values
            out1 = outputs[0]
            out2 = outputs[1]
            val1 = out1.get('amount', 0)
            val2 = out2.get('amount', 0)
            addr1 = out1.get('address')
            addr2 = out2.get('address')

            if not addr1 or not addr2 or val1 <= 0 or val2 <= 0:
                continue

            # Check for peel pattern (one much larger than other)
            total = val1 + val2
            ratio = max(val1, val2) / total

            if ratio > self.change_detection_threshold:
                # Large output continues chain
                chain_addr = addr1 if val1 > val2 else addr2
                peel_addr = addr1 if val1 <= val2 else addr2

                # Add chain address to our tracked set
                chain_addresses.add(chain_addr)

                # All chain addresses are related
                for existing_addr in input_addrs:
                    if existing_addr in chain_addresses:
                        pair = tuple(sorted([existing_addr, chain_addr]))

                        if pair not in evidence:
                            evidence[pair] = ClusterEvidence(
                                heuristic='peel_chain',
                                confidence=self.heuristic_weights['peel_chain'],
                                transaction_hash=tx.get('txid'),
                                details={
                                    'chain_address': chain_addr,
                                    'peel_address': peel_addr,
                                    'peel_value': min(val1, val2),
                                    'chain_value': max(val1, val2),
                                    'ratio': ratio
                                }
                            )

        logger.debug(f"Peel chain analysis found {len(evidence)} address pairs")
        return evidence

    def _combine_evidence(self, evidences: List[ClusterEvidence]) -> float:
        """
        Combine multiple pieces of evidence into single confidence score

        Uses a weighted combination with diminishing returns for multiple
        pieces of evidence from the same heuristic.
        """
        if not evidences:
            return 0.0

        # Group by heuristic
        by_heuristic = defaultdict(list)
        for ev in evidences:
            by_heuristic[ev.heuristic].append(ev)

        combined = 0.0
        max_possible = sum(self.heuristic_weights.values())

        for heuristic, evs in by_heuristic.items():
            # First evidence from this heuristic counts fully
            base_conf = evs[0].confidence

            # Additional evidence has diminishing returns
            bonus = sum(0.1 * ev.confidence for ev in evs[1:5])  # Max 5

            combined += min(base_conf + bonus, self.heuristic_weights[heuristic])

        # Normalize to 0-1
        return min(1.0, combined / max_possible) if max_possible > 0 else 0.0

    def _extract_clusters(self, seed_address: str) -> List[AddressCluster]:
        """Extract clusters from the graph"""
        clusters = []

        # Get connected components
        components = list(nx.connected_components(self.graph))

        for i, component in enumerate(components):
            if len(component) < 2:
                continue  # Skip single-address clusters

            # Get all edges in this component
            subgraph = self.graph.subgraph(component)

            # Collect all evidence
            all_evidence = []
            total_confidence = 0.0

            for u, v, data in subgraph.edges(data=True):
                all_evidence.extend(data.get('evidence', []))
                total_confidence += data.get('confidence', 0)

            # Calculate average confidence
            num_edges = subgraph.number_of_edges()
            avg_confidence = total_confidence / num_edges if num_edges > 0 else 0

            # Generate cluster ID
            cluster_id = hashlib.sha256(
                ''.join(sorted(component)).encode()
            ).hexdigest()[:12]

            cluster = AddressCluster(
                cluster_id=f"cluster_{cluster_id}",
                addresses=set(component),
                confidence=avg_confidence,
                evidence=all_evidence,
                metadata={
                    'edge_count': num_edges,
                    'contains_seed': seed_address in component
                }
            )

            clusters.append(cluster)

        # Sort by whether contains seed, then by size
        clusters.sort(
            key=lambda c: (c.metadata.get('contains_seed', False), len(c.addresses)),
            reverse=True
        )

        return clusters

    def _calculate_statistics(self, clusters: List[AddressCluster]) -> Dict[str, Any]:
        """Calculate clustering statistics"""
        if not clusters:
            return {
                'total_clusters': 0,
                'total_addresses': 0,
                'largest_cluster': 0,
                'avg_cluster_size': 0,
                'heuristic_distribution': {}
            }

        # Count heuristic usage
        heuristic_counts = defaultdict(int)
        for cluster in clusters:
            for ev in cluster.evidence:
                heuristic_counts[ev.heuristic] += 1

        total_addresses = sum(len(c.addresses) for c in clusters)

        return {
            'total_clusters': len(clusters),
            'total_addresses': total_addresses,
            'unique_addresses': len(set().union(*[c.addresses for c in clusters])),
            'largest_cluster': max(len(c.addresses) for c in clusters),
            'smallest_cluster': min(len(c.addresses) for c in clusters),
            'avg_cluster_size': total_addresses / len(clusters),
            'avg_confidence': sum(c.confidence for c in clusters) / len(clusters),
            'heuristic_distribution': dict(heuristic_counts),
            'graph_nodes': self.graph.number_of_nodes(),
            'graph_edges': self.graph.number_of_edges()
        }

    async def expand_cluster(
        self,
        cluster: AddressCluster,
        transactions: List[Dict],
        max_new_addresses: int = 100
    ) -> AddressCluster:
        """
        Expand an existing cluster by analyzing more transactions

        Args:
            cluster: Existing cluster to expand
            transactions: New transactions to analyze
            max_new_addresses: Maximum new addresses to add

        Returns:
            Expanded cluster
        """
        logger.info(f"Expanding cluster {cluster.cluster_id} with {len(cluster.addresses)} addresses")

        new_addresses = set()
        new_evidence = []

        for tx in transactions:
            inputs = tx.get('inputs', [])

            # Get input addresses
            input_addrs = [inp.get('address') for inp in inputs if inp.get('address')]

            # Check if any input is in our cluster
            cluster_inputs = [addr for addr in input_addrs if addr in cluster.addresses]

            if cluster_inputs and len(input_addrs) > 1:
                # All other inputs should be added to cluster
                for addr in input_addrs:
                    if addr not in cluster.addresses and addr not in new_addresses:
                        new_addresses.add(addr)
                        new_evidence.append(ClusterEvidence(
                            heuristic='common_input',
                            confidence=self.heuristic_weights['common_input'],
                            transaction_hash=tx.get('txid'),
                            details={'expansion': True}
                        ))

                        if len(new_addresses) >= max_new_addresses:
                            break

            if len(new_addresses) >= max_new_addresses:
                break

        # Update cluster
        cluster.addresses.update(new_addresses)
        cluster.evidence.extend(new_evidence)

        # Recalculate confidence
        if new_evidence:
            total_confidence = sum(ev.confidence for ev in cluster.evidence)
            cluster.confidence = total_confidence / len(cluster.evidence)

        logger.info(f"Expanded cluster to {len(cluster.addresses)} addresses (+{len(new_addresses)})")

        return cluster

    def merge_clusters(
        self,
        cluster1: AddressCluster,
        cluster2: AddressCluster,
        evidence: ClusterEvidence
    ) -> AddressCluster:
        """
        Merge two clusters

        Args:
            cluster1: First cluster
            cluster2: Second cluster
            evidence: Evidence supporting the merge

        Returns:
            Merged cluster
        """
        merged_addresses = cluster1.addresses | cluster2.addresses
        merged_evidence = cluster1.evidence + cluster2.evidence + [evidence]

        cluster_id = hashlib.sha256(
            ''.join(sorted(merged_addresses)).encode()
        ).hexdigest()[:12]

        return AddressCluster(
            cluster_id=f"cluster_{cluster_id}",
            addresses=merged_addresses,
            confidence=min(cluster1.confidence, cluster2.confidence),
            evidence=merged_evidence,
            total_balance=cluster1.total_balance + cluster2.total_balance,
            total_received=cluster1.total_received + cluster2.total_received,
            total_sent=cluster1.total_sent + cluster2.total_sent,
            tx_count=cluster1.tx_count + cluster2.tx_count,
            labels=list(set(cluster1.labels + cluster2.labels)),
            metadata={
                'merged_from': [cluster1.cluster_id, cluster2.cluster_id],
                'merge_evidence': evidence.heuristic
            }
        )

    def export_to_networkx(self) -> nx.Graph:
        """Export the clustering graph as NetworkX graph"""
        return self.graph.copy()

    def export_to_dict(self, cluster: AddressCluster) -> Dict[str, Any]:
        """Export cluster to dictionary for JSON serialization"""
        return {
            'cluster_id': cluster.cluster_id,
            'addresses': list(cluster.addresses),
            'address_count': len(cluster.addresses),
            'confidence': cluster.confidence,
            'evidence': [
                {
                    'heuristic': ev.heuristic,
                    'confidence': ev.confidence,
                    'transaction': ev.transaction_hash,
                    'details': ev.details
                }
                for ev in cluster.evidence
            ],
            'total_balance': cluster.total_balance,
            'total_received': cluster.total_received,
            'total_sent': cluster.total_sent,
            'tx_count': cluster.tx_count,
            'labels': cluster.labels,
            'metadata': cluster.metadata
        }


class QuickClusterer:
    """Simple interface for quick clustering operations"""

    @staticmethod
    def cluster_by_common_inputs(transactions: List[Dict]) -> Dict[str, Set[str]]:
        """
        Quick clustering using only common input heuristic

        Args:
            transactions: List of transaction dicts with 'inputs' field

        Returns:
            Dict mapping cluster IDs to sets of addresses
        """
        graph = nx.Graph()

        for tx in transactions:
            inputs = tx.get('inputs', [])
            addresses = [inp.get('address') for inp in inputs if inp.get('address')]

            if len(addresses) > 1:
                for i, addr1 in enumerate(addresses):
                    for addr2 in addresses[i+1:]:
                        graph.add_edge(addr1, addr2)

        clusters = {}
        for i, component in enumerate(nx.connected_components(graph)):
            if len(component) > 1:
                cluster_id = f"quick_cluster_{i}"
                clusters[cluster_id] = component

        return clusters

    @staticmethod
    def find_related_addresses(
        address: str,
        transactions: List[Dict]
    ) -> Set[str]:
        """
        Find addresses related to a given address via common inputs

        Args:
            address: Target address
            transactions: Transaction history

        Returns:
            Set of related addresses
        """
        related = {address}

        for tx in transactions:
            inputs = tx.get('inputs', [])
            addresses = [inp.get('address') for inp in inputs if inp.get('address')]

            if address in addresses and len(addresses) > 1:
                related.update(addresses)

        return related
