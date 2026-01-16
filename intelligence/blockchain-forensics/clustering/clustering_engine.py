"""
Wallet Clustering Engine

Main clustering engine that combines multiple heuristics to group
blockchain addresses that are likely controlled by the same entity.
"""

import asyncio
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from collections import defaultdict
import logging
import networkx as nx

logger = logging.getLogger(__name__)


@dataclass
class Cluster:
    """Represents a cluster of related addresses"""

    cluster_id: str
    addresses: Set[str]
    confidence: float  # 0-1
    evidence: List[str]  # List of heuristics that support this cluster
    label: Optional[str] = None  # exchange, criminal, etc.
    metadata: Dict = field(default_factory=dict)


@dataclass
class WalletCluster:
    """Simple wallet cluster result for API responses"""
    cluster_id: str
    addresses: Set[str]
    total_balance: float
    confidence_score: float
    clustering_method: str
    metadata: Dict = field(default_factory=dict)


class WalletClusteringEngine:
    """
    Main wallet clustering engine

    Combines multiple clustering heuristics:
    1. Common Input Ownership: addresses used as inputs in same transaction
    2. Change Address: identifying change addresses
    3. Co-spending: addresses that frequently spend together
    4. Peel Chains: long chains of transactions with specific patterns
    """

    def __init__(self, db_manager=None, api_manager=None, graph_client=None):
        self.db = db_manager
        self.api = api_manager
        self.graph = graph_client

        # Clustering graph
        self.clustering_graph = nx.Graph()

        # Clusters
        self.clusters: Dict[str, Cluster] = {}

        # Address to cluster mapping
        self.address_to_cluster: Dict[str, str] = {}

        logger.info("Wallet Clustering Engine initialized")

    async def build_cluster(
        self,
        seed_address: str,
        transactions: List
    ) -> Optional[WalletCluster]:
        """
        Build a cluster from a seed address and its transactions.
        Simplified method for API integration that doesn't require full DB setup.

        Args:
            seed_address: Starting wallet address
            transactions: List of Transaction objects from the seed address

        Returns:
            WalletCluster object or None
        """
        if not transactions:
            return None

        # Reset clustering graph for this operation
        self.clustering_graph.clear()

        # Add seed address as first node
        self.clustering_graph.add_node(seed_address)

        # Collect all addresses from transactions
        all_addresses = {seed_address}
        total_value = 0.0

        for tx in transactions:
            # Get addresses from transaction
            from_addrs = getattr(tx, 'from_addresses', [])
            to_addrs = getattr(tx, 'to_addresses', [])

            for addr in from_addrs + to_addrs:
                if addr:
                    all_addresses.add(addr)
                    self.clustering_graph.add_node(addr)

            # Apply common input ownership heuristic
            if len(from_addrs) > 1:
                for i, addr1 in enumerate(from_addrs):
                    for addr2 in from_addrs[i+1:]:
                        if addr1 and addr2:
                            self._add_cluster_edge(addr1, addr2, 1.0, "common_input")

            # Track value for balance estimation
            amount = float(getattr(tx, 'amount', 0) or 0)
            total_value += amount

            # Link seed to its transaction partners
            for addr in to_addrs:
                if addr and addr != seed_address:
                    self._add_cluster_edge(seed_address, addr, 0.3, "transaction_partner")

        # Extract connected component containing seed address
        if seed_address in self.clustering_graph:
            try:
                cluster_addresses = nx.node_connected_component(self.clustering_graph, seed_address)
            except nx.NetworkXError:
                cluster_addresses = {seed_address}
        else:
            cluster_addresses = {seed_address}

        # Calculate confidence based on number of edges
        subgraph = self.clustering_graph.subgraph(cluster_addresses)
        num_edges = subgraph.number_of_edges()
        confidence = min(1.0, num_edges * 0.2) if num_edges > 0 else 0.5

        # Generate cluster ID
        import hashlib
        cluster_id = f"cluster_{hashlib.sha256(seed_address.encode()).hexdigest()[:12]}"

        return WalletCluster(
            cluster_id=cluster_id,
            addresses=set(cluster_addresses),
            total_balance=total_value,
            confidence_score=confidence,
            clustering_method="common_input_ownership",
            metadata={
                "seed_address": seed_address,
                "transaction_count": len(transactions)
            }
        )

    def _add_cluster_edge(self, addr1: str, addr2: str, weight: float, evidence: str):
        """Helper to add or update an edge in the clustering graph"""
        if self.clustering_graph.has_edge(addr1, addr2):
            self.clustering_graph[addr1][addr2]["weight"] += weight
        else:
            self.clustering_graph.add_edge(addr1, addr2, weight=weight, evidence=evidence)

    async def cluster_addresses(
        self,
        addresses: List[str],
        blockchain: str = "btc",
        min_confidence: float = 0.7
    ) -> List[Cluster]:
        """
        Cluster a list of addresses

        Args:
            addresses: List of addresses to cluster
            blockchain: Blockchain type
            min_confidence: Minimum confidence to create cluster

        Returns:
            List of clusters
        """
        logger.info(f"Clustering {len(addresses)} addresses")

        # Reset clustering graph
        self.clustering_graph.clear()

        # Add all addresses as nodes
        for addr in addresses:
            self.clustering_graph.add_node(addr)

        # Apply clustering heuristics
        await self._apply_common_input_heuristic(addresses, blockchain)
        await self._apply_change_address_heuristic(addresses, blockchain)
        await self._apply_cospending_heuristic(addresses, blockchain)
        await self._apply_peel_chain_heuristic(addresses, blockchain)

        # Extract clusters from graph
        clusters = await self._extract_clusters(min_confidence)

        logger.info(f"Created {len(clusters)} clusters")
        return clusters

    async def expand_cluster(
        self,
        cluster_id: str,
        max_expansion: int = 100
    ) -> Cluster:
        """
        Expand an existing cluster by finding related addresses

        Args:
            cluster_id: ID of cluster to expand
            max_expansion: Maximum number of new addresses to add

        Returns:
            Expanded cluster
        """
        if cluster_id not in self.clusters:
            raise ValueError(f"Cluster {cluster_id} not found")

        cluster = self.clusters[cluster_id]
        original_size = len(cluster.addresses)

        logger.info(f"Expanding cluster {cluster_id} (size: {original_size})")

        # Find candidate addresses
        candidates = set()

        for address in cluster.addresses:
            # Get all transactions for this address
            txs = await self.api.get_address_transactions(address)

            for tx in txs:
                # Add connected addresses as candidates
                if tx["from_address"] not in cluster.addresses:
                    candidates.add(tx["from_address"])
                if tx["to_address"] not in cluster.addresses:
                    candidates.add(tx["to_address"])

                if len(candidates) >= max_expansion:
                    break

            if len(candidates) >= max_expansion:
                break

        # Test each candidate
        added = 0
        for candidate in candidates:
            # Check if candidate should be added to cluster
            should_add, confidence = await self._should_add_to_cluster(
                candidate,
                cluster
            )

            if should_add:
                cluster.addresses.add(candidate)
                self.address_to_cluster[candidate] = cluster_id
                added += 1

        logger.info(
            f"Expanded cluster {cluster_id} from {original_size} to "
            f"{len(cluster.addresses)} addresses (+{added})"
        )

        return cluster

    async def label_cluster(
        self,
        cluster_id: str,
        label: str,
        confidence: Optional[float] = None
    ):
        """
        Apply a label to a cluster

        Args:
            cluster_id: Cluster to label
            label: Label (e.g., "binance", "criminal", "mixer")
            confidence: Optional confidence override
        """
        if cluster_id not in self.clusters:
            raise ValueError(f"Cluster {cluster_id} not found")

        cluster = self.clusters[cluster_id]
        cluster.label = label

        if confidence is not None:
            cluster.confidence = confidence

        logger.info(f"Labeled cluster {cluster_id} as '{label}'")

    async def get_cluster_for_address(self, address: str) -> Optional[Cluster]:
        """Get the cluster containing an address"""
        cluster_id = self.address_to_cluster.get(address)
        if cluster_id:
            return self.clusters.get(cluster_id)
        return None

    async def merge_clusters(
        self,
        cluster_id1: str,
        cluster_id2: str,
        evidence: str
    ) -> Cluster:
        """
        Merge two clusters

        Args:
            cluster_id1: First cluster
            cluster_id2: Second cluster
            evidence: Reason for merge

        Returns:
            Merged cluster
        """
        if cluster_id1 not in self.clusters or cluster_id2 not in self.clusters:
            raise ValueError("One or both clusters not found")

        cluster1 = self.clusters[cluster_id1]
        cluster2 = self.clusters[cluster_id2]

        # Create merged cluster
        merged = Cluster(
            cluster_id=f"{cluster_id1}_merged",
            addresses=cluster1.addresses | cluster2.addresses,
            confidence=min(cluster1.confidence, cluster2.confidence),
            evidence=cluster1.evidence + cluster2.evidence + [f"merge:{evidence}"],
            label=cluster1.label or cluster2.label,
        )

        # Update mappings
        for addr in merged.addresses:
            self.address_to_cluster[addr] = merged.cluster_id

        # Remove old clusters
        del self.clusters[cluster_id1]
        del self.clusters[cluster_id2]

        # Add merged cluster
        self.clusters[merged.cluster_id] = merged

        logger.info(f"Merged clusters {cluster_id1} and {cluster_id2}")

        return merged

    async def get_cluster_statistics(self, cluster_id: str) -> Dict:
        """
        Get statistics for a cluster

        Returns:
            Dictionary with cluster statistics
        """
        if cluster_id not in self.clusters:
            raise ValueError(f"Cluster {cluster_id} not found")

        cluster = self.clusters[cluster_id]

        # Calculate statistics
        total_balance = 0.0
        total_transactions = 0
        first_activity = None
        last_activity = None

        for address in cluster.addresses:
            # Get address info
            txs = await self.api.get_address_transactions(address)

            total_transactions += len(txs)

            for tx in txs:
                if first_activity is None or tx["timestamp"] < first_activity:
                    first_activity = tx["timestamp"]
                if last_activity is None or tx["timestamp"] > last_activity:
                    last_activity = tx["timestamp"]

                # Calculate balance
                if tx["to_address"] == address:
                    total_balance += tx.get("amount", 0)
                else:
                    total_balance -= tx.get("amount", 0)

        return {
            "cluster_id": cluster_id,
            "address_count": len(cluster.addresses),
            "total_balance": total_balance,
            "total_transactions": total_transactions,
            "first_activity": first_activity.isoformat() if first_activity else None,
            "last_activity": last_activity.isoformat() if last_activity else None,
            "confidence": cluster.confidence,
            "label": cluster.label,
            "evidence_count": len(cluster.evidence),
        }

    # Private methods for clustering heuristics

    async def _apply_common_input_heuristic(
        self,
        addresses: List[str],
        blockchain: str
    ):
        """
        Apply common input ownership heuristic

        If multiple addresses are used as inputs in the same transaction,
        they are likely controlled by the same entity.
        """
        logger.debug("Applying common input heuristic")

        address_set = set(addresses)

        for address in addresses:
            txs = await self.api.get_address_transactions(address, blockchain)

            for tx in txs:
                # Get all input addresses
                inputs = tx.get("inputs", [])

                if len(inputs) > 1:
                    # Multiple inputs - likely same owner
                    input_addresses = [inp["address"] for inp in inputs if inp["address"] in address_set]

                    if len(input_addresses) > 1:
                        # Add edges between all input addresses
                        for i, addr1 in enumerate(input_addresses):
                            for addr2 in input_addresses[i+1:]:
                                # Add edge with high weight (strong evidence)
                                if self.clustering_graph.has_edge(addr1, addr2):
                                    self.clustering_graph[addr1][addr2]["weight"] += 1.0
                                else:
                                    self.clustering_graph.add_edge(
                                        addr1, addr2,
                                        weight=1.0,
                                        evidence="common_input"
                                    )

    async def _apply_change_address_heuristic(
        self,
        addresses: List[str],
        blockchain: str
    ):
        """
        Apply change address detection heuristic

        In a transaction with 2 outputs, if one goes to a new address and one
        to an address that has received before, the new address is likely change.
        """
        logger.debug("Applying change address heuristic")

        address_set = set(addresses)

        for address in addresses:
            txs = await self.api.get_address_transactions(address, blockchain)

            for tx in txs:
                if tx["from_address"] != address:
                    continue

                outputs = tx.get("outputs", [])

                if len(outputs) == 2:
                    # Potential change transaction
                    output_addresses = [out["address"] for out in outputs]

                    # Check which address appears to be change
                    for out_addr in output_addresses:
                        if out_addr in address_set and out_addr != address:
                            # Check if this is likely a change address
                            is_change = await self._is_likely_change_address(
                                out_addr, tx
                            )

                            if is_change:
                                # Link source and change address
                                if self.clustering_graph.has_edge(address, out_addr):
                                    self.clustering_graph[address][out_addr]["weight"] += 0.7
                                else:
                                    self.clustering_graph.add_edge(
                                        address, out_addr,
                                        weight=0.7,
                                        evidence="change_address"
                                    )

    async def _apply_cospending_heuristic(
        self,
        addresses: List[str],
        blockchain: str
    ):
        """
        Apply co-spending heuristic

        Addresses that frequently spend to the same destination are likely related.
        """
        logger.debug("Applying co-spending heuristic")

        # Track spending patterns
        spending_patterns = defaultdict(set)  # address -> set of destinations

        address_set = set(addresses)

        for address in addresses:
            txs = await self.api.get_address_transactions(address, blockchain)

            for tx in txs:
                if tx["from_address"] == address:
                    spending_patterns[address].add(tx["to_address"])

        # Find addresses with similar spending patterns
        for addr1 in addresses:
            for addr2 in addresses:
                if addr1 >= addr2:  # Avoid duplicates
                    continue

                # Calculate Jaccard similarity of spending patterns
                set1 = spending_patterns[addr1]
                set2 = spending_patterns[addr2]

                if not set1 or not set2:
                    continue

                intersection = len(set1 & set2)
                union = len(set1 | set2)

                similarity = intersection / union if union > 0 else 0

                if similarity > 0.3:  # Significant overlap
                    weight = similarity * 0.5

                    if self.clustering_graph.has_edge(addr1, addr2):
                        self.clustering_graph[addr1][addr2]["weight"] += weight
                    else:
                        self.clustering_graph.add_edge(
                            addr1, addr2,
                            weight=weight,
                            evidence="cospending"
                        )

    async def _apply_peel_chain_heuristic(
        self,
        addresses: List[str],
        blockchain: str
    ):
        """
        Apply peel chain detection heuristic

        A peel chain is a long sequence of transactions where a small amount
        is "peeled off" to different addresses while the bulk continues.
        """
        logger.debug("Applying peel chain heuristic")

        address_set = set(addresses)

        for address in addresses:
            # Check if this address is part of a peel chain
            chain = await self._detect_peel_chain(address, blockchain)

            if len(chain) > 3:  # Significant peel chain
                # Link all addresses in the chain
                for i, addr1 in enumerate(chain):
                    if addr1 not in address_set:
                        continue

                    for addr2 in chain[i+1:]:
                        if addr2 not in address_set:
                            continue

                        weight = 0.6 / (abs(chain.index(addr1) - chain.index(addr2)))

                        if self.clustering_graph.has_edge(addr1, addr2):
                            self.clustering_graph[addr1][addr2]["weight"] += weight
                        else:
                            self.clustering_graph.add_edge(
                                addr1, addr2,
                                weight=weight,
                                evidence="peel_chain"
                            )

    async def _extract_clusters(self, min_confidence: float) -> List[Cluster]:
        """Extract clusters from the clustering graph"""
        # Use connected components to find clusters
        components = nx.connected_components(self.clustering_graph)

        clusters = []

        for i, component in enumerate(components):
            if len(component) < 2:
                continue  # Skip single-address "clusters"

            # Calculate cluster confidence based on edge weights
            subgraph = self.clustering_graph.subgraph(component)
            total_weight = sum(data["weight"] for _, _, data in subgraph.edges(data=True))
            avg_weight = total_weight / len(subgraph.edges()) if subgraph.edges() else 0

            # Normalize to 0-1
            confidence = min(1.0, avg_weight)

            if confidence < min_confidence:
                continue

            # Collect evidence
            evidence = set()
            for _, _, data in subgraph.edges(data=True):
                evidence.add(data.get("evidence", "unknown"))

            cluster = Cluster(
                cluster_id=f"cluster_{i}",
                addresses=set(component),
                confidence=confidence,
                evidence=list(evidence),
            )

            clusters.append(cluster)
            self.clusters[cluster.cluster_id] = cluster

            # Update address mapping
            for addr in component:
                self.address_to_cluster[addr] = cluster.cluster_id

        return clusters

    async def _is_likely_change_address(
        self,
        address: str,
        transaction: Dict
    ) -> bool:
        """Determine if an address is likely a change address"""
        # Get transaction history for the address
        txs = await self.api.get_address_transactions(address)

        # Change addresses typically have:
        # 1. No prior incoming transactions
        # 2. Only one or few total transactions
        # 3. Output amount less than input amount in the transaction

        # Check if this is the first transaction to this address
        prior_txs = [tx for tx in txs if tx["timestamp"] < transaction["timestamp"]]

        if len(prior_txs) > 0:
            return False  # Not a new address

        # Check total transaction count
        if len(txs) > 5:
            return False  # Too many transactions for change address

        return True

    async def _detect_peel_chain(
        self,
        start_address: str,
        blockchain: str,
        max_length: int = 20
    ) -> List[str]:
        """
        Detect a peel chain starting from an address

        Returns list of addresses in the peel chain
        """
        chain = [start_address]
        current_address = start_address

        for _ in range(max_length):
            txs = await self.api.get_address_transactions(current_address, blockchain)

            # Look for a peel transaction (2 outputs, one small, one large)
            peel_tx = None
            for tx in txs:
                if tx["from_address"] != current_address:
                    continue

                outputs = tx.get("outputs", [])
                if len(outputs) == 2:
                    amounts = [out["amount"] for out in outputs]
                    max_amount = max(amounts)
                    min_amount = min(amounts)

                    # Peel if one output is much larger (>80% of total)
                    if max_amount > (max_amount + min_amount) * 0.8:
                        peel_tx = tx
                        break

            if not peel_tx:
                break  # No more peel transactions

            # Find the large output (continuation of chain)
            outputs = peel_tx["outputs"]
            large_output = max(outputs, key=lambda x: x["amount"])
            next_address = large_output["address"]

            if next_address in chain:
                break  # Cycle detected

            chain.append(next_address)
            current_address = next_address

        return chain

    async def _should_add_to_cluster(
        self,
        candidate: str,
        cluster: Cluster
    ) -> Tuple[bool, float]:
        """
        Determine if a candidate address should be added to a cluster

        Returns (should_add, confidence)
        """
        # Get transactions for candidate
        candidate_txs = await self.api.get_address_transactions(candidate)

        # Count connections to cluster addresses
        connections = 0
        total_shared_value = 0.0

        for tx in candidate_txs:
            for cluster_addr in cluster.addresses:
                if tx["from_address"] == cluster_addr or tx["to_address"] == cluster_addr:
                    connections += 1
                    total_shared_value += tx.get("amount_usd", 0)

        # Calculate confidence
        if connections == 0:
            return False, 0.0

        # More connections and higher value = higher confidence
        confidence = min(1.0, (connections / 10) + (total_shared_value / 1_000_000))

        should_add = confidence > 0.6

        return should_add, confidence
