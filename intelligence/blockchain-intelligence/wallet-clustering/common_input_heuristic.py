"""
Common Input Heuristic (CIH) Implementation
Clusters addresses based on multi-input transaction analysis
"""

import logging
from typing import Dict, List, Set, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class TransactionInput:
    """Represents an input in a transaction"""
    address: str
    transaction_hash: str
    input_index: int
    value: float
    script_type: str
    timestamp: Optional[datetime] = None


@dataclass
class MultiInputTransaction:
    """Transaction with multiple inputs"""
    transaction_hash: str
    input_addresses: List[str]
    output_addresses: List[str]
    timestamp: datetime
    total_input: float
    total_output: float
    fee: float
    input_count: int
    output_count: int


@dataclass
class CIHResult:
    """Result of common input heuristic analysis"""
    source_address: str
    related_addresses: List[Dict[str, Any]]
    multi_input_transactions: List[MultiInputTransaction]
    confidence_scores: Dict[str, float]
    address_groups: List[Set[str]]
    total_related: int
    analysis_depth: int


class CommonInputHeuristic:
    """
    Implements the Common Input Ownership Heuristic

    Based on the principle that all inputs to a transaction are
    controlled by the same entity (with exceptions for CoinJoin)
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize CIH analyzer

        Args:
            config: Configuration dictionary
        """
        self.config = config or {}

        # Analysis parameters
        self.min_inputs = self.config.get('min_inputs', 2)
        self.max_inputs = self.config.get('max_inputs', 100)  # Exclude CoinJoin
        self.min_confidence = self.config.get('min_confidence', 0.6)
        self.exclude_coinjoin = self.config.get('exclude_coinjoin', True)

        # Caches
        self.transaction_cache: Dict[str, MultiInputTransaction] = {}
        self.address_transaction_cache: Dict[str, List[str]] = defaultdict(list)

        logger.info("Common Input Heuristic analyzer initialized")

    def analyze_address(self, address: str, depth: int = 2) -> Dict[str, Any]:
        """
        Analyze address using common input heuristic

        Args:
            address: Address to analyze
            depth: How many hops to follow

        Returns:
            CIH analysis results
        """
        logger.info(f"Analyzing address {address} with CIH (depth={depth})")

        related_addresses: Set[str] = set()
        multi_input_txs: List[MultiInputTransaction] = []
        confidence_scores: Dict[str, float] = {}

        # Track addresses at each depth level
        current_level = {address}
        processed = set()

        for level in range(depth):
            next_level = set()

            logger.debug(f"CIH depth level {level}: {len(current_level)} addresses")

            for addr in current_level:
                if addr in processed:
                    continue

                processed.add(addr)

                # Find multi-input transactions
                txs = self._find_multi_input_transactions(addr)

                for tx in txs:
                    # Skip likely CoinJoin transactions
                    if self.exclude_coinjoin and self._is_likely_coinjoin(tx):
                        continue

                    multi_input_txs.append(tx)

                    # All input addresses are potentially controlled by same entity
                    for input_addr in tx.input_addresses:
                        if input_addr != addr and input_addr not in processed:
                            related_addresses.add(input_addr)
                            next_level.add(input_addr)

                            # Calculate confidence score
                            confidence = self._calculate_confidence(tx, addr, input_addr)

                            if input_addr not in confidence_scores:
                                confidence_scores[input_addr] = confidence
                            else:
                                # Take maximum confidence if seen multiple times
                                confidence_scores[input_addr] = max(
                                    confidence_scores[input_addr],
                                    confidence
                                )

            current_level = next_level

            if not current_level:
                break

        # Build address groups
        address_groups = self._build_address_groups(
            address,
            related_addresses,
            multi_input_txs
        )

        # Format results
        related_list = []
        for addr in related_addresses:
            confidence = confidence_scores.get(addr, 0.7)

            if confidence >= self.min_confidence:
                related_list.append({
                    'address': addr,
                    'confidence': confidence,
                    'evidence': {
                        'common_transactions': self._count_common_transactions(
                            address, addr, multi_input_txs
                        ),
                        'first_seen': self._get_first_seen(addr, multi_input_txs)
                    }
                })

        # Sort by confidence
        related_list.sort(key=lambda x: x['confidence'], reverse=True)

        result = {
            'source_address': address,
            'related_addresses': related_list,
            'multi_input_transactions': [self._serialize_transaction(tx)
                                        for tx in multi_input_txs],
            'confidence_scores': confidence_scores,
            'address_groups': [list(group) for group in address_groups],
            'total_related': len(related_list),
            'analysis_depth': depth
        }

        logger.info(f"CIH found {len(related_list)} related addresses")

        return result

    def expand_cluster(self, addresses: Set[str],
                      iterations: int = 1) -> Set[str]:
        """
        Expand a cluster by iteratively applying CIH

        Args:
            addresses: Initial set of addresses
            iterations: Number of expansion iterations

        Returns:
            Expanded set of addresses
        """
        logger.info(f"Expanding cluster of {len(addresses)} addresses")

        current_cluster = addresses.copy()

        for iteration in range(iterations):
            new_addresses = set()

            for addr in current_cluster:
                result = self.analyze_address(addr, depth=1)

                for related in result['related_addresses']:
                    if related['address'] not in current_cluster:
                        new_addresses.add(related['address'])

            if not new_addresses:
                break

            current_cluster.update(new_addresses)
            logger.info(f"Iteration {iteration + 1}: Added {len(new_addresses)} addresses")

        logger.info(f"Final cluster size: {len(current_cluster)} addresses")

        return current_cluster

    def calculate_cluster_confidence(self, addresses: Set[str]) -> float:
        """
        Calculate overall confidence that addresses belong to same entity

        Args:
            addresses: Set of addresses to evaluate

        Returns:
            Confidence score (0-1)
        """
        if len(addresses) < 2:
            return 1.0

        # Find all multi-input transactions involving these addresses
        transactions = []
        for addr in addresses:
            transactions.extend(self._find_multi_input_transactions(addr))

        # Remove duplicates
        unique_txs = {tx.transaction_hash: tx for tx in transactions}
        transactions = list(unique_txs.values())

        if not transactions:
            return 0.0

        # Calculate metrics
        total_links = 0
        strong_links = 0

        addresses_list = list(addresses)
        for i in range(len(addresses_list)):
            for j in range(i + 1, len(addresses_list)):
                addr1, addr2 = addresses_list[i], addresses_list[j]

                # Count common transactions
                common_count = self._count_common_transactions(
                    addr1, addr2, transactions
                )

                if common_count > 0:
                    total_links += 1
                    if common_count >= 2:
                        strong_links += 1

        # Calculate confidence based on link density
        possible_links = len(addresses) * (len(addresses) - 1) / 2
        link_density = total_links / possible_links if possible_links > 0 else 0

        # Strong links boost confidence
        strong_link_bonus = 0.2 * (strong_links / total_links) if total_links > 0 else 0

        confidence = min(1.0, link_density + strong_link_bonus)

        return confidence

    def _find_multi_input_transactions(self, address: str) -> List[MultiInputTransaction]:
        """Find all multi-input transactions involving address"""
        # This is a simulation - in production, query blockchain API
        transactions = []

        # Check cache
        if address in self.address_transaction_cache:
            tx_hashes = self.address_transaction_cache[address]
            for tx_hash in tx_hashes:
                if tx_hash in self.transaction_cache:
                    transactions.append(self.transaction_cache[tx_hash])
            return transactions

        # Simulate blockchain query
        # In production: query block explorer API or local blockchain node
        simulated_txs = self._simulate_blockchain_query(address)

        for tx_data in simulated_txs:
            if tx_data['input_count'] >= self.min_inputs:
                tx = MultiInputTransaction(
                    transaction_hash=tx_data['hash'],
                    input_addresses=tx_data['inputs'],
                    output_addresses=tx_data['outputs'],
                    timestamp=tx_data['timestamp'],
                    total_input=tx_data['total_input'],
                    total_output=tx_data['total_output'],
                    fee=tx_data['fee'],
                    input_count=tx_data['input_count'],
                    output_count=tx_data['output_count']
                )

                transactions.append(tx)
                self.transaction_cache[tx.transaction_hash] = tx
                self.address_transaction_cache[address].append(tx.transaction_hash)

        return transactions

    def _is_likely_coinjoin(self, tx: MultiInputTransaction) -> bool:
        """
        Detect if transaction is likely a CoinJoin

        CoinJoin characteristics:
        - Many inputs (>10)
        - Many outputs of same value
        - Specific patterns from Wasabi/Samourai
        """
        # Too many inputs
        if tx.input_count > self.max_inputs:
            return True

        # Check for equal-output pattern (common in CoinJoin)
        # In production, would check actual output values
        if tx.output_count > 5 and tx.input_count > 5:
            # Heuristic: likely CoinJoin if many inputs and outputs
            return True

        return False

    def _calculate_confidence(self, tx: MultiInputTransaction,
                            source_addr: str, target_addr: str) -> float:
        """Calculate confidence that two addresses share ownership"""
        confidence = 0.8  # Base confidence for CIH

        # Fewer inputs = higher confidence (less likely CoinJoin)
        if tx.input_count <= 3:
            confidence += 0.15
        elif tx.input_count > 10:
            confidence -= 0.2

        # Script type matching increases confidence
        # (would check in production)

        # Reasonable fee indicates normal transaction
        fee_ratio = tx.fee / tx.total_input if tx.total_input > 0 else 0
        if 0.0001 < fee_ratio < 0.01:
            confidence += 0.05

        return max(0.0, min(1.0, confidence))

    def _build_address_groups(self, source: str, related: Set[str],
                             transactions: List[MultiInputTransaction]) -> List[Set[str]]:
        """Build strongly connected groups of addresses"""
        # Use union-find to group addresses
        parent = {source: source}
        for addr in related:
            parent[addr] = addr

        def find(x):
            if parent[x] != x:
                parent[x] = find(parent[x])
            return parent[x]

        def union(x, y):
            px, py = find(x), find(y)
            if px != py:
                parent[px] = py

        # Union addresses that appear together
        for tx in transactions:
            if len(tx.input_addresses) > 1:
                first = tx.input_addresses[0]
                for addr in tx.input_addresses[1:]:
                    if addr in parent and first in parent:
                        union(first, addr)

        # Build groups
        groups_dict = defaultdict(set)
        for addr in parent:
            root = find(addr)
            groups_dict[root].add(addr)

        return list(groups_dict.values())

    def _count_common_transactions(self, addr1: str, addr2: str,
                                  transactions: List[MultiInputTransaction]) -> int:
        """Count transactions where both addresses appear as inputs"""
        count = 0
        for tx in transactions:
            if addr1 in tx.input_addresses and addr2 in tx.input_addresses:
                count += 1
        return count

    def _get_first_seen(self, address: str,
                       transactions: List[MultiInputTransaction]) -> Optional[str]:
        """Get first time address was seen in transactions"""
        earliest = None
        for tx in transactions:
            if address in tx.input_addresses or address in tx.output_addresses:
                if earliest is None or tx.timestamp < earliest:
                    earliest = tx.timestamp

        return earliest.isoformat() if earliest else None

    def _serialize_transaction(self, tx: MultiInputTransaction) -> Dict[str, Any]:
        """Convert transaction to serializable dict"""
        return {
            'transaction_hash': tx.transaction_hash,
            'input_addresses': tx.input_addresses,
            'output_addresses': tx.output_addresses,
            'timestamp': tx.timestamp.isoformat() if tx.timestamp else None,
            'total_input': tx.total_input,
            'total_output': tx.total_output,
            'fee': tx.fee,
            'input_count': tx.input_count,
            'output_count': tx.output_count
        }

    def _simulate_blockchain_query(self, address: str) -> List[Dict[str, Any]]:
        """
        Simulate blockchain API query
        In production: replace with real blockchain API calls
        """
        # Simulate multiple multi-input transactions
        import random
        from datetime import timedelta

        num_txs = random.randint(1, 5)
        transactions = []

        for i in range(num_txs):
            input_count = random.randint(2, 8)
            output_count = random.randint(1, 4)

            # Generate fake addresses
            inputs = [address] + [
                f"1{random.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ')}{random.randint(1000000, 9999999)}"
                for _ in range(input_count - 1)
            ]

            outputs = [
                f"1{random.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ')}{random.randint(1000000, 9999999)}"
                for _ in range(output_count)
            ]

            total_input = random.uniform(0.1, 10.0)
            fee = total_input * random.uniform(0.0001, 0.001)
            total_output = total_input - fee

            transactions.append({
                'hash': f"{random.randint(10000000, 99999999):08x}",
                'inputs': inputs,
                'outputs': outputs,
                'timestamp': datetime.now() - timedelta(days=random.randint(1, 365)),
                'total_input': total_input,
                'total_output': total_output,
                'fee': fee,
                'input_count': input_count,
                'output_count': output_count
            })

        return transactions
