"""
Wallet Clustering and Entity Attribution
Advanced heuristics for grouping related blockchain addresses
"""

import logging
from typing import Dict, List, Set, Tuple, Optional
from collections import defaultdict, Counter
from datetime import datetime, timedelta

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class WalletClusterer:
    """Advanced wallet clustering using multiple heuristics"""

    def __init__(self, bitcoin_tracker=None, ethereum_tracker=None):
        self.bitcoin_tracker = bitcoin_tracker
        self.ethereum_tracker = ethereum_tracker

        # Known entity patterns
        self.known_entities = {
            'exchanges': {},
            'mixers': {},
            'gambling': {},
            'darknet': {},
            'defi': {}
        }

        self.clusters = {}
        self.address_to_cluster = {}

    def cluster_bitcoin_addresses(self, seed_address: str, depth: int = 3) -> Dict:
        """
        Cluster Bitcoin addresses using multiple heuristics:
        1. Common Input Ownership
        2. Change Address Detection
        3. Peel Chain Analysis
        4. Temporal Analysis
        """
        logger.info(f"Clustering Bitcoin addresses from seed: {seed_address}")

        cluster = {
            'seed_address': seed_address,
            'addresses': set([seed_address]),
            'transactions': set(),
            'heuristics_used': [],
            'confidence_scores': {},
            'entity_type': None
        }

        to_process = [seed_address]
        processed = set()

        for level in range(depth):
            if not to_process:
                break

            logger.info(f"Processing level {level+1}, {len(to_process)} addresses")

            current_batch = to_process[:20]  # Process in batches
            to_process = to_process[20:]

            for addr in current_batch:
                if addr in processed:
                    continue

                processed.add(addr)

                # Apply clustering heuristics
                related_addrs = self._apply_bitcoin_heuristics(addr, cluster)

                for new_addr in related_addrs:
                    if new_addr not in cluster['addresses']:
                        cluster['addresses'].add(new_addr)
                        to_process.append(new_addr)

        # Calculate cluster statistics
        cluster['size'] = len(cluster['addresses'])
        cluster['transaction_count'] = len(cluster['transactions'])

        # Attempt entity identification
        cluster['entity_type'] = self._identify_entity_type(cluster)

        return cluster

    def _apply_bitcoin_heuristics(self, address: str, cluster: Dict) -> Set[str]:
        """Apply Bitcoin clustering heuristics"""
        related_addresses = set()

        if not self.bitcoin_tracker:
            return related_addresses

        try:
            addr_info = self.bitcoin_tracker.get_address_info(address)

            for tx in addr_info.get('transactions', [])[:50]:
                tx_hash = tx.get('hash')
                cluster['transactions'].add(tx_hash)

                # Heuristic 1: Common Input Ownership
                input_addrs = [inp.get('address') for inp in tx.get('inputs', [])
                              if inp.get('address')]

                if len(input_addrs) > 1 and address in input_addrs:
                    # All inputs likely controlled by same entity
                    for inp_addr in input_addrs:
                        if inp_addr != address:
                            related_addresses.add(inp_addr)
                            cluster['heuristics_used'].append('common_input')
                            cluster['confidence_scores'][inp_addr] = 0.9

                # Heuristic 2: Change Address Detection
                outputs = tx.get('outputs', [])
                if len(outputs) == 2:
                    # Likely one output is payment, one is change
                    change_addr = self._detect_change_address(address, outputs, tx)
                    if change_addr:
                        related_addresses.add(change_addr)
                        cluster['heuristics_used'].append('change_detection')
                        cluster['confidence_scores'][change_addr] = 0.7

                # Heuristic 3: Peel Chain Detection
                if self._is_peel_chain_tx(tx):
                    peel_target = self._get_peel_target(tx, address)
                    if peel_target:
                        related_addresses.add(peel_target)
                        cluster['heuristics_used'].append('peel_chain')
                        cluster['confidence_scores'][peel_target] = 0.6

        except Exception as e:
            logger.error(f"Error applying heuristics to {address}: {e}")

        return related_addresses

    def _detect_change_address(self, source_addr: str, outputs: List[Dict],
                               tx: Dict) -> Optional[str]:
        """Detect change address in transaction outputs"""
        if len(outputs) != 2:
            return None

        # Change address typically:
        # 1. Has not been seen before
        # 2. Is a different address type than the destination
        # 3. Has a round number for the payment output

        for i, output in enumerate(outputs):
            value = output.get('value', 0)
            addr = output.get('address')

            # Check if value is a round number (likely payment)
            if value > 0 and (value % 0.001 == 0 or value % 0.01 == 0):
                # The other output is likely change
                change_idx = 1 - i
                change_addr = outputs[change_idx].get('address')
                if change_addr and change_addr != source_addr:
                    return change_addr

        return None

    def _is_peel_chain_tx(self, tx: Dict) -> bool:
        """Detect if transaction is part of a peel chain"""
        outputs = tx.get('outputs', [])

        if len(outputs) == 2:
            values = [out.get('value', 0) for out in outputs]
            # Peel chain: one small output, one large output
            if min(values) < max(values) * 0.1:  # 10% threshold
                return True

        return False

    def _get_peel_target(self, tx: Dict, source_addr: str) -> Optional[str]:
        """Get the address receiving the larger amount in peel chain"""
        outputs = tx.get('outputs', [])

        if len(outputs) == 2:
            sorted_outputs = sorted(outputs, key=lambda x: x.get('value', 0), reverse=True)
            target_addr = sorted_outputs[0].get('address')

            if target_addr and target_addr != source_addr:
                return target_addr

        return None

    def cluster_ethereum_addresses(self, seed_address: str, depth: int = 2) -> Dict:
        """
        Cluster Ethereum addresses using:
        1. Contract interaction patterns
        2. Token transfer patterns
        3. Funding relationships
        4. DeFi protocol usage
        """
        logger.info(f"Clustering Ethereum addresses from seed: {seed_address}")

        cluster = {
            'seed_address': seed_address,
            'addresses': set([seed_address]),
            'transactions': set(),
            'contracts_interacted': set(),
            'tokens_used': set(),
            'defi_protocols': set(),
            'heuristics_used': [],
            'confidence_scores': {}
        }

        to_process = [seed_address]
        processed = set()

        for level in range(depth):
            if not to_process:
                break

            current_batch = to_process[:10]
            to_process = to_process[10:]

            for addr in current_batch:
                if addr in processed:
                    continue

                processed.add(addr)

                # Apply Ethereum-specific heuristics
                related_addrs = self._apply_ethereum_heuristics(addr, cluster)

                for new_addr in related_addrs:
                    if new_addr not in cluster['addresses']:
                        cluster['addresses'].add(new_addr)
                        to_process.append(new_addr)

        cluster['size'] = len(cluster['addresses'])
        cluster['transaction_count'] = len(cluster['transactions'])

        return cluster

    def _apply_ethereum_heuristics(self, address: str, cluster: Dict) -> Set[str]:
        """Apply Ethereum clustering heuristics"""
        related_addresses = set()

        if not self.ethereum_tracker:
            return related_addresses

        try:
            addr_info = self.ethereum_tracker.get_address_info(address)

            # Heuristic 1: Funding relationships (deposit addresses)
            funding_addrs = self._find_funding_sources(addr_info)
            related_addresses.update(funding_addrs)

            # Heuristic 2: Token transfer patterns
            token_related = self._find_token_related_addresses(addr_info, cluster)
            related_addresses.update(token_related)

            # Heuristic 3: Contract interaction patterns
            for tx in addr_info.get('transactions', [])[:30]:
                cluster['transactions'].add(tx.get('hash'))

                to_addr = tx.get('to')
                if to_addr:
                    cluster['contracts_interacted'].add(to_addr)

        except Exception as e:
            logger.error(f"Error applying Ethereum heuristics to {address}: {e}")

        return related_addresses

    def _find_funding_sources(self, addr_info: Dict) -> Set[str]:
        """Find addresses that funded this address"""
        funding_sources = set()

        transactions = addr_info.get('transactions', [])
        if not transactions:
            return funding_sources

        # Look for initial funding transactions
        sorted_txs = sorted(transactions, key=lambda x: x.get('time', datetime.now()))

        # Check first 5 transactions for funding sources
        for tx in sorted_txs[:5]:
            if tx.get('to') == addr_info.get('address'):
                from_addr = tx.get('from')
                if from_addr:
                    funding_sources.add(from_addr)

        return funding_sources

    def _find_token_related_addresses(self, addr_info: Dict, cluster: Dict) -> Set[str]:
        """Find addresses related through token transfers"""
        related = set()

        token_transfers = addr_info.get('token_transfers', [])

        # Track tokens used
        for transfer in token_transfers:
            token_addr = transfer.get('token_address')
            if token_addr:
                cluster['tokens_used'].add(token_addr)

        # Find addresses that receive/send same tokens within short timeframe
        if len(token_transfers) > 0:
            time_window = timedelta(minutes=30)

            for i, transfer in enumerate(token_transfers):
                tx_time = transfer.get('time')
                if not tx_time:
                    continue

                for j, other_transfer in enumerate(token_transfers[i+1:i+10]):
                    other_time = other_transfer.get('time')
                    if not other_time:
                        continue

                    # Same token, similar timeframe
                    if (transfer.get('token_address') == other_transfer.get('token_address') and
                        abs((tx_time - other_time).total_seconds()) < time_window.total_seconds()):

                        related.add(other_transfer.get('to'))
                        related.add(other_transfer.get('from'))

        return related

    def _identify_entity_type(self, cluster: Dict) -> Optional[str]:
        """Attempt to identify the type of entity controlling the cluster"""

        size = cluster.get('size', 0)
        tx_count = cluster.get('transaction_count', 0)

        # Heuristics for entity identification
        if size > 1000:
            return 'exchange'
        elif size > 100 and tx_count > 1000:
            return 'service_provider'
        elif 'peel_chain' in cluster.get('heuristics_used', []):
            return 'individual_obfuscating'
        elif size < 10 and tx_count < 50:
            return 'individual_user'
        elif tx_count / max(size, 1) > 50:
            return 'high_activity_entity'

        return 'unknown'

    def attribute_to_known_entity(self, addresses: Set[str]) -> Dict:
        """Attempt to attribute addresses to known entities"""
        logger.info(f"Attempting entity attribution for {len(addresses)} addresses")

        matches = {
            'exchanges': [],
            'mixers': [],
            'gambling': [],
            'darknet': [],
            'defi': []
        }

        # Known exchange patterns (example patterns)
        exchange_patterns = {
            'binance': ['bc1q', '1ndy', '3j98'],
            'coinbase': ['1cz', '3cd', 'bc1qgd'],
            'kraken': ['1kr', '3kr'],
            'huobi': ['1huo', '3huo']
        }

        # Known mixer patterns
        mixer_patterns = {
            'wasabi': ['bc1q'],
            'samourai': ['bc1q']
        }

        for addr in addresses:
            addr_lower = addr.lower()

            # Check exchange patterns
            for exchange, patterns in exchange_patterns.items():
                if any(addr_lower.startswith(p) for p in patterns):
                    matches['exchanges'].append({
                        'address': addr,
                        'entity': exchange,
                        'confidence': 0.6
                    })

            # Check mixer patterns
            for mixer, patterns in mixer_patterns.items():
                if any(addr_lower.startswith(p) for p in patterns):
                    matches['mixers'].append({
                        'address': addr,
                        'entity': mixer,
                        'confidence': 0.5
                    })

        return matches

    def analyze_cluster_behavior(self, cluster: Dict) -> Dict:
        """Analyze behavioral patterns in a cluster"""
        analysis = {
            'cluster_id': id(cluster),
            'size': cluster.get('size', 0),
            'risk_indicators': [],
            'behavioral_patterns': [],
            'risk_score': 0.0
        }

        # Check for suspicious patterns
        if 'peel_chain' in cluster.get('heuristics_used', []):
            analysis['risk_indicators'].append('peel_chain_usage')
            analysis['risk_score'] += 2.0

        if cluster.get('size', 0) > 100:
            analysis['behavioral_patterns'].append('large_cluster')
            analysis['risk_score'] += 1.0

        if cluster.get('transaction_count', 0) > 1000:
            analysis['behavioral_patterns'].append('high_transaction_volume')
            analysis['risk_score'] += 1.5

        # Normalize risk score
        analysis['risk_score'] = min(analysis['risk_score'], 10.0)

        return analysis

    def merge_clusters(self, cluster1: Dict, cluster2: Dict) -> Dict:
        """Merge two clusters that are determined to be related"""
        merged = {
            'seed_address': cluster1.get('seed_address'),
            'addresses': cluster1.get('addresses', set()).union(cluster2.get('addresses', set())),
            'transactions': cluster1.get('transactions', set()).union(cluster2.get('transactions', set())),
            'heuristics_used': list(set(cluster1.get('heuristics_used', []) + cluster2.get('heuristics_used', []))),
            'confidence_scores': {}
        }

        # Merge confidence scores (take maximum)
        for addr in merged['addresses']:
            score1 = cluster1.get('confidence_scores', {}).get(addr, 0)
            score2 = cluster2.get('confidence_scores', {}).get(addr, 0)
            merged['confidence_scores'][addr] = max(score1, score2)

        merged['size'] = len(merged['addresses'])
        merged['transaction_count'] = len(merged['transactions'])

        return merged

    def find_common_patterns(self, clusters: List[Dict]) -> Dict:
        """Find common patterns across multiple clusters"""
        logger.info(f"Analyzing patterns across {len(clusters)} clusters")

        patterns = {
            'common_addresses': set(),
            'common_transactions': set(),
            'shared_heuristics': Counter(),
            'entity_type_distribution': Counter()
        }

        # Find intersections
        if len(clusters) > 1:
            # Common addresses
            addr_sets = [cluster.get('addresses', set()) for cluster in clusters]
            patterns['common_addresses'] = set.intersection(*addr_sets) if addr_sets else set()

            # Common transactions
            tx_sets = [cluster.get('transactions', set()) for cluster in clusters]
            patterns['common_transactions'] = set.intersection(*tx_sets) if tx_sets else set()

        # Count heuristic usage
        for cluster in clusters:
            for heuristic in cluster.get('heuristics_used', []):
                patterns['shared_heuristics'][heuristic] += 1

            entity_type = cluster.get('entity_type')
            if entity_type:
                patterns['entity_type_distribution'][entity_type] += 1

        return patterns

    def export_cluster_graph(self, cluster: Dict) -> Dict:
        """Export cluster as graph structure for visualization"""
        graph = {
            'nodes': [],
            'edges': [],
            'metadata': {
                'cluster_size': cluster.get('size', 0),
                'entity_type': cluster.get('entity_type')
            }
        }

        # Add nodes
        for addr in cluster.get('addresses', []):
            confidence = cluster.get('confidence_scores', {}).get(addr, 0.5)
            graph['nodes'].append({
                'id': addr,
                'label': addr[:8] + '...' + addr[-6:],
                'confidence': confidence,
                'is_seed': addr == cluster.get('seed_address')
            })

        # Add edges based on transactions (simplified)
        # In a real implementation, this would parse actual transaction flows
        addresses_list = list(cluster.get('addresses', []))
        for i, addr1 in enumerate(addresses_list[:50]):  # Limit for performance
            for addr2 in addresses_list[i+1:i+5]:  # Connect to a few neighbors
                graph['edges'].append({
                    'source': addr1,
                    'target': addr2,
                    'weight': 1
                })

        return graph
