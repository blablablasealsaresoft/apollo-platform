"""
Entity Attribution System
Identifies and attributes wallet clusters to known entities
"""

import logging
import json
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class KnownEntity:
    """Known blockchain entity"""
    entity_id: str
    name: str
    entity_type: str  # 'exchange', 'merchant', 'mining_pool', 'darknet', etc.
    addresses: Set[str] = field(default_factory=set)
    address_patterns: List[str] = field(default_factory=list)
    behavioral_signatures: Dict[str, Any] = field(default_factory=dict)
    reputation: str = 'unknown'  # 'high', 'medium', 'low', 'malicious'
    tags: Set[str] = field(default_factory=set)
    last_updated: Optional[datetime] = None


@dataclass
class AttributionResult:
    """Result of entity attribution"""
    entity_identified: bool
    entity_type: Optional[str] = None
    entity_name: Optional[str] = None
    entity_id: Optional[str] = None
    confidence: float = 0.0
    matching_addresses: int = 0
    evidence: Dict[str, Any] = field(default_factory=dict)
    tags: Set[str] = field(default_factory=set)
    reputation: str = 'unknown'


class EntityAttributor:
    """
    Attributes wallet clusters to known entities using:
    - Known address databases
    - Behavioral patterns
    - Transaction patterns
    - Exchange signatures
    - Mining pool patterns
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize entity attributor

        Args:
            config: Configuration dictionary
        """
        self.config = config or {}

        # Attribution parameters
        self.min_confidence = self.config.get('min_confidence', 0.7)
        self.min_address_match = self.config.get('min_address_match', 1)

        # Known entity database
        self.known_entities: Dict[str, KnownEntity] = {}
        self.address_to_entity: Dict[str, str] = {}

        # Initialize with default entities
        self._initialize_known_entities()

        logger.info(f"Entity attributor initialized with {len(self.known_entities)} known entities")

    def attribute_cluster(self, cluster) -> Dict[str, Any]:
        """
        Attribute a wallet cluster to a known entity

        Args:
            cluster: AddressCluster object

        Returns:
            Attribution results
        """
        logger.info(f"Attributing cluster {cluster.cluster_id} with {len(cluster.addresses)} addresses")

        # Check for direct address matches
        direct_match = self._check_direct_matches(cluster.addresses)
        if direct_match:
            return direct_match

        # Check behavioral patterns
        behavioral_match = self._check_behavioral_patterns(cluster)
        if behavioral_match and behavioral_match['confidence'] >= self.min_confidence:
            return behavioral_match

        # Check transaction patterns
        pattern_match = self._check_transaction_patterns(cluster)
        if pattern_match and pattern_match['confidence'] >= self.min_confidence:
            return pattern_match

        # No confident attribution
        return {
            'entity_identified': False,
            'confidence': 0.0,
            'evidence': {
                'checked_entities': len(self.known_entities),
                'checked_addresses': len(cluster.addresses)
            }
        }

    def add_known_entity(self, entity: KnownEntity):
        """Add a known entity to the database"""
        self.known_entities[entity.entity_id] = entity

        for address in entity.addresses:
            self.address_to_entity[address] = entity.entity_id

        logger.info(f"Added entity {entity.name} with {len(entity.addresses)} addresses")

    def load_entities_from_file(self, file_path: str):
        """Load known entities from JSON file"""
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)

            for entity_data in data.get('entities', []):
                entity = KnownEntity(
                    entity_id=entity_data['entity_id'],
                    name=entity_data['name'],
                    entity_type=entity_data['entity_type'],
                    addresses=set(entity_data.get('addresses', [])),
                    address_patterns=entity_data.get('address_patterns', []),
                    behavioral_signatures=entity_data.get('behavioral_signatures', {}),
                    reputation=entity_data.get('reputation', 'unknown'),
                    tags=set(entity_data.get('tags', []))
                )
                self.add_known_entity(entity)

            logger.info(f"Loaded {len(data.get('entities', []))} entities from {file_path}")

        except Exception as e:
            logger.error(f"Error loading entities from {file_path}: {e}")

    def get_entity_info(self, entity_id: str) -> Optional[Dict[str, Any]]:
        """Get information about a known entity"""
        if entity_id not in self.known_entities:
            return None

        entity = self.known_entities[entity_id]

        return {
            'entity_id': entity.entity_id,
            'name': entity.name,
            'entity_type': entity.entity_type,
            'address_count': len(entity.addresses),
            'reputation': entity.reputation,
            'tags': list(entity.tags),
            'last_updated': entity.last_updated.isoformat() if entity.last_updated else None
        }

    def search_entities(self, query: str) -> List[Dict[str, Any]]:
        """Search for entities by name or type"""
        results = []

        query_lower = query.lower()

        for entity in self.known_entities.values():
            if (query_lower in entity.name.lower() or
                query_lower in entity.entity_type.lower() or
                any(query_lower in tag.lower() for tag in entity.tags)):

                results.append(self.get_entity_info(entity.entity_id))

        return results

    def _check_direct_matches(self, addresses: Set[str]) -> Optional[Dict[str, Any]]:
        """Check for direct address matches with known entities"""
        entity_matches = defaultdict(int)

        for address in addresses:
            if address in self.address_to_entity:
                entity_id = self.address_to_entity[address]
                entity_matches[entity_id] += 1

        if not entity_matches:
            return None

        # Find entity with most matches
        best_entity_id = max(entity_matches.items(), key=lambda x: x[1])[0]
        match_count = entity_matches[best_entity_id]

        entity = self.known_entities[best_entity_id]

        # Calculate confidence based on match ratio
        confidence = min(1.0, match_count / len(addresses) + 0.3)

        if match_count >= self.min_address_match:
            return {
                'entity_identified': True,
                'entity_type': entity.entity_type,
                'entity_name': entity.name,
                'entity_id': entity.entity_id,
                'confidence': confidence,
                'matching_addresses': match_count,
                'evidence': {
                    'match_type': 'direct_address_match',
                    'matched_addresses': match_count,
                    'total_addresses': len(addresses)
                },
                'tags': entity.tags,
                'reputation': entity.reputation
            }

        return None

    def _check_behavioral_patterns(self, cluster) -> Optional[Dict[str, Any]]:
        """Check cluster behavior against known entity patterns"""
        best_match = None
        best_confidence = 0.0

        for entity in self.known_entities.values():
            if not entity.behavioral_signatures:
                continue

            confidence = self._match_behavioral_signature(cluster, entity)

            if confidence > best_confidence and confidence >= self.min_confidence:
                best_confidence = confidence
                best_match = entity

        if best_match:
            return {
                'entity_identified': True,
                'entity_type': best_match.entity_type,
                'entity_name': best_match.name,
                'entity_id': best_match.entity_id,
                'confidence': best_confidence,
                'matching_addresses': 0,
                'evidence': {
                    'match_type': 'behavioral_pattern',
                    'signatures_matched': list(best_match.behavioral_signatures.keys())
                },
                'tags': best_match.tags,
                'reputation': best_match.reputation
            }

        return None

    def _check_transaction_patterns(self, cluster) -> Optional[Dict[str, Any]]:
        """Check transaction patterns for entity identification"""
        # Analyze transaction patterns in cluster
        patterns = self._analyze_cluster_patterns(cluster)

        # Exchange pattern
        if patterns.get('has_hot_wallet_pattern', False):
            return {
                'entity_identified': True,
                'entity_type': 'exchange',
                'entity_name': 'Unknown Exchange',
                'entity_id': 'exchange_unknown',
                'confidence': 0.75,
                'matching_addresses': 0,
                'evidence': {
                    'match_type': 'transaction_pattern',
                    'pattern': 'hot_wallet_consolidation'
                },
                'tags': {'exchange', 'custodial_service'},
                'reputation': 'unknown'
            }

        # Mining pool pattern
        if patterns.get('has_mining_pattern', False):
            return {
                'entity_identified': True,
                'entity_type': 'mining_pool',
                'entity_name': 'Unknown Mining Pool',
                'entity_id': 'mining_unknown',
                'confidence': 0.7,
                'matching_addresses': 0,
                'evidence': {
                    'match_type': 'transaction_pattern',
                    'pattern': 'mining_pool_distribution'
                },
                'tags': {'mining_pool'},
                'reputation': 'high'
            }

        # Merchant pattern
        if patterns.get('has_merchant_pattern', False):
            return {
                'entity_identified': True,
                'entity_type': 'merchant',
                'entity_name': 'Unknown Merchant',
                'entity_id': 'merchant_unknown',
                'confidence': 0.65,
                'matching_addresses': 0,
                'evidence': {
                    'match_type': 'transaction_pattern',
                    'pattern': 'merchant_payment_processor'
                },
                'tags': {'merchant', 'payment_processor'},
                'reputation': 'medium'
            }

        return None

    def _match_behavioral_signature(self, cluster, entity: KnownEntity) -> float:
        """Match cluster behavior against entity signature"""
        signatures = entity.behavioral_signatures
        confidence = 0.0
        matches = 0
        total_checks = 0

        # Check transaction volume pattern
        if 'avg_transaction_volume' in signatures:
            total_checks += 1
            expected_volume = signatures['avg_transaction_volume']
            actual_volume = cluster.total_volume / cluster.total_transactions if cluster.total_transactions > 0 else 0

            # Allow 50% variance
            if abs(actual_volume - expected_volume) / expected_volume < 0.5:
                matches += 1

        # Check transaction frequency
        if 'high_frequency' in signatures:
            total_checks += 1
            if cluster.total_transactions > signatures.get('min_transactions', 100):
                matches += 1

        # Check cluster size
        if 'typical_cluster_size' in signatures:
            total_checks += 1
            expected_size = signatures['typical_cluster_size']
            actual_size = len(cluster.addresses)

            if abs(actual_size - expected_size) / expected_size < 0.3:
                matches += 1

        # Check for specific tags
        if 'required_tags' in signatures:
            total_checks += 1
            required_tags = set(signatures['required_tags'])
            if required_tags.issubset(cluster.tags):
                matches += 1

        if total_checks > 0:
            confidence = matches / total_checks

        return confidence

    def _analyze_cluster_patterns(self, cluster) -> Dict[str, bool]:
        """Analyze cluster for characteristic patterns"""
        patterns = {
            'has_hot_wallet_pattern': False,
            'has_mining_pattern': False,
            'has_merchant_pattern': False
        }

        # Hot wallet pattern: large cluster with high transaction volume
        if len(cluster.addresses) > 100 and cluster.total_transactions > 1000:
            patterns['has_hot_wallet_pattern'] = True

        # Mining pool pattern: regular payouts
        if 'regular_payouts' in cluster.tags or cluster.total_transactions > 500:
            patterns['has_mining_pattern'] = True

        # Merchant pattern: many incoming transactions
        if 'payment_processor' in cluster.tags:
            patterns['has_merchant_pattern'] = True

        return patterns

    def _initialize_known_entities(self):
        """Initialize database with common known entities"""
        # Major exchanges
        exchanges = [
            {
                'entity_id': 'binance',
                'name': 'Binance',
                'entity_type': 'exchange',
                'reputation': 'high',
                'tags': ['exchange', 'custodial', 'major_exchange'],
                'behavioral_signatures': {
                    'high_frequency': True,
                    'min_transactions': 10000,
                    'typical_cluster_size': 5000
                }
            },
            {
                'entity_id': 'coinbase',
                'name': 'Coinbase',
                'entity_type': 'exchange',
                'reputation': 'high',
                'tags': ['exchange', 'custodial', 'major_exchange', 'regulated'],
                'behavioral_signatures': {
                    'high_frequency': True,
                    'min_transactions': 8000,
                    'typical_cluster_size': 3000
                }
            },
            {
                'entity_id': 'kraken',
                'name': 'Kraken',
                'entity_type': 'exchange',
                'reputation': 'high',
                'tags': ['exchange', 'custodial', 'major_exchange'],
                'behavioral_signatures': {
                    'high_frequency': True,
                    'min_transactions': 5000
                }
            }
        ]

        # Mining pools
        mining_pools = [
            {
                'entity_id': 'antpool',
                'name': 'AntPool',
                'entity_type': 'mining_pool',
                'reputation': 'high',
                'tags': ['mining_pool', 'large_pool'],
                'behavioral_signatures': {
                    'regular_payouts': True,
                    'min_transactions': 1000
                }
            },
            {
                'entity_id': 'f2pool',
                'name': 'F2Pool',
                'entity_type': 'mining_pool',
                'reputation': 'high',
                'tags': ['mining_pool', 'large_pool']
            }
        ]

        # Known malicious entities
        malicious = [
            {
                'entity_id': 'wannacry',
                'name': 'WannaCry Ransomware',
                'entity_type': 'ransomware',
                'reputation': 'malicious',
                'tags': ['ransomware', 'malware', 'criminal']
            },
            {
                'entity_id': 'silkroad',
                'name': 'Silk Road (Historical)',
                'entity_type': 'darknet_market',
                'reputation': 'malicious',
                'tags': ['darknet', 'illegal_marketplace', 'seized']
            }
        ]

        # Add all entities
        for entity_data in exchanges + mining_pools + malicious:
            entity = KnownEntity(
                entity_id=entity_data['entity_id'],
                name=entity_data['name'],
                entity_type=entity_data['entity_type'],
                addresses=set(),
                address_patterns=[],
                behavioral_signatures=entity_data.get('behavioral_signatures', {}),
                reputation=entity_data.get('reputation', 'unknown'),
                tags=set(entity_data.get('tags', [])),
                last_updated=datetime.now()
            )
            self.known_entities[entity.entity_id] = entity

        logger.info(f"Initialized {len(self.known_entities)} default entities")

    def export_entities(self, output_file: str):
        """Export known entities to JSON file"""
        export_data = {
            'export_timestamp': datetime.now().isoformat(),
            'total_entities': len(self.known_entities),
            'entities': []
        }

        for entity in self.known_entities.values():
            export_data['entities'].append({
                'entity_id': entity.entity_id,
                'name': entity.name,
                'entity_type': entity.entity_type,
                'addresses': list(entity.addresses),
                'address_patterns': entity.address_patterns,
                'behavioral_signatures': entity.behavioral_signatures,
                'reputation': entity.reputation,
                'tags': list(entity.tags),
                'last_updated': entity.last_updated.isoformat() if entity.last_updated else None
            })

        with open(output_file, 'w') as f:
            json.dump(export_data, f, indent=2)

        logger.info(f"Exported {len(self.known_entities)} entities to {output_file}")

    def get_statistics(self) -> Dict[str, Any]:
        """Get entity database statistics"""
        stats = {
            'total_entities': len(self.known_entities),
            'total_known_addresses': len(self.address_to_entity),
            'by_type': defaultdict(int),
            'by_reputation': defaultdict(int)
        }

        for entity in self.known_entities.values():
            stats['by_type'][entity.entity_type] += 1
            stats['by_reputation'][entity.reputation] += 1

        return dict(stats)
