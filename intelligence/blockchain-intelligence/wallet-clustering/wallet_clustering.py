"""
Advanced Wallet Clustering and Attribution System
Performs sophisticated blockchain analysis to cluster addresses and identify entities
"""

import hashlib
import json
import logging
from typing import Dict, List, Set, Optional, Tuple, Any
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict
import networkx as nx

from .common_input_heuristic import CommonInputHeuristic
from .change_address_detector import ChangeAddressDetector
from .peel_chain_analyzer import PeelChainAnalyzer
from .entity_attribution import EntityAttributor
from .mixing_detector import MixingDetector
from .exchange_identifier import ExchangeIdentifier

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class AddressCluster:
    """Represents a cluster of related addresses"""
    cluster_id: str
    addresses: Set[str] = field(default_factory=set)
    entity_type: Optional[str] = None
    entity_name: Optional[str] = None
    confidence: float = 0.0
    risk_score: float = 0.0
    tags: Set[str] = field(default_factory=set)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    total_transactions: int = 0
    total_volume: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ClusterLink:
    """Represents a link between two addresses in a cluster"""
    source: str
    target: str
    link_type: str  # 'common_input', 'change', 'peel_chain', etc.
    confidence: float
    transaction_hash: Optional[str] = None
    timestamp: Optional[datetime] = None
    evidence: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ClusteringResult:
    """Complete clustering analysis result"""
    wallet_address: str
    cluster: AddressCluster
    links: List[ClusterLink]
    attribution: Dict[str, Any]
    risk_assessment: Dict[str, Any]
    mixing_detected: bool
    exchange_interactions: List[Dict[str, Any]]
    peel_chains: List[Dict[str, Any]]
    analysis_timestamp: datetime
    graph: Optional[nx.Graph] = None


class WalletClusterer:
    """
    Advanced wallet clustering engine that combines multiple heuristics
    to identify related addresses and attribute them to entities
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize wallet clusterer

        Args:
            config: Configuration dictionary for clustering parameters
        """
        self.config = config or {}

        # Initialize analysis components
        self.cih = CommonInputHeuristic(self.config.get('cih', {}))
        self.change_detector = ChangeAddressDetector(self.config.get('change', {}))
        self.peel_analyzer = PeelChainAnalyzer(self.config.get('peel', {}))
        self.entity_attributor = EntityAttributor(self.config.get('entity', {}))
        self.mixing_detector = MixingDetector(self.config.get('mixing', {}))
        self.exchange_identifier = ExchangeIdentifier(self.config.get('exchange', {}))

        # Cluster storage
        self.clusters: Dict[str, AddressCluster] = {}
        self.address_to_cluster: Dict[str, str] = {}
        self.cluster_graph = nx.Graph()

        # Analysis thresholds
        self.min_confidence = self.config.get('min_confidence', 0.6)
        self.max_cluster_size = self.config.get('max_cluster_size', 10000)
        self.enable_aggressive_clustering = self.config.get('aggressive', False)

        logger.info("Wallet clusterer initialized")

    def analyze_wallet(self, address: str,
                       depth: int = 2,
                       include_mixing: bool = True) -> ClusteringResult:
        """
        Perform comprehensive wallet clustering analysis

        Args:
            address: Bitcoin/crypto address to analyze
            depth: How many transaction hops to analyze
            include_mixing: Whether to detect mixing services

        Returns:
            ClusteringResult with complete analysis
        """
        logger.info(f"Starting wallet clustering for {address} (depth={depth})")

        start_time = datetime.now()

        # Get or create cluster for this address
        cluster_id = self._get_or_create_cluster(address)
        cluster = self.clusters[cluster_id]

        # Collect all links
        all_links: List[ClusterLink] = []

        # Phase 1: Common Input Heuristic
        logger.info("Phase 1: Applying common input heuristic")
        cih_results = self.cih.analyze_address(address, depth=depth)
        cih_links = self._process_cih_results(cih_results, cluster)
        all_links.extend(cih_links)

        # Phase 2: Change Address Detection
        logger.info("Phase 2: Detecting change addresses")
        change_results = self.change_detector.analyze_transactions(address, depth=depth)
        change_links = self._process_change_results(change_results, cluster)
        all_links.extend(change_links)

        # Phase 3: Peel Chain Analysis
        logger.info("Phase 3: Analyzing peel chains")
        peel_results = self.peel_analyzer.analyze_address(address, depth=depth)
        peel_links = self._process_peel_results(peel_results, cluster)
        all_links.extend(peel_links)

        # Phase 4: Entity Attribution
        logger.info("Phase 4: Performing entity attribution")
        attribution = self.entity_attributor.attribute_cluster(cluster)
        self._apply_attribution(cluster, attribution)

        # Phase 5: Exchange Identification
        logger.info("Phase 5: Identifying exchange interactions")
        exchange_interactions = self.exchange_identifier.identify_exchanges(
            list(cluster.addresses)
        )

        # Phase 6: Mixing Detection (if enabled)
        mixing_detected = False
        if include_mixing:
            logger.info("Phase 6: Detecting mixing services")
            mixing_results = self.mixing_detector.detect_mixing(list(cluster.addresses))
            mixing_detected = mixing_results['detected']
            if mixing_detected:
                cluster.tags.add('mixing_service_user')
                cluster.risk_score += 0.3

        # Phase 7: Risk Assessment
        logger.info("Phase 7: Calculating risk score")
        risk_assessment = self._calculate_risk_score(
            cluster,
            all_links,
            mixing_detected,
            exchange_interactions,
            peel_results
        )

        # Build cluster graph
        logger.info("Building cluster graph")
        graph = self._build_cluster_graph(cluster, all_links)

        # Create result
        result = ClusteringResult(
            wallet_address=address,
            cluster=cluster,
            links=all_links,
            attribution=attribution,
            risk_assessment=risk_assessment,
            mixing_detected=mixing_detected,
            exchange_interactions=exchange_interactions,
            peel_chains=peel_results.get('chains', []),
            analysis_timestamp=datetime.now(),
            graph=graph
        )

        elapsed = (datetime.now() - start_time).total_seconds()
        logger.info(f"Clustering complete: {len(cluster.addresses)} addresses in {elapsed:.2f}s")

        return result

    def merge_clusters(self, cluster_id1: str, cluster_id2: str,
                      evidence: Dict[str, Any]) -> str:
        """
        Merge two clusters when new evidence links them

        Args:
            cluster_id1: First cluster ID
            cluster_id2: Second cluster ID
            evidence: Evidence supporting the merge

        Returns:
            ID of merged cluster
        """
        if cluster_id1 not in self.clusters or cluster_id2 not in self.clusters:
            raise ValueError("One or both clusters not found")

        cluster1 = self.clusters[cluster_id1]
        cluster2 = self.clusters[cluster_id2]

        logger.info(f"Merging clusters {cluster_id1} ({len(cluster1.addresses)} addrs) "
                   f"and {cluster_id2} ({len(cluster2.addresses)} addrs)")

        # Merge into cluster1
        cluster1.addresses.update(cluster2.addresses)
        cluster1.tags.update(cluster2.tags)
        cluster1.total_transactions += cluster2.total_transactions
        cluster1.total_volume += cluster2.total_volume

        # Update timestamps
        if cluster2.first_seen and (not cluster1.first_seen or
                                    cluster2.first_seen < cluster1.first_seen):
            cluster1.first_seen = cluster2.first_seen

        if cluster2.last_seen and (not cluster1.last_seen or
                                   cluster2.last_seen > cluster1.last_seen):
            cluster1.last_seen = cluster2.last_seen

        # Update address mappings
        for addr in cluster2.addresses:
            self.address_to_cluster[addr] = cluster_id1

        # Store merge evidence
        if 'merge_history' not in cluster1.metadata:
            cluster1.metadata['merge_history'] = []

        cluster1.metadata['merge_history'].append({
            'merged_cluster': cluster_id2,
            'timestamp': datetime.now().isoformat(),
            'evidence': evidence
        })

        # Remove old cluster
        del self.clusters[cluster_id2]

        logger.info(f"Merged cluster now contains {len(cluster1.addresses)} addresses")

        return cluster_id1

    def expand_cluster(self, cluster_id: str, depth: int = 1) -> Set[str]:
        """
        Expand a cluster by analyzing all member addresses more deeply

        Args:
            cluster_id: Cluster to expand
            depth: Analysis depth

        Returns:
            Set of newly discovered addresses
        """
        if cluster_id not in self.clusters:
            raise ValueError(f"Cluster {cluster_id} not found")

        cluster = self.clusters[cluster_id]
        original_addresses = cluster.addresses.copy()

        logger.info(f"Expanding cluster {cluster_id} with {len(original_addresses)} addresses")

        new_addresses = set()

        for address in original_addresses:
            # Analyze each address
            cih_results = self.cih.analyze_address(address, depth=depth)

            for related_addr in cih_results.get('related_addresses', []):
                if related_addr not in cluster.addresses:
                    cluster.addresses.add(related_addr)
                    self.address_to_cluster[related_addr] = cluster_id
                    new_addresses.add(related_addr)

        logger.info(f"Cluster expanded with {len(new_addresses)} new addresses")

        return new_addresses

    def get_cluster_summary(self, cluster_id: str) -> Dict[str, Any]:
        """Get detailed summary of a cluster"""
        if cluster_id not in self.clusters:
            raise ValueError(f"Cluster {cluster_id} not found")

        cluster = self.clusters[cluster_id]

        return {
            'cluster_id': cluster_id,
            'size': len(cluster.addresses),
            'entity_type': cluster.entity_type,
            'entity_name': cluster.entity_name,
            'confidence': cluster.confidence,
            'risk_score': cluster.risk_score,
            'tags': list(cluster.tags),
            'first_seen': cluster.first_seen.isoformat() if cluster.first_seen else None,
            'last_seen': cluster.last_seen.isoformat() if cluster.last_seen else None,
            'total_transactions': cluster.total_transactions,
            'total_volume': cluster.total_volume,
            'sample_addresses': list(cluster.addresses)[:10]
        }

    def export_clusters(self, output_file: str):
        """Export all clusters to JSON file"""
        export_data = {
            'export_timestamp': datetime.now().isoformat(),
            'total_clusters': len(self.clusters),
            'total_addresses': len(self.address_to_cluster),
            'clusters': []
        }

        for cluster_id, cluster in self.clusters.items():
            export_data['clusters'].append({
                'cluster_id': cluster_id,
                'addresses': list(cluster.addresses),
                'entity_type': cluster.entity_type,
                'entity_name': cluster.entity_name,
                'confidence': cluster.confidence,
                'risk_score': cluster.risk_score,
                'tags': list(cluster.tags),
                'metadata': cluster.metadata
            })

        with open(output_file, 'w') as f:
            json.dump(export_data, f, indent=2)

        logger.info(f"Exported {len(self.clusters)} clusters to {output_file}")

    def _get_or_create_cluster(self, address: str) -> str:
        """Get existing cluster for address or create new one"""
        if address in self.address_to_cluster:
            return self.address_to_cluster[address]

        # Create new cluster
        cluster_id = self._generate_cluster_id(address)
        cluster = AddressCluster(
            cluster_id=cluster_id,
            addresses={address}
        )

        self.clusters[cluster_id] = cluster
        self.address_to_cluster[address] = cluster_id

        return cluster_id

    def _generate_cluster_id(self, seed: str) -> str:
        """Generate unique cluster ID"""
        hash_input = f"{seed}_{datetime.now().isoformat()}"
        return hashlib.sha256(hash_input.encode()).hexdigest()[:16]

    def _process_cih_results(self, results: Dict[str, Any],
                            cluster: AddressCluster) -> List[ClusterLink]:
        """Process common input heuristic results"""
        links = []

        for addr_data in results.get('related_addresses', []):
            address = addr_data['address']
            confidence = addr_data.get('confidence', 0.8)

            if confidence >= self.min_confidence:
                # Add to cluster
                cluster.addresses.add(address)
                self.address_to_cluster[address] = cluster.cluster_id

                # Create link
                link = ClusterLink(
                    source=results.get('source_address', ''),
                    target=address,
                    link_type='common_input',
                    confidence=confidence,
                    transaction_hash=addr_data.get('transaction_hash'),
                    evidence=addr_data.get('evidence', {})
                )
                links.append(link)

        return links

    def _process_change_results(self, results: Dict[str, Any],
                               cluster: AddressCluster) -> List[ClusterLink]:
        """Process change address detection results"""
        links = []

        for change_data in results.get('change_addresses', []):
            address = change_data['address']
            confidence = change_data.get('confidence', 0.7)

            if confidence >= self.min_confidence:
                cluster.addresses.add(address)
                self.address_to_cluster[address] = cluster.cluster_id

                link = ClusterLink(
                    source=change_data.get('source_address', ''),
                    target=address,
                    link_type='change_address',
                    confidence=confidence,
                    transaction_hash=change_data.get('transaction_hash'),
                    evidence=change_data.get('evidence', {})
                )
                links.append(link)

        return links

    def _process_peel_results(self, results: Dict[str, Any],
                             cluster: AddressCluster) -> List[ClusterLink]:
        """Process peel chain analysis results"""
        links = []

        if results.get('is_peel_chain', False):
            cluster.tags.add('peel_chain')
            cluster.risk_score += 0.2

        for chain in results.get('chains', []):
            for addr in chain.get('addresses', []):
                cluster.addresses.add(addr)
                self.address_to_cluster[addr] = cluster.cluster_id

            # Create links for chain
            addresses = chain.get('addresses', [])
            for i in range(len(addresses) - 1):
                link = ClusterLink(
                    source=addresses[i],
                    target=addresses[i + 1],
                    link_type='peel_chain',
                    confidence=chain.get('confidence', 0.75),
                    evidence={'chain_length': len(addresses)}
                )
                links.append(link)

        return links

    def _apply_attribution(self, cluster: AddressCluster,
                          attribution: Dict[str, Any]):
        """Apply entity attribution to cluster"""
        if attribution.get('entity_identified', False):
            cluster.entity_type = attribution.get('entity_type')
            cluster.entity_name = attribution.get('entity_name')
            cluster.confidence = attribution.get('confidence', 0.0)

            # Add tags
            for tag in attribution.get('tags', []):
                cluster.tags.add(tag)

    def _calculate_risk_score(self, cluster: AddressCluster,
                             links: List[ClusterLink],
                             mixing_detected: bool,
                             exchange_interactions: List[Dict],
                             peel_results: Dict) -> Dict[str, Any]:
        """Calculate comprehensive risk score"""
        risk_factors = {
            'mixing_service_use': 0.0,
            'peel_chain_activity': 0.0,
            'exchange_interaction': 0.0,
            'cluster_complexity': 0.0,
            'suspicious_patterns': 0.0
        }

        # Mixing service usage
        if mixing_detected:
            risk_factors['mixing_service_use'] = 0.3

        # Peel chain activity
        if peel_results.get('is_peel_chain', False):
            chain_count = len(peel_results.get('chains', []))
            risk_factors['peel_chain_activity'] = min(0.25 * chain_count, 0.5)

        # Exchange interactions (legitimate exchanges reduce risk)
        if exchange_interactions:
            legitimate_exchanges = sum(1 for ex in exchange_interactions
                                      if ex.get('reputation', 'unknown') == 'high')
            risk_factors['exchange_interaction'] = -0.1 * min(legitimate_exchanges, 3)

        # Cluster complexity
        if len(cluster.addresses) > 100:
            risk_factors['cluster_complexity'] = 0.15

        # Suspicious patterns
        if 'darknet' in cluster.tags or 'ransomware' in cluster.tags:
            risk_factors['suspicious_patterns'] = 0.5

        # Calculate total risk score
        total_risk = max(0.0, min(1.0, sum(risk_factors.values())))
        cluster.risk_score = total_risk

        return {
            'total_risk_score': total_risk,
            'risk_level': self._get_risk_level(total_risk),
            'risk_factors': risk_factors,
            'explanation': self._generate_risk_explanation(risk_factors)
        }

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

    def _generate_risk_explanation(self, factors: Dict[str, float]) -> str:
        """Generate human-readable risk explanation"""
        explanations = []

        if factors['mixing_service_use'] > 0:
            explanations.append("Uses mixing/tumbling services")
        if factors['peel_chain_activity'] > 0:
            explanations.append("Exhibits peel chain patterns")
        if factors['exchange_interaction'] < 0:
            explanations.append("Interacts with legitimate exchanges")
        if factors['cluster_complexity'] > 0:
            explanations.append("Large complex wallet cluster")
        if factors['suspicious_patterns'] > 0:
            explanations.append("Associated with suspicious activity")

        return "; ".join(explanations) if explanations else "No significant risk factors"

    def _build_cluster_graph(self, cluster: AddressCluster,
                            links: List[ClusterLink]) -> nx.Graph:
        """Build NetworkX graph representation of cluster"""
        G = nx.Graph()

        # Add nodes
        for address in cluster.addresses:
            G.add_node(address, cluster_id=cluster.cluster_id)

        # Add edges
        for link in links:
            G.add_edge(
                link.source,
                link.target,
                link_type=link.link_type,
                confidence=link.confidence,
                transaction_hash=link.transaction_hash
            )

        return G
