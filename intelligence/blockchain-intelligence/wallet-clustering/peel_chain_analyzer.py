"""
Peel Chain Analysis System
Detects peel chain patterns used in money laundering and mixing
"""

import logging
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class PeelChainLink:
    """Single link in a peel chain"""
    transaction_hash: str
    from_address: str
    to_address: str
    peel_amount: float
    remaining_amount: float
    timestamp: datetime
    hop_number: int


@dataclass
class PeelChain:
    """Complete peel chain sequence"""
    chain_id: str
    links: List[PeelChainLink]
    addresses: List[str]
    start_address: str
    end_address: Optional[str]
    total_peeled: float
    total_amount: float
    chain_length: int
    avg_peel_ratio: float
    time_span: timedelta
    confidence: float
    characteristics: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PeelChainDetectionResult:
    """Result of peel chain detection"""
    address: str
    is_peel_chain: bool
    chains: List[PeelChain]
    total_chains: int
    max_chain_length: int
    risk_score: float
    indicators: List[str]


class PeelChainAnalyzer:
    """
    Detects and analyzes peel chain patterns

    Peel chain characteristics:
    - Sequential transactions
    - Each transaction "peels off" a small amount
    - Remaining balance moves to new address
    - Common in money laundering and mixing
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize peel chain analyzer

        Args:
            config: Configuration dictionary
        """
        self.config = config or {}

        # Detection parameters
        self.min_chain_length = self.config.get('min_chain_length', 3)
        self.max_peel_ratio = self.config.get('max_peel_ratio', 0.3)  # 30% per peel
        self.min_peel_ratio = self.config.get('min_peel_ratio', 0.01)  # 1% per peel
        self.max_time_between_hops = self.config.get('max_time_hours', 72)  # 72 hours
        self.min_confidence = self.config.get('min_confidence', 0.7)

        # Tracking
        self.detected_chains: Dict[str, PeelChain] = {}

        logger.info("Peel chain analyzer initialized")

    def analyze_address(self, address: str, depth: int = 10) -> Dict[str, Any]:
        """
        Analyze address for peel chain patterns

        Args:
            address: Address to analyze
            depth: Maximum chain depth to follow

        Returns:
            Peel chain analysis results
        """
        logger.info(f"Analyzing peel chains for {address} (depth={depth})")

        # Detect peel chains starting from this address
        chains = self._detect_peel_chains_from_address(address, depth)

        # Calculate statistics
        is_peel_chain = len(chains) > 0
        total_chains = len(chains)
        max_chain_length = max([c.chain_length for c in chains]) if chains else 0

        # Calculate risk score
        risk_score = self._calculate_peel_chain_risk(chains)

        # Generate indicators
        indicators = self._generate_indicators(chains)

        result = {
            'address': address,
            'is_peel_chain': is_peel_chain,
            'chains': [self._serialize_chain(c) for c in chains],
            'total_chains': total_chains,
            'max_chain_length': max_chain_length,
            'risk_score': risk_score,
            'indicators': indicators,
            'analysis_depth': depth
        }

        logger.info(f"Detected {total_chains} peel chains with max length {max_chain_length}")

        return result

    def detect_layering_activity(self, addresses: List[str]) -> Dict[str, Any]:
        """
        Detect money laundering layering activity across multiple addresses

        Args:
            addresses: List of addresses to analyze

        Returns:
            Layering detection results
        """
        logger.info(f"Analyzing {len(addresses)} addresses for layering activity")

        all_chains = []
        interconnected_addresses = set()

        for addr in addresses:
            result = self.analyze_address(addr, depth=5)
            all_chains.extend(result.get('chains', []))

            # Check if chains interconnect
            for chain in result.get('chains', []):
                chain_addrs = set(chain.get('addresses', []))
                if chain_addrs.intersection(set(addresses)):
                    interconnected_addresses.update(chain_addrs)

        # Analyze patterns
        is_layering = len(interconnected_addresses) > len(addresses) * 0.5

        layering_indicators = []
        if is_layering:
            layering_indicators.append('Multiple interconnected peel chains')

        if len(all_chains) > len(addresses) * 2:
            layering_indicators.append('High peel chain density')

        # Calculate complexity score
        complexity_score = min(1.0, len(interconnected_addresses) / 100.0)

        return {
            'is_layering_detected': is_layering,
            'total_peel_chains': len(all_chains),
            'interconnected_addresses': len(interconnected_addresses),
            'layering_indicators': layering_indicators,
            'complexity_score': complexity_score,
            'risk_level': 'HIGH' if is_layering else 'MEDIUM' if all_chains else 'LOW'
        }

    def _detect_peel_chains_from_address(self, start_address: str,
                                        max_depth: int) -> List[PeelChain]:
        """Detect peel chains starting from an address"""
        chains = []

        # Get transactions from address
        transactions = self._get_outgoing_transactions(start_address)

        for tx in transactions:
            # Check if this could be start of a peel chain
            chain = self._follow_peel_chain(tx, start_address, max_depth)

            if chain and chain.chain_length >= self.min_chain_length:
                if chain.confidence >= self.min_confidence:
                    chains.append(chain)
                    self.detected_chains[chain.chain_id] = chain

        return chains

    def _follow_peel_chain(self, start_tx: Dict[str, Any],
                          start_address: str,
                          max_depth: int) -> Optional[PeelChain]:
        """Follow a potential peel chain"""
        import hashlib

        links = []
        current_address = start_address
        current_tx = start_tx
        remaining_amount = start_tx.get('total_input', 0)
        total_peeled = 0

        for hop in range(max_depth):
            # Analyze transaction outputs
            outputs = current_tx.get('outputs', [])

            if len(outputs) != 2:
                # Peel chains typically have exactly 2 outputs
                break

            # Identify peel and change outputs
            peel_output, change_output = self._identify_peel_outputs(outputs, remaining_amount)

            if not peel_output or not change_output:
                break

            peel_amount = peel_output['value']
            change_amount = change_output['value']
            peel_ratio = peel_amount / remaining_amount if remaining_amount > 0 else 0

            # Check if this matches peel pattern
            if not (self.min_peel_ratio <= peel_ratio <= self.max_peel_ratio):
                break

            # Create link
            link = PeelChainLink(
                transaction_hash=current_tx['hash'],
                from_address=current_address,
                to_address=change_output['address'],
                peel_amount=peel_amount,
                remaining_amount=change_amount,
                timestamp=current_tx.get('timestamp', datetime.now()),
                hop_number=hop
            )
            links.append(link)

            total_peeled += peel_amount
            remaining_amount = change_amount

            # Follow to next transaction
            next_address = change_output['address']
            next_txs = self._get_outgoing_transactions(next_address)

            if not next_txs:
                break

            # Check timing
            next_tx = next_txs[0]
            time_diff = (next_tx.get('timestamp', datetime.now()) -
                        current_tx.get('timestamp', datetime.now()))

            if time_diff.total_seconds() > self.max_time_between_hops * 3600:
                break

            current_address = next_address
            current_tx = next_tx

        if len(links) < self.min_chain_length:
            return None

        # Calculate chain metrics
        addresses = [start_address] + [link.to_address for link in links]
        avg_peel_ratio = total_peeled / (remaining_amount + total_peeled) / len(links)
        time_span = links[-1].timestamp - links[0].timestamp

        # Calculate confidence
        confidence = self._calculate_chain_confidence(links, avg_peel_ratio)

        # Generate chain ID
        chain_id = hashlib.md5(f"{start_address}_{start_tx['hash']}".encode()).hexdigest()[:12]

        # Analyze characteristics
        characteristics = self._analyze_chain_characteristics(links)

        chain = PeelChain(
            chain_id=chain_id,
            links=links,
            addresses=addresses,
            start_address=start_address,
            end_address=links[-1].to_address if links else None,
            total_peeled=total_peeled,
            total_amount=remaining_amount + total_peeled,
            chain_length=len(links),
            avg_peel_ratio=avg_peel_ratio,
            time_span=time_span,
            confidence=confidence,
            characteristics=characteristics
        )

        return chain

    def _identify_peel_outputs(self, outputs: List[Dict[str, Any]],
                              total_amount: float) -> Tuple[Optional[Dict], Optional[Dict]]:
        """Identify which output is the peel and which is the change"""
        if len(outputs) != 2:
            return None, None

        output1, output2 = outputs
        value1, value2 = output1['value'], output2['value']

        # Smaller value is typically the peel, larger is change
        if value1 < value2:
            return output1, output2
        else:
            return output2, output1

    def _calculate_chain_confidence(self, links: List[PeelChainLink],
                                   avg_peel_ratio: float) -> float:
        """Calculate confidence that this is a genuine peel chain"""
        confidence = 0.5  # Base confidence

        # Length increases confidence
        if len(links) >= 5:
            confidence += 0.2
        elif len(links) >= 3:
            confidence += 0.1

        # Consistent peel ratios increase confidence
        peel_ratios = [
            link.peel_amount / (link.peel_amount + link.remaining_amount)
            for link in links
        ]
        variance = sum((r - avg_peel_ratio) ** 2 for r in peel_ratios) / len(peel_ratios)

        if variance < 0.01:  # Very consistent
            confidence += 0.2
        elif variance < 0.05:
            confidence += 0.1

        # Regular timing increases confidence
        if len(links) > 1:
            time_diffs = [
                (links[i+1].timestamp - links[i].timestamp).total_seconds()
                for i in range(len(links) - 1)
            ]
            avg_time_diff = sum(time_diffs) / len(time_diffs)
            time_variance = sum((t - avg_time_diff) ** 2 for t in time_diffs) / len(time_diffs)

            if time_variance < 3600 * 3600:  # Within 1 hour variance
                confidence += 0.1

        return min(1.0, confidence)

    def _analyze_chain_characteristics(self, links: List[PeelChainLink]) -> Dict[str, Any]:
        """Analyze characteristics of peel chain"""
        if not links:
            return {}

        peel_amounts = [link.peel_amount for link in links]
        time_diffs = [
            (links[i+1].timestamp - links[i].timestamp).total_seconds() / 3600
            for i in range(len(links) - 1)
        ] if len(links) > 1 else []

        return {
            'avg_peel_amount': sum(peel_amounts) / len(peel_amounts),
            'min_peel_amount': min(peel_amounts),
            'max_peel_amount': max(peel_amounts),
            'avg_time_between_hops_hours': sum(time_diffs) / len(time_diffs) if time_diffs else 0,
            'total_duration_hours': (links[-1].timestamp - links[0].timestamp).total_seconds() / 3600,
            'unique_addresses': len(set([link.from_address for link in links] +
                                       [link.to_address for link in links]))
        }

    def _calculate_peel_chain_risk(self, chains: List[PeelChain]) -> float:
        """Calculate risk score based on peel chain activity"""
        if not chains:
            return 0.0

        risk = 0.0

        # Multiple chains increase risk
        risk += min(0.3, len(chains) * 0.1)

        # Long chains increase risk
        max_length = max(c.chain_length for c in chains)
        risk += min(0.3, max_length / 20.0)

        # High total value increases risk
        total_value = sum(c.total_amount for c in chains)
        if total_value > 100:
            risk += 0.2
        elif total_value > 10:
            risk += 0.1

        # Complex patterns increase risk
        if len(chains) > 1:
            # Check for interconnected chains
            all_addresses = set()
            for chain in chains:
                all_addresses.update(chain.addresses)

            if len(all_addresses) < sum(len(c.addresses) for c in chains):
                risk += 0.2  # Address reuse across chains

        return min(1.0, risk)

    def _generate_indicators(self, chains: List[PeelChain]) -> List[str]:
        """Generate risk indicators from peel chains"""
        indicators = []

        if not chains:
            return indicators

        # Check various patterns
        if len(chains) > 2:
            indicators.append('Multiple peel chains detected')

        max_length = max(c.chain_length for c in chains)
        if max_length > 10:
            indicators.append(f'Very long peel chain ({max_length} hops)')
        elif max_length > 5:
            indicators.append(f'Long peel chain ({max_length} hops)')

        total_value = sum(c.total_amount for c in chains)
        if total_value > 100:
            indicators.append('High value peel chains')

        # Check timing patterns
        fast_chains = [c for c in chains if c.time_span.total_seconds() < 3600]
        if fast_chains:
            indicators.append('Rapid peel chain execution')

        # Check for consistent patterns (automated)
        avg_ratios = [c.avg_peel_ratio for c in chains]
        if len(avg_ratios) > 1:
            variance = sum((r - sum(avg_ratios) / len(avg_ratios)) ** 2
                          for r in avg_ratios) / len(avg_ratios)
            if variance < 0.01:
                indicators.append('Highly consistent peel ratios (automated)')

        return indicators

    def _get_outgoing_transactions(self, address: str) -> List[Dict[str, Any]]:
        """Get outgoing transactions from address"""
        # Simulate blockchain query
        import random
        from datetime import timedelta

        # Simulate 1-3 transactions
        num_txs = random.randint(1, 3)
        transactions = []

        current_time = datetime.now()

        for i in range(num_txs):
            # Simulate peel pattern: small peel + large change
            total_input = random.uniform(1.0, 10.0) if i == 0 else random.uniform(0.5, 5.0)
            peel_ratio = random.uniform(0.05, 0.2)  # 5-20% peel
            peel_amount = total_input * peel_ratio
            change_amount = total_input * (1 - peel_ratio) - 0.0001  # Fee

            outputs = [
                {
                    'address': f"1{random.choice('XYZ')}{random.randint(1000000, 9999999)}",
                    'value': peel_amount
                },
                {
                    'address': f"1{random.choice('ABC')}{random.randint(1000000, 9999999)}",
                    'value': change_amount
                }
            ]

            # Randomize output order
            if random.random() > 0.5:
                outputs = outputs[::-1]

            tx_time = current_time - timedelta(hours=random.uniform(0.5, 4))

            transactions.append({
                'hash': f"{random.randint(10000000, 99999999):08x}",
                'inputs': [address],
                'outputs': outputs,
                'timestamp': tx_time,
                'total_input': total_input,
                'total_output': peel_amount + change_amount,
                'fee': total_input - peel_amount - change_amount
            })

            current_time = tx_time

        return transactions

    def _serialize_chain(self, chain: PeelChain) -> Dict[str, Any]:
        """Serialize peel chain to dict"""
        return {
            'chain_id': chain.chain_id,
            'addresses': chain.addresses,
            'start_address': chain.start_address,
            'end_address': chain.end_address,
            'chain_length': chain.chain_length,
            'total_peeled': chain.total_peeled,
            'total_amount': chain.total_amount,
            'avg_peel_ratio': chain.avg_peel_ratio,
            'time_span_hours': chain.time_span.total_seconds() / 3600,
            'confidence': chain.confidence,
            'characteristics': chain.characteristics
        }
