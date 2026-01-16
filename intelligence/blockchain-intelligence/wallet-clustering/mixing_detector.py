"""
Mixing Service Detection System
Detects usage of cryptocurrency mixing/tumbling services
"""

import logging
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict
import re

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class MixingServiceSignature:
    """Signature of a known mixing service"""
    service_name: str
    service_type: str  # 'coinjoin', 'centralized_mixer', 'privacy_wallet'
    known_addresses: Set[str] = field(default_factory=set)
    transaction_patterns: Dict[str, Any] = field(default_factory=dict)
    typical_fees: List[float] = field(default_factory=list)
    min_participants: Optional[int] = None
    output_denominations: List[float] = field(default_factory=list)


@dataclass
class MixingDetectionResult:
    """Result of mixing service detection"""
    detected: bool
    service_type: Optional[str] = None
    service_name: Optional[str] = None
    confidence: float = 0.0
    mixing_transactions: List[str] = field(default_factory=list)
    indicators: List[str] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)


class MixingDetector:
    """
    Detects cryptocurrency mixing services:
    - CoinJoin (Wasabi Wallet, Samourai Whirlpool, JoinMarket)
    - Centralized mixers (ChipMixer, Bitcoin Fog, etc.)
    - Privacy wallets (Monero gateways, etc.)
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize mixing detector

        Args:
            config: Configuration dictionary
        """
        self.config = config or {}

        # Detection parameters
        self.min_confidence = self.config.get('min_confidence', 0.7)
        self.coinjoin_min_inputs = self.config.get('coinjoin_min_inputs', 5)
        self.coinjoin_min_equal_outputs = self.config.get('coinjoin_min_equal_outputs', 3)

        # Known mixing services
        self.mixing_services: Dict[str, MixingServiceSignature] = {}
        self._initialize_mixing_signatures()

        logger.info("Mixing detector initialized")

    def detect_mixing(self, addresses: List[str]) -> Dict[str, Any]:
        """
        Detect mixing service usage across addresses

        Args:
            addresses: List of addresses to analyze

        Returns:
            Mixing detection results
        """
        logger.info(f"Detecting mixing services for {len(addresses)} addresses")

        detected = False
        service_type = None
        service_name = None
        max_confidence = 0.0
        mixing_txs = []
        all_indicators = set()

        # Check each address
        for address in addresses:
            result = self._analyze_address_mixing(address)

            if result.detected and result.confidence > max_confidence:
                detected = True
                service_type = result.service_type
                service_name = result.service_name
                max_confidence = result.confidence
                mixing_txs.extend(result.mixing_transactions)
                all_indicators.update(result.indicators)

        # Compile evidence
        evidence = {
            'addresses_analyzed': len(addresses),
            'mixing_transactions_found': len(mixing_txs),
            'unique_services_detected': len(set([service_name] if service_name else []))
        }

        return {
            'detected': detected,
            'service_type': service_type,
            'service_name': service_name,
            'confidence': max_confidence,
            'mixing_transactions': mixing_txs,
            'indicators': list(all_indicators),
            'evidence': evidence
        }

    def detect_coinjoin(self, transaction: Dict[str, Any]) -> Dict[str, Any]:
        """
        Detect if a transaction is a CoinJoin

        Args:
            transaction: Transaction data

        Returns:
            CoinJoin detection result
        """
        tx_hash = transaction['hash']
        inputs = transaction.get('inputs', [])
        outputs = transaction.get('outputs', [])

        is_coinjoin = False
        coinjoin_type = None
        confidence = 0.0
        indicators = []

        # Check input count
        if len(inputs) < self.coinjoin_min_inputs:
            return {
                'is_coinjoin': False,
                'confidence': 0.0,
                'reason': 'Too few inputs'
            }

        # Check for equal-output pattern
        output_values = [o['value'] for o in outputs]
        equal_outputs = self._find_equal_outputs(output_values)

        if len(equal_outputs) >= self.coinjoin_min_equal_outputs:
            is_coinjoin = True
            confidence += 0.4
            indicators.append(f'{len(equal_outputs)} equal-value outputs')

        # Check for Wasabi Wallet pattern
        if self._is_wasabi_coinjoin(transaction):
            is_coinjoin = True
            coinjoin_type = 'Wasabi Wallet'
            confidence += 0.4
            indicators.append('Wasabi Wallet coordinator pattern')

        # Check for Samourai Whirlpool pattern
        if self._is_samourai_whirlpool(transaction):
            is_coinjoin = True
            coinjoin_type = 'Samourai Whirlpool'
            confidence += 0.3
            indicators.append('Samourai Whirlpool pattern')

        # Check for JoinMarket pattern
        if self._is_joinmarket(transaction):
            is_coinjoin = True
            coinjoin_type = 'JoinMarket'
            confidence += 0.3
            indicators.append('JoinMarket pattern')

        # High participant count
        if len(inputs) > 20:
            confidence += 0.1
            indicators.append(f'High participant count ({len(inputs)})')

        # Transaction size/fee patterns
        fee = transaction.get('fee', 0)
        total_input = transaction.get('total_input', 0)
        if total_input > 0:
            fee_rate = fee / total_input
            if 0.001 < fee_rate < 0.01:  # Typical CoinJoin fee range
                confidence += 0.05

        confidence = min(1.0, confidence)

        return {
            'is_coinjoin': is_coinjoin,
            'coinjoin_type': coinjoin_type,
            'confidence': confidence,
            'indicators': indicators,
            'transaction_hash': tx_hash,
            'num_participants': len(inputs),
            'equal_outputs': len(equal_outputs)
        }

    def detect_centralized_mixer(self, addresses: List[str]) -> Dict[str, Any]:
        """
        Detect centralized mixer usage

        Args:
            addresses: List of addresses to check

        Returns:
            Centralized mixer detection result
        """
        detected_mixers = []

        for address in addresses:
            # Check against known mixer addresses
            for service_id, service in self.mixing_services.items():
                if service.service_type == 'centralized_mixer':
                    if address in service.known_addresses:
                        detected_mixers.append({
                            'service': service.service_name,
                            'address': address,
                            'confidence': 0.95
                        })

        detected = len(detected_mixers) > 0

        return {
            'detected': detected,
            'mixers': detected_mixers,
            'total_mixer_addresses': len(detected_mixers)
        }

    def identify_privacy_tools(self, transaction_history: List[Dict]) -> Dict[str, Any]:
        """
        Identify use of privacy-enhancing tools

        Args:
            transaction_history: List of transactions

        Returns:
            Privacy tool identification results
        """
        privacy_tools = set()
        indicators = []

        for tx in transaction_history:
            # Check for Lightning Network usage
            if self._is_lightning_network(tx):
                privacy_tools.add('Lightning Network')
                indicators.append('Lightning Network transactions')

            # Check for atomic swaps
            if self._is_atomic_swap(tx):
                privacy_tools.add('Atomic Swap')
                indicators.append('Atomic swap detected')

            # Check for privacy coins (XMR gateway)
            if self._uses_privacy_coin_gateway(tx):
                privacy_tools.add('Privacy Coin Gateway')
                indicators.append('Privacy coin gateway usage')

        return {
            'privacy_tools_detected': list(privacy_tools),
            'indicators': indicators,
            'total_tools': len(privacy_tools)
        }

    def _analyze_address_mixing(self, address: str) -> MixingDetectionResult:
        """Analyze single address for mixing service usage"""
        # Get transactions for address
        transactions = self._get_transactions(address)

        detected = False
        service_type = None
        service_name = None
        max_confidence = 0.0
        mixing_txs = []
        indicators = []

        for tx in transactions:
            # Check for CoinJoin
            coinjoin_result = self.detect_coinjoin(tx)
            if coinjoin_result['is_coinjoin']:
                detected = True
                service_type = 'coinjoin'
                service_name = coinjoin_result.get('coinjoin_type', 'Unknown CoinJoin')
                max_confidence = max(max_confidence, coinjoin_result['confidence'])
                mixing_txs.append(tx['hash'])
                indicators.extend(coinjoin_result['indicators'])

            # Check against known mixer addresses
            for output in tx.get('outputs', []):
                for service_id, service in self.mixing_services.items():
                    if output['address'] in service.known_addresses:
                        detected = True
                        service_type = service.service_type
                        service_name = service.service_name
                        max_confidence = max(max_confidence, 0.9)
                        mixing_txs.append(tx['hash'])
                        indicators.append(f'Interaction with {service.service_name}')

        return MixingDetectionResult(
            detected=detected,
            service_type=service_type,
            service_name=service_name,
            confidence=max_confidence,
            mixing_transactions=mixing_txs,
            indicators=indicators
        )

    def _find_equal_outputs(self, values: List[float], tolerance: float = 0.00001) -> List[float]:
        """Find groups of equal-value outputs"""
        value_counts = defaultdict(int)

        for value in values:
            # Round to avoid floating point issues
            rounded = round(value, 8)
            value_counts[rounded] += 1

        # Return values that appear multiple times
        equal_values = [v for v, count in value_counts.items() if count >= 2]

        return equal_values

    def _is_wasabi_coinjoin(self, transaction: Dict[str, Any]) -> bool:
        """
        Detect Wasabi Wallet CoinJoin pattern

        Characteristics:
        - Many inputs (typically 100+)
        - Many equal-value outputs
        - Coordinator fee output
        - Specific transaction structure
        """
        outputs = transaction.get('outputs', [])
        inputs = transaction.get('inputs', [])

        # Wasabi typically has 100+ participants
        if len(inputs) < 50:
            return False

        # Check for equal denominations (0.1 BTC common)
        output_values = [o['value'] for o in outputs]
        equal_outputs = self._find_equal_outputs(output_values)

        if len(equal_outputs) >= 3:
            # Check if dominant value is a round number
            for value in equal_outputs:
                if value in [0.1, 0.01, 0.001, 1.0, 0.05]:
                    return True

        return False

    def _is_samourai_whirlpool(self, transaction: Dict[str, Any]) -> bool:
        """
        Detect Samourai Whirlpool pattern

        Characteristics:
        - Fixed denominations (0.01, 0.05, 0.5, 0.001 BTC)
        - 5 participants typically
        - Specific transaction structure
        """
        outputs = transaction.get('outputs', [])
        inputs = transaction.get('inputs', [])

        # Samourai Whirlpool typically has exactly 5 participants
        if not (4 <= len(inputs) <= 6):
            return False

        # Check for Whirlpool denominations
        whirlpool_denoms = [0.001, 0.01, 0.05, 0.5]
        output_values = [o['value'] for o in outputs]

        for denom in whirlpool_denoms:
            matching = sum(1 for v in output_values if abs(v - denom) < 0.00001)
            if matching >= 4:
                return True

        return False

    def _is_joinmarket(self, transaction: Dict[str, Any]) -> bool:
        """
        Detect JoinMarket CoinJoin pattern

        Characteristics:
        - Variable number of participants
        - Market-maker fee structure
        - Non-standard denominations
        """
        inputs = transaction.get('inputs', [])

        # JoinMarket can have varying participants
        if len(inputs) < 3:
            return False

        # JoinMarket typically doesn't use round denominations
        # This is a weak heuristic
        outputs = transaction.get('outputs', [])
        output_values = [o['value'] for o in outputs]

        # Check if outputs are NOT round numbers (characteristic of JoinMarket)
        non_round = sum(1 for v in output_values if not self._is_round_value(v))

        if non_round >= len(outputs) * 0.8:  # 80% non-round
            return len(inputs) >= 3

        return False

    def _is_lightning_network(self, transaction: Dict[str, Any]) -> bool:
        """Detect Lightning Network channel operations"""
        # Lightning channels have specific patterns
        outputs = transaction.get('outputs', [])

        # 2-of-2 multisig is common for Lightning channels
        for output in outputs:
            script_type = output.get('script_type', '')
            if 'multisig' in script_type.lower():
                return True

        return False

    def _is_atomic_swap(self, transaction: Dict[str, Any]) -> bool:
        """Detect atomic swap transactions"""
        # Atomic swaps use HTLC scripts
        outputs = transaction.get('outputs', [])

        for output in outputs:
            script_type = output.get('script_type', '')
            if 'htlc' in script_type.lower():
                return True

        return False

    def _uses_privacy_coin_gateway(self, transaction: Dict[str, Any]) -> bool:
        """Detect privacy coin gateway usage (e.g., XMR.to)"""
        # Check outputs for known gateway addresses
        outputs = transaction.get('outputs', [])

        for output in outputs:
            address = output.get('address', '')
            # Check against known gateway patterns
            # In production: maintain database of known gateways
            if 'xmr' in address.lower():  # Simplified check
                return True

        return False

    def _is_round_value(self, value: float) -> bool:
        """Check if value is a round number"""
        round_values = [0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0]
        return any(abs(value - rv) < 0.00001 for rv in round_values)

    def _get_transactions(self, address: str) -> List[Dict[str, Any]]:
        """Get transactions for address (simulated)"""
        import random

        # Simulate some transactions, some might be CoinJoins
        num_txs = random.randint(3, 10)
        transactions = []

        for i in range(num_txs):
            # Randomly create normal tx or CoinJoin
            is_coinjoin = random.random() > 0.7

            if is_coinjoin:
                # Create CoinJoin-like transaction
                num_inputs = random.randint(10, 50)
                num_outputs = random.randint(10, 50)
                common_value = random.choice([0.01, 0.1, 1.0])

                outputs = [
                    {
                        'address': f"1CJ{random.randint(1000000, 9999999)}",
                        'value': common_value
                    }
                    for _ in range(num_outputs - 2)
                ]
                # Add some change outputs
                outputs.extend([
                    {'address': f"1CH{random.randint(1000000, 9999999)}",
                     'value': random.uniform(0.001, 0.05)},
                    {'address': f"1CH{random.randint(1000000, 9999999)}",
                     'value': random.uniform(0.001, 0.05)}
                ])

            else:
                # Normal transaction
                num_inputs = random.randint(1, 3)
                num_outputs = random.randint(2, 4)

                outputs = [
                    {
                        'address': f"1N{random.randint(1000000, 9999999)}",
                        'value': random.uniform(0.01, 1.0)
                    }
                    for _ in range(num_outputs)
                ]

            transactions.append({
                'hash': f"{random.randint(10000000, 99999999):08x}",
                'inputs': [f"1IN{random.randint(100000, 999999)}" for _ in range(num_inputs)],
                'outputs': outputs,
                'total_input': sum(o['value'] for o in outputs) * 1.001,
                'total_output': sum(o['value'] for o in outputs),
                'fee': sum(o['value'] for o in outputs) * 0.001,
                'timestamp': datetime.now() - timedelta(days=random.randint(1, 365))
            })

        return transactions

    def _initialize_mixing_signatures(self):
        """Initialize known mixing service signatures"""
        # Wasabi Wallet
        self.mixing_services['wasabi'] = MixingServiceSignature(
            service_name='Wasabi Wallet',
            service_type='coinjoin',
            min_participants=50,
            output_denominations=[0.1, 0.01, 0.001]
        )

        # Samourai Whirlpool
        self.mixing_services['samourai'] = MixingServiceSignature(
            service_name='Samourai Whirlpool',
            service_type='coinjoin',
            min_participants=5,
            output_denominations=[0.001, 0.01, 0.05, 0.5]
        )

        # JoinMarket
        self.mixing_services['joinmarket'] = MixingServiceSignature(
            service_name='JoinMarket',
            service_type='coinjoin',
            min_participants=3
        )

        # ChipMixer (defunct but historical)
        self.mixing_services['chipmixer'] = MixingServiceSignature(
            service_name='ChipMixer',
            service_type='centralized_mixer',
            known_addresses=set()  # Would contain known addresses
        )

        logger.info(f"Initialized {len(self.mixing_services)} mixing service signatures")
