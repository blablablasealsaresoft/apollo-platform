"""
Change Address Detection System
Identifies change addresses using multiple heuristics
"""

import logging
import re
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from datetime import datetime
from collections import defaultdict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class OutputAnalysis:
    """Analysis of a transaction output"""
    address: str
    value: float
    output_index: int
    script_type: str
    is_change: bool
    change_confidence: float
    reasons: List[str]


@dataclass
class ChangeDetectionResult:
    """Result of change address detection"""
    transaction_hash: str
    source_address: str
    change_addresses: List[str]
    payment_addresses: List[str]
    outputs: List[OutputAnalysis]
    detection_methods: List[str]
    overall_confidence: float


class ChangeAddressDetector:
    """
    Detects change addresses using multiple heuristics:
    1. One-time change address (never seen before)
    2. Round number heuristic (payments are usually round numbers)
    3. Script type matching
    4. Client fingerprinting
    5. Optimal change heuristic
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize change address detector

        Args:
            config: Configuration dictionary
        """
        self.config = config or {}

        # Detection parameters
        self.min_confidence = self.config.get('min_confidence', 0.6)
        self.enable_round_number = self.config.get('round_number_heuristic', True)
        self.enable_one_time = self.config.get('one_time_heuristic', True)
        self.enable_script_type = self.config.get('script_type_heuristic', True)

        # Address history tracking
        self.address_usage: Dict[str, int] = defaultdict(int)
        self.address_first_seen: Dict[str, datetime] = {}

        logger.info("Change address detector initialized")

    def analyze_transactions(self, address: str, depth: int = 2) -> Dict[str, Any]:
        """
        Analyze transactions to detect change addresses

        Args:
            address: Source address to analyze
            depth: Transaction depth to analyze

        Returns:
            Dictionary containing change address analysis
        """
        logger.info(f"Analyzing change addresses for {address} (depth={depth})")

        # Get transactions for address
        transactions = self._get_transactions(address)

        change_addresses = []
        all_detections = []

        for tx in transactions:
            # Only analyze transactions where address is an input
            if address not in tx.get('inputs', []):
                continue

            result = self.detect_change_in_transaction(tx, address)
            all_detections.append(result)

            # Collect high-confidence change addresses
            for change_addr in result.change_addresses:
                for output in result.outputs:
                    if (output.address == change_addr and
                        output.is_change and
                        output.change_confidence >= self.min_confidence):

                        change_addresses.append({
                            'address': change_addr,
                            'confidence': output.change_confidence,
                            'source_address': address,
                            'transaction_hash': tx['hash'],
                            'evidence': {
                                'reasons': output.reasons,
                                'value': output.value,
                                'output_index': output.output_index
                            }
                        })

        return {
            'source_address': address,
            'change_addresses': change_addresses,
            'total_transactions_analyzed': len(transactions),
            'detections': [self._serialize_detection(d) for d in all_detections],
            'analysis_depth': depth
        }

    def detect_change_in_transaction(self, transaction: Dict[str, Any],
                                    source_address: str) -> ChangeDetectionResult:
        """
        Detect change address in a specific transaction

        Args:
            transaction: Transaction data
            source_address: Known input address

        Returns:
            ChangeDetectionResult with analysis
        """
        tx_hash = transaction['hash']
        outputs = transaction.get('outputs', [])

        if len(outputs) < 2:
            # No change detection needed for single output
            return ChangeDetectionResult(
                transaction_hash=tx_hash,
                source_address=source_address,
                change_addresses=[],
                payment_addresses=[outputs[0]['address']] if outputs else [],
                outputs=[],
                detection_methods=[],
                overall_confidence=0.0
            )

        # Analyze each output
        output_analyses = []
        detection_methods = set()

        for idx, output in enumerate(outputs):
            analysis = self._analyze_output(
                output,
                idx,
                transaction,
                source_address
            )
            output_analyses.append(analysis)

            if analysis.is_change:
                detection_methods.update(analysis.reasons)

        # Separate change and payment addresses
        change_addresses = [
            o.address for o in output_analyses
            if o.is_change and o.change_confidence >= self.min_confidence
        ]
        payment_addresses = [
            o.address for o in output_analyses
            if not o.is_change or o.change_confidence < self.min_confidence
        ]

        # Calculate overall confidence
        if change_addresses:
            confidences = [
                o.change_confidence for o in output_analyses if o.is_change
            ]
            overall_confidence = max(confidences)
        else:
            overall_confidence = 0.0

        result = ChangeDetectionResult(
            transaction_hash=tx_hash,
            source_address=source_address,
            change_addresses=change_addresses,
            payment_addresses=payment_addresses,
            outputs=output_analyses,
            detection_methods=list(detection_methods),
            overall_confidence=overall_confidence
        )

        return result

    def _analyze_output(self, output: Dict[str, Any],
                       index: int,
                       transaction: Dict[str, Any],
                       source_address: str) -> OutputAnalysis:
        """Analyze a single transaction output"""
        address = output['address']
        value = output['value']
        script_type = output.get('script_type', 'unknown')

        is_change = False
        confidence = 0.0
        reasons = []

        # Heuristic 1: One-time change address
        if self.enable_one_time:
            usage_count = self.address_usage.get(address, 0)
            if usage_count == 0:
                is_change = True
                confidence += 0.3
                reasons.append('one_time_address')

        # Heuristic 2: Round number heuristic
        if self.enable_round_number:
            if self._is_round_number(value):
                # Round numbers are likely payments, not change
                is_change = False
                confidence -= 0.4
                reasons.append('round_number_payment')
            else:
                # Non-round values are more likely change
                is_change = True
                confidence += 0.25
                reasons.append('non_round_change')

        # Heuristic 3: Script type matching
        if self.enable_script_type:
            source_script_type = self._get_address_script_type(source_address)
            if script_type == source_script_type:
                is_change = True
                confidence += 0.2
                reasons.append('script_type_match')

        # Heuristic 4: Optimal change (smallest output)
        output_values = [o['value'] for o in transaction.get('outputs', [])]
        if value == min(output_values):
            is_change = True
            confidence += 0.15
            reasons.append('smallest_output')

        # Heuristic 5: Position heuristic
        # Some wallets always put change as first or last output
        if index == 0 or index == len(transaction.get('outputs', [])) - 1:
            confidence += 0.1
            reasons.append('position_heuristic')

        # Heuristic 6: Value analysis
        total_input = transaction.get('total_input', 0)
        if value > total_input * 0.8:
            # Very large output is likely change
            is_change = True
            confidence += 0.2
            reasons.append('large_value_change')

        # Ensure confidence is in valid range
        confidence = max(0.0, min(1.0, confidence))

        # Update address usage tracking
        self.address_usage[address] += 1
        if address not in self.address_first_seen:
            self.address_first_seen[address] = datetime.now()

        return OutputAnalysis(
            address=address,
            value=value,
            output_index=index,
            script_type=script_type,
            is_change=is_change,
            change_confidence=confidence,
            reasons=reasons
        )

    def _is_round_number(self, value: float) -> bool:
        """
        Check if value is a round number

        Round numbers for crypto (in BTC):
        0.001, 0.01, 0.1, 1.0, 10.0, etc.
        """
        # Check if value matches common round patterns
        round_values = [
            0.001, 0.005, 0.01, 0.05, 0.1, 0.5,
            1.0, 5.0, 10.0, 50.0, 100.0
        ]

        # Check exact matches
        for round_val in round_values:
            if abs(value - round_val) < 0.00001:
                return True

        # Check if ends in many zeros (e.g., 1.50000000)
        value_str = f"{value:.8f}"
        if value_str.endswith('00000'):
            return True

        return False

    def _get_address_script_type(self, address: str) -> str:
        """
        Determine script type from address format

        Script types:
        - P2PKH: Legacy addresses starting with 1
        - P2SH: Addresses starting with 3
        - Bech32: Native SegWit starting with bc1
        """
        if address.startswith('1'):
            return 'P2PKH'
        elif address.startswith('3'):
            return 'P2SH'
        elif address.startswith('bc1'):
            if len(address) == 42:
                return 'P2WPKH'
            else:
                return 'P2WSH'
        else:
            return 'unknown'

    def _get_transactions(self, address: str) -> List[Dict[str, Any]]:
        """
        Get transactions for address
        In production: query blockchain API
        """
        # Simulate blockchain query
        import random
        from datetime import timedelta

        num_txs = random.randint(2, 8)
        transactions = []

        for i in range(num_txs):
            output_count = random.randint(2, 4)

            # Generate outputs
            outputs = []
            total_output = 0

            for idx in range(output_count):
                # Make some outputs round numbers (likely payments)
                if idx == 0 and random.random() > 0.5:
                    value = random.choice([0.001, 0.01, 0.1, 1.0, 5.0])
                else:
                    value = random.uniform(0.001, 2.0)

                total_output += value

                outputs.append({
                    'address': f"1{random.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ')}{random.randint(1000000, 9999999)}",
                    'value': value,
                    'script_type': random.choice(['P2PKH', 'P2SH', 'P2WPKH'])
                })

            fee = total_output * random.uniform(0.0001, 0.001)
            total_input = total_output + fee

            transactions.append({
                'hash': f"{random.randint(10000000, 99999999):08x}",
                'inputs': [address] + [f"1{random.choice('ABC')}{random.randint(100000, 999999)}"
                                      for _ in range(random.randint(0, 2))],
                'outputs': outputs,
                'timestamp': datetime.now() - timedelta(days=random.randint(1, 365)),
                'total_input': total_input,
                'total_output': total_output,
                'fee': fee
            })

        return transactions

    def _serialize_detection(self, result: ChangeDetectionResult) -> Dict[str, Any]:
        """Serialize detection result to dict"""
        return {
            'transaction_hash': result.transaction_hash,
            'source_address': result.source_address,
            'change_addresses': result.change_addresses,
            'payment_addresses': result.payment_addresses,
            'outputs': [
                {
                    'address': o.address,
                    'value': o.value,
                    'is_change': o.is_change,
                    'confidence': o.change_confidence,
                    'reasons': o.reasons
                }
                for o in result.outputs
            ],
            'detection_methods': result.detection_methods,
            'overall_confidence': result.overall_confidence
        }

    def get_statistics(self) -> Dict[str, Any]:
        """Get detector statistics"""
        total_addresses = len(self.address_usage)
        one_time_addresses = sum(1 for count in self.address_usage.values() if count == 1)

        return {
            'total_addresses_seen': total_addresses,
            'one_time_addresses': one_time_addresses,
            'reused_addresses': total_addresses - one_time_addresses,
            'reuse_rate': 1 - (one_time_addresses / total_addresses) if total_addresses > 0 else 0
        }
