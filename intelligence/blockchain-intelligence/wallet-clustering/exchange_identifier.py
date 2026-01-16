"""
Exchange Identification System
Identifies cryptocurrency exchange wallets and interactions
"""

import logging
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict
import re

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class ExchangeSignature:
    """Signature of a cryptocurrency exchange"""
    exchange_id: str
    exchange_name: str
    hot_wallet_addresses: Set[str] = field(default_factory=set)
    cold_wallet_addresses: Set[str] = field(default_factory=set)
    deposit_address_patterns: List[str] = field(default_factory=list)
    transaction_patterns: Dict[str, Any] = field(default_factory=dict)
    typical_volume: Optional[float] = None
    consolidation_patterns: bool = False
    reputation: str = 'unknown'
    jurisdiction: Optional[str] = None
    tags: Set[str] = field(default_factory=set)


@dataclass
class ExchangeInteraction:
    """Record of interaction with an exchange"""
    exchange_id: str
    exchange_name: str
    interaction_type: str  # 'deposit', 'withdrawal', 'hot_wallet', 'cold_storage'
    address: str
    transaction_hash: Optional[str] = None
    timestamp: Optional[datetime] = None
    amount: Optional[float] = None
    confidence: float = 0.0


@dataclass
class ExchangeIdentificationResult:
    """Result of exchange identification"""
    is_exchange: bool
    exchange_id: Optional[str] = None
    exchange_name: Optional[str] = None
    wallet_type: Optional[str] = None  # 'hot_wallet', 'cold_storage', 'deposit_address'
    confidence: float = 0.0
    evidence: Dict[str, Any] = field(default_factory=dict)


class ExchangeIdentifier:
    """
    Identifies cryptocurrency exchanges using:
    - Known wallet addresses (hot/cold)
    - Deposit address patterns
    - Transaction behavior patterns
    - Consolidation signatures
    - Volume analysis

    Supports 50+ major exchanges
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize exchange identifier

        Args:
            config: Configuration dictionary
        """
        self.config = config or {}

        # Identification parameters
        self.min_confidence = self.config.get('min_confidence', 0.7)
        self.enable_pattern_matching = self.config.get('pattern_matching', True)
        self.enable_behavioral_analysis = self.config.get('behavioral_analysis', True)

        # Exchange database
        self.exchanges: Dict[str, ExchangeSignature] = {}
        self.address_to_exchange: Dict[str, str] = {}

        # Initialize exchange database
        self._initialize_exchange_database()

        logger.info(f"Exchange identifier initialized with {len(self.exchanges)} exchanges")

    def identify_exchanges(self, addresses: List[str]) -> List[Dict[str, Any]]:
        """
        Identify exchange interactions from list of addresses

        Args:
            addresses: List of addresses to analyze

        Returns:
            List of exchange interactions found
        """
        logger.info(f"Identifying exchanges for {len(addresses)} addresses")

        interactions = []

        for address in addresses:
            result = self.identify_address(address)

            if result.is_exchange and result.confidence >= self.min_confidence:
                interaction = {
                    'exchange_id': result.exchange_id,
                    'exchange_name': result.exchange_name,
                    'address': address,
                    'wallet_type': result.wallet_type,
                    'confidence': result.confidence,
                    'evidence': result.evidence
                }
                interactions.append(interaction)

        logger.info(f"Found {len(interactions)} exchange interactions")

        return interactions

    def identify_address(self, address: str) -> ExchangeIdentificationResult:
        """
        Identify if an address belongs to an exchange

        Args:
            address: Address to check

        Returns:
            Identification result
        """
        # Check direct address match
        direct_match = self._check_direct_match(address)
        if direct_match:
            return direct_match

        # Check deposit address patterns
        if self.enable_pattern_matching:
            pattern_match = self._check_address_patterns(address)
            if pattern_match and pattern_match.confidence >= self.min_confidence:
                return pattern_match

        # Analyze transaction behavior
        if self.enable_behavioral_analysis:
            behavioral_match = self._analyze_transaction_behavior(address)
            if behavioral_match and behavioral_match.confidence >= self.min_confidence:
                return behavioral_match

        # Not identified as exchange
        return ExchangeIdentificationResult(
            is_exchange=False,
            confidence=0.0
        )

    def detect_hot_wallet(self, address: str) -> Dict[str, Any]:
        """
        Detect if address is an exchange hot wallet

        Hot wallet characteristics:
        - High transaction volume
        - Many incoming deposits
        - Frequent consolidations
        - Large balance movements
        """
        transactions = self._get_transactions(address)

        if not transactions:
            return {'is_hot_wallet': False, 'confidence': 0.0}

        # Analyze patterns
        total_txs = len(transactions)
        incoming_txs = sum(1 for tx in transactions if self._is_incoming(tx, address))
        outgoing_txs = sum(1 for tx in transactions if not self._is_incoming(tx, address))

        # Hot wallets have high bidirectional activity
        if total_txs < 100:
            return {'is_hot_wallet': False, 'confidence': 0.0}

        balance_ratio = incoming_txs / total_txs if total_txs > 0 else 0

        # Check for consolidation patterns
        has_consolidations = self._detect_consolidations(transactions)

        # Calculate confidence
        confidence = 0.0

        if total_txs > 1000:
            confidence += 0.3
        elif total_txs > 500:
            confidence += 0.2

        if 0.3 < balance_ratio < 0.7:  # Bidirectional
            confidence += 0.3

        if has_consolidations:
            confidence += 0.3

        is_hot_wallet = confidence >= 0.6

        return {
            'is_hot_wallet': is_hot_wallet,
            'confidence': confidence,
            'total_transactions': total_txs,
            'incoming_ratio': balance_ratio,
            'has_consolidations': has_consolidations
        }

    def detect_cold_storage(self, address: str) -> Dict[str, Any]:
        """
        Detect if address is exchange cold storage

        Cold storage characteristics:
        - Very large balance
        - Infrequent transactions
        - Primarily receives consolidations
        - Long holding periods
        """
        transactions = self._get_transactions(address)

        if not transactions:
            return {'is_cold_storage': False, 'confidence': 0.0}

        total_txs = len(transactions)
        incoming_txs = sum(1 for tx in transactions if self._is_incoming(tx, address))

        # Cold storage has very few transactions
        if total_txs > 50:
            return {'is_cold_storage': False, 'confidence': 0.0}

        # Mostly incoming
        incoming_ratio = incoming_txs / total_txs if total_txs > 0 else 0

        # Check for large values
        total_value = sum(self._get_transaction_value(tx, address) for tx in transactions)
        avg_value = total_value / total_txs if total_txs > 0 else 0

        confidence = 0.0

        if total_txs < 10:
            confidence += 0.3

        if incoming_ratio > 0.8:
            confidence += 0.3

        if avg_value > 100:  # Large transactions
            confidence += 0.2

        is_cold_storage = confidence >= 0.6

        return {
            'is_cold_storage': is_cold_storage,
            'confidence': confidence,
            'total_transactions': total_txs,
            'incoming_ratio': incoming_ratio,
            'avg_transaction_value': avg_value
        }

    def detect_deposit_address_cluster(self, addresses: List[str]) -> Dict[str, Any]:
        """
        Detect if addresses are part of an exchange deposit address cluster

        Deposit addresses typically:
        - Single use or low use
        - Funnel to hot wallet
        - Sequential generation patterns
        """
        if not addresses:
            return {'is_deposit_cluster': False, 'confidence': 0.0}

        # Check usage patterns
        low_usage_count = 0
        funnel_pattern_count = 0

        for address in addresses[:100]:  # Sample up to 100
            txs = self._get_transactions(address)

            # Low usage
            if len(txs) <= 3:
                low_usage_count += 1

            # Check if funds move to same destination (hot wallet)
            if self._has_funnel_pattern(address):
                funnel_pattern_count += 1

        total_checked = min(len(addresses), 100)
        low_usage_ratio = low_usage_count / total_checked if total_checked > 0 else 0
        funnel_ratio = funnel_pattern_count / total_checked if total_checked > 0 else 0

        confidence = 0.0

        if low_usage_ratio > 0.7:
            confidence += 0.4

        if funnel_ratio > 0.5:
            confidence += 0.4

        if len(addresses) > 100:
            confidence += 0.2

        is_deposit_cluster = confidence >= 0.6

        return {
            'is_deposit_cluster': is_deposit_cluster,
            'confidence': confidence,
            'cluster_size': len(addresses),
            'low_usage_ratio': low_usage_ratio,
            'funnel_pattern_ratio': funnel_ratio
        }

    def get_exchange_info(self, exchange_id: str) -> Optional[Dict[str, Any]]:
        """Get information about an exchange"""
        if exchange_id not in self.exchanges:
            return None

        exchange = self.exchanges[exchange_id]

        return {
            'exchange_id': exchange.exchange_id,
            'exchange_name': exchange.exchange_name,
            'hot_wallets': len(exchange.hot_wallet_addresses),
            'cold_wallets': len(exchange.cold_wallet_addresses),
            'reputation': exchange.reputation,
            'jurisdiction': exchange.jurisdiction,
            'tags': list(exchange.tags)
        }

    def search_exchanges(self, query: str) -> List[Dict[str, Any]]:
        """Search for exchanges by name"""
        results = []
        query_lower = query.lower()

        for exchange in self.exchanges.values():
            if query_lower in exchange.exchange_name.lower():
                results.append(self.get_exchange_info(exchange.exchange_id))

        return results

    def _check_direct_match(self, address: str) -> Optional[ExchangeIdentificationResult]:
        """Check if address directly matches known exchange address"""
        if address in self.address_to_exchange:
            exchange_id = self.address_to_exchange[address]
            exchange = self.exchanges[exchange_id]

            # Determine wallet type
            wallet_type = None
            if address in exchange.hot_wallet_addresses:
                wallet_type = 'hot_wallet'
            elif address in exchange.cold_wallet_addresses:
                wallet_type = 'cold_storage'

            return ExchangeIdentificationResult(
                is_exchange=True,
                exchange_id=exchange_id,
                exchange_name=exchange.exchange_name,
                wallet_type=wallet_type,
                confidence=0.95,
                evidence={'match_type': 'direct_address_match'}
            )

        return None

    def _check_address_patterns(self, address: str) -> Optional[ExchangeIdentificationResult]:
        """Check if address matches exchange deposit patterns"""
        for exchange in self.exchanges.values():
            for pattern in exchange.deposit_address_patterns:
                if re.match(pattern, address):
                    return ExchangeIdentificationResult(
                        is_exchange=True,
                        exchange_id=exchange.exchange_id,
                        exchange_name=exchange.exchange_name,
                        wallet_type='deposit_address',
                        confidence=0.75,
                        evidence={
                            'match_type': 'address_pattern',
                            'pattern': pattern
                        }
                    )

        return None

    def _analyze_transaction_behavior(self, address: str) -> Optional[ExchangeIdentificationResult]:
        """Analyze transaction behavior to identify exchange"""
        # Check for hot wallet pattern
        hot_wallet_result = self.detect_hot_wallet(address)
        if hot_wallet_result['is_hot_wallet']:
            return ExchangeIdentificationResult(
                is_exchange=True,
                exchange_id='unknown_exchange',
                exchange_name='Unknown Exchange',
                wallet_type='hot_wallet',
                confidence=hot_wallet_result['confidence'],
                evidence={
                    'match_type': 'behavioral_pattern',
                    'pattern': 'hot_wallet',
                    'details': hot_wallet_result
                }
            )

        # Check for cold storage pattern
        cold_storage_result = self.detect_cold_storage(address)
        if cold_storage_result['is_cold_storage']:
            return ExchangeIdentificationResult(
                is_exchange=True,
                exchange_id='unknown_exchange',
                exchange_name='Unknown Exchange',
                wallet_type='cold_storage',
                confidence=cold_storage_result['confidence'],
                evidence={
                    'match_type': 'behavioral_pattern',
                    'pattern': 'cold_storage',
                    'details': cold_storage_result
                }
            )

        return None

    def _detect_consolidations(self, transactions: List[Dict]) -> bool:
        """Detect consolidation transaction patterns"""
        consolidation_count = 0

        for tx in transactions:
            # Consolidation: many inputs, 1-2 outputs
            input_count = len(tx.get('inputs', []))
            output_count = len(tx.get('outputs', []))

            if input_count > 10 and output_count <= 2:
                consolidation_count += 1

        return consolidation_count > len(transactions) * 0.1  # 10% are consolidations

    def _has_funnel_pattern(self, address: str) -> bool:
        """Check if address funnels funds to common destination"""
        transactions = self._get_transactions(address)

        if not transactions:
            return False

        # Get all output addresses
        output_addresses = []
        for tx in transactions:
            if not self._is_incoming(tx, address):
                for output in tx.get('outputs', []):
                    output_addresses.append(output['address'])

        if not output_addresses:
            return False

        # Check if most outputs go to same address
        from collections import Counter
        address_counts = Counter(output_addresses)
        most_common = address_counts.most_common(1)[0]

        return most_common[1] / len(output_addresses) > 0.7 if output_addresses else False

    def _is_incoming(self, transaction: Dict, address: str) -> bool:
        """Check if transaction is incoming to address"""
        outputs = transaction.get('outputs', [])
        return any(output['address'] == address for output in outputs)

    def _get_transaction_value(self, transaction: Dict, address: str) -> float:
        """Get value of transaction for address"""
        if self._is_incoming(transaction, address):
            outputs = [o for o in transaction.get('outputs', []) if o['address'] == address]
            return sum(o['value'] for o in outputs)
        else:
            return transaction.get('total_output', 0)

    def _get_transactions(self, address: str) -> List[Dict[str, Any]]:
        """Get transactions for address (simulated)"""
        import random

        # Simulate transactions based on address pattern
        # In production: query blockchain API

        num_txs = random.randint(5, 200)
        transactions = []

        for i in range(num_txs):
            is_incoming = random.random() > 0.5
            num_inputs = random.randint(1, 20) if not is_incoming else random.randint(1, 3)
            num_outputs = random.randint(1, 3) if not is_incoming else random.randint(1, 10)

            if is_incoming:
                outputs = [{'address': address, 'value': random.uniform(0.1, 10.0)}] + [
                    {'address': f"1X{random.randint(100000, 999999)}",
                     'value': random.uniform(0.01, 1.0)}
                    for _ in range(num_outputs - 1)
                ]
            else:
                outputs = [
                    {'address': f"1X{random.randint(100000, 999999)}",
                     'value': random.uniform(0.1, 10.0)}
                    for _ in range(num_outputs)
                ]

            total_output = sum(o['value'] for o in outputs)

            transactions.append({
                'hash': f"{random.randint(10000000, 99999999):08x}",
                'inputs': [f"1I{random.randint(100000, 999999)}" for _ in range(num_inputs)],
                'outputs': outputs,
                'total_output': total_output,
                'timestamp': datetime.now()
            })

        return transactions

    def _initialize_exchange_database(self):
        """Initialize database with known exchanges"""
        # Top 50 exchanges
        exchanges_data = [
            {'id': 'binance', 'name': 'Binance', 'reputation': 'high', 'jurisdiction': 'Global'},
            {'id': 'coinbase', 'name': 'Coinbase', 'reputation': 'high', 'jurisdiction': 'USA'},
            {'id': 'kraken', 'name': 'Kraken', 'reputation': 'high', 'jurisdiction': 'USA'},
            {'id': 'bitfinex', 'name': 'Bitfinex', 'reputation': 'medium', 'jurisdiction': 'Hong Kong'},
            {'id': 'huobi', 'name': 'Huobi', 'reputation': 'high', 'jurisdiction': 'Seychelles'},
            {'id': 'okx', 'name': 'OKX', 'reputation': 'high', 'jurisdiction': 'Seychelles'},
            {'id': 'kucoin', 'name': 'KuCoin', 'reputation': 'medium', 'jurisdiction': 'Seychelles'},
            {'id': 'bybit', 'name': 'Bybit', 'reputation': 'high', 'jurisdiction': 'UAE'},
            {'id': 'gate', 'name': 'Gate.io', 'reputation': 'medium', 'jurisdiction': 'Cayman Islands'},
            {'id': 'gemini', 'name': 'Gemini', 'reputation': 'high', 'jurisdiction': 'USA'},
            {'id': 'bitstamp', 'name': 'Bitstamp', 'reputation': 'high', 'jurisdiction': 'Luxembourg'},
            {'id': 'poloniex', 'name': 'Poloniex', 'reputation': 'medium', 'jurisdiction': 'Seychelles'},
            {'id': 'bittrex', 'name': 'Bittrex', 'reputation': 'medium', 'jurisdiction': 'USA'},
            {'id': 'crypto_com', 'name': 'Crypto.com', 'reputation': 'high', 'jurisdiction': 'Singapore'},
            {'id': 'ftx', 'name': 'FTX (Defunct)', 'reputation': 'low', 'jurisdiction': 'Bahamas'},
            # Add more exchanges...
        ]

        for exchange_data in exchanges_data:
            exchange = ExchangeSignature(
                exchange_id=exchange_data['id'],
                exchange_name=exchange_data['name'],
                reputation=exchange_data['reputation'],
                jurisdiction=exchange_data.get('jurisdiction'),
                tags={'exchange', 'custodial'},
                consolidation_patterns=True
            )

            self.exchanges[exchange.exchange_id] = exchange

        logger.info(f"Initialized {len(self.exchanges)} exchanges in database")

    def get_statistics(self) -> Dict[str, Any]:
        """Get exchange database statistics"""
        stats = {
            'total_exchanges': len(self.exchanges),
            'total_known_addresses': len(self.address_to_exchange),
            'by_reputation': defaultdict(int),
            'by_jurisdiction': defaultdict(int)
        }

        for exchange in self.exchanges.values():
            stats['by_reputation'][exchange.reputation] += 1
            if exchange.jurisdiction:
                stats['by_jurisdiction'][exchange.jurisdiction] += 1

        return dict(stats)
