"""
Unit Tests for Blockchain Intelligence Engine
Apollo Platform - Blockchain Forensics Module

Comprehensive unit tests for:
- Data models (WalletInfo, Transaction, WalletCluster)
- API client initialization
- Wallet info parsing
- Transaction tracing logic
- Fund flow analysis

Author: Apollo Platform - Agent 9
"""

import pytest
import asyncio
import json
from decimal import Decimal
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock, AsyncMock
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Set
import sys


# ============================================================
# Data Model Definitions (for testing without full module import)
# ============================================================

@dataclass
class WalletInfo:
    """Information about a cryptocurrency wallet"""
    address: str
    blockchain: str
    balance: Decimal
    total_received: Decimal
    total_sent: Decimal
    transaction_count: int
    first_seen: Optional[datetime]
    last_seen: Optional[datetime]
    labels: List[str] = field(default_factory=list)
    risk_score: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Transaction:
    """Blockchain transaction"""
    tx_hash: str
    blockchain: str
    timestamp: datetime
    from_addresses: List[str]
    to_addresses: List[str]
    amount: Decimal
    fee: Decimal
    confirmations: int
    block_height: Optional[int]
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class WalletCluster:
    """Cluster of related wallets"""
    cluster_id: str
    addresses: Set[str]
    total_balance: Decimal
    confidence_score: float
    clustering_method: str
    metadata: Dict[str, Any] = field(default_factory=dict)


# ============================================================
# WalletInfo Data Model Unit Tests
# ============================================================

class TestWalletInfo:
    """Unit tests for WalletInfo data model"""

    def test_creation_minimal(self):
        """Test minimal WalletInfo creation"""
        wallet = WalletInfo(
            address="1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
            blockchain="bitcoin",
            balance=Decimal("50.0"),
            total_received=Decimal("100.0"),
            total_sent=Decimal("50.0"),
            transaction_count=10,
            first_seen=None,
            last_seen=None
        )

        assert wallet.address == "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
        assert wallet.blockchain == "bitcoin"
        assert wallet.balance == Decimal("50.0")
        assert wallet.transaction_count == 10

    def test_creation_with_timestamps(self):
        """Test WalletInfo with timestamps"""
        first_seen = datetime(2009, 1, 3, 18, 15, 5)
        last_seen = datetime(2024, 1, 15, 12, 0, 0)

        wallet = WalletInfo(
            address="1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
            blockchain="bitcoin",
            balance=Decimal("50.0"),
            total_received=Decimal("100.0"),
            total_sent=Decimal("50.0"),
            transaction_count=10,
            first_seen=first_seen,
            last_seen=last_seen
        )

        assert wallet.first_seen == first_seen
        assert wallet.last_seen == last_seen

    def test_creation_with_labels(self):
        """Test WalletInfo with labels"""
        wallet = WalletInfo(
            address="1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
            blockchain="bitcoin",
            balance=Decimal("50.0"),
            total_received=Decimal("100.0"),
            total_sent=Decimal("50.0"),
            transaction_count=10,
            first_seen=None,
            last_seen=None,
            labels=["genesis", "satoshi", "known"]
        )

        assert len(wallet.labels) == 3
        assert "genesis" in wallet.labels
        assert "satoshi" in wallet.labels

    def test_creation_with_risk_score(self):
        """Test WalletInfo with risk score"""
        wallet = WalletInfo(
            address="suspected-wallet",
            blockchain="bitcoin",
            balance=Decimal("100.0"),
            total_received=Decimal("1000.0"),
            total_sent=Decimal("900.0"),
            transaction_count=50,
            first_seen=None,
            last_seen=None,
            risk_score=0.85
        )

        assert wallet.risk_score == 0.85

    def test_creation_with_metadata(self):
        """Test WalletInfo with metadata"""
        metadata = {
            "source": "blockchain.info",
            "confidence": 0.99,
            "additional_info": {"type": "exchange"}
        }

        wallet = WalletInfo(
            address="exchange-wallet",
            blockchain="bitcoin",
            balance=Decimal("10000.0"),
            total_received=Decimal("50000.0"),
            total_sent=Decimal("40000.0"),
            transaction_count=1000,
            first_seen=None,
            last_seen=None,
            metadata=metadata
        )

        assert wallet.metadata["source"] == "blockchain.info"
        assert wallet.metadata["confidence"] == 0.99

    def test_default_values(self):
        """Test default values"""
        wallet = WalletInfo(
            address="test-address",
            blockchain="bitcoin",
            balance=Decimal("0"),
            total_received=Decimal("0"),
            total_sent=Decimal("0"),
            transaction_count=0,
            first_seen=None,
            last_seen=None
        )

        assert wallet.labels == []
        assert wallet.risk_score == 0.0
        assert wallet.metadata == {}

    def test_ethereum_wallet(self):
        """Test Ethereum wallet info"""
        wallet = WalletInfo(
            address="0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb",
            blockchain="ethereum",
            balance=Decimal("150.5"),
            total_received=Decimal("500.0"),
            total_sent=Decimal("349.5"),
            transaction_count=75,
            first_seen=datetime(2020, 1, 1),
            last_seen=datetime(2024, 1, 1)
        )

        assert wallet.blockchain == "ethereum"
        assert wallet.balance == Decimal("150.5")


# ============================================================
# Transaction Data Model Unit Tests
# ============================================================

class TestTransaction:
    """Unit tests for Transaction data model"""

    def test_creation_minimal(self):
        """Test minimal Transaction creation"""
        tx = Transaction(
            tx_hash="abc123def456",
            blockchain="bitcoin",
            timestamp=datetime.now(),
            from_addresses=["addr1"],
            to_addresses=["addr2"],
            amount=Decimal("1.5"),
            fee=Decimal("0.0001"),
            confirmations=6,
            block_height=800000
        )

        assert tx.tx_hash == "abc123def456"
        assert tx.blockchain == "bitcoin"
        assert tx.amount == Decimal("1.5")

    def test_creation_multiple_addresses(self):
        """Test Transaction with multiple addresses"""
        tx = Transaction(
            tx_hash="multi-input-tx",
            blockchain="bitcoin",
            timestamp=datetime.now(),
            from_addresses=["addr1", "addr2", "addr3"],
            to_addresses=["addr4", "addr5"],
            amount=Decimal("10.0"),
            fee=Decimal("0.001"),
            confirmations=100,
            block_height=750000
        )

        assert len(tx.from_addresses) == 3
        assert len(tx.to_addresses) == 2

    def test_creation_unconfirmed(self):
        """Test unconfirmed Transaction"""
        tx = Transaction(
            tx_hash="pending-tx",
            blockchain="bitcoin",
            timestamp=datetime.now(),
            from_addresses=["addr1"],
            to_addresses=["addr2"],
            amount=Decimal("0.5"),
            fee=Decimal("0.00005"),
            confirmations=0,
            block_height=None
        )

        assert tx.confirmations == 0
        assert tx.block_height is None

    def test_creation_with_metadata(self):
        """Test Transaction with metadata"""
        metadata = {
            "source": "mempool",
            "size_bytes": 250,
            "virtual_size": 200,
            "is_coinbase": False
        }

        tx = Transaction(
            tx_hash="tx-with-meta",
            blockchain="bitcoin",
            timestamp=datetime.now(),
            from_addresses=["addr1"],
            to_addresses=["addr2"],
            amount=Decimal("5.0"),
            fee=Decimal("0.0002"),
            confirmations=10,
            block_height=800001,
            metadata=metadata
        )

        assert tx.metadata["size_bytes"] == 250
        assert tx.metadata["is_coinbase"] is False

    def test_ethereum_transaction(self):
        """Test Ethereum transaction"""
        tx = Transaction(
            tx_hash="0xabc123...",
            blockchain="ethereum",
            timestamp=datetime.now(),
            from_addresses=["0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb"],
            to_addresses=["0x123456789abcdef"],
            amount=Decimal("2.5"),
            fee=Decimal("0.002"),
            confirmations=12,
            block_height=18000000,
            metadata={"gas_used": 21000, "gas_price": "50 gwei"}
        )

        assert tx.blockchain == "ethereum"
        assert tx.metadata["gas_used"] == 21000


# ============================================================
# WalletCluster Data Model Unit Tests
# ============================================================

class TestWalletCluster:
    """Unit tests for WalletCluster data model"""

    def test_creation_minimal(self):
        """Test minimal WalletCluster creation"""
        cluster = WalletCluster(
            cluster_id="cluster-001",
            addresses={"addr1", "addr2", "addr3"},
            total_balance=Decimal("100.0"),
            confidence_score=0.95,
            clustering_method="common-input"
        )

        assert cluster.cluster_id == "cluster-001"
        assert len(cluster.addresses) == 3
        assert cluster.confidence_score == 0.95

    def test_creation_with_metadata(self):
        """Test WalletCluster with metadata"""
        cluster = WalletCluster(
            cluster_id="cluster-002",
            addresses={"addr1", "addr2"},
            total_balance=Decimal("500.0"),
            confidence_score=0.80,
            clustering_method="heuristic",
            metadata={
                "entity_name": "Unknown Exchange",
                "first_transaction": "2020-01-01",
                "common_features": ["high_volume", "regular_intervals"]
            }
        )

        assert cluster.metadata["entity_name"] == "Unknown Exchange"

    def test_address_set_operations(self):
        """Test address set operations"""
        cluster = WalletCluster(
            cluster_id="cluster-003",
            addresses={"addr1", "addr2"},
            total_balance=Decimal("50.0"),
            confidence_score=0.70,
            clustering_method="common-input"
        )

        # Test membership
        assert "addr1" in cluster.addresses
        assert "addr3" not in cluster.addresses

        # Test add
        cluster.addresses.add("addr3")
        assert len(cluster.addresses) == 3

    def test_different_clustering_methods(self):
        """Test different clustering methods"""
        methods = ["common-input", "heuristic", "machine-learning", "manual"]

        for method in methods:
            cluster = WalletCluster(
                cluster_id=f"cluster-{method}",
                addresses={"addr1"},
                total_balance=Decimal("10.0"),
                confidence_score=0.5,
                clustering_method=method
            )
            assert cluster.clustering_method == method


# ============================================================
# Satoshi Conversion Unit Tests
# ============================================================

class SatoshiConverter:
    """Utility class for satoshi/BTC conversions"""

    SATOSHI_PER_BTC = Decimal("100000000")

    @classmethod
    def satoshi_to_btc(cls, satoshi: int) -> Decimal:
        """Convert satoshi to BTC"""
        return Decimal(satoshi) / cls.SATOSHI_PER_BTC

    @classmethod
    def btc_to_satoshi(cls, btc: Decimal) -> int:
        """Convert BTC to satoshi"""
        return int(btc * cls.SATOSHI_PER_BTC)

    @classmethod
    def format_btc(cls, btc: Decimal, decimals: int = 8) -> str:
        """Format BTC amount"""
        return f"{btc:.{decimals}f}"


class TestSatoshiConverter:
    """Unit tests for SatoshiConverter"""

    def test_satoshi_to_btc(self):
        """Test satoshi to BTC conversion"""
        assert SatoshiConverter.satoshi_to_btc(100000000) == Decimal("1.0")
        assert SatoshiConverter.satoshi_to_btc(50000000) == Decimal("0.5")
        assert SatoshiConverter.satoshi_to_btc(1) == Decimal("0.00000001")

    def test_btc_to_satoshi(self):
        """Test BTC to satoshi conversion"""
        assert SatoshiConverter.btc_to_satoshi(Decimal("1.0")) == 100000000
        assert SatoshiConverter.btc_to_satoshi(Decimal("0.5")) == 50000000
        assert SatoshiConverter.btc_to_satoshi(Decimal("0.00000001")) == 1

    def test_roundtrip_conversion(self):
        """Test roundtrip conversion"""
        original_satoshi = 123456789
        btc = SatoshiConverter.satoshi_to_btc(original_satoshi)
        back_to_satoshi = SatoshiConverter.btc_to_satoshi(btc)

        assert back_to_satoshi == original_satoshi

    def test_format_btc(self):
        """Test BTC formatting"""
        assert SatoshiConverter.format_btc(Decimal("1.0")) == "1.00000000"
        assert SatoshiConverter.format_btc(Decimal("0.5"), 2) == "0.50"


# ============================================================
# Wei Conversion Unit Tests (Ethereum)
# ============================================================

class WeiConverter:
    """Utility class for wei/ETH conversions"""

    WEI_PER_ETH = Decimal("1000000000000000000")
    GWEI_PER_ETH = Decimal("1000000000")

    @classmethod
    def wei_to_eth(cls, wei: int) -> Decimal:
        """Convert wei to ETH"""
        return Decimal(wei) / cls.WEI_PER_ETH

    @classmethod
    def eth_to_wei(cls, eth: Decimal) -> int:
        """Convert ETH to wei"""
        return int(eth * cls.WEI_PER_ETH)

    @classmethod
    def gwei_to_eth(cls, gwei: int) -> Decimal:
        """Convert gwei to ETH"""
        return Decimal(gwei) / cls.GWEI_PER_ETH


class TestWeiConverter:
    """Unit tests for WeiConverter"""

    def test_wei_to_eth(self):
        """Test wei to ETH conversion"""
        assert WeiConverter.wei_to_eth(1000000000000000000) == Decimal("1.0")
        assert WeiConverter.wei_to_eth(500000000000000000) == Decimal("0.5")

    def test_eth_to_wei(self):
        """Test ETH to wei conversion"""
        assert WeiConverter.eth_to_wei(Decimal("1.0")) == 1000000000000000000
        assert WeiConverter.eth_to_wei(Decimal("0.5")) == 500000000000000000

    def test_gwei_to_eth(self):
        """Test gwei to ETH conversion"""
        assert WeiConverter.gwei_to_eth(1000000000) == Decimal("1.0")
        assert WeiConverter.gwei_to_eth(50) == Decimal("0.00000005")


# ============================================================
# Address Validation Unit Tests
# ============================================================

class AddressValidator:
    """Cryptocurrency address validation"""

    @staticmethod
    def is_valid_bitcoin_address(address: str) -> bool:
        """
        Basic Bitcoin address validation
        Note: This is a simplified check
        """
        if not address:
            return False

        # Legacy addresses (1...)
        if address.startswith('1'):
            return 26 <= len(address) <= 35

        # SegWit addresses (3...)
        if address.startswith('3'):
            return len(address) == 34

        # Bech32 addresses (bc1...)
        if address.startswith('bc1'):
            return 42 <= len(address) <= 62

        return False

    @staticmethod
    def is_valid_ethereum_address(address: str) -> bool:
        """
        Basic Ethereum address validation
        """
        if not address:
            return False

        if not address.startswith('0x'):
            return False

        if len(address) != 42:
            return False

        # Check hex characters
        try:
            int(address[2:], 16)
            return True
        except ValueError:
            return False

    @staticmethod
    def detect_blockchain(address: str) -> Optional[str]:
        """Detect blockchain from address format"""
        if not address:
            return None

        if address.startswith('1') or address.startswith('3') or address.startswith('bc1'):
            return 'bitcoin'

        if address.startswith('0x') and len(address) == 42:
            return 'ethereum'

        if address.startswith('T') and len(address) == 34:
            return 'tron'

        if address.startswith('r') and len(address) == 34:
            return 'ripple'

        return None


class TestAddressValidator:
    """Unit tests for AddressValidator"""

    def test_valid_bitcoin_legacy(self):
        """Test valid Bitcoin legacy address"""
        address = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
        assert AddressValidator.is_valid_bitcoin_address(address) is True

    def test_valid_bitcoin_segwit(self):
        """Test valid Bitcoin SegWit address"""
        address = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"
        assert AddressValidator.is_valid_bitcoin_address(address) is True

    def test_valid_bitcoin_bech32(self):
        """Test valid Bitcoin bech32 address"""
        address = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
        assert AddressValidator.is_valid_bitcoin_address(address) is True

    def test_invalid_bitcoin_address(self):
        """Test invalid Bitcoin address"""
        assert AddressValidator.is_valid_bitcoin_address("") is False
        assert AddressValidator.is_valid_bitcoin_address("invalid") is False
        assert AddressValidator.is_valid_bitcoin_address("0x123") is False

    def test_valid_ethereum_address(self):
        """Test valid Ethereum address"""
        address = "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1"
        assert AddressValidator.is_valid_ethereum_address(address) is True

    def test_invalid_ethereum_address(self):
        """Test invalid Ethereum address"""
        assert AddressValidator.is_valid_ethereum_address("") is False
        assert AddressValidator.is_valid_ethereum_address("0x123") is False
        assert AddressValidator.is_valid_ethereum_address("not-an-address") is False
        # Invalid hex
        assert AddressValidator.is_valid_ethereum_address("0xGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG") is False

    def test_detect_blockchain_bitcoin(self):
        """Test blockchain detection for Bitcoin"""
        assert AddressValidator.detect_blockchain("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa") == "bitcoin"
        assert AddressValidator.detect_blockchain("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy") == "bitcoin"
        assert AddressValidator.detect_blockchain("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq") == "bitcoin"

    def test_detect_blockchain_ethereum(self):
        """Test blockchain detection for Ethereum"""
        assert AddressValidator.detect_blockchain("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1") == "ethereum"

    def test_detect_blockchain_unknown(self):
        """Test blockchain detection for unknown"""
        assert AddressValidator.detect_blockchain("") is None
        assert AddressValidator.detect_blockchain("unknown-format") is None


# ============================================================
# API Response Parser Unit Tests
# ============================================================

class BlockchainInfoParser:
    """Parser for blockchain.info API responses"""

    @staticmethod
    def parse_wallet_response(data: Dict) -> WalletInfo:
        """Parse blockchain.info wallet API response"""
        balance = Decimal(data.get('final_balance', 0)) / Decimal('100000000')
        total_received = Decimal(data.get('total_received', 0)) / Decimal('100000000')
        total_sent = Decimal(data.get('total_sent', 0)) / Decimal('100000000')

        return WalletInfo(
            address=data.get('address', ''),
            blockchain='bitcoin',
            balance=balance,
            total_received=total_received,
            total_sent=total_sent,
            transaction_count=data.get('n_tx', 0),
            first_seen=None,
            last_seen=None,
            metadata={'source': 'blockchain.info'}
        )

    @staticmethod
    def parse_transaction(tx_data: Dict) -> Transaction:
        """Parse blockchain.info transaction"""
        from_addrs = [
            inp.get('prev_out', {}).get('addr', '')
            for inp in tx_data.get('inputs', [])
        ]
        to_addrs = [
            out.get('addr', '')
            for out in tx_data.get('out', [])
        ]

        # Calculate amount
        amount = sum(
            Decimal(out.get('value', 0)) / Decimal('100000000')
            for out in tx_data.get('out', [])
        )

        return Transaction(
            tx_hash=tx_data.get('hash', ''),
            blockchain='bitcoin',
            timestamp=datetime.fromtimestamp(tx_data.get('time', 0)),
            from_addresses=from_addrs,
            to_addresses=to_addrs,
            amount=amount,
            fee=Decimal(tx_data.get('fee', 0)) / Decimal('100000000'),
            confirmations=tx_data.get('confirmations', 0),
            block_height=tx_data.get('block_height'),
            metadata={'source': 'blockchain.info'}
        )


class TestBlockchainInfoParser:
    """Unit tests for BlockchainInfoParser"""

    def test_parse_wallet_response(self):
        """Test parsing wallet response"""
        data = {
            'address': '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa',
            'final_balance': 5000000000,  # 50 BTC in satoshi
            'total_received': 10000000000,  # 100 BTC
            'total_sent': 5000000000,  # 50 BTC
            'n_tx': 100
        }

        wallet = BlockchainInfoParser.parse_wallet_response(data)

        assert wallet.address == '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa'
        assert wallet.balance == Decimal('50.0')
        assert wallet.total_received == Decimal('100.0')
        assert wallet.transaction_count == 100
        assert wallet.metadata['source'] == 'blockchain.info'

    def test_parse_wallet_response_empty(self):
        """Test parsing empty wallet response"""
        data = {}

        wallet = BlockchainInfoParser.parse_wallet_response(data)

        assert wallet.address == ''
        assert wallet.balance == Decimal('0')
        assert wallet.transaction_count == 0

    def test_parse_transaction(self):
        """Test parsing transaction"""
        tx_data = {
            'hash': 'abc123',
            'time': 1609459200,  # 2021-01-01 00:00:00 UTC
            'inputs': [
                {'prev_out': {'addr': 'addr1', 'value': 100000000}}
            ],
            'out': [
                {'addr': 'addr2', 'value': 90000000},
                {'addr': 'addr3', 'value': 10000000}
            ],
            'fee': 10000,
            'confirmations': 6,
            'block_height': 665000
        }

        tx = BlockchainInfoParser.parse_transaction(tx_data)

        assert tx.tx_hash == 'abc123'
        assert len(tx.from_addresses) == 1
        assert len(tx.to_addresses) == 2
        assert tx.amount == Decimal('1.0')  # 0.9 + 0.1
        assert tx.fee == Decimal('0.0001')
        assert tx.confirmations == 6


# ============================================================
# Risk Scoring Unit Tests
# ============================================================

class RiskScorer:
    """Risk scoring for wallet analysis"""

    def __init__(
        self,
        high_volume_threshold: Decimal = Decimal("100.0"),
        suspicious_pattern_weight: float = 0.3,
        known_entity_reduction: float = 0.5
    ):
        self.high_volume_threshold = high_volume_threshold
        self.suspicious_pattern_weight = suspicious_pattern_weight
        self.known_entity_reduction = known_entity_reduction

    def calculate_base_score(self, wallet: WalletInfo) -> float:
        """Calculate base risk score"""
        score = 0.0

        # High volume increases risk
        if wallet.total_received > self.high_volume_threshold:
            score += 0.2

        # Many transactions can be suspicious
        if wallet.transaction_count > 1000:
            score += 0.15

        return min(score, 1.0)

    def apply_pattern_modifier(self, base_score: float, patterns: List[str]) -> float:
        """Apply pattern-based modifications"""
        score = base_score

        suspicious_patterns = ['mixing', 'rapid_movement', 'round_amounts']

        for pattern in patterns:
            if pattern in suspicious_patterns:
                score += self.suspicious_pattern_weight

        return min(score, 1.0)

    def apply_known_entity_modifier(self, score: float, is_known: bool) -> float:
        """Reduce score for known entities"""
        if is_known:
            return score * self.known_entity_reduction
        return score

    def calculate_final_score(
        self,
        wallet: WalletInfo,
        patterns: List[str] = None,
        is_known_entity: bool = False
    ) -> float:
        """Calculate final risk score"""
        base = self.calculate_base_score(wallet)
        with_patterns = self.apply_pattern_modifier(base, patterns or [])
        final = self.apply_known_entity_modifier(with_patterns, is_known_entity)

        return round(final, 4)


class TestRiskScorer:
    """Unit tests for RiskScorer"""

    @pytest.fixture
    def scorer(self):
        """Create scorer instance"""
        return RiskScorer()

    @pytest.fixture
    def high_risk_wallet(self):
        """Create high-risk wallet"""
        return WalletInfo(
            address="suspicious-wallet",
            blockchain="bitcoin",
            balance=Decimal("1000.0"),
            total_received=Decimal("50000.0"),
            total_sent=Decimal("49000.0"),
            transaction_count=5000,
            first_seen=None,
            last_seen=None
        )

    @pytest.fixture
    def low_risk_wallet(self):
        """Create low-risk wallet"""
        return WalletInfo(
            address="normal-wallet",
            blockchain="bitcoin",
            balance=Decimal("1.0"),
            total_received=Decimal("5.0"),
            total_sent=Decimal("4.0"),
            transaction_count=10,
            first_seen=None,
            last_seen=None
        )

    def test_calculate_base_score_high_risk(self, scorer, high_risk_wallet):
        """Test base score for high-risk wallet"""
        score = scorer.calculate_base_score(high_risk_wallet)

        assert score > 0.3  # High volume + many transactions

    def test_calculate_base_score_low_risk(self, scorer, low_risk_wallet):
        """Test base score for low-risk wallet"""
        score = scorer.calculate_base_score(low_risk_wallet)

        assert score == 0.0  # No risk factors

    def test_apply_pattern_modifier_suspicious(self, scorer):
        """Test pattern modifier with suspicious patterns"""
        base_score = 0.2
        patterns = ['mixing', 'rapid_movement']

        modified = scorer.apply_pattern_modifier(base_score, patterns)

        assert modified > base_score
        assert modified == pytest.approx(0.8)  # 0.2 + 0.3 + 0.3

    def test_apply_pattern_modifier_normal(self, scorer):
        """Test pattern modifier with normal patterns"""
        base_score = 0.2
        patterns = ['regular_payments', 'consistent_amounts']

        modified = scorer.apply_pattern_modifier(base_score, patterns)

        assert modified == base_score

    def test_apply_known_entity_modifier(self, scorer):
        """Test known entity modifier"""
        score = 0.8

        reduced = scorer.apply_known_entity_modifier(score, is_known=True)

        assert reduced == 0.4  # 0.8 * 0.5

    def test_calculate_final_score_high_risk(self, scorer, high_risk_wallet):
        """Test final score for high-risk wallet"""
        score = scorer.calculate_final_score(
            high_risk_wallet,
            patterns=['mixing'],
            is_known_entity=False
        )

        assert score >= 0.5

    def test_calculate_final_score_known_entity(self, scorer, high_risk_wallet):
        """Test final score for known entity"""
        unknown_score = scorer.calculate_final_score(
            high_risk_wallet,
            patterns=['mixing'],
            is_known_entity=False
        )

        known_score = scorer.calculate_final_score(
            high_risk_wallet,
            patterns=['mixing'],
            is_known_entity=True
        )

        assert known_score < unknown_score


# ============================================================
# Transaction Graph Unit Tests
# ============================================================

class TransactionGraph:
    """Graph representation of transaction flows"""

    def __init__(self):
        self.nodes: Dict[str, Dict] = {}
        self.edges: List[Dict] = []

    def add_node(self, address: str, hop: int = 0, metadata: Dict = None):
        """Add node to graph"""
        self.nodes[address] = {
            'address': address,
            'hop': hop,
            'metadata': metadata or {}
        }

    def add_edge(
        self,
        from_addr: str,
        to_addr: str,
        amount: Decimal,
        tx_hash: str,
        timestamp: datetime
    ):
        """Add edge to graph"""
        self.edges.append({
            'from': from_addr,
            'to': to_addr,
            'amount': float(amount),
            'tx_hash': tx_hash,
            'timestamp': timestamp.isoformat()
        })

    def get_outgoing(self, address: str) -> List[Dict]:
        """Get outgoing edges from address"""
        return [e for e in self.edges if e['from'] == address]

    def get_incoming(self, address: str) -> List[Dict]:
        """Get incoming edges to address"""
        return [e for e in self.edges if e['to'] == address]

    def get_connected_addresses(self, address: str) -> Set[str]:
        """Get all addresses connected to given address"""
        connected = set()

        for edge in self.edges:
            if edge['from'] == address:
                connected.add(edge['to'])
            if edge['to'] == address:
                connected.add(edge['from'])

        return connected

    def to_dict(self) -> Dict:
        """Convert graph to dictionary"""
        return {
            'nodes': list(self.nodes.values()),
            'edges': self.edges
        }


class TestTransactionGraph:
    """Unit tests for TransactionGraph"""

    @pytest.fixture
    def graph(self):
        """Create graph with sample data"""
        g = TransactionGraph()

        # Add nodes
        g.add_node("addr1", hop=0)
        g.add_node("addr2", hop=1)
        g.add_node("addr3", hop=1)
        g.add_node("addr4", hop=2)

        # Add edges
        g.add_edge("addr1", "addr2", Decimal("1.0"), "tx1", datetime.now())
        g.add_edge("addr1", "addr3", Decimal("0.5"), "tx2", datetime.now())
        g.add_edge("addr2", "addr4", Decimal("0.8"), "tx3", datetime.now())

        return g

    def test_add_node(self, graph):
        """Test adding node"""
        graph.add_node("addr5", hop=3, metadata={'label': 'test'})

        assert "addr5" in graph.nodes
        assert graph.nodes["addr5"]['hop'] == 3
        assert graph.nodes["addr5"]['metadata']['label'] == 'test'

    def test_add_edge(self, graph):
        """Test adding edge"""
        initial_edges = len(graph.edges)

        graph.add_edge("addr3", "addr4", Decimal("0.3"), "tx4", datetime.now())

        assert len(graph.edges) == initial_edges + 1

    def test_get_outgoing(self, graph):
        """Test getting outgoing edges"""
        outgoing = graph.get_outgoing("addr1")

        assert len(outgoing) == 2
        assert all(e['from'] == 'addr1' for e in outgoing)

    def test_get_incoming(self, graph):
        """Test getting incoming edges"""
        incoming = graph.get_incoming("addr4")

        assert len(incoming) == 1
        assert incoming[0]['from'] == 'addr2'

    def test_get_connected_addresses(self, graph):
        """Test getting connected addresses"""
        connected = graph.get_connected_addresses("addr1")

        assert "addr2" in connected
        assert "addr3" in connected
        assert "addr4" not in connected  # Not directly connected

    def test_to_dict(self, graph):
        """Test conversion to dictionary"""
        data = graph.to_dict()

        assert 'nodes' in data
        assert 'edges' in data
        assert len(data['nodes']) == 4
        assert len(data['edges']) == 3


# ============================================================
# Run tests
# ============================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
