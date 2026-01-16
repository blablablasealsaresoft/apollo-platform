"""
Test suite for OneCoin tracking modules
"""

import pytest
import asyncio
from datetime import datetime
from unittest.mock import Mock, AsyncMock, patch


class TestOneCoinTracker:
    """Tests for OneCoin tracker"""

    @pytest.fixture
    def tracker(self):
        """Create tracker instance with mocked dependencies"""
        from blockchain_forensics.onecoin.tracker import OneCoinTracker

        db = Mock()
        api = Mock()
        graph = Mock()

        return OneCoinTracker(db, api, graph)

    @pytest.mark.asyncio
    async def test_track_address(self, tracker):
        """Test address tracking"""
        # Mock API response
        tracker.api.get_address_transactions = AsyncMock(return_value=[
            {
                "txid": "test123",
                "timestamp": datetime.utcnow(),
                "from_address": "addr1",
                "to_address": "addr2",
                "amount": 1.0,
                "amount_usd": 50000,
            }
        ])

        tracker.db.store_tracking_result = AsyncMock()
        tracker.db.get_known_onecoin_addresses = AsyncMock(return_value=set())
        tracker.db.get_ruja_ignatova_addresses = AsyncMock(return_value=set())

        # Track address
        result = await tracker.track_address("test_address", "btc", depth=1)

        assert result["address"] == "test_address"
        assert "transactions" in result
        assert "onecoin_confidence" in result

    @pytest.mark.asyncio
    async def test_onecoin_confidence_calculation(self, tracker):
        """Test OneCoin confidence scoring"""
        # Setup
        tracker.known_onecoin_addresses = {"known_addr"}

        transactions = [
            {
                "txid": "tx1",
                "from_address": "test_addr",
                "to_address": "known_addr",  # Connection to known OneCoin address
                "amount_usd": 100000,
                "timestamp": datetime.utcnow(),
            }
        ]

        patterns = ["rapid_splitting", "mixer_usage"]

        # Calculate confidence
        confidence = await tracker._calculate_onecoin_confidence(
            "test_addr",
            transactions,
            patterns
        )

        # Should have some confidence due to connection and patterns
        assert confidence > 0.0
        assert confidence <= 1.0


class TestRujaWalletIdentifier:
    """Tests for Ruja wallet identifier"""

    @pytest.fixture
    def identifier(self):
        """Create identifier instance"""
        from blockchain_forensics.onecoin.wallet_identifier import RujaWalletIdentifier

        db = Mock()
        api = Mock()
        graph = Mock()

        return RujaWalletIdentifier(db, api, graph)

    @pytest.mark.asyncio
    async def test_identify_ruja_wallets(self, identifier):
        """Test Ruja wallet identification"""
        # Mock dependencies
        identifier.api.get_address_transactions = AsyncMock(return_value=[
            {
                "txid": "tx1",
                "timestamp": datetime(2016, 6, 1),  # During OneCoin peak
                "amount_usd": 5_000_000,  # High value
                "from_address": "addr1",
                "to_address": "addr2",
            }
        ])

        identifier.db.query_wallets = AsyncMock(return_value=[
            {"address": "test_wallet"}
        ])

        identifier.db.get_associate_addresses = AsyncMock(return_value=set())
        identifier.db.get_all_associate_addresses = AsyncMock(return_value=set())

        # Identify wallets
        wallets = await identifier.identify_ruja_wallets(min_confidence=0.5)

        assert isinstance(wallets, list)

    @pytest.mark.asyncio
    async def test_wallet_comparison(self, identifier):
        """Test wallet similarity comparison"""
        # Mock API responses for both addresses
        identifier.api.get_address_transactions = AsyncMock(return_value=[
            {
                "txid": "tx1",
                "timestamp": datetime(2016, 6, 1),
                "from_address": "addr1",
                "to_address": "shared_addr",
                "amount_usd": 10000,
            }
        ])

        identifier.db.get_associate_addresses = AsyncMock(return_value=set())
        identifier.db.get_all_associate_addresses = AsyncMock(return_value=set())

        # Compare wallets
        comparison = await identifier.compare_wallets("addr1", "addr2")

        assert "similarity_score" in comparison
        assert "likely_same_owner" in comparison


class TestFundFlowAnalyzer:
    """Tests for fund flow analyzer"""

    @pytest.fixture
    def analyzer(self):
        """Create analyzer instance"""
        from blockchain_forensics.onecoin.fund_flow import FundFlowAnalyzer

        db = Mock()
        api = Mock()
        graph = Mock()

        return FundFlowAnalyzer(db, api, graph)

    @pytest.mark.asyncio
    async def test_trace_fund_flow(self, analyzer):
        """Test fund flow tracing"""
        # Mock transaction data
        analyzer.api.get_address_transactions = AsyncMock(return_value=[
            {
                "txid": "tx1",
                "from_address": "source",
                "to_address": "dest",
                "amount": 1.0,
                "amount_usd": 50000,
                "timestamp": datetime.utcnow(),
            }
        ])

        # Trace flow
        flows = await analyzer.trace_fund_flow("source_address", max_hops=3)

        assert isinstance(flows, list)

    @pytest.mark.asyncio
    async def test_consolidation_points(self, analyzer):
        """Test identification of consolidation points"""
        from blockchain_forensics.onecoin.fund_flow import FundFlow

        # Create test flows
        flows = [
            FundFlow(
                source_address="src1",
                destination_address="consolidation_point",
                amount=1.0,
                amount_usd=10000,
                timestamp=datetime.utcnow(),
                hops=2,
                path=["src1", "intermediate", "consolidation_point"],
            ),
            FundFlow(
                source_address="src2",
                destination_address="consolidation_point",
                amount=2.0,
                amount_usd=20000,
                timestamp=datetime.utcnow(),
                hops=1,
                path=["src2", "consolidation_point"],
            ),
        ]

        # Find consolidation points
        points = await analyzer.identify_consolidation_points(flows)

        assert len(points) > 0
        assert points[0]["address"] == "consolidation_point"
        assert points[0]["incoming_flow_count"] >= 2


# Run tests
if __name__ == "__main__":
    pytest.main([__file__, "-v"])
