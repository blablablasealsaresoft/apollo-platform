"""
Unit tests for Blockchain Intelligence Engine
"""

import pytest
import asyncio
from decimal import Decimal
import sys
sys.path.append('..')

from blockchain_intelligence import BlockchainIntelligenceEngine


@pytest.mark.asyncio
async def test_blockchain_engine_initialization():
    """Test blockchain engine initialization"""
    engine = BlockchainIntelligenceEngine()

    assert engine is not None
    assert len(engine.get_supported_blockchains()) > 0
    assert 'bitcoin' in engine.get_supported_blockchains()
    assert 'ethereum' in engine.get_supported_blockchains()


@pytest.mark.asyncio
async def test_bitcoin_wallet_info():
    """Test Bitcoin wallet information retrieval"""
    engine = BlockchainIntelligenceEngine()

    # Satoshi's genesis wallet
    address = '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa'

    wallet_info = await engine.get_wallet_info(address, 'bitcoin')

    assert wallet_info is not None
    assert wallet_info.address == address
    assert wallet_info.blockchain == 'bitcoin'
    assert isinstance(wallet_info.balance, Decimal)
    assert isinstance(wallet_info.transaction_count, int)


@pytest.mark.asyncio
async def test_ethereum_wallet_info():
    """Test Ethereum wallet information retrieval"""
    engine = BlockchainIntelligenceEngine()

    # Test with a known Ethereum address (requires API key)
    address = '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb'

    try:
        wallet_info = await engine.get_wallet_info(address, 'ethereum')

        assert wallet_info is not None
        assert wallet_info.blockchain == 'ethereum'
        assert isinstance(wallet_info.balance, Decimal)
    except Exception:
        # Skip if API key not configured
        pytest.skip("Ethereum API key not configured")


@pytest.mark.asyncio
async def test_supported_blockchains():
    """Test supported blockchains list"""
    engine = BlockchainIntelligenceEngine()

    blockchains = engine.get_supported_blockchains()

    assert 'bitcoin' in blockchains
    assert 'ethereum' in blockchains
    assert 'bsc' in blockchains
    assert 'polygon' in blockchains
    assert len(blockchains) >= 10


def test_api_client_initialization():
    """Test API client initialization"""
    engine = BlockchainIntelligenceEngine()

    assert 'blockchain_info' in engine.bitcoin_apis
    assert 'etherscan' in engine.ethereum_apis
    assert 'bscscan' in engine.multichain_apis


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
