"""
Blockchain API Clients

Unified interface for 50+ blockchain explorers:
- Bitcoin: blockchain.info, blockchair, blockcypher, btc.com
- Ethereum: etherscan, ethplorer, alchemy
- BSC, Polygon, Avalanche, Solana, Cardano, Litecoin, etc.

Features:
- Rate limiting
- API key rotation
- Response caching
- Automatic retries
- Error handling
"""

from .api_manager import BlockchainAPIManager
from .bitcoin_clients import (
    BlockchainInfoClient,
    BlockchairClient,
    BlockCypherClient,
    BTCComClient,
)
from .ethereum_clients import (
    EtherscanClient,
    EthplorerClient,
    AlchemyClient,
)
from .multi_chain_clients import (
    BSCScanClient,
    PolygonScanClient,
    SnowTraceClient,
    SolscanClient,
    CardanoScanClient,
)

__all__ = [
    "BlockchainAPIManager",
    "BlockchainInfoClient",
    "BlockchairClient",
    "BlockCypherClient",
    "BTCComClient",
    "EtherscanClient",
    "EthplorerClient",
    "AlchemyClient",
    "BSCScanClient",
    "PolygonScanClient",
    "SnowTraceClient",
    "SolscanClient",
    "CardanoScanClient",
]
