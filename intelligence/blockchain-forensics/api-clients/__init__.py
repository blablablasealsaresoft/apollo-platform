"""
Blockchain API Clients

Unified interface for 50+ blockchain explorers:
- Bitcoin: blockchain.info, blockchair, blockcypher, btc.com, blockstream, mempool.space
- Ethereum: etherscan, ethplorer, alchemy
- BSC, Polygon, Avalanche, Solana, Cardano, Litecoin, etc.

Features:
- Rate limiting
- API key rotation
- Response caching
- Automatic retries
- Error handling
- Real transaction tracking (no mock data)
"""

from .api_manager import BlockchainAPIManager
from .bitcoin_clients import (
    BlockchainInfoClient,
    BlockchairClient,
    BlockCypherClient,
    BTCComClient,
    BlockstreamAPIClient,
    MempoolSpaceAPIClient,
    CoinGeckoClient,
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
from .real_bitcoin_tracker import (
    RealBitcoinTracker,
    UTXO,
    BitcoinTransaction,
    AddressStats,
)
from .real_ethereum_tracker import (
    RealEthereumTracker,
    EthereumTransaction,
    EthereumAddressInfo,
    TokenTransfer,
    ERC20Token,
)

__all__ = [
    # API Manager
    "BlockchainAPIManager",
    # Bitcoin Clients
    "BlockchainInfoClient",
    "BlockchairClient",
    "BlockCypherClient",
    "BTCComClient",
    "BlockstreamAPIClient",
    "MempoolSpaceAPIClient",
    "CoinGeckoClient",
    # Real Bitcoin Tracker
    "RealBitcoinTracker",
    "UTXO",
    "BitcoinTransaction",
    "AddressStats",
    # Ethereum Clients
    "EtherscanClient",
    "EthplorerClient",
    "AlchemyClient",
    # Real Ethereum Tracker
    "RealEthereumTracker",
    "EthereumTransaction",
    "EthereumAddressInfo",
    "TokenTransfer",
    "ERC20Token",
    # Multi-chain
    "BSCScanClient",
    "PolygonScanClient",
    "SnowTraceClient",
    "SolscanClient",
    "CardanoScanClient",
]
