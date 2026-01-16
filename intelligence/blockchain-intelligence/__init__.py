"""
Blockchain Intelligence System
Comprehensive blockchain forensics for Bitcoin, Ethereum, and 50+ chains
"""

from .bitcoin_tracker import BitcoinTracker
from .ethereum_tracker import EthereumTracker
from .multi_chain_tracker import MultiChainTracker
from .wallet_clustering import WalletClusterer
from .transaction_tracer import TransactionTracer
from .exchange_monitor import ExchangeMonitor
from .blockchain_apis import BlockchainAPIOrchestrator, RateLimiter, APICache
from .onecoin_tracker import OneCoinTracker

__version__ = '1.0.0'
__author__ = 'Blockchain Intelligence Team'

__all__ = [
    'BitcoinTracker',
    'EthereumTracker',
    'MultiChainTracker',
    'WalletClusterer',
    'TransactionTracer',
    'ExchangeMonitor',
    'BlockchainAPIOrchestrator',
    'RateLimiter',
    'APICache',
    'OneCoinTracker'
]


def create_intelligence_suite(bitcoin_api_key=None, ethereum_api_key=None,
                              multi_chain_api_keys=None):
    """
    Create a fully integrated blockchain intelligence suite

    Args:
        bitcoin_api_key: Optional API key for Bitcoin services
        ethereum_api_key: Optional API key for Ethereum services (Etherscan)
        multi_chain_api_keys: Dict of API keys for various chains

    Returns:
        Dict containing all tracker instances
    """
    # Initialize API orchestrator
    api_orchestrator = BlockchainAPIOrchestrator()

    # Initialize trackers
    bitcoin_tracker = BitcoinTracker()
    ethereum_tracker = EthereumTracker(etherscan_api_key=ethereum_api_key)
    multi_chain_tracker = MultiChainTracker()

    # Initialize analysis tools
    wallet_clusterer = WalletClusterer(
        bitcoin_tracker=bitcoin_tracker,
        ethereum_tracker=ethereum_tracker
    )

    transaction_tracer = TransactionTracer(
        bitcoin_tracker=bitcoin_tracker,
        ethereum_tracker=ethereum_tracker,
        multi_chain_tracker=multi_chain_tracker
    )

    exchange_monitor = ExchangeMonitor(
        bitcoin_tracker=bitcoin_tracker,
        ethereum_tracker=ethereum_tracker,
        multi_chain_tracker=multi_chain_tracker
    )

    onecoin_tracker = OneCoinTracker(
        bitcoin_tracker=bitcoin_tracker,
        ethereum_tracker=ethereum_tracker,
        multi_chain_tracker=multi_chain_tracker
    )

    return {
        'api_orchestrator': api_orchestrator,
        'bitcoin': bitcoin_tracker,
        'ethereum': ethereum_tracker,
        'multi_chain': multi_chain_tracker,
        'clustering': wallet_clusterer,
        'tracer': transaction_tracer,
        'exchange': exchange_monitor,
        'onecoin': onecoin_tracker
    }


# Quick start example
def quick_start_example():
    """Example usage of the blockchain intelligence system"""

    # Create the intelligence suite
    suite = create_intelligence_suite(
        ethereum_api_key='YOUR_ETHERSCAN_API_KEY'
    )

    # Example 1: Analyze a Bitcoin wallet
    btc_analysis = suite['bitcoin'].analyze_wallet('1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa')
    print(f"Bitcoin Balance: {btc_analysis['balance']} BTC")

    # Example 2: Trace Ethereum funds
    eth_trace = suite['tracer'].trace_ethereum_funds(
        '0x742d35Cc6634C0532925a3b844Bc454e4438f44e',
        max_hops=3
    )
    print(f"Traced {eth_trace['unique_addresses']} unique addresses")

    # Example 3: Cluster related wallets
    cluster = suite['clustering'].cluster_bitcoin_addresses(
        '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa',
        depth=2
    )
    print(f"Cluster size: {cluster['size']} addresses")

    # Example 4: Monitor exchange activity
    exchange_report = suite['exchange'].generate_exchange_report('binance', hours=24)
    print(exchange_report)

    # Example 5: Multi-chain analysis
    multi_analysis = suite['multi_chain'].analyze_multi_chain_wallet(
        '0x742d35Cc6634C0532925a3b844Bc454e4438f44e',
        chains=['bsc', 'polygon', 'avalanche']
    )
    print(f"Active on {len(multi_analysis['chains_analyzed'])} chains")

    return suite
