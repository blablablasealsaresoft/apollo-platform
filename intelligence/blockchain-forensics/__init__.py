"""
Apollo Blockchain Forensics Platform
Advanced blockchain analysis and cryptocurrency tracking for elite investigations

Modules:
- onecoin: OneCoin fraud tracking and Ruja Ignatova wallet identification
- clustering: Wallet clustering and common ownership analysis
- tracer: Multi-blockchain transaction tracing
- exchanges: Exchange surveillance and deposit tracking
- api_clients: Integration with 50+ blockchain explorers (real APIs, no mocks)
- address_intel: Address intelligence and labeling
- visualization: Transaction flow visualization
- mixers: Mixer/tumbler detection and analysis
- aml: Anti-money laundering scoring with OFAC/sanctions support
- monitoring: Real-time address monitoring and alerts

Real API Implementations:
- Bitcoin: Blockstream, Mempool.space, Blockchain.info (no API key required)
- Ethereum: Etherscan (free tier), Ethplorer (free)
- Multi-chain: BSCScan, PolygonScan, SnowTrace, Solscan
"""

__version__ = "2.0.0"
__author__ = "Apollo Platform - Agent 2"

from typing import Dict, Any

# Real tracker imports
from .api_clients.real_bitcoin_tracker import RealBitcoinTracker
from .api_clients.real_ethereum_tracker import RealEthereumTracker
from .clustering.real_clustering_engine import RealWalletClusteringEngine
from .aml.real_aml_scoring import RealAMLScoringEngine

# Module exports
__all__ = [
    # Real implementations
    "RealBitcoinTracker",
    "RealEthereumTracker",
    "RealWalletClusteringEngine",
    "RealAMLScoringEngine",
    # Module references
    "onecoin",
    "clustering",
    "tracer",
    "exchanges",
    "api_clients",
    "address_intel",
    "visualization",
    "mixers",
    "aml",
    "monitoring",
]
