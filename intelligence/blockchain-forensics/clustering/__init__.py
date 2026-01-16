"""
Wallet Clustering Module

Advanced algorithms for clustering blockchain addresses:
- Common input ownership heuristic
- Change address detection
- Co-spending analysis
- Peel chain detection
- Mixer/tumbler detection
- Cluster labeling
"""

from .clustering_engine import WalletClusteringEngine, WalletCluster, Cluster
from .real_clustering_engine import (
    RealWalletClusteringEngine,
    AddressCluster,
    ClusterEvidence,
    ClusteringResult,
    QuickClusterer,
)

__all__ = [
    # Original engine
    "WalletClusteringEngine",
    "WalletCluster",
    "Cluster",
    # Real clustering engine
    "RealWalletClusteringEngine",
    "AddressCluster",
    "ClusterEvidence",
    "ClusteringResult",
    "QuickClusterer",
]
