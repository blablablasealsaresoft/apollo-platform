"""
Cryptocurrency Wallet Clustering and Attribution System

Advanced blockchain analysis tools for clustering addresses
and attributing them to real-world entities.
"""

from .wallet_clustering import (
    WalletClusterer,
    AddressCluster,
    ClusterLink,
    ClusteringResult
)

from .common_input_heuristic import (
    CommonInputHeuristic,
    MultiInputTransaction,
    CIHResult
)

from .change_address_detector import (
    ChangeAddressDetector,
    OutputAnalysis,
    ChangeDetectionResult
)

from .peel_chain_analyzer import (
    PeelChainAnalyzer,
    PeelChain,
    PeelChainLink,
    PeelChainDetectionResult
)

from .entity_attribution import (
    EntityAttributor,
    KnownEntity,
    AttributionResult
)

from .cluster_visualizer import (
    ClusterVisualizer
)

from .mixing_detector import (
    MixingDetector,
    MixingServiceSignature,
    MixingDetectionResult
)

from .exchange_identifier import (
    ExchangeIdentifier,
    ExchangeSignature,
    ExchangeInteraction,
    ExchangeIdentificationResult
)

__version__ = '1.0.0'
__author__ = 'Apollo Blockchain Intelligence'

__all__ = [
    # Main clustering
    'WalletClusterer',
    'AddressCluster',
    'ClusterLink',
    'ClusteringResult',

    # Common Input Heuristic
    'CommonInputHeuristic',
    'MultiInputTransaction',
    'CIHResult',

    # Change Detection
    'ChangeAddressDetector',
    'OutputAnalysis',
    'ChangeDetectionResult',

    # Peel Chain Analysis
    'PeelChainAnalyzer',
    'PeelChain',
    'PeelChainLink',
    'PeelChainDetectionResult',

    # Entity Attribution
    'EntityAttributor',
    'KnownEntity',
    'AttributionResult',

    # Visualization
    'ClusterVisualizer',

    # Mixing Detection
    'MixingDetector',
    'MixingServiceSignature',
    'MixingDetectionResult',

    # Exchange Identification
    'ExchangeIdentifier',
    'ExchangeSignature',
    'ExchangeInteraction',
    'ExchangeIdentificationResult',
]
