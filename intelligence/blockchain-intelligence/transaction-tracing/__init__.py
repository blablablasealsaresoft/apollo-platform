"""
Multi-Chain Transaction Tracing System
Comprehensive blockchain transaction analysis and visualization

Agent 18: Multi-Chain Transaction Tracing
"""

from .transaction_tracer import (
    TransactionTracer,
    BlockchainType,
    TransactionType,
    Transaction,
    TraceResult
)

from .bitcoin_tracer import (
    BitcoinTracer,
    UTXO,
    BitcoinTransaction,
    UTXOGraph
)

from .ethereum_tracer import (
    EthereumTracer,
    EthereumTransaction,
    TokenTransfer,
    InternalTransaction,
    ContractType,
    ContractInfo
)

from .cross_chain_tracer import (
    CrossChainTracer,
    CrossChainTransaction,
    BridgeType,
    AtomicSwap,
    BridgeContract
)

from .fund_flow_analyzer import (
    FundFlowAnalyzer,
    FlowAnalysis,
    FlowPattern,
    EntityType,
    FlowNode,
    FlowEdge
)

from .taint_analyzer import (
    TaintAnalyzer,
    TaintScore,
    TaintPath,
    TaintMethod,
    TaintSource
)

from .endpoint_identifier import (
    EndpointIdentifier,
    EndpointInfo,
    EndpointType
)

from .graph_generator import (
    GraphGenerator
)

__version__ = "1.0.0"
__author__ = "Agent 18"
__description__ = "Multi-Chain Transaction Tracing System"

__all__ = [
    # Transaction Tracer
    'TransactionTracer',
    'BlockchainType',
    'TransactionType',
    'Transaction',
    'TraceResult',

    # Bitcoin Tracer
    'BitcoinTracer',
    'UTXO',
    'BitcoinTransaction',
    'UTXOGraph',

    # Ethereum Tracer
    'EthereumTracer',
    'EthereumTransaction',
    'TokenTransfer',
    'InternalTransaction',
    'ContractType',
    'ContractInfo',

    # Cross-Chain Tracer
    'CrossChainTracer',
    'CrossChainTransaction',
    'BridgeType',
    'AtomicSwap',
    'BridgeContract',

    # Fund Flow Analyzer
    'FundFlowAnalyzer',
    'FlowAnalysis',
    'FlowPattern',
    'EntityType',
    'FlowNode',
    'FlowEdge',

    # Taint Analyzer
    'TaintAnalyzer',
    'TaintScore',
    'TaintPath',
    'TaintMethod',
    'TaintSource',

    # Endpoint Identifier
    'EndpointIdentifier',
    'EndpointInfo',
    'EndpointType',

    # Graph Generator
    'GraphGenerator',
]
