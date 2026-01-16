"""
Endpoint Identifier
Identify transaction endpoints (exchanges, merchants, etc.)
"""

import asyncio
import logging
from typing import Dict, List, Set, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict
import networkx as nx
from enum import Enum
import re


class EndpointType(Enum):
    """Types of endpoints"""
    EXCHANGE = "exchange"
    MERCHANT = "merchant"
    P2P = "p2p"
    GAMBLING = "gambling"
    DARKNET = "darknet"
    MIXER = "mixer"
    MINING_POOL = "mining_pool"
    ICO = "ico"
    PAYMENT_PROCESSOR = "payment_processor"
    ATM = "atm"
    OTC = "otc"
    DEFI_PROTOCOL = "defi_protocol"
    NFT_MARKETPLACE = "nft_marketplace"
    BRIDGE = "bridge"
    WALLET_SERVICE = "wallet_service"
    TERMINAL = "terminal"  # Dead-end address
    UNKNOWN = "unknown"


@dataclass
class EndpointInfo:
    """Information about an endpoint"""
    address: str
    blockchain: str
    endpoint_type: EndpointType
    name: Optional[str]
    confidence: float
    indicators: List[str]
    transaction_count: int
    total_volume: float
    first_seen: datetime
    last_seen: datetime
    risk_level: str  # low, medium, high, critical
    metadata: Dict[str, Any] = field(default_factory=dict)


class EndpointIdentifier:
    """
    Endpoint identification system

    Features:
    - Exchange deposit detection
    - Merchant payment identification
    - P2P transaction detection
    - Terminal address identification
    - Pattern-based classification
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize endpoint identifier

        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.logger = logging.getLogger(__name__)

        # Known endpoints database
        self.known_endpoints = self._load_known_endpoints()

        # Pattern matchers
        self.patterns = self._load_patterns()

        # Cache
        self.endpoint_cache: Dict[str, EndpointInfo] = {}

        # Statistics
        self.stats = {
            'identifications': 0,
            'endpoint_types': defaultdict(int),
            'cache_hits': 0
        }

    def _load_known_endpoints(self) -> Dict[str, EndpointInfo]:
        """Load known endpoint addresses"""
        known = {}

        # Major exchanges
        exchanges = {
            # Binance
            '0x3f5CE5FBFe3E9af3971dD833D26bA9b5C936f0bE': ('Binance', 'ethereum'),
            '0xD551234Ae421e3BCBA99A0Da6d736074f22192FF': ('Binance', 'ethereum'),
            '34xp4vRoCGJym3xR7yCVPFHoCNxv4Twseo': ('Binance', 'bitcoin'),

            # Coinbase
            '0x71660c4005BA85c37ccec55d0C4493E66Fe775d3': ('Coinbase', 'ethereum'),
            '0x503828976D22510aad0201ac7EC88293211D23Da': ('Coinbase', 'ethereum'),
            '3D2oetdNuZUqQHPJmcMDDHYoqkyNVsFk9r': ('Coinbase', 'bitcoin'),

            # Kraken
            '0x2910543Af39abA0Cd09dBb2D50200b3E800A63D2': ('Kraken', 'ethereum'),
            '0xAe2D4617c862309A3d75A0fFB358c7a5009c673F': ('Kraken', 'ethereum'),

            # Bitfinex
            '0x1151314c646Ce4E0eFD76d1aF4760aE66a9Fe30F': ('Bitfinex', 'ethereum'),
            '3D2oetdNuZUqQHPJmcMDDHYoqkyNVsFk9r': ('Bitfinex', 'bitcoin'),
        }

        for address, (name, blockchain) in exchanges.items():
            known[address] = EndpointInfo(
                address=address,
                blockchain=blockchain,
                endpoint_type=EndpointType.EXCHANGE,
                name=name,
                confidence=1.0,
                indicators=['known_database'],
                transaction_count=0,
                total_volume=0.0,
                first_seen=datetime.now(),
                last_seen=datetime.now(),
                risk_level='low',
                metadata={'verified': True}
            )

        # Known mixers
        mixers = {
            '0x8d12A197cB00D4747a1fe03395095ce2A5CC6819': ('Tornado Cash', 'ethereum'),
            '0xA160cdAB225685dA1d56aa342Ad8841c3b53f291': ('Tornado Cash', 'ethereum'),
        }

        for address, (name, blockchain) in mixers.items():
            known[address] = EndpointInfo(
                address=address,
                blockchain=blockchain,
                endpoint_type=EndpointType.MIXER,
                name=name,
                confidence=1.0,
                indicators=['known_database'],
                transaction_count=0,
                total_volume=0.0,
                first_seen=datetime.now(),
                last_seen=datetime.now(),
                risk_level='high',
                metadata={'verified': True, 'sanctioned': True}
            )

        # DeFi protocols
        defi = {
            '0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D': ('Uniswap V2', 'ethereum'),
            '0xE592427A0AEce92De3Edee1F18E0157C05861564': ('Uniswap V3', 'ethereum'),
            '0x1111111254fb6c44bAC0beD2854e76F90643097d': ('1inch', 'ethereum'),
        }

        for address, (name, blockchain) in defi.items():
            known[address] = EndpointInfo(
                address=address,
                blockchain=blockchain,
                endpoint_type=EndpointType.DEFI_PROTOCOL,
                name=name,
                confidence=1.0,
                indicators=['known_database'],
                transaction_count=0,
                total_volume=0.0,
                first_seen=datetime.now(),
                last_seen=datetime.now(),
                risk_level='low',
                metadata={'verified': True}
            )

        return known

    def _load_patterns(self) -> Dict[str, Any]:
        """Load identification patterns"""
        return {
            'exchange_patterns': {
                'high_volume': 1000,  # Many transactions
                'many_unique_senders': 100,  # Many different senders
                'deposit_pattern': True,  # Many inputs, few outputs
            },
            'mixer_patterns': {
                'equal_outputs': 0.8,  # High percentage of equal-value outputs
                'many_to_many': True,  # Many inputs and outputs
                'time_clustering': 3600,  # Transactions clustered in time
            },
            'merchant_patterns': {
                'regular_amounts': True,  # Round numbers
                'consistent_timing': True,  # Regular intervals
                'many_small_payments': True,
            },
            'terminal_patterns': {
                'no_outputs': True,  # No outgoing transactions
                'single_or_few_inputs': 5,
            }
        }

    async def identify(
        self,
        address: str,
        blockchain: str,
        transaction_data: Optional[Dict[str, Any]] = None
    ) -> Optional[EndpointInfo]:
        """
        Identify endpoint type for address

        Args:
            address: Address to identify
            blockchain: Blockchain type
            transaction_data: Optional transaction data for analysis

        Returns:
            EndpointInfo if identified
        """
        # Check cache
        cache_key = f"{blockchain}:{address}"
        if cache_key in self.endpoint_cache:
            self.stats['cache_hits'] += 1
            return self.endpoint_cache[cache_key]

        # Check known endpoints
        if address in self.known_endpoints:
            endpoint = self.known_endpoints[address]
            self.endpoint_cache[cache_key] = endpoint
            self.stats['identifications'] += 1
            self.stats['endpoint_types'][endpoint.endpoint_type.value] += 1
            return endpoint

        # Pattern-based identification
        if transaction_data:
            endpoint = await self._identify_by_pattern(address, blockchain, transaction_data)
            if endpoint:
                self.endpoint_cache[cache_key] = endpoint
                self.stats['identifications'] += 1
                self.stats['endpoint_types'][endpoint.endpoint_type.value] += 1
                return endpoint

        return None

    async def _identify_by_pattern(
        self,
        address: str,
        blockchain: str,
        data: Dict[str, Any]
    ) -> Optional[EndpointInfo]:
        """Identify endpoint by transaction patterns"""
        indicators = []
        confidence = 0.0
        endpoint_type = EndpointType.UNKNOWN

        # Get transaction statistics
        tx_count = data.get('transaction_count', 0)
        in_degree = data.get('in_degree', 0)
        out_degree = data.get('out_degree', 0)
        total_volume = data.get('total_volume', 0.0)
        unique_senders = data.get('unique_senders', 0)
        unique_receivers = data.get('unique_receivers', 0)

        # Check for exchange pattern
        if (tx_count > self.patterns['exchange_patterns']['high_volume'] and
            unique_senders > self.patterns['exchange_patterns']['many_unique_senders'] and
            in_degree > out_degree * 2):
            endpoint_type = EndpointType.EXCHANGE
            confidence = 0.75
            indicators.append('high_volume')
            indicators.append('deposit_pattern')

        # Check for mixer pattern
        elif (in_degree >= 10 and out_degree >= 10):
            # Check for equal outputs
            output_amounts = data.get('output_amounts', [])
            if output_amounts:
                amount_counts = defaultdict(int)
                for amount in output_amounts:
                    amount_counts[amount] += 1
                max_equal = max(amount_counts.values())
                equal_ratio = max_equal / len(output_amounts)

                if equal_ratio >= self.patterns['mixer_patterns']['equal_outputs']:
                    endpoint_type = EndpointType.MIXER
                    confidence = 0.85
                    indicators.append('equal_outputs')
                    indicators.append('many_to_many')

        # Check for terminal address
        elif out_degree == 0 and in_degree > 0:
            endpoint_type = EndpointType.TERMINAL
            confidence = 0.9
            indicators.append('no_outputs')

        # Check for merchant
        elif tx_count > 50 and unique_senders > 20:
            # Check for regular amounts
            amounts = data.get('amounts', [])
            if amounts and self._has_regular_amounts(amounts):
                endpoint_type = EndpointType.MERCHANT
                confidence = 0.7
                indicators.append('regular_amounts')
                indicators.append('many_customers')

        # Check for P2P
        elif in_degree <= 5 and out_degree <= 5 and tx_count >= 2:
            endpoint_type = EndpointType.P2P
            confidence = 0.6
            indicators.append('low_transaction_count')

        # Check for mining pool
        elif out_degree > 100 and in_degree < 10:
            # Many small payouts
            endpoint_type = EndpointType.MINING_POOL
            confidence = 0.75
            indicators.append('distribution_pattern')

        if endpoint_type != EndpointType.UNKNOWN:
            risk_level = self._calculate_risk_level(endpoint_type)

            return EndpointInfo(
                address=address,
                blockchain=blockchain,
                endpoint_type=endpoint_type,
                name=None,
                confidence=confidence,
                indicators=indicators,
                transaction_count=tx_count,
                total_volume=total_volume,
                first_seen=data.get('first_seen', datetime.now()),
                last_seen=data.get('last_seen', datetime.now()),
                risk_level=risk_level,
                metadata={}
            )

        return None

    def _has_regular_amounts(self, amounts: List[float]) -> bool:
        """Check if amounts show regular pattern"""
        if len(amounts) < 10:
            return False

        # Check for round numbers
        round_count = sum(1 for amt in amounts if amt == round(amt, 2))
        round_ratio = round_count / len(amounts)

        return round_ratio > 0.5

    def _calculate_risk_level(self, endpoint_type: EndpointType) -> str:
        """Calculate risk level based on endpoint type"""
        high_risk = [
            EndpointType.MIXER,
            EndpointType.DARKNET,
            EndpointType.GAMBLING
        ]
        medium_risk = [
            EndpointType.P2P,
            EndpointType.OTC,
            EndpointType.ATM
        ]
        low_risk = [
            EndpointType.EXCHANGE,
            EndpointType.MERCHANT,
            EndpointType.PAYMENT_PROCESSOR,
            EndpointType.DEFI_PROTOCOL
        ]

        if endpoint_type in high_risk:
            return 'high'
        elif endpoint_type in medium_risk:
            return 'medium'
        elif endpoint_type in low_risk:
            return 'low'
        else:
            return 'unknown'

    async def batch_identify(
        self,
        addresses: List[Tuple[str, str]],
        graph: Optional[nx.DiGraph] = None
    ) -> Dict[str, EndpointInfo]:
        """
        Identify multiple addresses

        Args:
            addresses: List of (address, blockchain) tuples
            graph: Optional transaction graph for pattern analysis

        Returns:
            Dictionary of address -> EndpointInfo
        """
        results = {}

        for address, blockchain in addresses:
            # Gather transaction data from graph
            tx_data = None
            if graph and address in graph.nodes():
                tx_data = {
                    'transaction_count': graph.degree(address),
                    'in_degree': graph.in_degree(address),
                    'out_degree': graph.out_degree(address),
                    'unique_senders': len(list(graph.predecessors(address))),
                    'unique_receivers': len(list(graph.successors(address))),
                }

            endpoint = await self.identify(address, blockchain, tx_data)
            if endpoint:
                results[address] = endpoint

        return results

    async def find_exchanges(
        self,
        graph: nx.DiGraph
    ) -> List[EndpointInfo]:
        """
        Find all exchange endpoints in graph

        Args:
            graph: Transaction graph

        Returns:
            List of exchange endpoints
        """
        exchanges = []

        for node in graph.nodes():
            # Analyze node
            tx_data = {
                'transaction_count': graph.degree(node),
                'in_degree': graph.in_degree(node),
                'out_degree': graph.out_degree(node),
                'unique_senders': len(list(graph.predecessors(node))),
                'unique_receivers': len(list(graph.successors(node))),
            }

            endpoint = await self._identify_by_pattern(node, 'unknown', tx_data)
            if endpoint and endpoint.endpoint_type == EndpointType.EXCHANGE:
                exchanges.append(endpoint)

        return exchanges

    async def find_terminal_addresses(
        self,
        graph: nx.DiGraph
    ) -> List[EndpointInfo]:
        """
        Find all terminal addresses (no outputs)

        Args:
            graph: Transaction graph

        Returns:
            List of terminal endpoints
        """
        terminals = []

        for node in graph.nodes():
            if graph.out_degree(node) == 0 and graph.in_degree(node) > 0:
                # Calculate volume
                total_volume = sum(
                    data.get('amount', 0)
                    for _, _, data in graph.in_edges(node, data=True)
                )

                # Get timestamps
                timestamps = [
                    data.get('timestamp')
                    for _, _, data in graph.in_edges(node, data=True)
                    if 'timestamp' in data
                ]

                terminal = EndpointInfo(
                    address=node,
                    blockchain='unknown',
                    endpoint_type=EndpointType.TERMINAL,
                    name=None,
                    confidence=1.0,
                    indicators=['no_outputs'],
                    transaction_count=graph.in_degree(node),
                    total_volume=total_volume,
                    first_seen=min(timestamps) if timestamps else datetime.now(),
                    last_seen=max(timestamps) if timestamps else datetime.now(),
                    risk_level='unknown'
                )

                terminals.append(terminal)

        return terminals

    def get_endpoint_summary(
        self,
        endpoints: List[EndpointInfo]
    ) -> Dict[str, Any]:
        """
        Get summary of endpoints

        Args:
            endpoints: List of endpoints

        Returns:
            Summary statistics
        """
        summary = {
            'total_endpoints': len(endpoints),
            'by_type': defaultdict(int),
            'by_risk': defaultdict(int),
            'total_volume': 0.0,
            'high_confidence': 0
        }

        for endpoint in endpoints:
            summary['by_type'][endpoint.endpoint_type.value] += 1
            summary['by_risk'][endpoint.risk_level] += 1
            summary['total_volume'] += endpoint.total_volume

            if endpoint.confidence >= 0.8:
                summary['high_confidence'] += 1

        summary['by_type'] = dict(summary['by_type'])
        summary['by_risk'] = dict(summary['by_risk'])

        return summary

    def get_statistics(self) -> Dict[str, Any]:
        """Get identifier statistics"""
        return {
            'identifications': self.stats['identifications'],
            'endpoint_types': dict(self.stats['endpoint_types']),
            'cache_hits': self.stats['cache_hits'],
            'cache_size': len(self.endpoint_cache),
            'known_endpoints': len(self.known_endpoints)
        }


# Example usage
async def main():
    """Example usage of EndpointIdentifier"""
    identifier = EndpointIdentifier()

    # Create sample graph
    graph = nx.DiGraph()

    # Simulate exchange (many inputs, few outputs)
    exchange_addr = "exchange_address"
    for i in range(150):
        graph.add_edge(f"user_{i}", exchange_addr, amount=1.5)

    for i in range(10):
        graph.add_edge(exchange_addr, f"withdrawal_{i}", amount=10.0)

    # Find exchanges
    exchanges = await identifier.find_exchanges(graph)
    print(f"Exchanges found: {len(exchanges)}")
    for exchange in exchanges:
        print(f"  {exchange.address}: {exchange.confidence:.2%} confidence")

    # Find terminals
    terminals = await identifier.find_terminal_addresses(graph)
    print(f"\nTerminal addresses: {len(terminals)}")

    # Get summary
    all_endpoints = exchanges + terminals
    summary = identifier.get_endpoint_summary(all_endpoints)
    print(f"\nEndpoint summary:")
    print(f"  Total: {summary['total_endpoints']}")
    print(f"  By type: {summary['by_type']}")


if __name__ == "__main__":
    asyncio.run(main())
