"""
Cross-Chain Transaction Tracer
Bridge detection and multi-chain fund flow analysis
"""

import asyncio
import logging
from typing import Dict, List, Set, Optional, Tuple, Any
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict, deque
import networkx as nx
from enum import Enum


class BridgeType(Enum):
    """Types of cross-chain bridges"""
    LOCK_AND_MINT = "lock_and_mint"
    BURN_AND_MINT = "burn_and_mint"
    ATOMIC_SWAP = "atomic_swap"
    WRAPPED_TOKEN = "wrapped_token"
    RELAY = "relay"
    LIQUIDITY_POOL = "liquidity_pool"


class ChainPair(Enum):
    """Common chain pairs"""
    ETH_BSC = ("ethereum", "bsc")
    ETH_POLYGON = ("ethereum", "polygon")
    ETH_ARBITRUM = ("ethereum", "arbitrum")
    ETH_OPTIMISM = ("ethereum", "optimism")
    BTC_ETH = ("bitcoin", "ethereum")
    ETH_AVALANCHE = ("ethereum", "avalanche")
    ETH_FANTOM = ("ethereum", "fantom")


@dataclass
class BridgeContract:
    """Bridge contract information"""
    address: str
    name: str
    bridge_type: BridgeType
    source_chain: str
    destination_chain: str
    supported_tokens: List[str]
    is_trusted: bool
    risk_level: str  # low, medium, high


@dataclass
class CrossChainTransaction:
    """Cross-chain transaction"""
    source_tx_hash: str
    source_chain: str
    source_address: str
    destination_tx_hash: Optional[str]
    destination_chain: str
    destination_address: Optional[str]
    bridge_contract: str
    bridge_type: BridgeType
    amount: float
    token: str
    timestamp: datetime
    confirmations: int
    status: str  # pending, completed, failed
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AtomicSwap:
    """Atomic swap transaction"""
    swap_id: str
    initiator: str
    participant: str
    chain_a: str
    chain_b: str
    tx_a_hash: str
    tx_b_hash: Optional[str]
    amount_a: float
    amount_b: float
    hash_lock: str
    time_lock: datetime
    status: str  # initiated, completed, refunded


class CrossChainTracer:
    """
    Cross-chain transaction tracer

    Features:
    - Bridge transaction detection
    - Atomic swap identification
    - Cross-chain fund flow tracking
    - Multi-chain correlation
    - Wrapped token tracking
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize cross-chain tracer

        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.logger = logging.getLogger(__name__)

        # Known bridges
        self.bridges = self._load_known_bridges()

        # Caches
        self.cross_chain_tx_cache: Dict[str, CrossChainTransaction] = {}
        self.atomic_swap_cache: Dict[str, AtomicSwap] = {}

        # Statistics
        self.stats = {
            'cross_chain_txs_found': 0,
            'atomic_swaps_found': 0,
            'bridges_used': set(),
            'chain_pairs': defaultdict(int)
        }

    def _load_known_bridges(self) -> Dict[str, BridgeContract]:
        """Load known bridge contracts"""
        bridges = {
            # Ethereum bridges
            '0x3ee18B2214AFF97000D974cf647E7C347E8fa585': BridgeContract(
                address='0x3ee18B2214AFF97000D974cf647E7C347E8fa585',
                name='Polygon PoS Bridge',
                bridge_type=BridgeType.LOCK_AND_MINT,
                source_chain='ethereum',
                destination_chain='polygon',
                supported_tokens=['ETH', 'USDC', 'USDT', 'DAI'],
                is_trusted=True,
                risk_level='low'
            ),
            '0x8484Ef722627bf18ca5Ae6BcF031c23E6e922B30': BridgeContract(
                address='0x8484Ef722627bf18ca5Ae6BcF031c23E6e922B30',
                name='Multichain Bridge',
                bridge_type=BridgeType.LOCK_AND_MINT,
                source_chain='ethereum',
                destination_chain='bsc',
                supported_tokens=['ETH', 'BTC', 'USDC'],
                is_trusted=True,
                risk_level='medium'
            ),
            '0x40ec5B33f54e0E8A33A975908C5BA1c14e5BbbDf': BridgeContract(
                address='0x40ec5B33f54e0E8A33A975908C5BA1c14e5BbbDf',
                name='Polygon ERC20 Bridge',
                bridge_type=BridgeType.LOCK_AND_MINT,
                source_chain='ethereum',
                destination_chain='polygon',
                supported_tokens=['MATIC', 'USDC', 'DAI'],
                is_trusted=True,
                risk_level='low'
            ),
            # Wrapped Bitcoin bridges
            '0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599': BridgeContract(
                address='0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599',
                name='Wrapped BTC',
                bridge_type=BridgeType.WRAPPED_TOKEN,
                source_chain='bitcoin',
                destination_chain='ethereum',
                supported_tokens=['BTC'],
                is_trusted=True,
                risk_level='low'
            ),
        }
        return bridges

    async def detect_bridge_transaction(
        self,
        tx_hash: str,
        source_chain: str
    ) -> Optional[CrossChainTransaction]:
        """
        Detect if transaction is a bridge transaction

        Args:
            tx_hash: Transaction hash
            source_chain: Source blockchain

        Returns:
            CrossChainTransaction if detected
        """
        # Check cache
        if tx_hash in self.cross_chain_tx_cache:
            return self.cross_chain_tx_cache[tx_hash]

        # Get transaction details
        tx_details = await self._get_transaction_details(tx_hash, source_chain)
        if not tx_details:
            return None

        # Check if interacting with known bridge
        bridge_info = None
        for bridge_addr, bridge in self.bridges.items():
            if (bridge.source_chain == source_chain and
                tx_details.get('to_address', '').lower() == bridge_addr.lower()):
                bridge_info = bridge
                break

        if not bridge_info:
            # Try to detect bridge by pattern
            bridge_info = await self._detect_bridge_by_pattern(tx_details, source_chain)

        if bridge_info:
            # Try to find destination transaction
            dest_tx = await self._find_destination_transaction(
                tx_hash,
                source_chain,
                bridge_info.destination_chain,
                tx_details
            )

            cross_chain_tx = CrossChainTransaction(
                source_tx_hash=tx_hash,
                source_chain=source_chain,
                source_address=tx_details.get('from_address', ''),
                destination_tx_hash=dest_tx.get('tx_hash') if dest_tx else None,
                destination_chain=bridge_info.destination_chain,
                destination_address=dest_tx.get('to_address') if dest_tx else None,
                bridge_contract=bridge_info.address,
                bridge_type=bridge_info.bridge_type,
                amount=tx_details.get('amount', 0),
                token=tx_details.get('token', 'NATIVE'),
                timestamp=tx_details.get('timestamp', datetime.now()),
                confirmations=tx_details.get('confirmations', 0),
                status='completed' if dest_tx else 'pending',
                metadata={
                    'bridge_name': bridge_info.name,
                    'risk_level': bridge_info.risk_level
                }
            )

            # Cache and update stats
            self.cross_chain_tx_cache[tx_hash] = cross_chain_tx
            self.stats['cross_chain_txs_found'] += 1
            self.stats['bridges_used'].add(bridge_info.name)
            self.stats['chain_pairs'][(source_chain, bridge_info.destination_chain)] += 1

            return cross_chain_tx

        return None

    async def trace_cross_chain_flow(
        self,
        start_address: str,
        start_chain: str,
        max_hops: int = 5
    ) -> nx.DiGraph:
        """
        Trace cross-chain fund flow

        Args:
            start_address: Starting address
            start_chain: Starting blockchain
            max_hops: Maximum cross-chain hops

        Returns:
            Multi-chain transaction graph
        """
        graph = nx.DiGraph()
        graph.add_node(
            f"{start_chain}:{start_address}",
            chain=start_chain,
            address=start_address,
            is_source=True
        )

        # Queue: (chain, address, hop)
        queue = deque([(start_chain, start_address, 0)])
        visited = {(start_chain, start_address)}

        while queue:
            chain, address, hop = queue.popleft()

            if hop >= max_hops:
                continue

            # Get transactions on current chain
            transactions = await self._get_address_transactions(address, chain)

            for tx in transactions:
                tx_hash = tx.get('hash', '')

                # Check if bridge transaction
                cross_chain_tx = await self.detect_bridge_transaction(tx_hash, chain)

                if cross_chain_tx:
                    # Add cross-chain edge
                    source_node = f"{chain}:{address}"
                    dest_node = f"{cross_chain_tx.destination_chain}:{cross_chain_tx.destination_address}"

                    graph.add_node(
                        dest_node,
                        chain=cross_chain_tx.destination_chain,
                        address=cross_chain_tx.destination_address
                    )

                    graph.add_edge(
                        source_node,
                        dest_node,
                        tx_hash=tx_hash,
                        dest_tx_hash=cross_chain_tx.destination_tx_hash,
                        bridge=cross_chain_tx.bridge_contract,
                        amount=cross_chain_tx.amount,
                        token=cross_chain_tx.token,
                        timestamp=cross_chain_tx.timestamp,
                        is_cross_chain=True
                    )

                    # Continue on destination chain
                    next_key = (cross_chain_tx.destination_chain, cross_chain_tx.destination_address)
                    if next_key not in visited and cross_chain_tx.destination_address:
                        visited.add(next_key)
                        queue.append((
                            cross_chain_tx.destination_chain,
                            cross_chain_tx.destination_address,
                            hop + 1
                        ))

        return graph

    async def find_atomic_swaps(
        self,
        address: str,
        chain_a: str,
        chain_b: str,
        time_window: timedelta = timedelta(hours=24)
    ) -> List[AtomicSwap]:
        """
        Find atomic swaps involving address

        Args:
            address: Address to analyze
            chain_a: First blockchain
            chain_b: Second blockchain
            time_window: Time window for matching swaps

        Returns:
            List of atomic swaps
        """
        atomic_swaps = []

        # Get transactions on both chains
        txs_a = await self._get_address_transactions(address, chain_a)
        txs_b = await self._get_address_transactions(address, chain_b)

        # Look for hash time locked contracts (HTLC)
        htlc_a = await self._find_htlc_transactions(txs_a, chain_a)
        htlc_b = await self._find_htlc_transactions(txs_b, chain_b)

        # Match HTLCs by hash lock
        for htlc_tx_a in htlc_a:
            hash_lock = htlc_tx_a.get('hash_lock')
            if not hash_lock:
                continue

            # Find matching HTLC on chain B
            for htlc_tx_b in htlc_b:
                if htlc_tx_b.get('hash_lock') == hash_lock:
                    # Check time correlation
                    time_diff = abs(
                        htlc_tx_a['timestamp'] - htlc_tx_b['timestamp']
                    )

                    if time_diff <= time_window:
                        # Found atomic swap
                        swap = AtomicSwap(
                            swap_id=f"{htlc_tx_a['hash']}_{htlc_tx_b['hash']}",
                            initiator=address,
                            participant=htlc_tx_b.get('counterparty', ''),
                            chain_a=chain_a,
                            chain_b=chain_b,
                            tx_a_hash=htlc_tx_a['hash'],
                            tx_b_hash=htlc_tx_b['hash'],
                            amount_a=htlc_tx_a['amount'],
                            amount_b=htlc_tx_b['amount'],
                            hash_lock=hash_lock,
                            time_lock=htlc_tx_a['time_lock'],
                            status='completed'
                        )

                        atomic_swaps.append(swap)
                        self.stats['atomic_swaps_found'] += 1

        return atomic_swaps

    async def correlate_addresses_cross_chain(
        self,
        addresses: List[Tuple[str, str]]
    ) -> Dict[str, Any]:
        """
        Correlate addresses across chains

        Args:
            addresses: List of (address, chain) tuples

        Returns:
            Correlation analysis
        """
        correlation = {
            'addresses': addresses,
            'connections': [],
            'shared_bridges': [],
            'temporal_correlation': 0.0,
            'amount_correlation': 0.0
        }

        # Find cross-chain transactions for each address
        cross_chain_txs = {}
        for address, chain in addresses:
            txs = await self._get_address_transactions(address, chain)
            bridge_txs = []

            for tx in txs:
                bridge_tx = await self.detect_bridge_transaction(tx.get('hash', ''), chain)
                if bridge_tx:
                    bridge_txs.append(bridge_tx)

            cross_chain_txs[(address, chain)] = bridge_txs

        # Find connections
        for (addr1, chain1), txs1 in cross_chain_txs.items():
            for (addr2, chain2), txs2 in cross_chain_txs.items():
                if (addr1, chain1) == (addr2, chain2):
                    continue

                # Check for matching transactions
                for tx1 in txs1:
                    for tx2 in txs2:
                        # Same destination chain?
                        if tx1.destination_chain == chain2:
                            correlation['connections'].append({
                                'source': (addr1, chain1),
                                'destination': (addr2, chain2),
                                'bridge': tx1.bridge_contract,
                                'amount': tx1.amount,
                                'timestamp': tx1.timestamp
                            })

        # Temporal correlation
        if len(cross_chain_txs) >= 2:
            all_timestamps = []
            for txs in cross_chain_txs.values():
                all_timestamps.extend([tx.timestamp for tx in txs])

            if len(all_timestamps) > 1:
                all_timestamps.sort()
                time_diffs = [
                    (all_timestamps[i+1] - all_timestamps[i]).total_seconds()
                    for i in range(len(all_timestamps)-1)
                ]
                avg_diff = sum(time_diffs) / len(time_diffs) if time_diffs else 0
                # Lower average = higher correlation
                correlation['temporal_correlation'] = max(0, 1 - (avg_diff / 86400))

        return correlation

    async def track_wrapped_tokens(
        self,
        original_chain: str,
        wrapped_chain: str,
        token: str
    ) -> Dict[str, Any]:
        """
        Track wrapped token flows

        Args:
            original_chain: Original blockchain (e.g., 'bitcoin')
            wrapped_chain: Wrapped token blockchain (e.g., 'ethereum')
            token: Token symbol (e.g., 'BTC')

        Returns:
            Wrapped token flow analysis
        """
        analysis = {
            'original_chain': original_chain,
            'wrapped_chain': wrapped_chain,
            'token': token,
            'total_locked': 0.0,
            'total_minted': 0.0,
            'total_burned': 0.0,
            'total_unlocked': 0.0,
            'active_wraps': []
        }

        # Find wrapped token contract
        wrapped_contract = None
        for bridge in self.bridges.values():
            if (bridge.source_chain == original_chain and
                bridge.destination_chain == wrapped_chain and
                token in bridge.supported_tokens):
                wrapped_contract = bridge.address
                break

        if not wrapped_contract:
            return analysis

        # Get all bridge events
        lock_events = await self._get_lock_events(wrapped_contract, original_chain)
        mint_events = await self._get_mint_events(wrapped_contract, wrapped_chain)
        burn_events = await self._get_burn_events(wrapped_contract, wrapped_chain)
        unlock_events = await self._get_unlock_events(wrapped_contract, original_chain)

        analysis['total_locked'] = sum(e.get('amount', 0) for e in lock_events)
        analysis['total_minted'] = sum(e.get('amount', 0) for e in mint_events)
        analysis['total_burned'] = sum(e.get('amount', 0) for e in burn_events)
        analysis['total_unlocked'] = sum(e.get('amount', 0) for e in unlock_events)

        # Match lock/mint pairs
        for lock_event in lock_events:
            matching_mint = next(
                (m for m in mint_events if m.get('lock_id') == lock_event.get('id')),
                None
            )
            if matching_mint:
                analysis['active_wraps'].append({
                    'lock_tx': lock_event.get('tx_hash'),
                    'mint_tx': matching_mint.get('tx_hash'),
                    'amount': lock_event.get('amount'),
                    'user': lock_event.get('user')
                })

        return analysis

    async def _get_transaction_details(
        self,
        tx_hash: str,
        chain: str
    ) -> Optional[Dict[str, Any]]:
        """Get transaction details from blockchain"""
        # Simulate API call
        await asyncio.sleep(0.01)
        return None

    async def _detect_bridge_by_pattern(
        self,
        tx_details: Dict[str, Any],
        chain: str
    ) -> Optional[BridgeContract]:
        """Detect bridge by transaction pattern"""
        # Look for bridge-like patterns in transaction data
        return None

    async def _find_destination_transaction(
        self,
        source_tx_hash: str,
        source_chain: str,
        dest_chain: str,
        source_tx_details: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Find corresponding destination transaction"""
        # Match by timestamp, amount, and recipient
        await asyncio.sleep(0.01)
        return None

    async def _get_address_transactions(
        self,
        address: str,
        chain: str
    ) -> List[Dict[str, Any]]:
        """Get transactions for address on specific chain"""
        await asyncio.sleep(0.01)
        return []

    async def _find_htlc_transactions(
        self,
        transactions: List[Dict[str, Any]],
        chain: str
    ) -> List[Dict[str, Any]]:
        """Find Hash Time Locked Contract transactions"""
        htlc_txs = []
        for tx in transactions:
            # Check for HTLC patterns
            if 'hash_lock' in tx or 'time_lock' in tx:
                htlc_txs.append(tx)
        return htlc_txs

    async def _get_lock_events(
        self,
        contract: str,
        chain: str
    ) -> List[Dict[str, Any]]:
        """Get lock events from bridge contract"""
        await asyncio.sleep(0.01)
        return []

    async def _get_mint_events(
        self,
        contract: str,
        chain: str
    ) -> List[Dict[str, Any]]:
        """Get mint events from bridge contract"""
        await asyncio.sleep(0.01)
        return []

    async def _get_burn_events(
        self,
        contract: str,
        chain: str
    ) -> List[Dict[str, Any]]:
        """Get burn events from bridge contract"""
        await asyncio.sleep(0.01)
        return []

    async def _get_unlock_events(
        self,
        contract: str,
        chain: str
    ) -> List[Dict[str, Any]]:
        """Get unlock events from bridge contract"""
        await asyncio.sleep(0.01)
        return []

    def get_statistics(self) -> Dict[str, Any]:
        """Get tracer statistics"""
        return {
            'cross_chain_txs_found': self.stats['cross_chain_txs_found'],
            'atomic_swaps_found': self.stats['atomic_swaps_found'],
            'bridges_used': list(self.stats['bridges_used']),
            'chain_pairs': dict(self.stats['chain_pairs'])
        }


# Example usage
async def main():
    """Example usage of CrossChainTracer"""
    tracer = CrossChainTracer()

    # Trace cross-chain flow
    graph = await tracer.trace_cross_chain_flow(
        start_address='0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb',
        start_chain='ethereum',
        max_hops=3
    )

    print(f"Cross-chain graph:")
    print(f"  Nodes: {graph.number_of_nodes()}")
    print(f"  Edges: {graph.number_of_edges()}")

    # Find atomic swaps
    swaps = await tracer.find_atomic_swaps(
        address='bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh',
        chain_a='bitcoin',
        chain_b='ethereum'
    )

    print(f"\nAtomic swaps found: {len(swaps)}")


if __name__ == "__main__":
    asyncio.run(main())
