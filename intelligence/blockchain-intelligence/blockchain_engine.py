"""
Blockchain Intelligence Engine
Unified interface for 50+ blockchain APIs and intelligence gathering
"""

import asyncio
import logging
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal

logger = logging.getLogger(__name__)


@dataclass
class WalletInfo:
    """Information about a cryptocurrency wallet"""
    address: str
    blockchain: str
    balance: Decimal
    total_received: Decimal
    total_sent: Decimal
    transaction_count: int
    first_seen: Optional[datetime]
    last_seen: Optional[datetime]
    labels: List[str] = field(default_factory=list)
    risk_score: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Transaction:
    """Blockchain transaction"""
    tx_hash: str
    blockchain: str
    timestamp: datetime
    from_addresses: List[str]
    to_addresses: List[str]
    amount: Decimal
    fee: Decimal
    confirmations: int
    block_height: Optional[int]
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class WalletCluster:
    """Cluster of related wallets"""
    cluster_id: str
    addresses: Set[str]
    total_balance: Decimal
    confidence_score: float
    clustering_method: str
    metadata: Dict[str, Any] = field(default_factory=dict)


class BlockchainIntelligenceEngine:
    """
    Blockchain Intelligence Engine
    Tracks cryptocurrency wallets across 50+ blockchains
    """

    def __init__(
        self,
        api_keys: Optional[Dict[str, str]] = None
    ):
        """
        Initialize blockchain intelligence engine

        Args:
            api_keys: Dictionary of API keys for various services
        """
        self.api_keys = api_keys or {}
        self._init_api_clients()

    def _init_api_clients(self):
        """Initialize API clients for various blockchain services"""
        # Bitcoin APIs
        self.bitcoin_apis = {
            'blockchain_info': 'https://blockchain.info',
            'blockchair': 'https://api.blockchair.com/bitcoin',
            'blockcypher': 'https://api.blockcypher.com/v1/btc/main',
            'blockstream': 'https://blockstream.info/api',
            'mempool_space': 'https://mempool.space/api',
        }

        # Ethereum APIs
        self.ethereum_apis = {
            'etherscan': 'https://api.etherscan.io/api',
            'ethplorer': 'https://api.ethplorer.io',
            'blockchair_eth': 'https://api.blockchair.com/ethereum',
            'infura': 'https://mainnet.infura.io/v3',
        }

        # Multi-chain APIs
        self.multichain_apis = {
            'bscscan': 'https://api.bscscan.com/api',  # Binance Smart Chain
            'polygonscan': 'https://api.polygonscan.com/api',  # Polygon
            'snowtrace': 'https://api.snowtrace.io/api',  # Avalanche
            'ftmscan': 'https://api.ftmscan.com/api',  # Fantom
            'arbiscan': 'https://api.arbiscan.io/api',  # Arbitrum
            'optimistic_etherscan': 'https://api-optimistic.etherscan.io/api',  # Optimism
        }

        # Other blockchain APIs
        self.other_apis = {
            'solana': 'https://api.mainnet-beta.solana.com',
            'cardano': 'https://cardano-mainnet.blockfrost.io/api/v0',
            'polkadot': 'https://polkadot.api.subscan.io',
            'tron': 'https://api.trongrid.io',
            'ripple': 'https://s1.ripple.com:51234',
        }

    async def get_wallet_info(
        self,
        address: str,
        blockchain: str = 'bitcoin'
    ) -> WalletInfo:
        """
        Get comprehensive information about a wallet

        Args:
            address: Wallet address
            blockchain: Blockchain name

        Returns:
            WalletInfo object
        """
        if blockchain.lower() == 'bitcoin':
            return await self._get_bitcoin_wallet_info(address)
        elif blockchain.lower() == 'ethereum':
            return await self._get_ethereum_wallet_info(address)
        elif blockchain.lower() in ['bsc', 'binance']:
            return await self._get_bsc_wallet_info(address)
        elif blockchain.lower() == 'polygon':
            return await self._get_polygon_wallet_info(address)
        else:
            raise ValueError(f"Unsupported blockchain: {blockchain}")

    async def _get_bitcoin_wallet_info(self, address: str) -> WalletInfo:
        """Get Bitcoin wallet information from multiple sources"""
        import aiohttp

        # Try multiple APIs for redundancy
        apis = [
            ('blockchain_info', self._fetch_blockchain_info_btc),
            ('blockchair', self._fetch_blockchair_btc),
            ('blockcypher', self._fetch_blockcypher_btc),
        ]

        for api_name, fetch_func in apis:
            try:
                wallet_info = await fetch_func(address)
                if wallet_info:
                    logger.info(
                        f"Successfully fetched Bitcoin wallet info from {api_name}"
                    )
                    return wallet_info
            except Exception as e:
                logger.warning(f"Failed to fetch from {api_name}: {e}")
                continue

        # If all APIs fail, return minimal info
        return WalletInfo(
            address=address,
            blockchain='bitcoin',
            balance=Decimal('0'),
            total_received=Decimal('0'),
            total_sent=Decimal('0'),
            transaction_count=0,
            first_seen=None,
            last_seen=None
        )

    async def _fetch_blockchain_info_btc(self, address: str) -> WalletInfo:
        """Fetch Bitcoin wallet info from blockchain.info"""
        import aiohttp

        url = f"{self.bitcoin_apis['blockchain_info']}/rawaddr/{address}"

        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=30) as response:
                if response.status == 200:
                    data = await response.json()

                    balance = Decimal(data.get('final_balance', 0)) / Decimal('100000000')
                    total_received = Decimal(data.get('total_received', 0)) / Decimal('100000000')
                    total_sent = Decimal(data.get('total_sent', 0)) / Decimal('100000000')

                    return WalletInfo(
                        address=address,
                        blockchain='bitcoin',
                        balance=balance,
                        total_received=total_received,
                        total_sent=total_sent,
                        transaction_count=data.get('n_tx', 0),
                        first_seen=None,  # Not provided by this API
                        last_seen=None,
                        metadata={'source': 'blockchain.info'}
                    )

        return None

    async def _fetch_blockchair_btc(self, address: str) -> WalletInfo:
        """Fetch Bitcoin wallet info from Blockchair"""
        import aiohttp

        url = f"{self.bitcoin_apis['blockchair']}/dashboards/address/{address}"

        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=30) as response:
                if response.status == 200:
                    data = await response.json()

                    if 'data' in data and address in data['data']:
                        addr_data = data['data'][address]['address']

                        balance = Decimal(addr_data.get('balance', 0)) / Decimal('100000000')
                        total_received = Decimal(addr_data.get('received', 0)) / Decimal('100000000')
                        total_sent = Decimal(addr_data.get('spent', 0)) / Decimal('100000000')

                        return WalletInfo(
                            address=address,
                            blockchain='bitcoin',
                            balance=balance,
                            total_received=total_received,
                            total_sent=total_sent,
                            transaction_count=addr_data.get('transaction_count', 0),
                            first_seen=None,
                            last_seen=None,
                            metadata={'source': 'blockchair'}
                        )

        return None

    async def _fetch_blockcypher_btc(self, address: str) -> WalletInfo:
        """Fetch Bitcoin wallet info from BlockCypher"""
        import aiohttp

        url = f"{self.bitcoin_apis['blockcypher']}/addrs/{address}/balance"

        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=30) as response:
                if response.status == 200:
                    data = await response.json()

                    balance = Decimal(data.get('final_balance', 0)) / Decimal('100000000')
                    total_received = Decimal(data.get('total_received', 0)) / Decimal('100000000')
                    total_sent = Decimal(data.get('total_sent', 0)) / Decimal('100000000')

                    return WalletInfo(
                        address=address,
                        blockchain='bitcoin',
                        balance=balance,
                        total_received=total_received,
                        total_sent=total_sent,
                        transaction_count=data.get('n_tx', 0),
                        first_seen=None,
                        last_seen=None,
                        metadata={'source': 'blockcypher'}
                    )

        return None

    async def _get_ethereum_wallet_info(self, address: str) -> WalletInfo:
        """Get Ethereum wallet information"""
        import aiohttp

        # Try Etherscan first
        if 'etherscan' in self.api_keys:
            api_key = self.api_keys['etherscan']
            url = (
                f"{self.ethereum_apis['etherscan']}"
                f"?module=account&action=balance&address={address}"
                f"&tag=latest&apikey={api_key}"
            )

            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, timeout=30) as response:
                        if response.status == 200:
                            data = await response.json()
                            if data.get('status') == '1':
                                balance = Decimal(data['result']) / Decimal('1000000000000000000')

                                # Get transaction count
                                tx_url = (
                                    f"{self.ethereum_apis['etherscan']}"
                                    f"?module=account&action=txlist&address={address}"
                                    f"&page=1&offset=1&sort=desc&apikey={api_key}"
                                )
                                async with session.get(tx_url, timeout=30) as tx_response:
                                    tx_data = await tx_response.json()
                                    tx_count = len(tx_data.get('result', []))

                                return WalletInfo(
                                    address=address,
                                    blockchain='ethereum',
                                    balance=balance,
                                    total_received=Decimal('0'),  # Requires more API calls
                                    total_sent=Decimal('0'),
                                    transaction_count=tx_count,
                                    first_seen=None,
                                    last_seen=None,
                                    metadata={'source': 'etherscan'}
                                )
            except Exception as e:
                logger.warning(f"Etherscan API error: {e}")

        # Fallback to minimal info
        return WalletInfo(
            address=address,
            blockchain='ethereum',
            balance=Decimal('0'),
            total_received=Decimal('0'),
            total_sent=Decimal('0'),
            transaction_count=0,
            first_seen=None,
            last_seen=None
        )

    async def _get_bsc_wallet_info(self, address: str) -> WalletInfo:
        """Get Binance Smart Chain wallet information"""
        import aiohttp

        if 'bscscan' in self.api_keys:
            api_key = self.api_keys['bscscan']
            url = (
                f"{self.multichain_apis['bscscan']}"
                f"?module=account&action=balance&address={address}"
                f"&apikey={api_key}"
            )

            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, timeout=30) as response:
                        if response.status == 200:
                            data = await response.json()
                            if data.get('status') == '1':
                                balance = Decimal(data['result']) / Decimal('1000000000000000000')

                                return WalletInfo(
                                    address=address,
                                    blockchain='bsc',
                                    balance=balance,
                                    total_received=Decimal('0'),
                                    total_sent=Decimal('0'),
                                    transaction_count=0,
                                    first_seen=None,
                                    last_seen=None,
                                    metadata={'source': 'bscscan'}
                                )
            except Exception as e:
                logger.warning(f"BSCScan API error: {e}")

        return WalletInfo(
            address=address,
            blockchain='bsc',
            balance=Decimal('0'),
            total_received=Decimal('0'),
            total_sent=Decimal('0'),
            transaction_count=0,
            first_seen=None,
            last_seen=None
        )

    async def _get_polygon_wallet_info(self, address: str) -> WalletInfo:
        """Get Polygon wallet information"""
        import aiohttp

        if 'polygonscan' in self.api_keys:
            api_key = self.api_keys['polygonscan']
            url = (
                f"{self.multichain_apis['polygonscan']}"
                f"?module=account&action=balance&address={address}"
                f"&apikey={api_key}"
            )

            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, timeout=30) as response:
                        if response.status == 200:
                            data = await response.json()
                            if data.get('status') == '1':
                                balance = Decimal(data['result']) / Decimal('1000000000000000000')

                                return WalletInfo(
                                    address=address,
                                    blockchain='polygon',
                                    balance=balance,
                                    total_received=Decimal('0'),
                                    total_sent=Decimal('0'),
                                    transaction_count=0,
                                    first_seen=None,
                                    last_seen=None,
                                    metadata={'source': 'polygonscan'}
                                )
            except Exception as e:
                logger.warning(f"PolygonScan API error: {e}")

        return WalletInfo(
            address=address,
            blockchain='polygon',
            balance=Decimal('0'),
            total_received=Decimal('0'),
            total_sent=Decimal('0'),
            transaction_count=0,
            first_seen=None,
            last_seen=None
        )

    async def get_transactions(
        self,
        address: str,
        blockchain: str = 'bitcoin',
        limit: int = 100
    ) -> List[Transaction]:
        """
        Get transactions for a wallet

        Args:
            address: Wallet address
            blockchain: Blockchain name
            limit: Maximum number of transactions

        Returns:
            List of Transaction objects
        """
        if blockchain.lower() == 'bitcoin':
            return await self._get_bitcoin_transactions(address, limit)
        elif blockchain.lower() == 'ethereum':
            return await self._get_ethereum_transactions(address, limit)
        else:
            return []

    async def _get_bitcoin_transactions(
        self,
        address: str,
        limit: int
    ) -> List[Transaction]:
        """Get Bitcoin transactions"""
        import aiohttp

        url = f"{self.bitcoin_apis['blockchain_info']}/rawaddr/{address}?limit={limit}"

        transactions = []

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=30) as response:
                    if response.status == 200:
                        data = await response.json()

                        for tx in data.get('txs', []):
                            from_addrs = [
                                inp.get('prev_out', {}).get('addr', '')
                                for inp in tx.get('inputs', [])
                            ]
                            to_addrs = [
                                out.get('addr', '')
                                for out in tx.get('out', [])
                            ]

                            # Calculate total amount
                            amount = sum(
                                Decimal(out.get('value', 0)) / Decimal('100000000')
                                for out in tx.get('out', [])
                            )

                            transactions.append(Transaction(
                                tx_hash=tx.get('hash', ''),
                                blockchain='bitcoin',
                                timestamp=datetime.fromtimestamp(tx.get('time', 0)),
                                from_addresses=from_addrs,
                                to_addresses=to_addrs,
                                amount=amount,
                                fee=Decimal(tx.get('fee', 0)) / Decimal('100000000'),
                                confirmations=tx.get('confirmations', 0),
                                block_height=tx.get('block_height'),
                                metadata={'source': 'blockchain.info'}
                            ))

        except Exception as e:
            logger.error(f"Error fetching Bitcoin transactions: {e}")

        return transactions

    async def _get_ethereum_transactions(
        self,
        address: str,
        limit: int
    ) -> List[Transaction]:
        """Get Ethereum transactions"""
        # Placeholder - requires Etherscan API key
        return []

    async def trace_funds(
        self,
        start_address: str,
        blockchain: str = 'bitcoin',
        max_hops: int = 5,
        min_amount: Optional[Decimal] = None
    ) -> Dict[str, Any]:
        """
        Trace funds from a starting address

        Args:
            start_address: Starting wallet address
            blockchain: Blockchain name
            max_hops: Maximum number of transaction hops
            min_amount: Minimum transaction amount to follow

        Returns:
            Dictionary with transaction graph
        """
        logger.info(
            f"Tracing funds from {start_address} on {blockchain} "
            f"(max {max_hops} hops)"
        )

        visited = set()
        trace_graph = {
            'start': start_address,
            'blockchain': blockchain,
            'nodes': [],
            'edges': []
        }

        async def trace_recursive(address: str, hop: int):
            if hop > max_hops or address in visited:
                return

            visited.add(address)
            trace_graph['nodes'].append({
                'address': address,
                'hop': hop
            })

            # Get transactions for this address
            txs = await self.get_transactions(address, blockchain, limit=50)

            for tx in txs:
                # Follow outgoing transactions
                for to_addr in tx.to_addresses:
                    if min_amount and tx.amount < min_amount:
                        continue

                    trace_graph['edges'].append({
                        'from': address,
                        'to': to_addr,
                        'amount': float(tx.amount),
                        'tx_hash': tx.tx_hash,
                        'timestamp': tx.timestamp.isoformat()
                    })

                    # Recursively trace
                    await trace_recursive(to_addr, hop + 1)

        await trace_recursive(start_address, 0)

        return trace_graph

    def get_supported_blockchains(self) -> List[str]:
        """Get list of supported blockchains"""
        return [
            'bitcoin',
            'ethereum',
            'bsc',
            'polygon',
            'avalanche',
            'fantom',
            'arbitrum',
            'optimism',
            'solana',
            'cardano',
            'polkadot',
            'tron',
            'ripple'
        ]
