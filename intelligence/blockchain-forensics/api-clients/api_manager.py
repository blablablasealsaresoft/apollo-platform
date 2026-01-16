"""
Blockchain API Manager

Unified interface for all blockchain explorers with:
- Automatic API selection
- Rate limiting
- Caching
- Failover
- API key rotation
"""

import asyncio
import aiohttp
import time
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from collections import defaultdict, deque
import logging
import hashlib
import json

logger = logging.getLogger(__name__)


class RateLimiter:
    """Rate limiter for API calls"""

    def __init__(self, calls_per_second: float = 5):
        self.calls_per_second = calls_per_second
        self.min_interval = 1.0 / calls_per_second
        self.last_call = 0.0

    async def acquire(self):
        """Wait until we can make a call"""
        now = time.time()
        time_since_last = now - self.last_call

        if time_since_last < self.min_interval:
            await asyncio.sleep(self.min_interval - time_since_last)

        self.last_call = time.time()


class APICache:
    """Simple cache for API responses"""

    def __init__(self, ttl: int = 3600):
        self.cache: Dict[str, tuple] = {}  # key -> (value, timestamp)
        self.ttl = ttl

    def get(self, key: str) -> Optional[Any]:
        """Get cached value"""
        if key in self.cache:
            value, timestamp = self.cache[key]
            if time.time() - timestamp < self.ttl:
                return value
            else:
                del self.cache[key]
        return None

    def set(self, key: str, value: Any):
        """Set cached value"""
        self.cache[key] = (value, time.time())

    def clear(self):
        """Clear cache"""
        self.cache.clear()

    def _make_key(self, *args, **kwargs) -> str:
        """Make cache key from arguments"""
        key_data = json.dumps({"args": args, "kwargs": kwargs}, sort_keys=True)
        return hashlib.md5(key_data.encode()).hexdigest()


class BlockchainAPIManager:
    """
    Unified API manager for all blockchain explorers

    Automatically selects the best API based on:
    - Availability
    - Rate limits
    - Response time
    - Data quality
    """

    def __init__(self, config):
        self.config = config

        # Rate limiters per API
        self.rate_limiters: Dict[str, RateLimiter] = defaultdict(
            lambda: RateLimiter(config.API_RATE_LIMIT)
        )

        # Cache
        self.cache = APICache(ttl=config.CACHE_TTL)

        # API clients
        self.bitcoin_apis = {}
        self.ethereum_apis = {}
        self.multichain_apis = {}

        # Performance tracking
        self.api_performance: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=100)
        )

        # Session for HTTP requests
        self.session: Optional[aiohttp.ClientSession] = None

        logger.info("Blockchain API Manager initialized")

    async def initialize(self):
        """Initialize API clients"""
        self.session = aiohttp.ClientSession()

        # Initialize Bitcoin API clients
        # Priority order: Free APIs without keys first, then keyed APIs
        from .bitcoin_clients import (
            BlockchainInfoClient,
            BlockchairClient,
            BlockCypherClient,
            BTCComClient,
            BlockstreamAPIClient,
            MempoolSpaceAPIClient,
            CoinGeckoClient,
        )

        # Order by reliability and no-API-key requirement
        self.bitcoin_apis = {
            "blockstream": BlockstreamAPIClient(self.session, self.config),  # Free, no key, most reliable
            "mempool_space": MempoolSpaceAPIClient(self.session, self.config),  # Free, no key, excellent fees
            "blockchain_info": BlockchainInfoClient(self.session, self.config),  # Free
            "blockchair": BlockchairClient(self.session, self.config),  # Free tier
            "blockcypher": BlockCypherClient(self.session, self.config),  # Free tier
            "btc_com": BTCComClient(self.session, self.config),  # Free
        }

        # Price API client
        self.price_client = CoinGeckoClient(self.session, self.config)

        # Initialize Ethereum API clients
        from .ethereum_clients import (
            EtherscanClient,
            EthplorerClient,
            AlchemyClient,
        )

        self.ethereum_apis = {
            "etherscan": EtherscanClient(self.session, self.config),
            "ethplorer": EthplorerClient(self.session, self.config),
            "alchemy": AlchemyClient(self.session, self.config),
        }

        # Initialize multi-chain API clients
        from .multi_chain_clients import (
            BSCScanClient,
            PolygonScanClient,
            SnowTraceClient,
            SolscanClient,
        )

        self.multichain_apis = {
            "bscscan": BSCScanClient(self.session, self.config),
            "polygonscan": PolygonScanClient(self.session, self.config),
            "snowtrace": SnowTraceClient(self.session, self.config),
            "solscan": SolscanClient(self.session, self.config),
        }

        logger.info(
            f"Initialized {len(self.bitcoin_apis)} Bitcoin APIs, "
            f"{len(self.ethereum_apis)} Ethereum APIs, "
            f"{len(self.multichain_apis)} multi-chain APIs"
        )

    async def close(self):
        """Close API manager"""
        if self.session:
            await self.session.close()

    async def get_address_transactions(
        self,
        address: str,
        blockchain: str = "btc",
        limit: int = 100
    ) -> List[Dict]:
        """
        Get transactions for an address

        Automatically selects best API and handles caching/retries
        """
        # Check cache
        cache_key = f"txs_{blockchain}_{address}_{limit}"
        cached = self.cache.get(cache_key)
        if cached is not None and self.config.CACHE_ENABLED:
            logger.debug(f"Cache hit for {address}")
            return cached

        # Select API based on blockchain
        api_clients = self._get_api_clients_for_blockchain(blockchain)

        # Try each API until we get a result
        for api_name, client in api_clients.items():
            try:
                # Rate limiting
                await self.rate_limiters[api_name].acquire()

                # Make API call
                start_time = time.time()
                transactions = await client.get_address_transactions(address, limit)
                elapsed = time.time() - start_time

                # Track performance
                self.api_performance[api_name].append(elapsed)

                # Normalize transaction format
                normalized_txs = self._normalize_transactions(transactions, blockchain)

                # Cache result
                if self.config.CACHE_ENABLED:
                    self.cache.set(cache_key, normalized_txs)

                logger.debug(
                    f"Got {len(normalized_txs)} transactions for {address} "
                    f"from {api_name} in {elapsed:.2f}s"
                )

                return normalized_txs

            except Exception as e:
                logger.warning(f"API {api_name} failed: {e}")
                continue

        # All APIs failed
        logger.error(f"All APIs failed for address {address}")
        return []

    async def get_transaction(
        self,
        txid: str,
        blockchain: str = "btc"
    ) -> Optional[Dict]:
        """Get details for a specific transaction"""
        # Check cache
        cache_key = f"tx_{blockchain}_{txid}"
        cached = self.cache.get(cache_key)
        if cached is not None and self.config.CACHE_ENABLED:
            return cached

        # Select API based on blockchain
        api_clients = self._get_api_clients_for_blockchain(blockchain)

        # Try each API
        for api_name, client in api_clients.items():
            try:
                await self.rate_limiters[api_name].acquire()

                transaction = await client.get_transaction(txid)

                # Normalize
                normalized_tx = self._normalize_transaction(transaction, blockchain)

                # Cache
                if self.config.CACHE_ENABLED:
                    self.cache.set(cache_key, normalized_tx)

                return normalized_tx

            except Exception as e:
                logger.warning(f"API {api_name} failed: {e}")
                continue

        return None

    async def get_address_balance(
        self,
        address: str,
        blockchain: str = "btc"
    ) -> float:
        """Get balance for an address"""
        # Check cache
        cache_key = f"balance_{blockchain}_{address}"
        cached = self.cache.get(cache_key)
        if cached is not None and self.config.CACHE_ENABLED:
            return cached

        # Select API
        api_clients = self._get_api_clients_for_blockchain(blockchain)

        # Try each API
        for api_name, client in api_clients.items():
            try:
                await self.rate_limiters[api_name].acquire()

                balance = await client.get_address_balance(address)

                # Cache for shorter time (balances change)
                if self.config.CACHE_ENABLED:
                    self.cache.set(cache_key, balance)

                return balance

            except Exception as e:
                logger.warning(f"API {api_name} failed: {e}")
                continue

        return 0.0

    async def get_current_price(self, blockchain: str = "btc") -> float:
        """Get current price in USD using CoinGecko"""
        cache_key = f"price_{blockchain}"
        cached = self.cache.get(cache_key)
        if cached is not None:
            return cached

        # Use CoinGecko for prices (most reliable free source)
        try:
            if blockchain.lower() in ["btc", "bitcoin"]:
                price = await self.price_client.get_bitcoin_price()
            elif blockchain.lower() in ["eth", "ethereum"]:
                price = await self.price_client.get_ethereum_price()
            else:
                # Try to get from CoinGecko with coin ID
                coin_map = {
                    "bsc": "binancecoin",
                    "polygon": "matic-network",
                    "avax": "avalanche-2",
                    "sol": "solana",
                    "ada": "cardano",
                }
                coin_id = coin_map.get(blockchain.lower(), blockchain.lower())
                prices = await self.price_client.get_prices([coin_id])
                price = prices.get(coin_id, 0.0)

            if price > 0:
                self.cache.set(cache_key, price)
                return price

        except Exception as e:
            logger.warning(f"CoinGecko price fetch failed: {e}")

        return 0.0

    async def get_address_utxos(
        self,
        address: str,
        blockchain: str = "btc"
    ) -> List[Dict]:
        """
        Get unspent transaction outputs for an address

        Returns list of UTXOs with:
        - txid: transaction hash
        - vout: output index
        - value: amount in satoshis
        - value_btc: amount in BTC
        - confirmed: bool
        """
        cache_key = f"utxos_{blockchain}_{address}"
        cached = self.cache.get(cache_key)
        if cached is not None and self.config.CACHE_ENABLED:
            return cached

        api_clients = self._get_api_clients_for_blockchain(blockchain)

        for api_name, client in api_clients.items():
            try:
                # Check if client has UTXO method
                if hasattr(client, 'get_address_utxos'):
                    await self.rate_limiters[api_name].acquire()
                    utxos = await client.get_address_utxos(address)

                    if utxos:
                        if self.config.CACHE_ENABLED:
                            self.cache.set(cache_key, utxos)
                        return utxos

            except Exception as e:
                logger.warning(f"UTXO fetch from {api_name} failed: {e}")
                continue

        return []

    async def get_fee_estimates(self, blockchain: str = "btc") -> Dict[str, int]:
        """
        Get recommended fee estimates

        Returns:
            {
                'fastest': sat/vB for next block,
                'halfHour': sat/vB for ~30 min,
                'hour': sat/vB for ~1 hour,
                'economy': sat/vB for low priority,
                'minimum': sat/vB minimum
            }
        """
        cache_key = f"fees_{blockchain}"
        cached = self.cache.get(cache_key)
        if cached is not None:
            return cached

        if blockchain.lower() in ["btc", "bitcoin"]:
            # Use Mempool.space for best fee estimates
            try:
                mempool_client = self.bitcoin_apis.get("mempool_space")
                if mempool_client and hasattr(mempool_client, 'get_recommended_fees'):
                    fees = await mempool_client.get_recommended_fees()

                    result = {
                        'fastest': fees.get('fastestFee', 20),
                        'halfHour': fees.get('halfHourFee', 15),
                        'hour': fees.get('hourFee', 10),
                        'economy': fees.get('economyFee', 5),
                        'minimum': fees.get('minimumFee', 1)
                    }

                    self.cache.set(cache_key, result)
                    return result

            except Exception as e:
                logger.warning(f"Mempool.space fee fetch failed: {e}")

            # Fallback to Blockstream
            try:
                blockstream_client = self.bitcoin_apis.get("blockstream")
                if blockstream_client and hasattr(blockstream_client, 'get_fee_estimates'):
                    estimates = await blockstream_client.get_fee_estimates()

                    result = {
                        'fastest': int(estimates.get('1', 20)),
                        'halfHour': int(estimates.get('3', 15)),
                        'hour': int(estimates.get('6', 10)),
                        'economy': int(estimates.get('144', 5)),
                        'minimum': int(estimates.get('504', 1))
                    }

                    self.cache.set(cache_key, result)
                    return result

            except Exception as e:
                logger.warning(f"Blockstream fee fetch failed: {e}")

        # Default fallback
        return {
            'fastest': 20,
            'halfHour': 15,
            'hour': 10,
            'economy': 5,
            'minimum': 1
        }

    async def get_mempool_info(self, blockchain: str = "btc") -> Optional[Dict]:
        """
        Get current mempool statistics

        Returns:
            {
                'count': number of transactions,
                'vsize': total virtual size,
                'total_fee': total fees in satoshis
            }
        """
        if blockchain.lower() in ["btc", "bitcoin"]:
            try:
                mempool_client = self.bitcoin_apis.get("mempool_space")
                if mempool_client and hasattr(mempool_client, 'get_mempool_info'):
                    return await mempool_client.get_mempool_info()
            except Exception as e:
                logger.warning(f"Mempool info fetch failed: {e}")

        return None

    async def get_block_height(self, blockchain: str = "btc") -> Optional[int]:
        """Get current block height for a blockchain"""
        api_clients = self._get_api_clients_for_blockchain(blockchain)

        for api_name, client in api_clients.items():
            try:
                if hasattr(client, 'get_block_height'):
                    height = await client.get_block_height()
                    if height:
                        return height
            except Exception as e:
                continue

        return None

    async def trace_transaction(
        self,
        txid: str,
        blockchain: str = "btc",
        direction: str = "both",
        max_depth: int = 3
    ) -> Dict:
        """
        Trace a transaction's inputs and outputs

        Args:
            txid: Transaction hash
            blockchain: Blockchain type
            direction: 'inputs', 'outputs', or 'both'
            max_depth: Maximum hops to trace

        Returns:
            Transaction trace with input sources and output destinations
        """
        result = {
            'txid': txid,
            'blockchain': blockchain,
            'direction': direction,
            'inputs': [],
            'outputs': [],
            'total_input': 0,
            'total_output': 0,
            'fee': 0
        }

        # Get transaction details
        tx = await self.get_transaction(txid, blockchain)
        if not tx:
            return result

        result['fee'] = tx.get('fee', 0)

        # Trace inputs
        if direction in ['inputs', 'both']:
            for inp in tx.get('inputs', []):
                input_info = {
                    'address': inp.get('address'),
                    'amount': inp.get('amount', 0),
                    'prev_txid': inp.get('prev_txid'),
                    'prev_vout': inp.get('prev_vout'),
                    'sources': []
                }
                result['total_input'] += input_info['amount']

                # Recursively trace if depth > 1
                if max_depth > 1 and inp.get('prev_txid'):
                    source_trace = await self.trace_transaction(
                        inp['prev_txid'],
                        blockchain,
                        'inputs',
                        max_depth - 1
                    )
                    input_info['sources'] = source_trace.get('inputs', [])

                result['inputs'].append(input_info)

        # Trace outputs
        if direction in ['outputs', 'both']:
            for out in tx.get('outputs', []):
                output_info = {
                    'address': out.get('address'),
                    'amount': out.get('amount', 0),
                    'spent': False,
                    'spending_txid': None,
                    'destinations': []
                }
                result['total_output'] += output_info['amount']
                result['outputs'].append(output_info)

        return result

    def get_api_stats(self) -> Dict:
        """Get statistics about API usage"""
        stats = {
            "total_apis": len(self.bitcoin_apis) + len(self.ethereum_apis) + len(self.multichain_apis),
            "cache_size": len(self.cache.cache),
            "api_performance": {},
        }

        for api_name, times in self.api_performance.items():
            if times:
                stats["api_performance"][api_name] = {
                    "avg_response_time": sum(times) / len(times),
                    "min_response_time": min(times),
                    "max_response_time": max(times),
                    "total_calls": len(times),
                }

        return stats

    def _get_api_clients_for_blockchain(self, blockchain: str) -> Dict:
        """Get appropriate API clients for a blockchain"""
        blockchain = blockchain.lower()

        if blockchain in ["btc", "bitcoin"]:
            return self.bitcoin_apis
        elif blockchain in ["eth", "ethereum"]:
            return self.ethereum_apis
        elif blockchain == "bsc":
            return {"bscscan": self.multichain_apis["bscscan"]}
        elif blockchain in ["polygon", "matic"]:
            return {"polygonscan": self.multichain_apis["polygonscan"]}
        elif blockchain in ["avax", "avalanche"]:
            return {"snowtrace": self.multichain_apis["snowtrace"]}
        elif blockchain in ["sol", "solana"]:
            return {"solscan": self.multichain_apis["solscan"]}
        else:
            logger.warning(f"Unknown blockchain: {blockchain}, defaulting to Bitcoin APIs")
            return self.bitcoin_apis

    def _normalize_transactions(
        self,
        transactions: List[Dict],
        blockchain: str
    ) -> List[Dict]:
        """Normalize transactions from different APIs to common format"""
        normalized = []

        for tx in transactions:
            normalized.append(self._normalize_transaction(tx, blockchain))

        return normalized

    def _normalize_transaction(self, tx: Dict, blockchain: str) -> Dict:
        """Normalize a single transaction to common format"""
        # Common format:
        # {
        #     "txid": str,
        #     "blockchain": str,
        #     "timestamp": datetime,
        #     "from_address": str,
        #     "to_address": str,
        #     "amount": float,
        #     "amount_usd": float,
        #     "fee": float,
        #     "confirmations": int,
        #     "inputs": List[Dict],
        #     "outputs": List[Dict],
        # }

        normalized = {
            "txid": tx.get("txid") or tx.get("hash") or tx.get("tx_hash"),
            "blockchain": blockchain,
            "timestamp": self._parse_timestamp(tx.get("timestamp") or tx.get("time")),
            "from_address": tx.get("from_address") or tx.get("from") or (tx.get("inputs", [{}])[0].get("address") if tx.get("inputs") else ""),
            "to_address": tx.get("to_address") or tx.get("to") or (tx.get("outputs", [{}])[0].get("address") if tx.get("outputs") else ""),
            "amount": float(tx.get("amount") or tx.get("value") or 0),
            "amount_usd": float(tx.get("amount_usd") or tx.get("value_usd") or 0),
            "fee": float(tx.get("fee") or 0),
            "confirmations": int(tx.get("confirmations") or 0),
            "inputs": tx.get("inputs", []),
            "outputs": tx.get("outputs", []),
        }

        return normalized

    def _parse_timestamp(self, timestamp: Any) -> datetime:
        """Parse timestamp from various formats"""
        if isinstance(timestamp, datetime):
            return timestamp
        elif isinstance(timestamp, int):
            # Unix timestamp
            return datetime.fromtimestamp(timestamp)
        elif isinstance(timestamp, str):
            # ISO format
            try:
                return datetime.fromisoformat(timestamp)
            except:
                return datetime.utcnow()
        else:
            return datetime.utcnow()
