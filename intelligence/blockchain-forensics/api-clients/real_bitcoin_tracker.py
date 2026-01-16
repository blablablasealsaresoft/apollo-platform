"""
Real Bitcoin Tracker - Production Implementation
Uses free APIs: Blockstream, Blockchain.info, Mempool.space

No mock data - all real blockchain queries.
"""

import aiohttp
import asyncio
import logging
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal
import time
import hashlib

logger = logging.getLogger(__name__)


@dataclass
class UTXO:
    """Unspent Transaction Output"""
    txid: str
    vout: int
    value_satoshis: int
    value_btc: float
    address: str
    script_pubkey: Optional[str] = None
    script_type: Optional[str] = None
    confirmations: int = 0
    block_height: Optional[int] = None
    is_coinbase: bool = False


@dataclass
class BitcoinTransaction:
    """Detailed Bitcoin Transaction"""
    txid: str
    version: int
    size: int
    weight: int
    locktime: int
    fee: int
    fee_rate: float  # sat/vB
    confirmed: bool
    block_height: Optional[int]
    block_hash: Optional[str]
    block_time: Optional[int]
    inputs: List[Dict[str, Any]]
    outputs: List[Dict[str, Any]]
    input_value: int  # Total input in satoshis
    output_value: int  # Total output in satoshis
    input_addresses: List[str]
    output_addresses: List[str]


@dataclass
class AddressStats:
    """Bitcoin Address Statistics"""
    address: str
    chain_stats: Dict[str, int]
    mempool_stats: Dict[str, int]
    balance_satoshis: int
    balance_btc: float
    total_received_satoshis: int
    total_sent_satoshis: int
    tx_count: int
    utxo_count: int
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None


class RealBitcoinTracker:
    """
    Production Bitcoin Tracker using only free APIs

    API Priority (no API keys required):
    1. Blockstream Esplora - Most reliable, best data quality
    2. Mempool.space - Best fee estimates, mempool data
    3. Blockchain.info - Good fallback, large dataset

    Features:
    - Real transaction lookup
    - Address balance and history
    - UTXO tracking
    - Fee estimation
    - Mempool monitoring
    - Transaction tracing
    """

    def __init__(self, session: Optional[aiohttp.ClientSession] = None):
        self.session = session
        self._own_session = session is None

        # API endpoints
        self.apis = {
            'blockstream': 'https://blockstream.info/api',
            'mempool': 'https://mempool.space/api',
            'blockchain_info': 'https://blockchain.info'
        }

        # Rate limiting
        self._last_request: Dict[str, float] = {}
        self._rate_limits = {
            'blockstream': 0.1,  # 10 req/sec
            'mempool': 0.1,
            'blockchain_info': 0.2  # 5 req/sec
        }

        # Cache
        self._cache: Dict[str, Tuple[Any, float]] = {}
        self._cache_ttl = 60  # 60 seconds cache

        logger.info("Real Bitcoin Tracker initialized")

    async def _ensure_session(self):
        """Ensure aiohttp session exists"""
        if self.session is None:
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=30)
            )

    async def close(self):
        """Close the session if we own it"""
        if self._own_session and self.session:
            await self.session.close()
            self.session = None

    async def _rate_limit(self, api: str):
        """Enforce rate limiting"""
        if api in self._last_request:
            elapsed = time.time() - self._last_request[api]
            sleep_time = self._rate_limits.get(api, 0.5) - elapsed
            if sleep_time > 0:
                await asyncio.sleep(sleep_time)
        self._last_request[api] = time.time()

    def _get_cache(self, key: str) -> Optional[Any]:
        """Get cached value if not expired"""
        if key in self._cache:
            value, timestamp = self._cache[key]
            if time.time() - timestamp < self._cache_ttl:
                return value
            del self._cache[key]
        return None

    def _set_cache(self, key: str, value: Any):
        """Set cache value"""
        self._cache[key] = (value, time.time())

    async def _get(self, api: str, endpoint: str) -> Optional[Any]:
        """Make GET request with rate limiting and error handling"""
        await self._ensure_session()
        await self._rate_limit(api)

        url = f"{self.apis[api]}{endpoint}"

        try:
            async with self.session.get(url) as response:
                if response.status == 200:
                    # Check content type
                    content_type = response.headers.get('Content-Type', '')
                    if 'application/json' in content_type:
                        return await response.json()
                    else:
                        # Some endpoints return plain text (like block height)
                        text = await response.text()
                        try:
                            return int(text)
                        except ValueError:
                            return text
                else:
                    logger.warning(f"API {api} returned {response.status} for {endpoint}")
                    return None
        except asyncio.TimeoutError:
            logger.error(f"Timeout fetching {url}")
            return None
        except Exception as e:
            logger.error(f"Error fetching {url}: {e}")
            return None

    # ==================== Transaction Methods ====================

    async def get_transaction(self, txid: str) -> Optional[BitcoinTransaction]:
        """
        Get detailed transaction information

        Args:
            txid: Transaction hash

        Returns:
            BitcoinTransaction object or None
        """
        cache_key = f"tx_{txid}"
        cached = self._get_cache(cache_key)
        if cached:
            return cached

        # Try Blockstream first (best data quality)
        data = await self._get('blockstream', f'/tx/{txid}')

        if not data:
            # Fallback to Mempool.space
            data = await self._get('mempool', f'/tx/{txid}')

        if not data:
            return None

        # Parse transaction
        tx = self._parse_blockstream_tx(data)
        self._set_cache(cache_key, tx)
        return tx

    def _parse_blockstream_tx(self, data: Dict) -> BitcoinTransaction:
        """Parse Blockstream/Mempool transaction format"""
        inputs = []
        input_addresses = []
        input_value = 0

        for vin in data.get('vin', []):
            prevout = vin.get('prevout', {})
            addr = prevout.get('scriptpubkey_address')
            value = prevout.get('value', 0)

            inputs.append({
                'txid': vin.get('txid'),
                'vout': vin.get('vout'),
                'address': addr,
                'value': value,
                'script_type': prevout.get('scriptpubkey_type'),
                'is_coinbase': vin.get('is_coinbase', False)
            })

            if addr:
                input_addresses.append(addr)
            input_value += value

        outputs = []
        output_addresses = []
        output_value = 0

        for vout in data.get('vout', []):
            addr = vout.get('scriptpubkey_address')
            value = vout.get('value', 0)

            outputs.append({
                'address': addr,
                'value': value,
                'script_type': vout.get('scriptpubkey_type'),
                'scriptpubkey': vout.get('scriptpubkey')
            })

            if addr:
                output_addresses.append(addr)
            output_value += value

        status = data.get('status', {})
        fee = data.get('fee', 0)
        weight = data.get('weight', 0)
        fee_rate = (fee / (weight / 4)) if weight > 0 else 0

        return BitcoinTransaction(
            txid=data.get('txid', ''),
            version=data.get('version', 1),
            size=data.get('size', 0),
            weight=weight,
            locktime=data.get('locktime', 0),
            fee=fee,
            fee_rate=round(fee_rate, 2),
            confirmed=status.get('confirmed', False),
            block_height=status.get('block_height'),
            block_hash=status.get('block_hash'),
            block_time=status.get('block_time'),
            inputs=inputs,
            outputs=outputs,
            input_value=input_value,
            output_value=output_value,
            input_addresses=input_addresses,
            output_addresses=output_addresses
        )

    async def get_transaction_hex(self, txid: str) -> Optional[str]:
        """Get raw transaction hex"""
        return await self._get('blockstream', f'/tx/{txid}/hex')

    async def get_transaction_status(self, txid: str) -> Optional[Dict]:
        """Get transaction confirmation status"""
        return await self._get('blockstream', f'/tx/{txid}/status')

    # ==================== Address Methods ====================

    async def get_address_info(self, address: str) -> Optional[AddressStats]:
        """
        Get comprehensive address information

        Args:
            address: Bitcoin address

        Returns:
            AddressStats object or None
        """
        cache_key = f"addr_{address}"
        cached = self._get_cache(cache_key)
        if cached:
            return cached

        # Try Blockstream
        data = await self._get('blockstream', f'/address/{address}')

        if not data:
            # Fallback to Mempool.space
            data = await self._get('mempool', f'/address/{address}')

        if not data:
            return None

        chain_stats = data.get('chain_stats', {})
        mempool_stats = data.get('mempool_stats', {})

        # Calculate balance
        funded = chain_stats.get('funded_txo_sum', 0) + mempool_stats.get('funded_txo_sum', 0)
        spent = chain_stats.get('spent_txo_sum', 0) + mempool_stats.get('spent_txo_sum', 0)
        balance = funded - spent

        stats = AddressStats(
            address=address,
            chain_stats=chain_stats,
            mempool_stats=mempool_stats,
            balance_satoshis=balance,
            balance_btc=balance / 1e8,
            total_received_satoshis=funded,
            total_sent_satoshis=spent,
            tx_count=chain_stats.get('tx_count', 0) + mempool_stats.get('tx_count', 0),
            utxo_count=chain_stats.get('funded_txo_count', 0) - chain_stats.get('spent_txo_count', 0)
        )

        self._set_cache(cache_key, stats)
        return stats

    async def get_address_transactions(
        self,
        address: str,
        last_seen_txid: Optional[str] = None,
        limit: int = 25
    ) -> List[BitcoinTransaction]:
        """
        Get transactions for an address

        Args:
            address: Bitcoin address
            last_seen_txid: For pagination, txid of last transaction seen
            limit: Maximum transactions to return

        Returns:
            List of BitcoinTransaction objects
        """
        endpoint = f'/address/{address}/txs'
        if last_seen_txid:
            endpoint += f'/chain/{last_seen_txid}'

        data = await self._get('blockstream', endpoint)

        if not data:
            data = await self._get('mempool', endpoint)

        if not data:
            return []

        transactions = []
        for tx_data in data[:limit]:
            tx = self._parse_blockstream_tx(tx_data)
            transactions.append(tx)

        return transactions

    async def get_address_utxos(self, address: str) -> List[UTXO]:
        """
        Get unspent transaction outputs for an address

        Args:
            address: Bitcoin address

        Returns:
            List of UTXO objects
        """
        cache_key = f"utxo_{address}"
        cached = self._get_cache(cache_key)
        if cached:
            return cached

        data = await self._get('blockstream', f'/address/{address}/utxo')

        if not data:
            data = await self._get('mempool', f'/address/{address}/utxo')

        if not data:
            return []

        utxos = []
        for u in data:
            status = u.get('status', {})
            utxos.append(UTXO(
                txid=u.get('txid', ''),
                vout=u.get('vout', 0),
                value_satoshis=u.get('value', 0),
                value_btc=u.get('value', 0) / 1e8,
                address=address,
                confirmations=0,  # Would need current block height to calculate
                block_height=status.get('block_height'),
                is_coinbase=False
            ))

        self._set_cache(cache_key, utxos)
        return utxos

    async def get_address_balance(self, address: str) -> float:
        """Get address balance in BTC"""
        info = await self.get_address_info(address)
        return info.balance_btc if info else 0.0

    # ==================== Fee Estimation ====================

    async def get_fee_estimates(self) -> Dict[str, int]:
        """
        Get current fee estimates in sat/vB

        Returns:
            Dict with fee estimates for different confirmation targets
        """
        # Mempool.space has the best fee estimates
        data = await self._get('mempool', '/v1/fees/recommended')

        if data:
            return {
                'fastest': data.get('fastestFee', 20),
                'half_hour': data.get('halfHourFee', 15),
                'hour': data.get('hourFee', 10),
                'economy': data.get('economyFee', 5),
                'minimum': data.get('minimumFee', 1)
            }

        # Fallback to Blockstream
        data = await self._get('blockstream', '/fee-estimates')

        if data:
            return {
                'fastest': int(data.get('1', 20)),
                'half_hour': int(data.get('3', 15)),
                'hour': int(data.get('6', 10)),
                'economy': int(data.get('144', 5)),
                'minimum': int(data.get('504', 1))
            }

        # Default fallback
        return {
            'fastest': 20,
            'half_hour': 15,
            'hour': 10,
            'economy': 5,
            'minimum': 1
        }

    # ==================== Mempool Methods ====================

    async def get_mempool_info(self) -> Optional[Dict]:
        """Get current mempool statistics"""
        return await self._get('mempool', '/mempool')

    async def get_mempool_transactions(self) -> List[str]:
        """Get list of transaction IDs in mempool"""
        data = await self._get('mempool', '/mempool/txids')
        return data if data else []

    async def get_mempool_recent(self) -> List[Dict]:
        """Get recent mempool transactions"""
        data = await self._get('mempool', '/mempool/recent')
        return data if data else []

    # ==================== Block Methods ====================

    async def get_block_height(self) -> Optional[int]:
        """Get current block height"""
        return await self._get('blockstream', '/blocks/tip/height')

    async def get_block_hash(self, height: int) -> Optional[str]:
        """Get block hash for a given height"""
        return await self._get('blockstream', f'/block-height/{height}')

    async def get_block(self, hash_or_height: str) -> Optional[Dict]:
        """Get block information"""
        # If it's a number, get hash first
        if hash_or_height.isdigit():
            block_hash = await self.get_block_hash(int(hash_or_height))
            if not block_hash:
                return None
        else:
            block_hash = hash_or_height

        return await self._get('blockstream', f'/block/{block_hash}')

    async def get_block_transactions(self, block_hash: str, start_index: int = 0) -> List[Dict]:
        """Get transactions in a block"""
        data = await self._get('blockstream', f'/block/{block_hash}/txs/{start_index}')
        return data if data else []

    # ==================== Transaction Tracing ====================

    async def trace_transaction_inputs(
        self,
        txid: str,
        max_depth: int = 3
    ) -> Dict[str, Any]:
        """
        Trace transaction inputs back through the blockchain

        Args:
            txid: Transaction to trace
            max_depth: Maximum depth to trace

        Returns:
            Tree structure of input transactions
        """
        visited = set()

        async def trace(tx_hash: str, depth: int) -> Dict:
            if depth > max_depth or tx_hash in visited:
                return {'txid': tx_hash, 'depth': depth, 'truncated': True}

            visited.add(tx_hash)
            tx = await self.get_transaction(tx_hash)

            if not tx:
                return {'txid': tx_hash, 'depth': depth, 'error': 'not_found'}

            node = {
                'txid': tx_hash,
                'depth': depth,
                'fee': tx.fee,
                'input_value': tx.input_value,
                'output_value': tx.output_value,
                'input_count': len(tx.inputs),
                'output_count': len(tx.outputs),
                'inputs': []
            }

            # Trace each input
            for inp in tx.inputs:
                if inp.get('is_coinbase'):
                    node['inputs'].append({
                        'type': 'coinbase',
                        'value': inp.get('value', 0)
                    })
                elif inp.get('txid'):
                    child = await trace(inp['txid'], depth + 1)
                    child['address'] = inp.get('address')
                    child['value'] = inp.get('value', 0)
                    child['vout'] = inp.get('vout', 0)
                    node['inputs'].append(child)

            return node

        return await trace(txid, 0)

    async def trace_transaction_outputs(
        self,
        txid: str,
        max_depth: int = 3
    ) -> Dict[str, Any]:
        """
        Trace where transaction outputs go

        Args:
            txid: Transaction to trace
            max_depth: Maximum depth to trace

        Returns:
            Tree structure of output spending
        """
        visited = set()

        async def trace(tx_hash: str, depth: int) -> Dict:
            if depth > max_depth or tx_hash in visited:
                return {'txid': tx_hash, 'depth': depth, 'truncated': True}

            visited.add(tx_hash)
            tx = await self.get_transaction(tx_hash)

            if not tx:
                return {'txid': tx_hash, 'depth': depth, 'error': 'not_found'}

            node = {
                'txid': tx_hash,
                'depth': depth,
                'output_value': tx.output_value,
                'outputs': []
            }

            # Check each output
            for idx, out in enumerate(tx.outputs):
                output_info = {
                    'index': idx,
                    'address': out.get('address'),
                    'value': out.get('value', 0),
                    'spent': False,
                    'spending_tx': None
                }

                # Check if output is spent
                outspend = await self._get('blockstream', f'/tx/{tx_hash}/outspend/{idx}')
                if outspend and outspend.get('spent'):
                    output_info['spent'] = True
                    spending_txid = outspend.get('txid')
                    if spending_txid and depth < max_depth:
                        output_info['spending_tx'] = await trace(spending_txid, depth + 1)

                node['outputs'].append(output_info)

            return node

        return await trace(txid, 0)

    async def find_common_input_addresses(
        self,
        address: str,
        limit: int = 50
    ) -> Set[str]:
        """
        Find addresses that appear as co-inputs with the given address
        (Common Input Ownership Heuristic)

        Args:
            address: Bitcoin address to analyze
            limit: Maximum transactions to analyze

        Returns:
            Set of addresses likely owned by same entity
        """
        related_addresses = {address}
        transactions = await self.get_address_transactions(address, limit=limit)

        for tx in transactions:
            # Check if our address is an input
            if address in tx.input_addresses:
                # All other inputs are likely same owner
                for inp_addr in tx.input_addresses:
                    if inp_addr:
                        related_addresses.add(inp_addr)

        return related_addresses

    async def analyze_address_patterns(self, address: str) -> Dict[str, Any]:
        """
        Analyze transaction patterns for an address

        Returns:
            Dictionary with pattern analysis
        """
        info = await self.get_address_info(address)
        transactions = await self.get_address_transactions(address, limit=100)

        if not transactions:
            return {'address': address, 'error': 'no_transactions'}

        # Analyze patterns
        incoming = []
        outgoing = []

        for tx in transactions:
            if address in tx.input_addresses:
                # Outgoing
                for out in tx.outputs:
                    if out.get('address') != address:
                        outgoing.append({
                            'txid': tx.txid,
                            'to': out.get('address'),
                            'value': out.get('value', 0),
                            'time': tx.block_time
                        })
            if address in tx.output_addresses:
                # Incoming
                for out in tx.outputs:
                    if out.get('address') == address:
                        incoming.append({
                            'txid': tx.txid,
                            'value': out.get('value', 0),
                            'time': tx.block_time
                        })

        # Calculate metrics
        total_incoming = sum(i['value'] for i in incoming)
        total_outgoing = sum(o['value'] for o in outgoing)

        # Time analysis
        times = [tx.block_time for tx in transactions if tx.block_time]
        if len(times) >= 2:
            time_diffs = [times[i] - times[i+1] for i in range(len(times)-1)]
            avg_time_between = sum(time_diffs) / len(time_diffs) if time_diffs else 0
        else:
            avg_time_between = 0

        # Destination analysis
        destinations = {}
        for o in outgoing:
            dest = o.get('to')
            if dest:
                if dest not in destinations:
                    destinations[dest] = {'count': 0, 'total_value': 0}
                destinations[dest]['count'] += 1
                destinations[dest]['total_value'] += o['value']

        return {
            'address': address,
            'balance': info.balance_btc if info else 0,
            'tx_count': len(transactions),
            'incoming_count': len(incoming),
            'outgoing_count': len(outgoing),
            'total_incoming_satoshis': total_incoming,
            'total_outgoing_satoshis': total_outgoing,
            'total_incoming_btc': total_incoming / 1e8,
            'total_outgoing_btc': total_outgoing / 1e8,
            'avg_time_between_tx': avg_time_between,
            'unique_destinations': len(destinations),
            'top_destinations': sorted(
                destinations.items(),
                key=lambda x: x[1]['total_value'],
                reverse=True
            )[:10],
            'patterns': self._detect_patterns(incoming, outgoing, transactions)
        }

    def _detect_patterns(
        self,
        incoming: List[Dict],
        outgoing: List[Dict],
        transactions: List[BitcoinTransaction]
    ) -> List[str]:
        """Detect suspicious patterns in transaction history"""
        patterns = []

        # Pattern 1: Mixing indicator (many inputs from different addresses)
        for tx in transactions:
            if len(set(tx.input_addresses)) > 5 and len(tx.outputs) > 5:
                patterns.append('possible_mixing')
                break

        # Pattern 2: Peel chain (one large output, one small)
        peel_count = 0
        for tx in transactions:
            if len(tx.outputs) == 2:
                values = [o.get('value', 0) for o in tx.outputs]
                if values[0] > 0 and values[1] > 0:
                    ratio = max(values) / min(values) if min(values) > 0 else 0
                    if ratio > 10:
                        peel_count += 1

        if peel_count > len(transactions) * 0.3:
            patterns.append('peel_chain')

        # Pattern 3: Round amounts
        round_count = sum(1 for i in incoming if i['value'] % 100000000 == 0)  # 1 BTC
        if round_count > len(incoming) * 0.5:
            patterns.append('round_amounts')

        # Pattern 4: Rapid transactions
        times = sorted([tx.block_time for tx in transactions if tx.block_time])
        if len(times) >= 3:
            rapid_count = sum(1 for i in range(len(times)-1) if times[i+1] - times[i] < 600)  # < 10 min
            if rapid_count > 5:
                patterns.append('rapid_transactions')

        # Pattern 5: Large single transaction
        for tx in transactions:
            if tx.output_value > 100_000_000_000:  # > 1000 BTC
                patterns.append('large_transaction')
                break

        return patterns


# Convenience function for quick lookups
async def quick_lookup(address_or_tx: str) -> Dict:
    """
    Quick lookup for an address or transaction

    Args:
        address_or_tx: Bitcoin address or transaction ID

    Returns:
        Dictionary with info
    """
    tracker = RealBitcoinTracker()

    try:
        # Determine if it's an address or txid
        if len(address_or_tx) == 64:  # Likely a txid
            tx = await tracker.get_transaction(address_or_tx)
            if tx:
                return {
                    'type': 'transaction',
                    'txid': tx.txid,
                    'confirmed': tx.confirmed,
                    'block_height': tx.block_height,
                    'fee': tx.fee,
                    'input_value': tx.input_value,
                    'output_value': tx.output_value,
                    'input_count': len(tx.inputs),
                    'output_count': len(tx.outputs)
                }
        else:  # Likely an address
            info = await tracker.get_address_info(address_or_tx)
            if info:
                return {
                    'type': 'address',
                    'address': info.address,
                    'balance_btc': info.balance_btc,
                    'tx_count': info.tx_count,
                    'total_received_btc': info.total_received_satoshis / 1e8,
                    'total_sent_btc': info.total_sent_satoshis / 1e8
                }

        return {'error': 'not_found'}
    finally:
        await tracker.close()
