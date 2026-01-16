"""
Blockstream API Client - Real Bitcoin Blockchain Data

Blockstream's Esplora API provides free, no-API-key-required access to Bitcoin blockchain data.
This is one of the most reliable free APIs for Bitcoin forensics.

API Documentation: https://github.com/Blockstream/esplora/blob/master/API.md
"""

import aiohttp
import asyncio
from typing import Dict, List, Optional, Any
from datetime import datetime
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)


@dataclass
class UTXO:
    """Unspent Transaction Output"""
    txid: str
    vout: int
    value: int  # satoshis
    status: Dict

    @property
    def value_btc(self) -> float:
        return self.value / 1e8


@dataclass
class BitcoinTransaction:
    """Parsed Bitcoin transaction"""
    txid: str
    version: int
    locktime: int
    size: int
    weight: int
    fee: int
    status: Dict
    inputs: List[Dict]
    outputs: List[Dict]

    @property
    def confirmed(self) -> bool:
        return self.status.get('confirmed', False)

    @property
    def block_height(self) -> Optional[int]:
        return self.status.get('block_height')

    @property
    def block_time(self) -> Optional[datetime]:
        block_time = self.status.get('block_time')
        if block_time:
            return datetime.fromtimestamp(block_time)
        return None

    @property
    def fee_btc(self) -> float:
        return self.fee / 1e8


class BlockstreamClient:
    """
    Blockstream Esplora API Client

    Free, no API key required. Rate limited to ~10 requests/second.
    Provides comprehensive Bitcoin blockchain data including:
    - Transaction details with full input/output data
    - Address balances and transaction history
    - UTXO set for addresses
    - Mempool data
    - Fee estimates
    """

    # API endpoints
    BASE_URL = "https://blockstream.info/api"
    TESTNET_URL = "https://blockstream.info/testnet/api"

    def __init__(
        self,
        session: Optional[aiohttp.ClientSession] = None,
        use_testnet: bool = False,
        timeout: int = 30
    ):
        self.session = session
        self._owns_session = session is None
        self.base_url = self.TESTNET_URL if use_testnet else self.BASE_URL
        self.timeout = aiohttp.ClientTimeout(total=timeout)

    async def _ensure_session(self):
        """Ensure we have an active session"""
        if self.session is None:
            self.session = aiohttp.ClientSession(timeout=self.timeout)
            self._owns_session = True

    async def close(self):
        """Close the session if we own it"""
        if self._owns_session and self.session:
            await self.session.close()
            self.session = None

    async def _get(self, endpoint: str, params: Optional[Dict] = None) -> Any:
        """Make GET request to API"""
        await self._ensure_session()
        url = f"{self.base_url}{endpoint}"

        try:
            async with self.session.get(url, params=params) as response:
                if response.status == 200:
                    content_type = response.headers.get('content-type', '')
                    if 'application/json' in content_type:
                        return await response.json()
                    else:
                        return await response.text()
                elif response.status == 404:
                    logger.debug(f"Not found: {url}")
                    return None
                else:
                    logger.error(f"API error {response.status}: {url}")
                    return None
        except asyncio.TimeoutError:
            logger.error(f"Timeout requesting {url}")
            return None
        except Exception as e:
            logger.error(f"Request error for {url}: {e}")
            return None

    async def _post(self, endpoint: str, data: str) -> Any:
        """Make POST request to API"""
        await self._ensure_session()
        url = f"{self.base_url}{endpoint}"

        try:
            async with self.session.post(
                url,
                data=data,
                headers={'Content-Type': 'text/plain'}
            ) as response:
                if response.status == 200:
                    return await response.text()
                else:
                    logger.error(f"POST error {response.status}: {url}")
                    return None
        except Exception as e:
            logger.error(f"POST error for {url}: {e}")
            return None

    # ===== Transaction Endpoints =====

    async def get_transaction(self, txid: str) -> Optional[BitcoinTransaction]:
        """
        Get full transaction details by txid

        Args:
            txid: Transaction hash

        Returns:
            BitcoinTransaction object or None
        """
        data = await self._get(f"/tx/{txid}")

        if not data:
            return None

        return BitcoinTransaction(
            txid=data.get('txid'),
            version=data.get('version'),
            locktime=data.get('locktime'),
            size=data.get('size'),
            weight=data.get('weight'),
            fee=data.get('fee', 0),
            status=data.get('status', {}),
            inputs=data.get('vin', []),
            outputs=data.get('vout', [])
        )

    async def get_transaction_hex(self, txid: str) -> Optional[str]:
        """Get raw transaction hex"""
        return await self._get(f"/tx/{txid}/hex")

    async def get_transaction_status(self, txid: str) -> Optional[Dict]:
        """Get transaction confirmation status"""
        return await self._get(f"/tx/{txid}/status")

    async def get_transaction_merkle_proof(self, txid: str) -> Optional[Dict]:
        """Get merkle proof for a confirmed transaction"""
        return await self._get(f"/tx/{txid}/merkle-proof")

    async def get_transaction_outspend(self, txid: str, vout: int) -> Optional[Dict]:
        """
        Check if a specific output has been spent

        Returns spending transaction info if spent, or {'spent': false}
        """
        return await self._get(f"/tx/{txid}/outspend/{vout}")

    async def get_transaction_outspends(self, txid: str) -> Optional[List[Dict]]:
        """Get spending status for all outputs in a transaction"""
        return await self._get(f"/tx/{txid}/outspends")

    async def broadcast_transaction(self, tx_hex: str) -> Optional[str]:
        """
        Broadcast a raw transaction to the network

        Args:
            tx_hex: Raw transaction in hex format

        Returns:
            txid if successful, None otherwise
        """
        return await self._post("/tx", tx_hex)

    # ===== Address Endpoints =====

    async def get_address(self, address: str) -> Optional[Dict]:
        """
        Get address information including balance and transaction stats

        Returns:
            {
                'address': str,
                'chain_stats': {
                    'funded_txo_count': int,
                    'funded_txo_sum': int (satoshis),
                    'spent_txo_count': int,
                    'spent_txo_sum': int (satoshis)
                },
                'mempool_stats': {...}
            }
        """
        return await self._get(f"/address/{address}")

    async def get_address_balance(self, address: str) -> Dict[str, int]:
        """
        Get address balance (confirmed + unconfirmed)

        Returns:
            {'confirmed': satoshis, 'unconfirmed': satoshis}
        """
        data = await self.get_address(address)

        if not data:
            return {'confirmed': 0, 'unconfirmed': 0}

        chain_stats = data.get('chain_stats', {})
        mempool_stats = data.get('mempool_stats', {})

        confirmed = (
            chain_stats.get('funded_txo_sum', 0) -
            chain_stats.get('spent_txo_sum', 0)
        )

        unconfirmed = (
            mempool_stats.get('funded_txo_sum', 0) -
            mempool_stats.get('spent_txo_sum', 0)
        )

        return {
            'confirmed': confirmed,
            'unconfirmed': unconfirmed,
            'total': confirmed + unconfirmed
        }

    async def get_address_transactions(
        self,
        address: str,
        last_seen_txid: Optional[str] = None,
        limit: int = 25
    ) -> List[Dict]:
        """
        Get transactions for an address

        Args:
            address: Bitcoin address
            last_seen_txid: For pagination, pass the last txid from previous response
            limit: Max 25 per request (API limit)

        Returns:
            List of transaction objects
        """
        endpoint = f"/address/{address}/txs"

        if last_seen_txid:
            endpoint = f"/address/{address}/txs/chain/{last_seen_txid}"

        data = await self._get(endpoint)
        return data if data else []

    async def get_all_address_transactions(
        self,
        address: str,
        max_transactions: int = 1000
    ) -> List[Dict]:
        """
        Get all transactions for an address with automatic pagination

        Args:
            address: Bitcoin address
            max_transactions: Maximum transactions to fetch

        Returns:
            List of all transaction objects
        """
        all_transactions = []
        last_txid = None

        while len(all_transactions) < max_transactions:
            batch = await self.get_address_transactions(
                address,
                last_seen_txid=last_txid
            )

            if not batch:
                break

            all_transactions.extend(batch)

            if len(batch) < 25:  # Less than page size means no more
                break

            last_txid = batch[-1].get('txid')

            # Small delay to respect rate limits
            await asyncio.sleep(0.1)

        return all_transactions[:max_transactions]

    async def get_address_utxos(self, address: str) -> List[UTXO]:
        """
        Get unspent transaction outputs (UTXOs) for an address

        Returns:
            List of UTXO objects
        """
        data = await self._get(f"/address/{address}/utxo")

        if not data:
            return []

        return [
            UTXO(
                txid=utxo.get('txid'),
                vout=utxo.get('vout'),
                value=utxo.get('value'),
                status=utxo.get('status', {})
            )
            for utxo in data
        ]

    async def get_scripthash_utxos(self, scripthash: str) -> List[UTXO]:
        """Get UTXOs by scripthash (for more complex address types)"""
        data = await self._get(f"/scripthash/{scripthash}/utxo")

        if not data:
            return []

        return [
            UTXO(
                txid=utxo.get('txid'),
                vout=utxo.get('vout'),
                value=utxo.get('value'),
                status=utxo.get('status', {})
            )
            for utxo in data
        ]

    # ===== Block Endpoints =====

    async def get_block(self, block_hash: str) -> Optional[Dict]:
        """Get block information by hash"""
        return await self._get(f"/block/{block_hash}")

    async def get_block_by_height(self, height: int) -> Optional[str]:
        """Get block hash by height"""
        return await self._get(f"/block-height/{height}")

    async def get_block_transactions(
        self,
        block_hash: str,
        start_index: int = 0
    ) -> List[Dict]:
        """Get transactions in a block (25 per request)"""
        return await self._get(f"/block/{block_hash}/txs/{start_index}") or []

    async def get_block_txids(self, block_hash: str) -> List[str]:
        """Get all transaction IDs in a block"""
        return await self._get(f"/block/{block_hash}/txids") or []

    async def get_latest_block_hash(self) -> Optional[str]:
        """Get the hash of the latest block"""
        return await self._get("/blocks/tip/hash")

    async def get_latest_block_height(self) -> Optional[int]:
        """Get the height of the latest block"""
        data = await self._get("/blocks/tip/height")
        return int(data) if data else None

    async def get_recent_blocks(self, start_height: Optional[int] = None) -> List[Dict]:
        """Get 10 most recent blocks"""
        if start_height:
            return await self._get(f"/blocks/{start_height}") or []
        return await self._get("/blocks") or []

    # ===== Mempool Endpoints =====

    async def get_mempool(self) -> Optional[Dict]:
        """
        Get mempool statistics

        Returns:
            {
                'count': int,  # number of transactions
                'vsize': int,  # total virtual size
                'total_fee': int,  # total fees in satoshis
                'fee_histogram': [[fee_rate, vsize], ...]
            }
        """
        return await self._get("/mempool")

    async def get_mempool_txids(self) -> List[str]:
        """Get all transaction IDs in the mempool"""
        return await self._get("/mempool/txids") or []

    async def get_mempool_recent(self) -> List[Dict]:
        """Get 10 most recent mempool transactions"""
        return await self._get("/mempool/recent") or []

    # ===== Fee Estimation =====

    async def get_fee_estimates(self) -> Dict[str, float]:
        """
        Get fee estimates for different confirmation targets

        Returns:
            Dictionary mapping confirmation target (blocks) to fee rate (sat/vB)
            Example: {'1': 15.0, '3': 12.0, '6': 10.0, ...}
        """
        return await self._get("/fee-estimates") or {}

    async def get_recommended_fees(self) -> Dict[str, int]:
        """
        Get recommended fees for different priority levels

        This is a convenience wrapper that maps fee estimates to
        human-readable priority levels.

        Returns:
            {
                'fastest': sat/vB for next block,
                'halfHour': sat/vB for ~30 min,
                'hour': sat/vB for ~1 hour,
                'economy': sat/vB for low priority,
                'minimum': sat/vB minimum relay fee
            }
        """
        estimates = await self.get_fee_estimates()

        if not estimates:
            return {
                'fastest': 20,
                'halfHour': 15,
                'hour': 10,
                'economy': 5,
                'minimum': 1
            }

        return {
            'fastest': int(estimates.get('1', 20)),
            'halfHour': int(estimates.get('3', 15)),
            'hour': int(estimates.get('6', 10)),
            'economy': int(estimates.get('144', 5)),
            'minimum': int(estimates.get('504', 1))
        }

    # ===== High-Level Forensics Methods =====

    async def trace_transaction_inputs(self, txid: str, depth: int = 3) -> Dict:
        """
        Trace the source of funds in a transaction

        Args:
            txid: Transaction to trace
            depth: How many hops back to trace

        Returns:
            Tree structure of input sources
        """
        result = {
            'txid': txid,
            'inputs': [],
            'total_input_value': 0
        }

        tx = await self.get_transaction(txid)
        if not tx:
            return result

        for vin in tx.inputs:
            input_info = {
                'prev_txid': vin.get('txid'),
                'prev_vout': vin.get('vout'),
                'address': vin.get('prevout', {}).get('scriptpubkey_address'),
                'value': vin.get('prevout', {}).get('value', 0),
                'sources': []
            }

            result['total_input_value'] += input_info['value']

            # Recursively trace if depth > 1
            if depth > 1 and input_info['prev_txid']:
                source_trace = await self.trace_transaction_inputs(
                    input_info['prev_txid'],
                    depth - 1
                )
                input_info['sources'] = source_trace

            result['inputs'].append(input_info)

        return result

    async def trace_transaction_outputs(self, txid: str, depth: int = 3) -> Dict:
        """
        Trace where funds from a transaction went

        Args:
            txid: Transaction to trace
            depth: How many hops forward to trace

        Returns:
            Tree structure of output destinations
        """
        result = {
            'txid': txid,
            'outputs': [],
            'total_output_value': 0
        }

        tx = await self.get_transaction(txid)
        if not tx:
            return result

        # Get spending info for all outputs
        outspends = await self.get_transaction_outspends(txid)

        for i, vout in enumerate(tx.outputs):
            output_info = {
                'vout': i,
                'address': vout.get('scriptpubkey_address'),
                'value': vout.get('value', 0),
                'spent': False,
                'spending_txid': None,
                'destinations': []
            }

            result['total_output_value'] += output_info['value']

            # Check if output is spent
            if outspends and i < len(outspends):
                spend_info = outspends[i]
                output_info['spent'] = spend_info.get('spent', False)

                if output_info['spent'] and depth > 1:
                    spending_txid = spend_info.get('txid')
                    output_info['spending_txid'] = spending_txid

                    if spending_txid:
                        dest_trace = await self.trace_transaction_outputs(
                            spending_txid,
                            depth - 1
                        )
                        output_info['destinations'] = dest_trace

            result['outputs'].append(output_info)

        return result

    async def get_address_first_seen(self, address: str) -> Optional[datetime]:
        """Get the timestamp of the first transaction involving this address"""
        transactions = await self.get_address_transactions(address)

        if not transactions:
            return None

        # Find oldest transaction with confirmed status
        oldest_time = None
        for tx in transactions:
            status = tx.get('status', {})
            if status.get('confirmed') and status.get('block_time'):
                tx_time = datetime.fromtimestamp(status['block_time'])
                if oldest_time is None or tx_time < oldest_time:
                    oldest_time = tx_time

        return oldest_time

    async def get_address_last_seen(self, address: str) -> Optional[datetime]:
        """Get the timestamp of the most recent transaction involving this address"""
        transactions = await self.get_address_transactions(address)

        if not transactions:
            return None

        # First transaction in list is most recent
        for tx in transactions:
            status = tx.get('status', {})
            if status.get('block_time'):
                return datetime.fromtimestamp(status['block_time'])

        return None

    async def find_common_inputs(
        self,
        addresses: List[str]
    ) -> List[Dict]:
        """
        Find transactions where multiple addresses were used as inputs
        (Common Input Ownership heuristic)

        Args:
            addresses: List of addresses to check

        Returns:
            List of transactions where multiple addresses appear as inputs
        """
        address_set = set(addresses)
        common_input_txs = []
        seen_txids = set()

        for address in addresses:
            transactions = await self.get_address_transactions(address)

            for tx in transactions:
                txid = tx.get('txid')
                if txid in seen_txids:
                    continue

                seen_txids.add(txid)

                # Get input addresses
                input_addresses = set()
                for vin in tx.get('vin', []):
                    prevout = vin.get('prevout', {})
                    addr = prevout.get('scriptpubkey_address')
                    if addr:
                        input_addresses.add(addr)

                # Check if multiple target addresses are inputs
                common = input_addresses & address_set
                if len(common) > 1:
                    common_input_txs.append({
                        'txid': txid,
                        'common_addresses': list(common),
                        'all_input_addresses': list(input_addresses),
                        'timestamp': tx.get('status', {}).get('block_time')
                    })

        return common_input_txs
