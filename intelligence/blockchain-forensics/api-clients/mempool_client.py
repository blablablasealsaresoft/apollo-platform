"""
Mempool.space API Client - Real Bitcoin Blockchain Data

Mempool.space provides a free, open-source API with excellent fee estimation
and mempool visualization data. No API key required.

API Documentation: https://mempool.space/docs/api/rest
"""

import aiohttp
import asyncio
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)


@dataclass
class FeeRecommendation:
    """Fee recommendation for different priorities"""
    fastest_fee: int  # sat/vB for next block
    half_hour_fee: int  # sat/vB for ~30 min
    hour_fee: int  # sat/vB for ~1 hour
    economy_fee: int  # sat/vB for low priority (~1 day)
    minimum_fee: int  # sat/vB minimum relay


@dataclass
class MempoolInfo:
    """Current mempool state"""
    count: int  # Number of transactions
    vsize: int  # Total virtual size (vbytes)
    total_fee: int  # Total fees in satoshis
    fee_histogram: List[Tuple[float, int]]  # [(fee_rate, vsize), ...]


class MempoolSpaceClient:
    """
    Mempool.space API Client

    Free, no API key required. Excellent for:
    - Real-time fee estimation
    - Mempool analysis
    - Transaction status tracking
    - Block data

    Rate limit: 10 requests/minute for the public API
    """

    BASE_URL = "https://mempool.space/api"
    TESTNET_URL = "https://mempool.space/testnet/api"
    SIGNET_URL = "https://mempool.space/signet/api"

    def __init__(
        self,
        session: Optional[aiohttp.ClientSession] = None,
        network: str = "mainnet",
        timeout: int = 30
    ):
        self.session = session
        self._owns_session = session is None
        self.timeout = aiohttp.ClientTimeout(total=timeout)

        if network == "testnet":
            self.base_url = self.TESTNET_URL
        elif network == "signet":
            self.base_url = self.SIGNET_URL
        else:
            self.base_url = self.BASE_URL

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

    async def _get(self, endpoint: str) -> Any:
        """Make GET request to API"""
        await self._ensure_session()
        url = f"{self.base_url}{endpoint}"

        try:
            async with self.session.get(url) as response:
                if response.status == 200:
                    content_type = response.headers.get('content-type', '')
                    if 'application/json' in content_type:
                        return await response.json()
                    else:
                        return await response.text()
                elif response.status == 404:
                    return None
                else:
                    logger.error(f"API error {response.status}: {url}")
                    return None
        except asyncio.TimeoutError:
            logger.error(f"Timeout: {url}")
            return None
        except Exception as e:
            logger.error(f"Request error: {e}")
            return None

    async def _post(self, endpoint: str, data: str) -> Any:
        """Make POST request"""
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
                return None
        except Exception as e:
            logger.error(f"POST error: {e}")
            return None

    # ===== Fee Estimation =====

    async def get_recommended_fees(self) -> FeeRecommendation:
        """
        Get recommended transaction fees

        Returns fee rates in sat/vB for different confirmation targets
        """
        data = await self._get("/v1/fees/recommended")

        if not data:
            # Default fallback values
            return FeeRecommendation(
                fastest_fee=20,
                half_hour_fee=15,
                hour_fee=10,
                economy_fee=5,
                minimum_fee=1
            )

        return FeeRecommendation(
            fastest_fee=data.get('fastestFee', 20),
            half_hour_fee=data.get('halfHourFee', 15),
            hour_fee=data.get('hourFee', 10),
            economy_fee=data.get('economyFee', 5),
            minimum_fee=data.get('minimumFee', 1)
        )

    async def get_fee_histogram(self) -> List[Tuple[float, int]]:
        """
        Get mempool fee histogram

        Returns list of (fee_rate, vsize) tuples showing fee distribution
        """
        data = await self._get("/v1/fees/mempool-blocks")
        if not data:
            return []

        histogram = []
        for block in data:
            for rate in block.get('feeRange', []):
                histogram.append((rate, block.get('blockVSize', 0)))

        return histogram

    # ===== Mempool =====

    async def get_mempool(self) -> Optional[MempoolInfo]:
        """Get current mempool statistics"""
        data = await self._get("/mempool")

        if not data:
            return None

        return MempoolInfo(
            count=data.get('count', 0),
            vsize=data.get('vsize', 0),
            total_fee=data.get('total_fee', 0),
            fee_histogram=data.get('fee_histogram', [])
        )

    async def get_mempool_txids(self) -> List[str]:
        """Get all transaction IDs in mempool"""
        return await self._get("/mempool/txids") or []

    async def get_mempool_recent(self) -> List[Dict]:
        """Get 10 most recent mempool transactions"""
        return await self._get("/mempool/recent") or []

    # ===== Transactions =====

    async def get_transaction(self, txid: str) -> Optional[Dict]:
        """Get transaction details"""
        return await self._get(f"/tx/{txid}")

    async def get_transaction_hex(self, txid: str) -> Optional[str]:
        """Get raw transaction hex"""
        return await self._get(f"/tx/{txid}/hex")

    async def get_transaction_status(self, txid: str) -> Optional[Dict]:
        """
        Get transaction confirmation status

        Returns:
            {
                'confirmed': bool,
                'block_height': int (if confirmed),
                'block_hash': str (if confirmed),
                'block_time': int (unix timestamp, if confirmed)
            }
        """
        return await self._get(f"/tx/{txid}/status")

    async def get_transaction_merkle_proof(self, txid: str) -> Optional[Dict]:
        """Get merkle proof for confirmed transaction"""
        return await self._get(f"/tx/{txid}/merkle-proof")

    async def get_transaction_outspend(self, txid: str, vout: int) -> Optional[Dict]:
        """Check if a specific output is spent"""
        return await self._get(f"/tx/{txid}/outspend/{vout}")

    async def get_transaction_outspends(self, txid: str) -> Optional[List[Dict]]:
        """Get spending status for all outputs"""
        return await self._get(f"/tx/{txid}/outspends")

    async def broadcast_transaction(self, tx_hex: str) -> Optional[str]:
        """Broadcast raw transaction, returns txid"""
        return await self._post("/tx", tx_hex)

    # ===== Addresses =====

    async def get_address(self, address: str) -> Optional[Dict]:
        """
        Get address info

        Returns:
            {
                'address': str,
                'chain_stats': {
                    'funded_txo_count': int,
                    'funded_txo_sum': int (satoshis),
                    'spent_txo_count': int,
                    'spent_txo_sum': int (satoshis),
                    'tx_count': int
                },
                'mempool_stats': {...}
            }
        """
        return await self._get(f"/address/{address}")

    async def get_address_transactions(
        self,
        address: str,
        after_txid: Optional[str] = None
    ) -> List[Dict]:
        """
        Get transactions for address (50 per request max)

        Args:
            address: Bitcoin address
            after_txid: For pagination, fetch transactions after this txid
        """
        if after_txid:
            return await self._get(f"/address/{address}/txs/chain/{after_txid}") or []
        return await self._get(f"/address/{address}/txs") or []

    async def get_address_mempool_transactions(self, address: str) -> List[Dict]:
        """Get unconfirmed transactions for address"""
        return await self._get(f"/address/{address}/txs/mempool") or []

    async def get_address_utxos(self, address: str) -> List[Dict]:
        """
        Get unspent transaction outputs for address

        Returns list of:
            {
                'txid': str,
                'vout': int,
                'value': int (satoshis),
                'status': {
                    'confirmed': bool,
                    'block_height': int,
                    'block_hash': str,
                    'block_time': int
                }
            }
        """
        return await self._get(f"/address/{address}/utxo") or []

    async def validate_address(self, address: str) -> bool:
        """Check if address is valid by attempting to fetch it"""
        data = await self.get_address(address)
        return data is not None

    # ===== Blocks =====

    async def get_block(self, block_hash: str) -> Optional[Dict]:
        """Get block header info"""
        return await self._get(f"/block/{block_hash}")

    async def get_block_by_height(self, height: int) -> Optional[str]:
        """Get block hash by height"""
        return await self._get(f"/block-height/{height}")

    async def get_block_header(self, block_hash: str) -> Optional[str]:
        """Get raw block header hex"""
        return await self._get(f"/block/{block_hash}/header")

    async def get_block_status(self, block_hash: str) -> Optional[Dict]:
        """
        Get block status

        Returns:
            {
                'in_best_chain': bool,
                'height': int,
                'next_best': str (hash of next block)
            }
        """
        return await self._get(f"/block/{block_hash}/status")

    async def get_block_transactions(
        self,
        block_hash: str,
        start_index: int = 0
    ) -> List[Dict]:
        """Get transactions in block (25 per request)"""
        return await self._get(f"/block/{block_hash}/txs/{start_index}") or []

    async def get_block_txids(self, block_hash: str) -> List[str]:
        """Get all transaction IDs in block"""
        return await self._get(f"/block/{block_hash}/txids") or []

    async def get_latest_block_hash(self) -> Optional[str]:
        """Get tip block hash"""
        return await self._get("/blocks/tip/hash")

    async def get_latest_block_height(self) -> Optional[int]:
        """Get tip block height"""
        data = await self._get("/blocks/tip/height")
        return int(data) if data else None

    async def get_recent_blocks(self, start_height: Optional[int] = None) -> List[Dict]:
        """Get recent blocks (15 per request)"""
        if start_height:
            return await self._get(f"/v1/blocks/{start_height}") or []
        return await self._get("/v1/blocks") or []

    # ===== Mining =====

    async def get_mining_pools(self, timeframe: str = "1w") -> Optional[Dict]:
        """
        Get mining pool statistics

        Args:
            timeframe: 24h, 3d, 1w, 1m, 3m, 6m, 1y, 2y, 3y, all
        """
        return await self._get(f"/v1/mining/pools/{timeframe}")

    async def get_mining_pool_hashrate(
        self,
        pool_slug: str,
        timeframe: str = "1w"
    ) -> Optional[Dict]:
        """Get hashrate data for a specific pool"""
        return await self._get(f"/v1/mining/pool/{pool_slug}/hashrate/{timeframe}")

    async def get_hashrate_difficulty(self, timeframe: str = "1w") -> Optional[Dict]:
        """Get network hashrate and difficulty data"""
        return await self._get(f"/v1/mining/hashrate/{timeframe}")

    async def get_reward_stats(self) -> Optional[Dict]:
        """Get mining reward statistics"""
        return await self._get("/v1/mining/reward-stats")

    # ===== Lightning Network =====

    async def get_lightning_statistics(self) -> Optional[Dict]:
        """Get Lightning Network statistics"""
        return await self._get("/v1/lightning/statistics/latest")

    async def search_lightning_nodes(self, query: str) -> List[Dict]:
        """Search Lightning nodes by alias or pubkey"""
        return await self._get(f"/v1/lightning/search?searchText={query}") or []

    async def get_lightning_node(self, pubkey: str) -> Optional[Dict]:
        """Get Lightning node details"""
        return await self._get(f"/v1/lightning/nodes/{pubkey}")

    async def get_lightning_node_channels(self, pubkey: str) -> List[Dict]:
        """Get channels for a Lightning node"""
        return await self._get(f"/v1/lightning/nodes/{pubkey}/channels") or []

    async def get_lightning_channel(self, short_channel_id: str) -> Optional[Dict]:
        """Get Lightning channel details"""
        return await self._get(f"/v1/lightning/channels/{short_channel_id}")

    # ===== High-Level Analysis Methods =====

    async def calculate_transaction_fee(
        self,
        inputs: List[Dict],
        outputs: List[Dict],
        priority: str = "hour"
    ) -> Dict[str, int]:
        """
        Calculate transaction fee for given inputs/outputs

        Args:
            inputs: List of UTXOs to spend
            outputs: List of outputs to create
            priority: 'fastest', 'halfHour', 'hour', 'economy'

        Returns:
            {
                'estimated_vsize': int,
                'fee_rate': int (sat/vB),
                'total_fee': int (satoshis)
            }
        """
        # Estimate vsize
        # P2WPKH input: ~68 vbytes
        # P2PKH input: ~148 vbytes
        # P2WPKH output: ~31 vbytes
        # P2PKH output: ~34 vbytes
        # Overhead: ~10 vbytes

        input_vsize = len(inputs) * 68  # Assume P2WPKH
        output_vsize = len(outputs) * 31
        overhead = 10

        estimated_vsize = input_vsize + output_vsize + overhead

        # Get fee rate
        fees = await self.get_recommended_fees()
        fee_rates = {
            'fastest': fees.fastest_fee,
            'halfHour': fees.half_hour_fee,
            'hour': fees.hour_fee,
            'economy': fees.economy_fee
        }

        fee_rate = fee_rates.get(priority, fees.hour_fee)
        total_fee = estimated_vsize * fee_rate

        return {
            'estimated_vsize': estimated_vsize,
            'fee_rate': fee_rate,
            'total_fee': total_fee
        }

    async def get_address_stats(self, address: str) -> Dict:
        """
        Get comprehensive address statistics

        Returns detailed stats about an address including:
        - Balance (confirmed + unconfirmed)
        - Transaction counts
        - First/last seen timestamps
        - Total received/sent
        """
        addr_data = await self.get_address(address)

        if not addr_data:
            return {
                'address': address,
                'valid': False
            }

        chain_stats = addr_data.get('chain_stats', {})
        mempool_stats = addr_data.get('mempool_stats', {})

        confirmed_balance = (
            chain_stats.get('funded_txo_sum', 0) -
            chain_stats.get('spent_txo_sum', 0)
        )

        unconfirmed_balance = (
            mempool_stats.get('funded_txo_sum', 0) -
            mempool_stats.get('spent_txo_sum', 0)
        )

        # Get first/last transaction
        transactions = await self.get_address_transactions(address)
        first_seen = None
        last_seen = None

        if transactions:
            for tx in reversed(transactions):
                status = tx.get('status', {})
                if status.get('block_time'):
                    first_seen = datetime.fromtimestamp(status['block_time'])
                    break

            for tx in transactions:
                status = tx.get('status', {})
                if status.get('block_time'):
                    last_seen = datetime.fromtimestamp(status['block_time'])
                    break

        return {
            'address': address,
            'valid': True,
            'balance': {
                'confirmed': confirmed_balance,
                'unconfirmed': unconfirmed_balance,
                'total': confirmed_balance + unconfirmed_balance,
                'confirmed_btc': confirmed_balance / 1e8,
                'total_btc': (confirmed_balance + unconfirmed_balance) / 1e8
            },
            'transactions': {
                'total_count': chain_stats.get('tx_count', 0),
                'funded_count': chain_stats.get('funded_txo_count', 0),
                'spent_count': chain_stats.get('spent_txo_count', 0),
                'mempool_count': mempool_stats.get('tx_count', 0)
            },
            'volume': {
                'total_received': chain_stats.get('funded_txo_sum', 0),
                'total_sent': chain_stats.get('spent_txo_sum', 0),
                'total_received_btc': chain_stats.get('funded_txo_sum', 0) / 1e8,
                'total_sent_btc': chain_stats.get('spent_txo_sum', 0) / 1e8
            },
            'activity': {
                'first_seen': first_seen.isoformat() if first_seen else None,
                'last_seen': last_seen.isoformat() if last_seen else None,
                'active_days': (last_seen - first_seen).days if first_seen and last_seen else 0
            }
        }

    async def analyze_transaction_flow(
        self,
        txid: str,
        direction: str = 'both'
    ) -> Dict:
        """
        Analyze transaction flow (inputs and outputs)

        Args:
            txid: Transaction ID
            direction: 'inputs', 'outputs', or 'both'

        Returns:
            Detailed analysis of transaction flow
        """
        tx = await self.get_transaction(txid)

        if not tx:
            return {'error': 'Transaction not found'}

        result = {
            'txid': txid,
            'confirmed': tx.get('status', {}).get('confirmed', False),
            'block_height': tx.get('status', {}).get('block_height'),
            'block_time': tx.get('status', {}).get('block_time'),
            'size': tx.get('size'),
            'weight': tx.get('weight'),
            'fee': tx.get('fee'),
            'fee_rate': tx.get('fee', 0) / (tx.get('weight', 1) / 4) if tx.get('weight') else 0
        }

        if direction in ['inputs', 'both']:
            result['inputs'] = []
            total_input = 0

            for vin in tx.get('vin', []):
                prevout = vin.get('prevout', {})
                value = prevout.get('value', 0)
                total_input += value

                result['inputs'].append({
                    'txid': vin.get('txid'),
                    'vout': vin.get('vout'),
                    'address': prevout.get('scriptpubkey_address'),
                    'value': value,
                    'value_btc': value / 1e8,
                    'script_type': prevout.get('scriptpubkey_type')
                })

            result['total_input'] = total_input
            result['total_input_btc'] = total_input / 1e8

        if direction in ['outputs', 'both']:
            result['outputs'] = []
            total_output = 0

            outspends = await self.get_transaction_outspends(txid)

            for i, vout in enumerate(tx.get('vout', [])):
                value = vout.get('value', 0)
                total_output += value

                output_info = {
                    'vout': i,
                    'address': vout.get('scriptpubkey_address'),
                    'value': value,
                    'value_btc': value / 1e8,
                    'script_type': vout.get('scriptpubkey_type')
                }

                # Add spending info
                if outspends and i < len(outspends):
                    spend = outspends[i]
                    output_info['spent'] = spend.get('spent', False)
                    if spend.get('spent'):
                        output_info['spending_txid'] = spend.get('txid')
                        output_info['spending_vin'] = spend.get('vin')

                result['outputs'].append(output_info)

            result['total_output'] = total_output
            result['total_output_btc'] = total_output / 1e8

        return result

    async def check_address_reuse(self, address: str) -> Dict:
        """
        Check for address reuse patterns (privacy analysis)

        Returns:
            Analysis of address usage patterns
        """
        transactions = await self.get_address_transactions(address)

        if not transactions:
            return {'address': address, 'reused': False, 'transaction_count': 0}

        # Count receives and spends
        receive_count = 0
        spend_count = 0

        for tx in transactions:
            # Check if address received
            for vout in tx.get('vout', []):
                if vout.get('scriptpubkey_address') == address:
                    receive_count += 1

            # Check if address spent
            for vin in tx.get('vin', []):
                prevout = vin.get('prevout', {})
                if prevout.get('scriptpubkey_address') == address:
                    spend_count += 1

        is_reused = receive_count > 1

        return {
            'address': address,
            'reused': is_reused,
            'transaction_count': len(transactions),
            'receive_count': receive_count,
            'spend_count': spend_count,
            'privacy_score': 100 if not is_reused else max(0, 100 - (receive_count * 20))
        }
