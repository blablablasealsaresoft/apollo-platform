"""
Real Ethereum Tracker - Production Implementation
Uses Etherscan API (free tier) and Ethplorer (free with 'freekey')

No mock data - all real blockchain queries.
"""

import aiohttp
import asyncio
import logging
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal
import time
import json

logger = logging.getLogger(__name__)


@dataclass
class ERC20Token:
    """ERC-20 Token Information"""
    contract_address: str
    name: str
    symbol: str
    decimals: int
    total_supply: Optional[str] = None
    holders_count: Optional[int] = None


@dataclass
class TokenBalance:
    """Token Balance for an Address"""
    contract_address: str
    name: str
    symbol: str
    decimals: int
    balance: Decimal
    balance_raw: int


@dataclass
class EthereumTransaction:
    """Ethereum Transaction"""
    tx_hash: str
    block_number: int
    block_hash: str
    timestamp: int
    from_address: str
    to_address: str
    value_wei: int
    value_eth: float
    gas: int
    gas_price: int
    gas_used: int
    fee_wei: int
    fee_eth: float
    nonce: int
    input_data: str
    is_error: bool
    confirmations: int
    contract_address: Optional[str] = None
    function_name: Optional[str] = None


@dataclass
class InternalTransaction:
    """Internal (Trace) Transaction"""
    tx_hash: str
    block_number: int
    timestamp: int
    from_address: str
    to_address: str
    value_wei: int
    value_eth: float
    trace_type: str
    is_error: bool


@dataclass
class TokenTransfer:
    """ERC-20 Token Transfer"""
    tx_hash: str
    block_number: int
    timestamp: int
    from_address: str
    to_address: str
    value: Decimal
    value_raw: int
    token_name: str
    token_symbol: str
    token_decimals: int
    contract_address: str


@dataclass
class EthereumAddressInfo:
    """Ethereum Address Information"""
    address: str
    balance_wei: int
    balance_eth: float
    tx_count: int
    is_contract: bool
    token_balances: List[TokenBalance] = field(default_factory=list)
    first_tx_timestamp: Optional[int] = None
    last_tx_timestamp: Optional[int] = None


class RealEthereumTracker:
    """
    Production Ethereum Tracker using free APIs

    APIs Used:
    1. Etherscan - Free tier (5 calls/sec, 100k calls/day)
    2. Ethplorer - Free with 'freekey' (2 calls/sec)

    Features:
    - Transaction lookup
    - Address balance and history
    - ERC-20 token tracking
    - Internal transactions (traces)
    - Contract verification
    - Gas price estimation
    """

    def __init__(
        self,
        etherscan_api_key: str = '',
        ethplorer_api_key: str = 'freekey',
        session: Optional[aiohttp.ClientSession] = None
    ):
        self.etherscan_api_key = etherscan_api_key
        self.ethplorer_api_key = ethplorer_api_key
        self.session = session
        self._own_session = session is None

        # API endpoints
        self.apis = {
            'etherscan': 'https://api.etherscan.io/api',
            'ethplorer': 'https://api.ethplorer.io'
        }

        # Rate limiting
        self._last_request: Dict[str, float] = {}
        self._rate_limits = {
            'etherscan': 0.2,  # 5 req/sec
            'ethplorer': 0.5   # 2 req/sec
        }

        # Cache
        self._cache: Dict[str, tuple] = {}
        self._cache_ttl = 60

        logger.info("Real Ethereum Tracker initialized")

    async def _ensure_session(self):
        """Ensure aiohttp session exists"""
        if self.session is None:
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=30)
            )

    async def close(self):
        """Close session if we own it"""
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

    async def _etherscan_get(self, params: Dict) -> Optional[Dict]:
        """Make Etherscan API request"""
        await self._ensure_session()
        await self._rate_limit('etherscan')

        params['apikey'] = self.etherscan_api_key

        try:
            async with self.session.get(self.apis['etherscan'], params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    if data.get('status') == '1' or data.get('message') == 'OK':
                        return data
                    elif 'No transactions found' in str(data.get('result', '')):
                        return {'result': []}
                    else:
                        logger.warning(f"Etherscan error: {data.get('message', 'Unknown')}")
                        return data  # Return anyway, caller can handle
                else:
                    logger.error(f"Etherscan HTTP error: {response.status}")
                    return None
        except Exception as e:
            logger.error(f"Etherscan request error: {e}")
            return None

    async def _ethplorer_get(self, endpoint: str, params: Dict = None) -> Optional[Dict]:
        """Make Ethplorer API request"""
        await self._ensure_session()
        await self._rate_limit('ethplorer')

        params = params or {}
        params['apiKey'] = self.ethplorer_api_key

        url = f"{self.apis['ethplorer']}{endpoint}"

        try:
            async with self.session.get(url, params=params) as response:
                if response.status == 200:
                    return await response.json()
                else:
                    logger.error(f"Ethplorer HTTP error: {response.status}")
                    return None
        except Exception as e:
            logger.error(f"Ethplorer request error: {e}")
            return None

    # ==================== Balance & Address Methods ====================

    async def get_address_balance(self, address: str) -> float:
        """
        Get ETH balance for an address

        Args:
            address: Ethereum address

        Returns:
            Balance in ETH
        """
        data = await self._etherscan_get({
            'module': 'account',
            'action': 'balance',
            'address': address,
            'tag': 'latest'
        })

        if data and 'result' in data:
            balance_wei = int(data['result'])
            return balance_wei / 1e18

        return 0.0

    async def get_address_info(self, address: str) -> Optional[EthereumAddressInfo]:
        """
        Get comprehensive address information

        Args:
            address: Ethereum address

        Returns:
            EthereumAddressInfo object
        """
        cache_key = f"eth_addr_{address}"
        cached = self._get_cache(cache_key)
        if cached:
            return cached

        # Get balance
        balance_data = await self._etherscan_get({
            'module': 'account',
            'action': 'balance',
            'address': address,
            'tag': 'latest'
        })

        balance_wei = int(balance_data['result']) if balance_data and 'result' in balance_data else 0

        # Get transaction count
        tx_data = await self._etherscan_get({
            'module': 'proxy',
            'action': 'eth_getTransactionCount',
            'address': address,
            'tag': 'latest'
        })

        tx_count = int(tx_data['result'], 16) if tx_data and 'result' in tx_data else 0

        # Check if contract
        code_data = await self._etherscan_get({
            'module': 'proxy',
            'action': 'eth_getCode',
            'address': address,
            'tag': 'latest'
        })

        is_contract = code_data and code_data.get('result', '0x') not in ['0x', '0x0']

        # Get token balances from Ethplorer
        token_balances = []
        ethplorer_data = await self._ethplorer_get(f'/getAddressInfo/{address}')

        if ethplorer_data:
            for token in ethplorer_data.get('tokens', []):
                token_info = token.get('tokenInfo', {})
                decimals = int(token_info.get('decimals', 18) or 18)
                balance_raw = int(token.get('balance', 0))

                token_balances.append(TokenBalance(
                    contract_address=token_info.get('address', ''),
                    name=token_info.get('name', 'Unknown'),
                    symbol=token_info.get('symbol', ''),
                    decimals=decimals,
                    balance=Decimal(balance_raw) / Decimal(10 ** decimals),
                    balance_raw=balance_raw
                ))

        info = EthereumAddressInfo(
            address=address,
            balance_wei=balance_wei,
            balance_eth=balance_wei / 1e18,
            tx_count=tx_count,
            is_contract=is_contract,
            token_balances=token_balances
        )

        self._set_cache(cache_key, info)
        return info

    async def get_multi_address_balance(self, addresses: List[str]) -> Dict[str, float]:
        """
        Get balances for multiple addresses (max 20)

        Args:
            addresses: List of Ethereum addresses

        Returns:
            Dictionary of address -> balance
        """
        if len(addresses) > 20:
            addresses = addresses[:20]

        data = await self._etherscan_get({
            'module': 'account',
            'action': 'balancemulti',
            'address': ','.join(addresses),
            'tag': 'latest'
        })

        balances = {}
        if data and 'result' in data:
            for item in data['result']:
                addr = item.get('account', '')
                balance_wei = int(item.get('balance', 0))
                balances[addr] = balance_wei / 1e18

        return balances

    # ==================== Transaction Methods ====================

    async def get_transaction(self, tx_hash: str) -> Optional[EthereumTransaction]:
        """
        Get detailed transaction information

        Args:
            tx_hash: Transaction hash

        Returns:
            EthereumTransaction object
        """
        cache_key = f"eth_tx_{tx_hash}"
        cached = self._get_cache(cache_key)
        if cached:
            return cached

        # Get transaction
        tx_data = await self._etherscan_get({
            'module': 'proxy',
            'action': 'eth_getTransactionByHash',
            'txhash': tx_hash
        })

        if not tx_data or 'result' not in tx_data or not tx_data['result']:
            return None

        tx = tx_data['result']

        # Get receipt for gas used
        receipt_data = await self._etherscan_get({
            'module': 'proxy',
            'action': 'eth_getTransactionReceipt',
            'txhash': tx_hash
        })

        receipt = receipt_data.get('result', {}) if receipt_data else {}

        # Parse values
        block_number = int(tx.get('blockNumber', '0x0'), 16) if tx.get('blockNumber') else 0
        value_wei = int(tx.get('value', '0x0'), 16)
        gas = int(tx.get('gas', '0x0'), 16)
        gas_price = int(tx.get('gasPrice', '0x0'), 16)
        gas_used = int(receipt.get('gasUsed', '0x0'), 16) if receipt else gas
        nonce = int(tx.get('nonce', '0x0'), 16)

        fee_wei = gas_used * gas_price

        # Get block timestamp
        timestamp = 0
        if block_number > 0:
            block_data = await self._etherscan_get({
                'module': 'proxy',
                'action': 'eth_getBlockByNumber',
                'tag': hex(block_number),
                'boolean': 'false'
            })
            if block_data and 'result' in block_data:
                timestamp = int(block_data['result'].get('timestamp', '0x0'), 16)

        # Current block for confirmations
        current_block = await self.get_block_number()
        confirmations = current_block - block_number if current_block and block_number else 0

        eth_tx = EthereumTransaction(
            tx_hash=tx.get('hash', ''),
            block_number=block_number,
            block_hash=tx.get('blockHash', ''),
            timestamp=timestamp,
            from_address=tx.get('from', ''),
            to_address=tx.get('to', ''),
            value_wei=value_wei,
            value_eth=value_wei / 1e18,
            gas=gas,
            gas_price=gas_price,
            gas_used=gas_used,
            fee_wei=fee_wei,
            fee_eth=fee_wei / 1e18,
            nonce=nonce,
            input_data=tx.get('input', '0x'),
            is_error=receipt.get('status', '0x1') == '0x0' if receipt else False,
            confirmations=confirmations,
            contract_address=receipt.get('contractAddress')
        )

        self._set_cache(cache_key, eth_tx)
        return eth_tx

    async def get_address_transactions(
        self,
        address: str,
        start_block: int = 0,
        end_block: int = 99999999,
        page: int = 1,
        offset: int = 100,
        sort: str = 'desc'
    ) -> List[EthereumTransaction]:
        """
        Get transactions for an address

        Args:
            address: Ethereum address
            start_block: Starting block
            end_block: Ending block
            page: Page number
            offset: Results per page (max 10000)
            sort: 'asc' or 'desc'

        Returns:
            List of EthereumTransaction objects
        """
        data = await self._etherscan_get({
            'module': 'account',
            'action': 'txlist',
            'address': address,
            'startblock': start_block,
            'endblock': end_block,
            'page': page,
            'offset': min(offset, 10000),
            'sort': sort
        })

        transactions = []
        if data and 'result' in data and isinstance(data['result'], list):
            for tx in data['result']:
                gas_price = int(tx.get('gasPrice', 0))
                gas_used = int(tx.get('gasUsed', 0))
                value_wei = int(tx.get('value', 0))

                transactions.append(EthereumTransaction(
                    tx_hash=tx.get('hash', ''),
                    block_number=int(tx.get('blockNumber', 0)),
                    block_hash=tx.get('blockHash', ''),
                    timestamp=int(tx.get('timeStamp', 0)),
                    from_address=tx.get('from', ''),
                    to_address=tx.get('to', ''),
                    value_wei=value_wei,
                    value_eth=value_wei / 1e18,
                    gas=int(tx.get('gas', 0)),
                    gas_price=gas_price,
                    gas_used=gas_used,
                    fee_wei=gas_price * gas_used,
                    fee_eth=(gas_price * gas_used) / 1e18,
                    nonce=int(tx.get('nonce', 0)),
                    input_data=tx.get('input', '0x'),
                    is_error=tx.get('isError') == '1',
                    confirmations=int(tx.get('confirmations', 0)),
                    contract_address=tx.get('contractAddress') or None,
                    function_name=tx.get('functionName')
                ))

        return transactions

    async def get_internal_transactions(
        self,
        address: str,
        start_block: int = 0,
        end_block: int = 99999999,
        page: int = 1,
        offset: int = 100,
        sort: str = 'desc'
    ) -> List[InternalTransaction]:
        """
        Get internal (trace) transactions for an address

        Args:
            address: Ethereum address

        Returns:
            List of InternalTransaction objects
        """
        data = await self._etherscan_get({
            'module': 'account',
            'action': 'txlistinternal',
            'address': address,
            'startblock': start_block,
            'endblock': end_block,
            'page': page,
            'offset': min(offset, 10000),
            'sort': sort
        })

        transactions = []
        if data and 'result' in data and isinstance(data['result'], list):
            for tx in data['result']:
                value_wei = int(tx.get('value', 0))

                transactions.append(InternalTransaction(
                    tx_hash=tx.get('hash', ''),
                    block_number=int(tx.get('blockNumber', 0)),
                    timestamp=int(tx.get('timeStamp', 0)),
                    from_address=tx.get('from', ''),
                    to_address=tx.get('to', ''),
                    value_wei=value_wei,
                    value_eth=value_wei / 1e18,
                    trace_type=tx.get('type', 'call'),
                    is_error=tx.get('isError') == '1'
                ))

        return transactions

    # ==================== ERC-20 Token Methods ====================

    async def get_erc20_transfers(
        self,
        address: str,
        contract_address: Optional[str] = None,
        start_block: int = 0,
        end_block: int = 99999999,
        page: int = 1,
        offset: int = 100,
        sort: str = 'desc'
    ) -> List[TokenTransfer]:
        """
        Get ERC-20 token transfers for an address

        Args:
            address: Ethereum address
            contract_address: Optional specific token contract

        Returns:
            List of TokenTransfer objects
        """
        params = {
            'module': 'account',
            'action': 'tokentx',
            'address': address,
            'startblock': start_block,
            'endblock': end_block,
            'page': page,
            'offset': min(offset, 10000),
            'sort': sort
        }

        if contract_address:
            params['contractaddress'] = contract_address

        data = await self._etherscan_get(params)

        transfers = []
        if data and 'result' in data and isinstance(data['result'], list):
            for tx in data['result']:
                decimals = int(tx.get('tokenDecimal', 18))
                value_raw = int(tx.get('value', 0))

                transfers.append(TokenTransfer(
                    tx_hash=tx.get('hash', ''),
                    block_number=int(tx.get('blockNumber', 0)),
                    timestamp=int(tx.get('timeStamp', 0)),
                    from_address=tx.get('from', ''),
                    to_address=tx.get('to', ''),
                    value=Decimal(value_raw) / Decimal(10 ** decimals),
                    value_raw=value_raw,
                    token_name=tx.get('tokenName', 'Unknown'),
                    token_symbol=tx.get('tokenSymbol', ''),
                    token_decimals=decimals,
                    contract_address=tx.get('contractAddress', '')
                ))

        return transfers

    async def get_token_info(self, contract_address: str) -> Optional[ERC20Token]:
        """
        Get ERC-20 token information

        Args:
            contract_address: Token contract address

        Returns:
            ERC20Token object
        """
        data = await self._ethplorer_get(f'/getTokenInfo/{contract_address}')

        if not data or 'error' in data:
            return None

        return ERC20Token(
            contract_address=contract_address,
            name=data.get('name', 'Unknown'),
            symbol=data.get('symbol', ''),
            decimals=int(data.get('decimals', 18) or 18),
            total_supply=data.get('totalSupply'),
            holders_count=data.get('holdersCount')
        )

    async def get_token_holders(
        self,
        contract_address: str,
        limit: int = 100
    ) -> List[Dict]:
        """
        Get top token holders

        Args:
            contract_address: Token contract address
            limit: Max holders to return

        Returns:
            List of holder info dicts
        """
        data = await self._ethplorer_get(
            f'/getTopTokenHolders/{contract_address}',
            {'limit': min(limit, 1000)}
        )

        if not data or 'holders' not in data:
            return []

        return [
            {
                'address': h.get('address', ''),
                'balance': float(h.get('balance', 0)),
                'share': float(h.get('share', 0))
            }
            for h in data.get('holders', [])
        ]

    # ==================== Contract Methods ====================

    async def is_contract(self, address: str) -> bool:
        """Check if address is a contract"""
        data = await self._etherscan_get({
            'module': 'proxy',
            'action': 'eth_getCode',
            'address': address,
            'tag': 'latest'
        })

        if data and 'result' in data:
            return data['result'] not in ['0x', '0x0', '']

        return False

    async def get_contract_abi(self, address: str) -> Optional[str]:
        """
        Get verified contract ABI

        Args:
            address: Contract address

        Returns:
            ABI JSON string or None
        """
        data = await self._etherscan_get({
            'module': 'contract',
            'action': 'getabi',
            'address': address
        })

        if data and data.get('status') == '1':
            return data.get('result')

        return None

    async def get_contract_source(self, address: str) -> Optional[Dict]:
        """
        Get verified contract source code

        Args:
            address: Contract address

        Returns:
            Dict with source code info
        """
        data = await self._etherscan_get({
            'module': 'contract',
            'action': 'getsourcecode',
            'address': address
        })

        if data and data.get('status') == '1' and data.get('result'):
            return data['result'][0]

        return None

    # ==================== Gas Methods ====================

    async def get_gas_oracle(self) -> Dict[str, int]:
        """
        Get current gas prices in Gwei

        Returns:
            Dict with safe, propose, fast gas prices
        """
        data = await self._etherscan_get({
            'module': 'gastracker',
            'action': 'gasoracle'
        })

        if data and data.get('status') == '1' and data.get('result'):
            result = data['result']
            return {
                'safe': int(result.get('SafeGasPrice', 20)),
                'propose': int(result.get('ProposeGasPrice', 25)),
                'fast': int(result.get('FastGasPrice', 35)),
                'base_fee': float(result.get('suggestBaseFee', 0))
            }

        return {'safe': 20, 'propose': 25, 'fast': 35, 'base_fee': 0}

    async def estimate_gas(
        self,
        from_address: str,
        to_address: str,
        value: int = 0,
        data: str = '0x'
    ) -> Optional[int]:
        """
        Estimate gas for a transaction

        Args:
            from_address: Sender address
            to_address: Recipient address
            value: Value in wei
            data: Transaction data

        Returns:
            Estimated gas units
        """
        result = await self._etherscan_get({
            'module': 'proxy',
            'action': 'eth_estimateGas',
            'to': to_address,
            'value': hex(value),
            'data': data
        })

        if result and 'result' in result:
            return int(result['result'], 16)

        return None

    # ==================== Block Methods ====================

    async def get_block_number(self) -> Optional[int]:
        """Get current block number"""
        data = await self._etherscan_get({
            'module': 'proxy',
            'action': 'eth_blockNumber'
        })

        if data and 'result' in data:
            return int(data['result'], 16)

        return None

    async def get_eth_price(self) -> Dict[str, float]:
        """Get current ETH price"""
        data = await self._etherscan_get({
            'module': 'stats',
            'action': 'ethprice'
        })

        if data and data.get('status') == '1' and data.get('result'):
            result = data['result']
            return {
                'usd': float(result.get('ethusd', 0)),
                'btc': float(result.get('ethbtc', 0)),
                'timestamp': int(result.get('ethusd_timestamp', 0))
            }

        return {'usd': 0, 'btc': 0, 'timestamp': 0}

    # ==================== Analysis Methods ====================

    async def analyze_address(self, address: str) -> Dict[str, Any]:
        """
        Comprehensive address analysis

        Args:
            address: Ethereum address

        Returns:
            Analysis results
        """
        info = await self.get_address_info(address)
        if not info:
            return {'address': address, 'error': 'not_found'}

        # Get transactions
        transactions = await self.get_address_transactions(address, offset=100)
        token_transfers = await self.get_erc20_transfers(address, offset=100)
        internal_txs = await self.get_internal_transactions(address, offset=100)

        # Analyze patterns
        incoming_eth = sum(tx.value_eth for tx in transactions if tx.to_address.lower() == address.lower())
        outgoing_eth = sum(tx.value_eth for tx in transactions if tx.from_address.lower() == address.lower())

        # Unique counterparties
        counterparties = set()
        for tx in transactions:
            if tx.from_address.lower() == address.lower():
                counterparties.add(tx.to_address)
            else:
                counterparties.add(tx.from_address)

        # Token activity
        unique_tokens = set()
        for transfer in token_transfers:
            unique_tokens.add(transfer.contract_address)

        return {
            'address': address,
            'balance_eth': info.balance_eth,
            'is_contract': info.is_contract,
            'tx_count': info.tx_count,
            'token_count': len(info.token_balances),
            'total_incoming_eth': incoming_eth,
            'total_outgoing_eth': outgoing_eth,
            'unique_counterparties': len(counterparties),
            'unique_tokens_traded': len(unique_tokens),
            'internal_tx_count': len(internal_txs),
            'token_transfer_count': len(token_transfers),
            'top_tokens': [
                {
                    'symbol': tb.symbol,
                    'name': tb.name,
                    'balance': float(tb.balance)
                }
                for tb in sorted(info.token_balances, key=lambda x: x.balance, reverse=True)[:10]
            ],
            'patterns': self._detect_patterns(transactions, token_transfers)
        }

    def _detect_patterns(
        self,
        transactions: List[EthereumTransaction],
        token_transfers: List[TokenTransfer]
    ) -> List[str]:
        """Detect suspicious patterns"""
        patterns = []

        if not transactions:
            return patterns

        # Pattern 1: Contract interactions
        contract_calls = sum(1 for tx in transactions if tx.input_data and tx.input_data != '0x')
        if contract_calls > len(transactions) * 0.8:
            patterns.append('heavy_contract_user')

        # Pattern 2: Many failed transactions
        failed = sum(1 for tx in transactions if tx.is_error)
        if failed > len(transactions) * 0.3:
            patterns.append('many_failed_transactions')

        # Pattern 3: High gas spender
        total_gas_eth = sum(tx.fee_eth for tx in transactions)
        if total_gas_eth > 1.0:  # > 1 ETH in gas
            patterns.append('high_gas_spender')

        # Pattern 4: Token trader
        if len(token_transfers) > 50:
            patterns.append('active_token_trader')

        # Pattern 5: Rapid transactions
        if len(transactions) >= 3:
            times = sorted([tx.timestamp for tx in transactions if tx.timestamp])
            rapid = sum(1 for i in range(len(times)-1) if times[i+1] - times[i] < 60)
            if rapid > 5:
                patterns.append('rapid_transactions')

        return patterns


# Convenience function
async def quick_eth_lookup(address_or_tx: str, api_key: str = '') -> Dict:
    """Quick lookup for Ethereum address or transaction"""
    tracker = RealEthereumTracker(etherscan_api_key=api_key)

    try:
        if address_or_tx.startswith('0x') and len(address_or_tx) == 66:
            # Transaction hash
            tx = await tracker.get_transaction(address_or_tx)
            if tx:
                return {
                    'type': 'transaction',
                    'tx_hash': tx.tx_hash,
                    'from': tx.from_address,
                    'to': tx.to_address,
                    'value_eth': tx.value_eth,
                    'fee_eth': tx.fee_eth,
                    'block': tx.block_number,
                    'confirmed': tx.confirmations > 0
                }
        elif address_or_tx.startswith('0x') and len(address_or_tx) == 42:
            # Address
            info = await tracker.get_address_info(address_or_tx)
            if info:
                return {
                    'type': 'address',
                    'address': info.address,
                    'balance_eth': info.balance_eth,
                    'tx_count': info.tx_count,
                    'is_contract': info.is_contract,
                    'token_count': len(info.token_balances)
                }

        return {'error': 'invalid_input'}
    finally:
        await tracker.close()
