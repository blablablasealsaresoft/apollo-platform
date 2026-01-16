"""
Enhanced Etherscan API Client - Real Ethereum Blockchain Data

Etherscan provides comprehensive Ethereum data including:
- Transaction history
- ERC-20 token transfers
- ERC-721 NFT transfers
- Contract interactions
- Internal transactions
- Gas tracking

Free tier: 5 calls/second, 100,000 calls/day
API Key required for higher limits.
"""

import aiohttp
import asyncio
from typing import Dict, List, Optional, Any
from datetime import datetime
from dataclasses import dataclass
from decimal import Decimal
import logging

logger = logging.getLogger(__name__)


@dataclass
class ERC20Transfer:
    """ERC-20 token transfer"""
    block_number: int
    timestamp: datetime
    tx_hash: str
    from_address: str
    to_address: str
    value: Decimal
    token_name: str
    token_symbol: str
    token_decimals: int
    contract_address: str

    @property
    def formatted_value(self) -> Decimal:
        """Get human-readable token value"""
        return self.value / Decimal(10 ** self.token_decimals)


@dataclass
class InternalTransaction:
    """Internal (trace) transaction"""
    block_number: int
    timestamp: datetime
    tx_hash: str
    from_address: str
    to_address: str
    value: Decimal  # in wei
    contract_address: str
    type: str  # call, create, suicide
    error: Optional[str]

    @property
    def value_eth(self) -> Decimal:
        return self.value / Decimal(10 ** 18)


class EtherscanEnhancedClient:
    """
    Enhanced Etherscan API Client

    Supports:
    - Normal transactions
    - Internal transactions (traces)
    - ERC-20 token transfers
    - ERC-721 NFT transfers
    - Contract ABI and source code
    - Gas oracle
    - Event logs
    """

    BASE_URL = "https://api.etherscan.io/api"

    # Network-specific endpoints
    NETWORK_URLS = {
        "mainnet": "https://api.etherscan.io/api",
        "goerli": "https://api-goerli.etherscan.io/api",
        "sepolia": "https://api-sepolia.etherscan.io/api",
        "arbitrum": "https://api.arbiscan.io/api",
        "optimism": "https://api-optimistic.etherscan.io/api",
        "polygon": "https://api.polygonscan.com/api",
        "bsc": "https://api.bscscan.com/api",
        "avalanche": "https://api.snowtrace.io/api",
    }

    def __init__(
        self,
        api_key: str = "",
        network: str = "mainnet",
        session: Optional[aiohttp.ClientSession] = None,
        timeout: int = 30
    ):
        self.api_key = api_key
        self.network = network
        self.base_url = self.NETWORK_URLS.get(network, self.BASE_URL)
        self.session = session
        self._owns_session = session is None
        self.timeout = aiohttp.ClientTimeout(total=timeout)

        # Rate limiting
        self._last_request = 0
        self._min_interval = 0.2  # 5 requests/second for free tier

    async def _ensure_session(self):
        """Ensure we have an active session"""
        if self.session is None:
            self.session = aiohttp.ClientSession(timeout=self.timeout)
            self._owns_session = True

    async def close(self):
        """Close session if we own it"""
        if self._owns_session and self.session:
            await self.session.close()
            self.session = None

    async def _rate_limit(self):
        """Apply rate limiting"""
        import time
        now = time.time()
        elapsed = now - self._last_request
        if elapsed < self._min_interval:
            await asyncio.sleep(self._min_interval - elapsed)
        self._last_request = time.time()

    async def _get(self, params: Dict) -> Optional[Dict]:
        """Make GET request to Etherscan API"""
        await self._ensure_session()
        await self._rate_limit()

        # Add API key if available
        if self.api_key:
            params['apikey'] = self.api_key

        try:
            async with self.session.get(self.base_url, params=params) as response:
                if response.status == 200:
                    data = await response.json()

                    # Check for API errors
                    if data.get('status') == '0':
                        message = data.get('message', '')
                        result = data.get('result', '')

                        # "No transactions found" is not an error
                        if 'No transactions found' in str(result):
                            return {'status': '1', 'result': []}

                        logger.warning(f"Etherscan API warning: {message} - {result}")
                        return None

                    return data
                else:
                    logger.error(f"Etherscan API error: {response.status}")
                    return None

        except asyncio.TimeoutError:
            logger.error("Etherscan request timeout")
            return None
        except Exception as e:
            logger.error(f"Etherscan request error: {e}")
            return None

    # ===== Account Methods =====

    async def get_balance(self, address: str) -> Decimal:
        """Get ETH balance for an address (in wei)"""
        params = {
            'module': 'account',
            'action': 'balance',
            'address': address,
            'tag': 'latest'
        }

        data = await self._get(params)
        if data and data.get('status') == '1':
            return Decimal(data.get('result', '0'))
        return Decimal(0)

    async def get_balance_eth(self, address: str) -> Decimal:
        """Get ETH balance in ETH units"""
        wei = await self.get_balance(address)
        return wei / Decimal(10 ** 18)

    async def get_multi_balance(self, addresses: List[str]) -> Dict[str, Decimal]:
        """Get balances for multiple addresses (max 20)"""
        params = {
            'module': 'account',
            'action': 'balancemulti',
            'address': ','.join(addresses[:20]),
            'tag': 'latest'
        }

        data = await self._get(params)
        if data and data.get('status') == '1':
            return {
                item['account']: Decimal(item['balance'])
                for item in data.get('result', [])
            }
        return {}

    async def get_transactions(
        self,
        address: str,
        start_block: int = 0,
        end_block: int = 99999999,
        page: int = 1,
        offset: int = 100,
        sort: str = 'desc'
    ) -> List[Dict]:
        """
        Get normal transactions for an address

        Args:
            address: Ethereum address
            start_block: Start block number
            end_block: End block number
            page: Page number
            offset: Number of results per page (max 10000)
            sort: 'asc' or 'desc'
        """
        params = {
            'module': 'account',
            'action': 'txlist',
            'address': address,
            'startblock': start_block,
            'endblock': end_block,
            'page': page,
            'offset': min(offset, 10000),
            'sort': sort
        }

        data = await self._get(params)
        if data and data.get('status') == '1':
            return data.get('result', [])
        return []

    async def get_internal_transactions(
        self,
        address: str = None,
        txhash: str = None,
        start_block: int = 0,
        end_block: int = 99999999,
        page: int = 1,
        offset: int = 100
    ) -> List[InternalTransaction]:
        """
        Get internal transactions (traces)

        Can query by address or specific transaction hash
        """
        if txhash:
            params = {
                'module': 'account',
                'action': 'txlistinternal',
                'txhash': txhash
            }
        else:
            params = {
                'module': 'account',
                'action': 'txlistinternal',
                'address': address,
                'startblock': start_block,
                'endblock': end_block,
                'page': page,
                'offset': offset
            }

        data = await self._get(params)
        if data and data.get('status') == '1':
            return [
                InternalTransaction(
                    block_number=int(tx.get('blockNumber', 0)),
                    timestamp=datetime.fromtimestamp(int(tx.get('timeStamp', 0))),
                    tx_hash=tx.get('hash', ''),
                    from_address=tx.get('from', ''),
                    to_address=tx.get('to', ''),
                    value=Decimal(tx.get('value', '0')),
                    contract_address=tx.get('contractAddress', ''),
                    type=tx.get('type', 'call'),
                    error=tx.get('errCode')
                )
                for tx in data.get('result', [])
            ]
        return []

    async def get_erc20_transfers(
        self,
        address: str = None,
        contract_address: str = None,
        start_block: int = 0,
        end_block: int = 99999999,
        page: int = 1,
        offset: int = 100
    ) -> List[ERC20Transfer]:
        """
        Get ERC-20 token transfers

        Can filter by address, contract, or both
        """
        params = {
            'module': 'account',
            'action': 'tokentx',
            'startblock': start_block,
            'endblock': end_block,
            'page': page,
            'offset': offset,
            'sort': 'desc'
        }

        if address:
            params['address'] = address
        if contract_address:
            params['contractaddress'] = contract_address

        data = await self._get(params)
        if data and data.get('status') == '1':
            return [
                ERC20Transfer(
                    block_number=int(tx.get('blockNumber', 0)),
                    timestamp=datetime.fromtimestamp(int(tx.get('timeStamp', 0))),
                    tx_hash=tx.get('hash', ''),
                    from_address=tx.get('from', ''),
                    to_address=tx.get('to', ''),
                    value=Decimal(tx.get('value', '0')),
                    token_name=tx.get('tokenName', ''),
                    token_symbol=tx.get('tokenSymbol', ''),
                    token_decimals=int(tx.get('tokenDecimal', 18)),
                    contract_address=tx.get('contractAddress', '')
                )
                for tx in data.get('result', [])
            ]
        return []

    async def get_erc721_transfers(
        self,
        address: str = None,
        contract_address: str = None,
        start_block: int = 0,
        end_block: int = 99999999,
        page: int = 1,
        offset: int = 100
    ) -> List[Dict]:
        """Get ERC-721 (NFT) transfers"""
        params = {
            'module': 'account',
            'action': 'tokennfttx',
            'startblock': start_block,
            'endblock': end_block,
            'page': page,
            'offset': offset,
            'sort': 'desc'
        }

        if address:
            params['address'] = address
        if contract_address:
            params['contractaddress'] = contract_address

        data = await self._get(params)
        if data and data.get('status') == '1':
            return data.get('result', [])
        return []

    async def get_erc1155_transfers(
        self,
        address: str = None,
        contract_address: str = None,
        start_block: int = 0,
        end_block: int = 99999999
    ) -> List[Dict]:
        """Get ERC-1155 multi-token transfers"""
        params = {
            'module': 'account',
            'action': 'token1155tx',
            'startblock': start_block,
            'endblock': end_block,
            'sort': 'desc'
        }

        if address:
            params['address'] = address
        if contract_address:
            params['contractaddress'] = contract_address

        data = await self._get(params)
        if data and data.get('status') == '1':
            return data.get('result', [])
        return []

    # ===== Transaction Methods =====

    async def get_transaction_status(self, txhash: str) -> Optional[Dict]:
        """Get transaction receipt status"""
        params = {
            'module': 'transaction',
            'action': 'gettxreceiptstatus',
            'txhash': txhash
        }

        data = await self._get(params)
        if data and data.get('status') == '1':
            return data.get('result')
        return None

    async def get_transaction_receipt(self, txhash: str) -> Optional[Dict]:
        """Get transaction receipt using proxy API"""
        params = {
            'module': 'proxy',
            'action': 'eth_getTransactionReceipt',
            'txhash': txhash
        }

        data = await self._get(params)
        return data.get('result') if data else None

    async def get_transaction_by_hash(self, txhash: str) -> Optional[Dict]:
        """Get transaction details by hash"""
        params = {
            'module': 'proxy',
            'action': 'eth_getTransactionByHash',
            'txhash': txhash
        }

        data = await self._get(params)
        return data.get('result') if data else None

    # ===== Contract Methods =====

    async def get_contract_abi(self, address: str) -> Optional[str]:
        """Get ABI for a verified contract"""
        params = {
            'module': 'contract',
            'action': 'getabi',
            'address': address
        }

        data = await self._get(params)
        if data and data.get('status') == '1':
            return data.get('result')
        return None

    async def get_contract_source(self, address: str) -> Optional[Dict]:
        """Get source code for a verified contract"""
        params = {
            'module': 'contract',
            'action': 'getsourcecode',
            'address': address
        }

        data = await self._get(params)
        if data and data.get('status') == '1':
            result = data.get('result', [])
            return result[0] if result else None
        return None

    async def is_contract(self, address: str) -> bool:
        """Check if an address is a contract"""
        params = {
            'module': 'proxy',
            'action': 'eth_getCode',
            'address': address,
            'tag': 'latest'
        }

        data = await self._get(params)
        if data:
            code = data.get('result', '0x')
            return code != '0x' and len(code) > 2
        return False

    # ===== Block Methods =====

    async def get_block_by_number(self, block_number: int) -> Optional[Dict]:
        """Get block details by number"""
        params = {
            'module': 'proxy',
            'action': 'eth_getBlockByNumber',
            'tag': hex(block_number),
            'boolean': 'true'
        }

        data = await self._get(params)
        return data.get('result') if data else None

    async def get_block_countdown(self, block_number: int) -> Optional[Dict]:
        """Get estimated time to reach a block number"""
        params = {
            'module': 'block',
            'action': 'getblockcountdown',
            'blockno': block_number
        }

        data = await self._get(params)
        if data and data.get('status') == '1':
            return data.get('result')
        return None

    async def get_block_number_by_timestamp(
        self,
        timestamp: int,
        closest: str = 'before'
    ) -> Optional[int]:
        """Get block number closest to a timestamp"""
        params = {
            'module': 'block',
            'action': 'getblocknobytime',
            'timestamp': timestamp,
            'closest': closest
        }

        data = await self._get(params)
        if data and data.get('status') == '1':
            return int(data.get('result', 0))
        return None

    # ===== Gas Methods =====

    async def get_gas_oracle(self) -> Optional[Dict]:
        """
        Get current gas prices

        Returns:
            {
                'SafeGasPrice': str (gwei),
                'ProposeGasPrice': str (gwei),
                'FastGasPrice': str (gwei),
                'suggestBaseFee': str (gwei),
                'gasUsedRatio': str
            }
        """
        params = {
            'module': 'gastracker',
            'action': 'gasoracle'
        }

        data = await self._get(params)
        if data and data.get('status') == '1':
            return data.get('result')
        return None

    async def get_gas_estimate(self, gas_price: int) -> Optional[int]:
        """Get estimated confirmation time for a gas price"""
        params = {
            'module': 'gastracker',
            'action': 'gasestimate',
            'gasprice': gas_price
        }

        data = await self._get(params)
        if data and data.get('status') == '1':
            return int(data.get('result', 0))
        return None

    # ===== Stats Methods =====

    async def get_eth_price(self) -> Optional[Dict]:
        """Get current ETH price and market cap"""
        params = {
            'module': 'stats',
            'action': 'ethprice'
        }

        data = await self._get(params)
        if data and data.get('status') == '1':
            return data.get('result')
        return None

    async def get_eth_supply(self) -> Optional[Decimal]:
        """Get total ETH supply"""
        params = {
            'module': 'stats',
            'action': 'ethsupply'
        }

        data = await self._get(params)
        if data and data.get('status') == '1':
            return Decimal(data.get('result', '0'))
        return None

    async def get_token_supply(self, contract_address: str) -> Optional[Decimal]:
        """Get total supply of an ERC-20 token"""
        params = {
            'module': 'stats',
            'action': 'tokensupply',
            'contractaddress': contract_address
        }

        data = await self._get(params)
        if data and data.get('status') == '1':
            return Decimal(data.get('result', '0'))
        return None

    # ===== Event Log Methods =====

    async def get_logs(
        self,
        address: str = None,
        from_block: int = 0,
        to_block: int = 99999999,
        topic0: str = None,
        topic1: str = None,
        topic2: str = None,
        topic3: str = None
    ) -> List[Dict]:
        """
        Get event logs matching filters

        Useful for tracking specific contract events
        """
        params = {
            'module': 'logs',
            'action': 'getLogs',
            'fromBlock': from_block,
            'toBlock': to_block
        }

        if address:
            params['address'] = address
        if topic0:
            params['topic0'] = topic0
        if topic1:
            params['topic1'] = topic1
        if topic2:
            params['topic2'] = topic2
        if topic3:
            params['topic3'] = topic3

        data = await self._get(params)
        if data and data.get('status') == '1':
            return data.get('result', [])
        return []

    # ===== High-Level Forensics Methods =====

    async def get_address_summary(self, address: str) -> Dict:
        """
        Get comprehensive summary of an address

        Combines balance, transactions, and token data
        """
        # Get balance
        balance = await self.get_balance_eth(address)

        # Get transaction count
        transactions = await self.get_transactions(address, offset=1)
        tx_count = len(transactions) if transactions else 0

        # Get ERC-20 tokens
        tokens = await self.get_erc20_transfers(address, offset=100)

        # Get unique tokens
        unique_tokens = {}
        for transfer in tokens:
            contract = transfer.contract_address
            if contract not in unique_tokens:
                unique_tokens[contract] = {
                    'name': transfer.token_name,
                    'symbol': transfer.token_symbol,
                    'decimals': transfer.token_decimals,
                    'transfers': 0
                }
            unique_tokens[contract]['transfers'] += 1

        # Check if contract
        is_contract = await self.is_contract(address)

        return {
            'address': address,
            'balance_eth': float(balance),
            'is_contract': is_contract,
            'transaction_count': tx_count,
            'unique_tokens': len(unique_tokens),
            'token_details': list(unique_tokens.values())[:10],
            'first_activity': transactions[-1].get('timeStamp') if transactions else None,
            'last_activity': transactions[0].get('timeStamp') if transactions else None
        }

    async def trace_token_flow(
        self,
        address: str,
        token_contract: str,
        direction: str = 'both',
        max_transfers: int = 100
    ) -> Dict:
        """
        Trace ERC-20 token flow for an address

        Args:
            address: Address to trace
            token_contract: ERC-20 contract address
            direction: 'in', 'out', or 'both'
            max_transfers: Maximum transfers to analyze
        """
        transfers = await self.get_erc20_transfers(
            address=address,
            contract_address=token_contract,
            offset=max_transfers
        )

        incoming = []
        outgoing = []

        for transfer in transfers:
            transfer_info = {
                'from': transfer.from_address,
                'to': transfer.to_address,
                'value': float(transfer.formatted_value),
                'tx_hash': transfer.tx_hash,
                'timestamp': transfer.timestamp.isoformat(),
                'block': transfer.block_number
            }

            if transfer.to_address.lower() == address.lower():
                incoming.append(transfer_info)
            if transfer.from_address.lower() == address.lower():
                outgoing.append(transfer_info)

        result = {
            'address': address,
            'token_contract': token_contract,
            'total_transfers': len(transfers)
        }

        if direction in ['in', 'both']:
            result['incoming'] = incoming
            result['total_received'] = sum(t['value'] for t in incoming)

        if direction in ['out', 'both']:
            result['outgoing'] = outgoing
            result['total_sent'] = sum(t['value'] for t in outgoing)

        return result

    async def find_common_counterparties(
        self,
        addresses: List[str],
        limit: int = 50
    ) -> Dict:
        """
        Find addresses that have transacted with multiple target addresses

        Useful for identifying related wallets or common services
        """
        counterparty_count = {}

        for address in addresses:
            transactions = await self.get_transactions(address, offset=limit)

            for tx in transactions:
                from_addr = tx.get('from', '').lower()
                to_addr = tx.get('to', '').lower()
                addr_lower = address.lower()

                counterparty = to_addr if from_addr == addr_lower else from_addr

                if counterparty and counterparty != addr_lower:
                    if counterparty not in counterparty_count:
                        counterparty_count[counterparty] = set()
                    counterparty_count[counterparty].add(address)

        # Find counterparties that appear with multiple addresses
        common = []
        for counterparty, connected in counterparty_count.items():
            if len(connected) > 1:
                common.append({
                    'address': counterparty,
                    'connected_count': len(connected),
                    'connected_addresses': list(connected)
                })

        # Sort by number of connections
        common.sort(key=lambda x: x['connected_count'], reverse=True)

        return {
            'target_addresses': addresses,
            'common_counterparties': common[:20]
        }

    async def decode_input_data(self, tx_hash: str, abi: str = None) -> Optional[Dict]:
        """
        Decode transaction input data

        If ABI is not provided, attempts to fetch from Etherscan
        """
        tx = await self.get_transaction_by_hash(tx_hash)
        if not tx:
            return None

        input_data = tx.get('input', '0x')
        to_address = tx.get('to', '')

        if input_data == '0x':
            return {'type': 'transfer', 'decoded': None}

        # Get method signature (first 4 bytes)
        method_id = input_data[:10]

        # Common method signatures
        common_methods = {
            '0xa9059cbb': 'transfer(address,uint256)',
            '0x23b872dd': 'transferFrom(address,address,uint256)',
            '0x095ea7b3': 'approve(address,uint256)',
            '0x70a08231': 'balanceOf(address)',
            '0x18160ddd': 'totalSupply()',
            '0xdd62ed3e': 'allowance(address,address)',
            '0x40c10f19': 'mint(address,uint256)',
            '0x42966c68': 'burn(uint256)',
            '0x39509351': 'increaseAllowance(address,uint256)',
            '0xa457c2d7': 'decreaseAllowance(address,uint256)',
        }

        return {
            'tx_hash': tx_hash,
            'to': to_address,
            'method_id': method_id,
            'method_name': common_methods.get(method_id, 'unknown'),
            'input_data': input_data,
            'value': int(tx.get('value', '0x0'), 16)
        }
