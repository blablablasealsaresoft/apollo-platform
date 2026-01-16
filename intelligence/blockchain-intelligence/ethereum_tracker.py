"""
Ethereum Blockchain Intelligence Tracker
Comprehensive Ethereum, ERC-20, and smart contract analysis
"""

import requests
import time
from typing import Dict, List, Optional, Set
from datetime import datetime
import logging
from decimal import Decimal

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class EthereumTracker:
    """Advanced Ethereum blockchain tracker with DeFi analysis"""

    def __init__(self, etherscan_api_key: Optional[str] = None):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'EthereumIntelligence/1.0'
        })

        self.etherscan_api_key = etherscan_api_key or 'YourApiKeyToken'

        # API endpoints
        self.apis = {
            'etherscan': 'https://api.etherscan.io/api',
            'ethplorer': 'https://api.ethplorer.io',
            'blockchair': 'https://api.blockchair.com/ethereum',
            'alchemy': 'https://eth-mainnet.g.alchemy.com/v2',
            'infura': 'https://mainnet.infura.io/v3'
        }

        # Rate limiting
        self.rate_limits = {
            'etherscan': 0.2,     # 5 req/sec
            'ethplorer': 1.0,     # 1 req/sec (free tier)
            'blockchair': 0.34    # 3 req/sec
        }

        self.last_request = {}
        self.cache = {}

        # Known DeFi protocols
        self.defi_protocols = {
            '0x7a250d5630b4cf539739df2c5dacb4c659f2488d': 'Uniswap V2 Router',
            '0xe592427a0aece92de3edee1f18e0157c05861564': 'Uniswap V3 Router',
            '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45': 'Uniswap Universal Router',
            '0x1111111254fb6c44bac0bed2854e76f90643097d': '1inch V4 Router',
            '0x6b175474e89094c44da98b954eedeac495271d0f': 'DAI Stablecoin',
            '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48': 'USDC',
            '0xdac17f958d2ee523a2206206994597c13d831ec7': 'USDT',
            '0x7d2768de32b0b80b7a3454c06bdac94a69ddc7a9': 'Aave V2 Pool',
            '0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2': 'Aave V3 Pool',
            '0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2': 'WETH',
            '0x2260fac5e5542a773aa44fbcfedf7c193bc2c599': 'WBTC'
        }

    def _rate_limit(self, api: str):
        """Enforce rate limiting for API calls"""
        if api in self.last_request:
            elapsed = time.time() - self.last_request[api]
            sleep_time = self.rate_limits.get(api, 1) - elapsed
            if sleep_time > 0:
                time.sleep(sleep_time)
        self.last_request[api] = time.time()

    def get_address_info(self, address: str, api: str = 'etherscan') -> Dict:
        """Get comprehensive Ethereum address information"""
        cache_key = f"eth_addr_{address}_{api}"
        if cache_key in self.cache:
            return self.cache[cache_key]

        try:
            if api == 'etherscan':
                return self._get_etherscan_address(address)
            elif api == 'ethplorer':
                return self._get_ethplorer_address(address)
            elif api == 'blockchair':
                return self._get_blockchair_address(address)
        except Exception as e:
            logger.error(f"Error fetching address {address} from {api}: {e}")
            # Try fallback
            if api != 'ethplorer':
                return self.get_address_info(address, 'ethplorer')
            return {}

    def _get_etherscan_address(self, address: str) -> Dict:
        """Get address info from Etherscan"""
        self._rate_limit('etherscan')

        # Get ETH balance
        balance_params = {
            'module': 'account',
            'action': 'balance',
            'address': address,
            'tag': 'latest',
            'apikey': self.etherscan_api_key
        }

        response = self.session.get(self.apis['etherscan'], params=balance_params, timeout=10)
        response.raise_for_status()
        balance_data = response.json()

        eth_balance = int(balance_data.get('result', 0)) / 1e18

        # Get transaction count
        time.sleep(self.rate_limits['etherscan'])
        txcount_params = {
            'module': 'proxy',
            'action': 'eth_getTransactionCount',
            'address': address,
            'tag': 'latest',
            'apikey': self.etherscan_api_key
        }

        response = self.session.get(self.apis['etherscan'], params=txcount_params, timeout=10)
        txcount_data = response.json()
        tx_count = int(txcount_data.get('result', '0x0'), 16)

        # Get normal transactions
        time.sleep(self.rate_limits['etherscan'])
        tx_params = {
            'module': 'account',
            'action': 'txlist',
            'address': address,
            'startblock': 0,
            'endblock': 99999999,
            'page': 1,
            'offset': 100,
            'sort': 'desc',
            'apikey': self.etherscan_api_key
        }

        response = self.session.get(self.apis['etherscan'], params=tx_params, timeout=10)
        tx_data = response.json()

        transactions = []
        for tx in tx_data.get('result', []):
            if isinstance(tx, dict):
                transactions.append({
                    'hash': tx.get('hash'),
                    'from': tx.get('from'),
                    'to': tx.get('to'),
                    'value': int(tx.get('value', 0)) / 1e18,
                    'gas': int(tx.get('gas', 0)),
                    'gas_price': int(tx.get('gasPrice', 0)) / 1e9,  # Gwei
                    'block_number': int(tx.get('blockNumber', 0)),
                    'time': datetime.fromtimestamp(int(tx.get('timeStamp', 0))),
                    'is_error': tx.get('isError') == '1',
                    'contract_address': tx.get('contractAddress')
                })

        # Get ERC-20 token transfers
        time.sleep(self.rate_limits['etherscan'])
        token_params = {
            'module': 'account',
            'action': 'tokentx',
            'address': address,
            'startblock': 0,
            'endblock': 99999999,
            'page': 1,
            'offset': 100,
            'sort': 'desc',
            'apikey': self.etherscan_api_key
        }

        response = self.session.get(self.apis['etherscan'], params=token_params, timeout=10)
        token_data = response.json()

        token_transfers = []
        for tx in token_data.get('result', []):
            if isinstance(tx, dict):
                decimals = int(tx.get('tokenDecimal', 18))
                value = int(tx.get('value', 0)) / (10 ** decimals)

                token_transfers.append({
                    'hash': tx.get('hash'),
                    'from': tx.get('from'),
                    'to': tx.get('to'),
                    'value': value,
                    'token_name': tx.get('tokenName'),
                    'token_symbol': tx.get('tokenSymbol'),
                    'token_address': tx.get('contractAddress'),
                    'time': datetime.fromtimestamp(int(tx.get('timeStamp', 0)))
                })

        result = {
            'address': address,
            'eth_balance': eth_balance,
            'tx_count': tx_count,
            'transactions': transactions,
            'token_transfers': token_transfers,
            'api_source': 'etherscan'
        }

        self.cache[cache_key] = result
        return result

    def _get_ethplorer_address(self, address: str) -> Dict:
        """Get address info from Ethplorer"""
        self._rate_limit('ethplorer')

        url = f"{self.apis['ethplorer']}/getAddressInfo/{address}"
        params = {'apiKey': 'freekey'}

        response = self.session.get(url, params=params, timeout=10)
        response.raise_for_status()
        data = response.json()

        # Parse token balances
        token_balances = []
        for token in data.get('tokens', []):
            token_info = token.get('tokenInfo', {})
            balance = float(token.get('balance', 0)) / (10 ** int(token_info.get('decimals', 18)))

            token_balances.append({
                'token_name': token_info.get('name'),
                'token_symbol': token_info.get('symbol'),
                'token_address': token_info.get('address'),
                'balance': balance,
                'price_usd': token_info.get('price', {}).get('rate', 0)
            })

        result = {
            'address': address,
            'eth_balance': data.get('ETH', {}).get('balance', 0),
            'tx_count': data.get('countTxs', 0),
            'token_balances': token_balances,
            'api_source': 'ethplorer'
        }

        self.cache[f"eth_addr_{address}_ethplorer"] = result
        return result

    def _get_blockchair_address(self, address: str) -> Dict:
        """Get address info from Blockchair"""
        self._rate_limit('blockchair')

        url = f"{self.apis['blockchair']}/dashboards/address/{address}"
        response = self.session.get(url, timeout=10)
        response.raise_for_status()

        data = response.json()['data'][address]
        addr_data = data['address']

        result = {
            'address': address,
            'eth_balance': float(addr_data.get('balance', 0)) / 1e18,
            'tx_count': addr_data.get('transaction_count', 0),
            'first_seen': addr_data.get('first_seen_receiving'),
            'last_seen': addr_data.get('last_seen_receiving'),
            'api_source': 'blockchair'
        }

        self.cache[f"eth_addr_{address}_blockchair"] = result
        return result

    def get_token_balances(self, address: str) -> List[Dict]:
        """Get all ERC-20 token balances for an address"""
        logger.info(f"Getting token balances for {address}")

        addr_info = self.get_address_info(address, 'ethplorer')
        return addr_info.get('token_balances', [])

    def analyze_smart_contract(self, contract_address: str) -> Dict:
        """Analyze a smart contract"""
        logger.info(f"Analyzing smart contract: {contract_address}")

        self._rate_limit('etherscan')

        # Get contract source code
        params = {
            'module': 'contract',
            'action': 'getsourcecode',
            'address': contract_address,
            'apikey': self.etherscan_api_key
        }

        response = self.session.get(self.apis['etherscan'], params=params, timeout=10)
        data = response.json()

        if data.get('status') == '1' and data.get('result'):
            contract_data = data['result'][0]

            return {
                'address': contract_address,
                'name': contract_data.get('ContractName'),
                'compiler_version': contract_data.get('CompilerVersion'),
                'optimization': contract_data.get('OptimizationUsed') == '1',
                'source_code': contract_data.get('SourceCode', '')[:1000],  # First 1000 chars
                'abi': contract_data.get('ABI', ''),
                'constructor_arguments': contract_data.get('ConstructorArguments'),
                'is_proxy': contract_data.get('Proxy') == '1',
                'verified': contract_data.get('SourceCode') != ''
            }

        return {'address': contract_address, 'verified': False}

    def trace_transaction(self, tx_hash: str) -> Dict:
        """Trace a transaction and its internal transactions"""
        logger.info(f"Tracing transaction: {tx_hash}")

        self._rate_limit('etherscan')

        # Get transaction details
        tx_params = {
            'module': 'proxy',
            'action': 'eth_getTransactionByHash',
            'txhash': tx_hash,
            'apikey': self.etherscan_api_key
        }

        response = self.session.get(self.apis['etherscan'], params=tx_params, timeout=10)
        tx_data = response.json()

        tx_result = tx_data.get('result', {})

        # Get transaction receipt
        time.sleep(self.rate_limits['etherscan'])
        receipt_params = {
            'module': 'proxy',
            'action': 'eth_getTransactionReceipt',
            'txhash': tx_hash,
            'apikey': self.etherscan_api_key
        }

        response = self.session.get(self.apis['etherscan'], params=receipt_params, timeout=10)
        receipt_data = response.json()
        receipt = receipt_data.get('result', {})

        # Get internal transactions
        time.sleep(self.rate_limits['etherscan'])
        internal_params = {
            'module': 'account',
            'action': 'txlistinternal',
            'txhash': tx_hash,
            'apikey': self.etherscan_api_key
        }

        response = self.session.get(self.apis['etherscan'], params=internal_params, timeout=10)
        internal_data = response.json()

        internal_txs = []
        for itx in internal_data.get('result', []):
            if isinstance(itx, dict):
                internal_txs.append({
                    'from': itx.get('from'),
                    'to': itx.get('to'),
                    'value': int(itx.get('value', 0)) / 1e18,
                    'type': itx.get('type')
                })

        return {
            'hash': tx_hash,
            'from': tx_result.get('from'),
            'to': tx_result.get('to'),
            'value': int(tx_result.get('value', '0x0'), 16) / 1e18,
            'gas': int(tx_result.get('gas', '0x0'), 16),
            'gas_price': int(tx_result.get('gasPrice', '0x0'), 16) / 1e9,
            'gas_used': int(receipt.get('gasUsed', '0x0'), 16),
            'block_number': int(tx_result.get('blockNumber', '0x0'), 16),
            'status': receipt.get('status') == '0x1',
            'internal_transactions': internal_txs,
            'logs': receipt.get('logs', [])
        }

    def analyze_defi_activity(self, address: str) -> Dict:
        """Analyze DeFi protocol interactions"""
        logger.info(f"Analyzing DeFi activity for {address}")

        addr_info = self.get_address_info(address)

        defi_interactions = {
            'protocols': [],
            'token_swaps': [],
            'liquidity_provisions': [],
            'lending_activity': []
        }

        # Analyze transactions for DeFi interactions
        for tx in addr_info.get('transactions', []):
            to_addr = tx.get('to', '').lower()

            if to_addr in self.defi_protocols:
                protocol_name = self.defi_protocols[to_addr]

                defi_interactions['protocols'].append({
                    'protocol': protocol_name,
                    'tx_hash': tx.get('hash'),
                    'time': tx.get('time'),
                    'value': tx.get('value')
                })

                # Categorize by protocol type
                if 'Uniswap' in protocol_name or '1inch' in protocol_name:
                    defi_interactions['token_swaps'].append({
                        'protocol': protocol_name,
                        'tx_hash': tx.get('hash'),
                        'time': tx.get('time')
                    })
                elif 'Aave' in protocol_name:
                    defi_interactions['lending_activity'].append({
                        'protocol': protocol_name,
                        'tx_hash': tx.get('hash'),
                        'time': tx.get('time')
                    })

        # Count unique protocols
        unique_protocols = set(item['protocol'] for item in defi_interactions['protocols'])

        return {
            'address': address,
            'unique_protocols': list(unique_protocols),
            'total_defi_txs': len(defi_interactions['protocols']),
            'defi_interactions': defi_interactions
        }

    def track_token_transfers(self, token_address: str, from_address: Optional[str] = None) -> List[Dict]:
        """Track ERC-20 token transfers"""
        logger.info(f"Tracking token transfers for {token_address}")

        self._rate_limit('etherscan')

        params = {
            'module': 'account',
            'action': 'tokentx',
            'contractaddress': token_address,
            'page': 1,
            'offset': 100,
            'sort': 'desc',
            'apikey': self.etherscan_api_key
        }

        if from_address:
            params['address'] = from_address

        response = self.session.get(self.apis['etherscan'], params=params, timeout=10)
        data = response.json()

        transfers = []
        for tx in data.get('result', []):
            if isinstance(tx, dict):
                decimals = int(tx.get('tokenDecimal', 18))
                value = int(tx.get('value', 0)) / (10 ** decimals)

                transfers.append({
                    'hash': tx.get('hash'),
                    'from': tx.get('from'),
                    'to': tx.get('to'),
                    'value': value,
                    'token_name': tx.get('tokenName'),
                    'token_symbol': tx.get('tokenSymbol'),
                    'time': datetime.fromtimestamp(int(tx.get('timeStamp', 0))),
                    'block_number': int(tx.get('blockNumber', 0))
                })

        return transfers

    def analyze_wallet(self, address: str) -> Dict:
        """Comprehensive Ethereum wallet analysis"""
        logger.info(f"Analyzing Ethereum wallet: {address}")

        # Get basic info
        addr_info = self.get_address_info(address)

        # Get token balances
        token_balances = self.get_token_balances(address)

        # Analyze DeFi activity
        defi_activity = self.analyze_defi_activity(address)

        # Calculate portfolio value
        portfolio_value = addr_info.get('eth_balance', 0) * 3000  # Rough ETH price
        for token in token_balances:
            portfolio_value += token.get('balance', 0) * token.get('price_usd', 0)

        analysis = {
            'address': address,
            'eth_balance': addr_info.get('eth_balance', 0),
            'tx_count': addr_info.get('tx_count', 0),
            'token_count': len(token_balances),
            'portfolio_value_usd': portfolio_value,
            'defi_protocols_used': defi_activity.get('unique_protocols', []),
            'defi_tx_count': defi_activity.get('total_defi_txs', 0),
            'risk_score': 0,
            'flags': []
        }

        # Calculate risk score
        analysis['risk_score'] = self._calculate_risk_score(analysis)

        return analysis

    def _calculate_risk_score(self, analysis: Dict) -> float:
        """Calculate risk score for Ethereum wallet"""
        score = 0.0

        # High transaction volume
        if analysis['tx_count'] > 1000:
            score += 2.0
        elif analysis['tx_count'] > 100:
            score += 1.0

        # DeFi activity
        if analysis['defi_tx_count'] > 50:
            score += 1.5

        # Large portfolio
        if analysis['portfolio_value_usd'] > 100000:
            score += 2.0
        elif analysis['portfolio_value_usd'] > 10000:
            score += 1.0

        return min(score, 10.0)
