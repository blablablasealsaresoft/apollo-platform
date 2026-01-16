"""
Multi-Chain Blockchain Intelligence Tracker
Support for 50+ blockchain networks including BSC, Polygon, Avalanche, etc.
"""

import requests
import time
from typing import Dict, List, Optional
from datetime import datetime
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class MultiChainTracker:
    """Universal blockchain tracker supporting 50+ chains"""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'MultiChainIntelligence/1.0'
        })

        # Supported chains configuration
        self.chains = {
            # EVM Compatible Chains
            'bsc': {
                'name': 'Binance Smart Chain',
                'chain_id': 56,
                'explorer_api': 'https://api.bscscan.com/api',
                'native_token': 'BNB',
                'decimals': 18
            },
            'polygon': {
                'name': 'Polygon',
                'chain_id': 137,
                'explorer_api': 'https://api.polygonscan.com/api',
                'native_token': 'MATIC',
                'decimals': 18
            },
            'avalanche': {
                'name': 'Avalanche C-Chain',
                'chain_id': 43114,
                'explorer_api': 'https://api.snowtrace.io/api',
                'native_token': 'AVAX',
                'decimals': 18
            },
            'fantom': {
                'name': 'Fantom',
                'chain_id': 250,
                'explorer_api': 'https://api.ftmscan.com/api',
                'native_token': 'FTM',
                'decimals': 18
            },
            'arbitrum': {
                'name': 'Arbitrum One',
                'chain_id': 42161,
                'explorer_api': 'https://api.arbiscan.io/api',
                'native_token': 'ETH',
                'decimals': 18
            },
            'optimism': {
                'name': 'Optimism',
                'chain_id': 10,
                'explorer_api': 'https://api-optimistic.etherscan.io/api',
                'native_token': 'ETH',
                'decimals': 18
            },
            'cronos': {
                'name': 'Cronos',
                'chain_id': 25,
                'explorer_api': 'https://api.cronoscan.com/api',
                'native_token': 'CRO',
                'decimals': 18
            },
            'moonbeam': {
                'name': 'Moonbeam',
                'chain_id': 1284,
                'explorer_api': 'https://api-moonbeam.moonscan.io/api',
                'native_token': 'GLMR',
                'decimals': 18
            },
            'moonriver': {
                'name': 'Moonriver',
                'chain_id': 1285,
                'explorer_api': 'https://api-moonriver.moonscan.io/api',
                'native_token': 'MOVR',
                'decimals': 18
            },
            'gnosis': {
                'name': 'Gnosis Chain',
                'chain_id': 100,
                'explorer_api': 'https://api.gnosisscan.io/api',
                'native_token': 'xDAI',
                'decimals': 18
            },
            'celo': {
                'name': 'Celo',
                'chain_id': 42220,
                'explorer_api': 'https://api.celoscan.io/api',
                'native_token': 'CELO',
                'decimals': 18
            },
            'harmony': {
                'name': 'Harmony',
                'chain_id': 1666600000,
                'explorer_api': 'https://api.harmonyscan.com/api',
                'native_token': 'ONE',
                'decimals': 18
            },
            'aurora': {
                'name': 'Aurora',
                'chain_id': 1313161554,
                'explorer_api': 'https://api.aurorascan.dev/api',
                'native_token': 'ETH',
                'decimals': 18
            },
            'klaytn': {
                'name': 'Klaytn',
                'chain_id': 8217,
                'explorer_api': 'https://api-cypress.klaytnscope.com/v2',
                'native_token': 'KLAY',
                'decimals': 18
            },
            'metis': {
                'name': 'Metis',
                'chain_id': 1088,
                'explorer_api': 'https://api.explorer.metis.io/api',
                'native_token': 'METIS',
                'decimals': 18
            },
            'base': {
                'name': 'Base',
                'chain_id': 8453,
                'explorer_api': 'https://api.basescan.org/api',
                'native_token': 'ETH',
                'decimals': 18
            },
            'linea': {
                'name': 'Linea',
                'chain_id': 59144,
                'explorer_api': 'https://api.lineascan.build/api',
                'native_token': 'ETH',
                'decimals': 18
            },
            'scroll': {
                'name': 'Scroll',
                'chain_id': 534352,
                'explorer_api': 'https://api.scrollscan.com/api',
                'native_token': 'ETH',
                'decimals': 18
            },
            'zksync': {
                'name': 'zkSync Era',
                'chain_id': 324,
                'explorer_api': 'https://api-era.zksync.network/api',
                'native_token': 'ETH',
                'decimals': 18
            },
            'polygon_zkevm': {
                'name': 'Polygon zkEVM',
                'chain_id': 1101,
                'explorer_api': 'https://api-zkevm.polygonscan.com/api',
                'native_token': 'ETH',
                'decimals': 18
            },
            # Additional Layer 2s
            'mantle': {
                'name': 'Mantle',
                'chain_id': 5000,
                'explorer_api': 'https://api.mantlescan.xyz/api',
                'native_token': 'MNT',
                'decimals': 18
            },
            'blast': {
                'name': 'Blast',
                'chain_id': 81457,
                'explorer_api': 'https://api.blastscan.io/api',
                'native_token': 'ETH',
                'decimals': 18
            },
            # Additional L1s
            'boba': {
                'name': 'Boba Network',
                'chain_id': 288,
                'explorer_api': 'https://api.bobascan.com/api',
                'native_token': 'ETH',
                'decimals': 18
            },
            'kava': {
                'name': 'Kava EVM',
                'chain_id': 2222,
                'explorer_api': 'https://api.kavascan.io/api',
                'native_token': 'KAVA',
                'decimals': 18
            },
            'fuse': {
                'name': 'Fuse',
                'chain_id': 122,
                'explorer_api': 'https://api.fusescan.io/api',
                'native_token': 'FUSE',
                'decimals': 18
            },
            'evmos': {
                'name': 'Evmos',
                'chain_id': 9001,
                'explorer_api': 'https://api.evmosscan.com/api',
                'native_token': 'EVMOS',
                'decimals': 18
            },
            'oasis_emerald': {
                'name': 'Oasis Emerald',
                'chain_id': 42262,
                'explorer_api': 'https://api.explorer.emerald.oasis.dev/api',
                'native_token': 'ROSE',
                'decimals': 18
            },
            'telos': {
                'name': 'Telos EVM',
                'chain_id': 40,
                'explorer_api': 'https://api.teloscan.io/api',
                'native_token': 'TLOS',
                'decimals': 18
            },
            'syscoin': {
                'name': 'Syscoin NEVM',
                'chain_id': 57,
                'explorer_api': 'https://api.syscoin.org/api',
                'native_token': 'SYS',
                'decimals': 18
            },
            'velas': {
                'name': 'Velas',
                'chain_id': 106,
                'explorer_api': 'https://api.velascan.org/api',
                'native_token': 'VLX',
                'decimals': 18
            },
            # Testnets (for development)
            'goerli': {
                'name': 'Goerli Testnet',
                'chain_id': 5,
                'explorer_api': 'https://api-goerli.etherscan.io/api',
                'native_token': 'ETH',
                'decimals': 18
            },
            'sepolia': {
                'name': 'Sepolia Testnet',
                'chain_id': 11155111,
                'explorer_api': 'https://api-sepolia.etherscan.io/api',
                'native_token': 'ETH',
                'decimals': 18
            },
            'mumbai': {
                'name': 'Mumbai Testnet',
                'chain_id': 80001,
                'explorer_api': 'https://api-testnet.polygonscan.com/api',
                'native_token': 'MATIC',
                'decimals': 18
            },
            # Additional chains
            'heco': {
                'name': 'Huobi ECO Chain',
                'chain_id': 128,
                'explorer_api': 'https://api.hecoinfo.com/api',
                'native_token': 'HT',
                'decimals': 18
            },
            'okx': {
                'name': 'OKX Chain',
                'chain_id': 66,
                'explorer_api': 'https://api.oklink.com/api',
                'native_token': 'OKT',
                'decimals': 18
            },
            'theta': {
                'name': 'Theta',
                'chain_id': 361,
                'explorer_api': 'https://api.thetascan.io/api',
                'native_token': 'TFUEL',
                'decimals': 18
            },
            'wemix': {
                'name': 'WEMIX',
                'chain_id': 1111,
                'explorer_api': 'https://api.wemixscan.com/api',
                'native_token': 'WEMIX',
                'decimals': 18
            },
            'astar': {
                'name': 'Astar',
                'chain_id': 592,
                'explorer_api': 'https://api.astar.network/api',
                'native_token': 'ASTR',
                'decimals': 18
            },
            'shiden': {
                'name': 'Shiden',
                'chain_id': 336,
                'explorer_api': 'https://api.shiden.network/api',
                'native_token': 'SDN',
                'decimals': 18
            },
            'iotex': {
                'name': 'IoTeX',
                'chain_id': 4689,
                'explorer_api': 'https://api.iotexscan.io/api',
                'native_token': 'IOTX',
                'decimals': 18
            },
            'thundercore': {
                'name': 'ThunderCore',
                'chain_id': 108,
                'explorer_api': 'https://api.thundercore.com/api',
                'native_token': 'TT',
                'decimals': 18
            },
            'energi': {
                'name': 'Energi',
                'chain_id': 39797,
                'explorer_api': 'https://api.energiscan.com/api',
                'native_token': 'NRG',
                'decimals': 18
            },
            'smartbch': {
                'name': 'Smart Bitcoin Cash',
                'chain_id': 10000,
                'explorer_api': 'https://api.smartscan.cash/api',
                'native_token': 'BCH',
                'decimals': 18
            },
            'elrond': {
                'name': 'MultiversX (Elrond)',
                'chain_id': 1,
                'explorer_api': 'https://api.multiversx.com',
                'native_token': 'EGLD',
                'decimals': 18
            },
            'near': {
                'name': 'NEAR (Aurora)',
                'chain_id': 1313161554,
                'explorer_api': 'https://api.nearblocks.io',
                'native_token': 'NEAR',
                'decimals': 24
            },
            'algorand': {
                'name': 'Algorand',
                'chain_id': 4160,
                'explorer_api': 'https://algoexplorer.io/api',
                'native_token': 'ALGO',
                'decimals': 6
            },
            'flow': {
                'name': 'Flow',
                'chain_id': 747,
                'explorer_api': 'https://flowscan.org/api',
                'native_token': 'FLOW',
                'decimals': 8
            },
            'hedera': {
                'name': 'Hedera',
                'chain_id': 295,
                'explorer_api': 'https://mainnet-public.mirrornode.hedera.com/api',
                'native_token': 'HBAR',
                'decimals': 8
            },
            'aptos': {
                'name': 'Aptos',
                'chain_id': 1,
                'explorer_api': 'https://fullnode.mainnet.aptoslabs.com/v1',
                'native_token': 'APT',
                'decimals': 8
            },
            'sui': {
                'name': 'Sui',
                'chain_id': 1,
                'explorer_api': 'https://fullnode.mainnet.sui.io',
                'native_token': 'SUI',
                'decimals': 9
            }
        }

        self.cache = {}
        self.rate_limit_delay = 0.3  # 3 requests per second

    def get_supported_chains(self) -> List[str]:
        """Get list of all supported blockchain networks"""
        return list(self.chains.keys())

    def get_chain_info(self, chain: str) -> Dict:
        """Get information about a specific chain"""
        return self.chains.get(chain, {})

    def get_address_balance(self, chain: str, address: str, api_key: Optional[str] = None) -> Dict:
        """Get native token balance for an address on any chain"""
        if chain not in self.chains:
            return {'error': f'Unsupported chain: {chain}'}

        chain_info = self.chains[chain]

        try:
            # For EVM-compatible chains
            if 'explorer_api' in chain_info and 'etherscan' in chain_info['explorer_api'].lower():
                return self._get_evm_balance(chain, address, api_key)
            else:
                # Custom implementation for non-EVM chains
                return self._get_custom_balance(chain, address)
        except Exception as e:
            logger.error(f"Error fetching balance for {address} on {chain}: {e}")
            return {'error': str(e)}

    def _get_evm_balance(self, chain: str, address: str, api_key: Optional[str] = None) -> Dict:
        """Get balance for EVM-compatible chains"""
        chain_info = self.chains[chain]
        time.sleep(self.rate_limit_delay)

        params = {
            'module': 'account',
            'action': 'balance',
            'address': address,
            'tag': 'latest'
        }

        if api_key:
            params['apikey'] = api_key

        response = self.session.get(chain_info['explorer_api'], params=params, timeout=10)
        response.raise_for_status()
        data = response.json()

        if data.get('status') == '1':
            balance_wei = int(data.get('result', 0))
            balance = balance_wei / (10 ** chain_info['decimals'])

            return {
                'chain': chain,
                'chain_name': chain_info['name'],
                'address': address,
                'balance': balance,
                'token': chain_info['native_token'],
                'balance_wei': balance_wei
            }
        else:
            return {'error': data.get('message', 'Unknown error')}

    def _get_custom_balance(self, chain: str, address: str) -> Dict:
        """Get balance for non-EVM chains (placeholder for custom implementations)"""
        chain_info = self.chains[chain]

        # Placeholder - actual implementations would vary by chain
        return {
            'chain': chain,
            'chain_name': chain_info['name'],
            'address': address,
            'balance': 0,
            'token': chain_info['native_token'],
            'note': 'Custom implementation required'
        }

    def get_transactions(self, chain: str, address: str, api_key: Optional[str] = None,
                        limit: int = 100) -> List[Dict]:
        """Get transaction history for an address on any chain"""
        if chain not in self.chains:
            return []

        chain_info = self.chains[chain]

        try:
            if 'explorer_api' in chain_info and 'scan' in chain_info['explorer_api'].lower():
                return self._get_evm_transactions(chain, address, api_key, limit)
            else:
                return []
        except Exception as e:
            logger.error(f"Error fetching transactions for {address} on {chain}: {e}")
            return []

    def _get_evm_transactions(self, chain: str, address: str, api_key: Optional[str] = None,
                             limit: int = 100) -> List[Dict]:
        """Get transactions for EVM-compatible chains"""
        chain_info = self.chains[chain]
        time.sleep(self.rate_limit_delay)

        params = {
            'module': 'account',
            'action': 'txlist',
            'address': address,
            'startblock': 0,
            'endblock': 99999999,
            'page': 1,
            'offset': limit,
            'sort': 'desc'
        }

        if api_key:
            params['apikey'] = api_key

        response = self.session.get(chain_info['explorer_api'], params=params, timeout=10)
        response.raise_for_status()
        data = response.json()

        transactions = []
        if data.get('status') == '1':
            for tx in data.get('result', []):
                if isinstance(tx, dict):
                    transactions.append({
                        'hash': tx.get('hash'),
                        'from': tx.get('from'),
                        'to': tx.get('to'),
                        'value': int(tx.get('value', 0)) / (10 ** chain_info['decimals']),
                        'block_number': int(tx.get('blockNumber', 0)),
                        'timestamp': datetime.fromtimestamp(int(tx.get('timeStamp', 0))),
                        'gas_used': int(tx.get('gasUsed', 0)),
                        'status': tx.get('isError') == '0'
                    })

        return transactions

    def analyze_multi_chain_wallet(self, address: str, chains: Optional[List[str]] = None,
                                   api_keys: Optional[Dict[str, str]] = None) -> Dict:
        """Analyze wallet across multiple chains"""
        if chains is None:
            # Use major chains by default
            chains = ['bsc', 'polygon', 'avalanche', 'fantom', 'arbitrum', 'optimism']

        api_keys = api_keys or {}

        logger.info(f"Analyzing wallet {address} across {len(chains)} chains")

        results = {
            'address': address,
            'chains_analyzed': [],
            'total_balance_usd': 0,
            'chain_balances': []
        }

        for chain in chains:
            try:
                balance_info = self.get_address_balance(chain, address, api_keys.get(chain))

                if 'error' not in balance_info:
                    results['chains_analyzed'].append(chain)
                    results['chain_balances'].append(balance_info)

            except Exception as e:
                logger.error(f"Error analyzing {chain}: {e}")

        return results

    def trace_cross_chain_activity(self, address: str, chains: List[str],
                                   api_keys: Optional[Dict[str, str]] = None) -> Dict:
        """Trace activity across multiple chains"""
        api_keys = api_keys or {}

        logger.info(f"Tracing cross-chain activity for {address}")

        activity = {
            'address': address,
            'chains': {},
            'total_transactions': 0,
            'first_seen': None,
            'last_seen': None
        }

        for chain in chains:
            try:
                txs = self.get_transactions(chain, address, api_keys.get(chain), limit=50)

                if txs:
                    activity['chains'][chain] = {
                        'tx_count': len(txs),
                        'first_tx': txs[-1]['timestamp'] if txs else None,
                        'last_tx': txs[0]['timestamp'] if txs else None
                    }

                    activity['total_transactions'] += len(txs)

                    # Update first/last seen
                    if txs:
                        if activity['first_seen'] is None or txs[-1]['timestamp'] < activity['first_seen']:
                            activity['first_seen'] = txs[-1]['timestamp']
                        if activity['last_seen'] is None or txs[0]['timestamp'] > activity['last_seen']:
                            activity['last_seen'] = txs[0]['timestamp']

            except Exception as e:
                logger.error(f"Error tracing {chain}: {e}")

        return activity

    def get_token_balances_multi_chain(self, address: str, chains: List[str],
                                      api_keys: Optional[Dict[str, str]] = None) -> Dict:
        """Get token balances across multiple chains"""
        api_keys = api_keys or {}

        logger.info(f"Getting token balances for {address} across {len(chains)} chains")

        token_balances = {
            'address': address,
            'chains': {}
        }

        for chain in chains:
            try:
                chain_info = self.chains[chain]
                if 'explorer_api' not in chain_info:
                    continue

                time.sleep(self.rate_limit_delay)

                params = {
                    'module': 'account',
                    'action': 'tokentx',
                    'address': address,
                    'page': 1,
                    'offset': 100,
                    'sort': 'desc'
                }

                if api_keys.get(chain):
                    params['apikey'] = api_keys[chain]

                response = self.session.get(chain_info['explorer_api'], params=params, timeout=10)
                if response.status_code == 200:
                    data = response.json()

                    if data.get('status') == '1':
                        tokens = {}
                        for tx in data.get('result', []):
                            if isinstance(tx, dict):
                                token_addr = tx.get('contractAddress')
                                if token_addr not in tokens:
                                    tokens[token_addr] = {
                                        'name': tx.get('tokenName'),
                                        'symbol': tx.get('tokenSymbol'),
                                        'address': token_addr
                                    }

                        token_balances['chains'][chain] = {
                            'token_count': len(tokens),
                            'tokens': list(tokens.values())
                        }

            except Exception as e:
                logger.error(f"Error getting tokens on {chain}: {e}")

        return token_balances
