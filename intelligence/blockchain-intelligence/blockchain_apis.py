"""
Blockchain API Orchestration
Unified interface for 50+ blockchain APIs with rate limiting and fallbacks
"""

import requests
import time
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from collections import defaultdict
import logging
from functools import wraps

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class RateLimiter:
    """Rate limiter for API calls"""

    def __init__(self):
        self.call_history = defaultdict(list)
        self.limits = {}

    def set_limit(self, api_name: str, calls_per_second: float):
        """Set rate limit for an API"""
        self.limits[api_name] = calls_per_second

    def check_limit(self, api_name: str) -> bool:
        """Check if API call is within rate limit"""
        if api_name not in self.limits:
            return True

        limit = self.limits[api_name]
        now = time.time()

        # Clean old entries (older than 1 second)
        self.call_history[api_name] = [
            t for t in self.call_history[api_name]
            if now - t < 1.0
        ]

        # Check if we're at the limit
        if len(self.call_history[api_name]) >= limit:
            return False

        return True

    def wait_if_needed(self, api_name: str):
        """Wait if necessary to respect rate limit"""
        while not self.check_limit(api_name):
            time.sleep(0.1)

        self.call_history[api_name].append(time.time())


class APICache:
    """Simple cache for API responses"""

    def __init__(self, ttl_seconds: int = 60):
        self.cache = {}
        self.ttl = ttl_seconds

    def get(self, key: str) -> Optional[Any]:
        """Get cached value if not expired"""
        if key in self.cache:
            value, timestamp = self.cache[key]
            if time.time() - timestamp < self.ttl:
                return value
            else:
                del self.cache[key]
        return None

    def set(self, key: str, value: Any):
        """Cache a value with timestamp"""
        self.cache[key] = (value, time.time())

    def clear(self):
        """Clear all cached values"""
        self.cache.clear()


class BlockchainAPIOrchestrator:
    """Orchestrate calls to 50+ blockchain APIs"""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'BlockchainIntelligence/1.0'
        })

        self.rate_limiter = RateLimiter()
        self.cache = APICache(ttl_seconds=60)

        # API configurations
        self.apis = self._initialize_apis()
        self._setup_rate_limits()

    def _initialize_apis(self) -> Dict:
        """Initialize all API configurations"""
        return {
            # Bitcoin APIs
            'blockchain_info': {
                'name': 'Blockchain.info',
                'base_url': 'https://blockchain.info',
                'type': 'bitcoin',
                'endpoints': {
                    'address': '/rawaddr/{address}',
                    'transaction': '/rawtx/{tx_hash}',
                    'block': '/rawblock/{block_hash}'
                },
                'requires_key': False
            },
            'blockchair_btc': {
                'name': 'Blockchair Bitcoin',
                'base_url': 'https://api.blockchair.com/bitcoin',
                'type': 'bitcoin',
                'endpoints': {
                    'address': '/dashboards/address/{address}',
                    'transaction': '/dashboards/transaction/{tx_hash}'
                },
                'requires_key': False
            },
            'blockcypher_btc': {
                'name': 'BlockCypher Bitcoin',
                'base_url': 'https://api.blockcypher.com/v1/btc/main',
                'type': 'bitcoin',
                'endpoints': {
                    'address': '/addrs/{address}',
                    'transaction': '/txs/{tx_hash}'
                },
                'requires_key': False
            },
            'blockstream': {
                'name': 'Blockstream',
                'base_url': 'https://blockstream.info/api',
                'type': 'bitcoin',
                'endpoints': {
                    'address': '/address/{address}',
                    'transaction': '/tx/{tx_hash}'
                },
                'requires_key': False
            },
            'mempool_space': {
                'name': 'Mempool.space',
                'base_url': 'https://mempool.space/api',
                'type': 'bitcoin',
                'endpoints': {
                    'address': '/address/{address}',
                    'transaction': '/tx/{tx_hash}'
                },
                'requires_key': False
            },
            # Ethereum APIs
            'etherscan': {
                'name': 'Etherscan',
                'base_url': 'https://api.etherscan.io/api',
                'type': 'ethereum',
                'endpoints': {
                    'address': '?module=account&action=balance&address={address}',
                    'transactions': '?module=account&action=txlist&address={address}'
                },
                'requires_key': True
            },
            'ethplorer': {
                'name': 'Ethplorer',
                'base_url': 'https://api.ethplorer.io',
                'type': 'ethereum',
                'endpoints': {
                    'address': '/getAddressInfo/{address}'
                },
                'requires_key': False
            },
            'blockchair_eth': {
                'name': 'Blockchair Ethereum',
                'base_url': 'https://api.blockchair.com/ethereum',
                'type': 'ethereum',
                'endpoints': {
                    'address': '/dashboards/address/{address}'
                },
                'requires_key': False
            },
            # BSC APIs
            'bscscan': {
                'name': 'BscScan',
                'base_url': 'https://api.bscscan.com/api',
                'type': 'bsc',
                'endpoints': {
                    'address': '?module=account&action=balance&address={address}'
                },
                'requires_key': True
            },
            # Polygon APIs
            'polygonscan': {
                'name': 'PolygonScan',
                'base_url': 'https://api.polygonscan.com/api',
                'type': 'polygon',
                'endpoints': {
                    'address': '?module=account&action=balance&address={address}'
                },
                'requires_key': True
            },
            # Avalanche APIs
            'snowtrace': {
                'name': 'Snowtrace',
                'base_url': 'https://api.snowtrace.io/api',
                'type': 'avalanche',
                'endpoints': {
                    'address': '?module=account&action=balance&address={address}'
                },
                'requires_key': True
            },
            # Fantom APIs
            'ftmscan': {
                'name': 'FTMScan',
                'base_url': 'https://api.ftmscan.com/api',
                'type': 'fantom',
                'endpoints': {
                    'address': '?module=account&action=balance&address={address}'
                },
                'requires_key': True
            },
            # Arbitrum APIs
            'arbiscan': {
                'name': 'Arbiscan',
                'base_url': 'https://api.arbiscan.io/api',
                'type': 'arbitrum',
                'endpoints': {
                    'address': '?module=account&action=balance&address={address}'
                },
                'requires_key': True
            },
            # Optimism APIs
            'optimism_etherscan': {
                'name': 'Optimism Etherscan',
                'base_url': 'https://api-optimistic.etherscan.io/api',
                'type': 'optimism',
                'endpoints': {
                    'address': '?module=account&action=balance&address={address}'
                },
                'requires_key': True
            },
            # Additional APIs
            'covalent': {
                'name': 'Covalent',
                'base_url': 'https://api.covalenthq.com/v1',
                'type': 'multi-chain',
                'endpoints': {
                    'address_balance': '/{chain_id}/address/{address}/balances_v2/'
                },
                'requires_key': True
            },
            'moralis': {
                'name': 'Moralis',
                'base_url': 'https://deep-index.moralis.io/api/v2',
                'type': 'multi-chain',
                'endpoints': {
                    'address_balance': '/{address}/balance'
                },
                'requires_key': True
            },
            'alchemy': {
                'name': 'Alchemy',
                'base_url': 'https://eth-mainnet.g.alchemy.com/v2',
                'type': 'ethereum',
                'endpoints': {},
                'requires_key': True
            },
            'infura': {
                'name': 'Infura',
                'base_url': 'https://mainnet.infura.io/v3',
                'type': 'ethereum',
                'endpoints': {},
                'requires_key': True
            },
            'quicknode': {
                'name': 'QuickNode',
                'base_url': 'https://api.quicknode.com',
                'type': 'multi-chain',
                'endpoints': {},
                'requires_key': True
            },
            'ankr': {
                'name': 'Ankr',
                'base_url': 'https://rpc.ankr.com',
                'type': 'multi-chain',
                'endpoints': {},
                'requires_key': False
            },
            'pokt': {
                'name': 'Pocket Network',
                'base_url': 'https://eth-mainnet.gateway.pokt.network/v1',
                'type': 'multi-chain',
                'endpoints': {},
                'requires_key': False
            },
            # Price/Market APIs
            'coingecko': {
                'name': 'CoinGecko',
                'base_url': 'https://api.coingecko.com/api/v3',
                'type': 'market_data',
                'endpoints': {
                    'price': '/simple/price',
                    'coin': '/coins/{id}'
                },
                'requires_key': False
            },
            'coinmarketcap': {
                'name': 'CoinMarketCap',
                'base_url': 'https://pro-api.coinmarketcap.com/v1',
                'type': 'market_data',
                'endpoints': {
                    'quotes': '/cryptocurrency/quotes/latest'
                },
                'requires_key': True
            },
            'cryptocompare': {
                'name': 'CryptoCompare',
                'base_url': 'https://min-api.cryptocompare.com/data',
                'type': 'market_data',
                'endpoints': {
                    'price': '/price'
                },
                'requires_key': False
            }
        }

    def _setup_rate_limits(self):
        """Setup rate limits for all APIs"""
        rate_limits = {
            'blockchain_info': 3,  # 3 calls/sec
            'blockchair_btc': 1,
            'blockcypher_btc': 3,
            'blockstream': 10,
            'mempool_space': 10,
            'etherscan': 5,
            'ethplorer': 1,
            'blockchair_eth': 1,
            'bscscan': 5,
            'polygonscan': 5,
            'snowtrace': 5,
            'ftmscan': 5,
            'arbiscan': 5,
            'optimism_etherscan': 5,
            'coingecko': 10,
            'coinmarketcap': 10,
            'cryptocompare': 10
        }

        for api_name, limit in rate_limits.items():
            self.rate_limiter.set_limit(api_name, limit)

    def call_api(self, api_name: str, endpoint: str, params: Optional[Dict] = None,
                api_key: Optional[str] = None, use_cache: bool = True) -> Dict:
        """
        Make an API call with rate limiting and caching

        Args:
            api_name: Name of the API to call
            endpoint: Endpoint path
            params: Query parameters
            api_key: API key if required
            use_cache: Whether to use cached results
        """
        if api_name not in self.apis:
            return {'error': f'Unknown API: {api_name}'}

        api_config = self.apis[api_name]

        # Check cache
        cache_key = f"{api_name}:{endpoint}:{str(params)}"
        if use_cache:
            cached = self.cache.get(cache_key)
            if cached is not None:
                logger.debug(f"Cache hit for {cache_key}")
                return cached

        # Rate limiting
        self.rate_limiter.wait_if_needed(api_name)

        # Build URL
        url = api_config['base_url'] + endpoint

        # Add API key if required
        if api_config.get('requires_key') and api_key:
            if params is None:
                params = {}
            params['apikey'] = api_key

        try:
            logger.info(f"Calling {api_name}: {endpoint}")
            response = self.session.get(url, params=params, timeout=10)
            response.raise_for_status()

            result = response.json()

            # Cache result
            if use_cache:
                self.cache.set(cache_key, result)

            return result

        except requests.exceptions.RequestException as e:
            logger.error(f"Error calling {api_name}: {e}")
            return {'error': str(e)}

    def call_with_fallback(self, api_names: List[str], endpoint_type: str,
                          params: Dict, api_keys: Optional[Dict[str, str]] = None) -> Dict:
        """
        Call APIs with automatic fallback to alternatives

        Args:
            api_names: List of API names to try in order
            endpoint_type: Type of endpoint (e.g., 'address', 'transaction')
            params: Parameters for the endpoint
            api_keys: Dictionary of API keys
        """
        api_keys = api_keys or {}

        for api_name in api_names:
            if api_name not in self.apis:
                continue

            api_config = self.apis[api_name]
            endpoint_template = api_config['endpoints'].get(endpoint_type)

            if not endpoint_template:
                continue

            # Format endpoint with parameters
            try:
                endpoint = endpoint_template.format(**params)
            except KeyError:
                continue

            # Make the call
            result = self.call_api(
                api_name,
                endpoint,
                params=None,
                api_key=api_keys.get(api_name),
                use_cache=True
            )

            # Check if successful
            if 'error' not in result:
                result['_source_api'] = api_name
                return result

            logger.warning(f"API {api_name} failed, trying next fallback")

        return {'error': 'All API calls failed'}

    def get_bitcoin_address(self, address: str, api_keys: Optional[Dict] = None) -> Dict:
        """Get Bitcoin address info with automatic fallback"""
        apis = ['blockstream', 'blockchain_info', 'blockcypher_btc', 'blockchair_btc', 'mempool_space']
        return self.call_with_fallback(apis, 'address', {'address': address}, api_keys)

    def get_ethereum_address(self, address: str, api_keys: Optional[Dict] = None) -> Dict:
        """Get Ethereum address info with automatic fallback"""
        apis = ['etherscan', 'ethplorer', 'blockchair_eth']
        return self.call_with_fallback(apis, 'address', {'address': address}, api_keys)

    def get_token_price(self, token_id: str, api_keys: Optional[Dict] = None) -> Dict:
        """Get token price from market data APIs"""
        # Try CoinGecko first (no key needed)
        result = self.call_api(
            'coingecko',
            '/simple/price',
            params={'ids': token_id, 'vs_currencies': 'usd'},
            use_cache=True
        )

        if 'error' not in result:
            return result

        # Fallback to CoinMarketCap
        if api_keys and 'coinmarketcap' in api_keys:
            result = self.call_api(
                'coinmarketcap',
                '/cryptocurrency/quotes/latest',
                params={'symbol': token_id.upper()},
                api_key=api_keys['coinmarketcap'],
                use_cache=True
            )

        return result

    def get_api_status(self) -> Dict:
        """Get status of all configured APIs"""
        status = {
            'total_apis': len(self.apis),
            'by_type': defaultdict(int),
            'by_status': defaultdict(int),
            'apis': []
        }

        for api_name, api_config in self.apis.items():
            api_type = api_config['type']
            status['by_type'][api_type] += 1

            api_status = {
                'name': api_name,
                'display_name': api_config['name'],
                'type': api_type,
                'requires_key': api_config.get('requires_key', False),
                'base_url': api_config['base_url']
            }

            status['apis'].append(api_status)

        status['by_type'] = dict(status['by_type'])
        status['by_status'] = dict(status['by_status'])

        return status

    def clear_cache(self):
        """Clear all cached API responses"""
        self.cache.clear()
        logger.info("API cache cleared")

    def get_supported_chains(self) -> List[str]:
        """Get list of all supported blockchain networks"""
        chains = set()
        for api_config in self.apis.values():
            chain_type = api_config['type']
            if chain_type != 'market_data':
                chains.add(chain_type)
        return sorted(list(chains))


def with_retry(max_retries: int = 3, delay: float = 1.0):
    """Decorator to retry API calls on failure"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    if attempt == max_retries - 1:
                        raise
                    logger.warning(f"Attempt {attempt + 1} failed: {e}. Retrying...")
                    time.sleep(delay * (attempt + 1))
            return None
        return wrapper
    return decorator
