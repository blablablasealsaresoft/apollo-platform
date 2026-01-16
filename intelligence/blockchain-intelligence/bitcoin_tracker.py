"""
Bitcoin Blockchain Intelligence Tracker
Comprehensive Bitcoin wallet analysis and transaction tracking
"""

import requests
import time
from typing import Dict, List, Optional, Set, Tuple
from datetime import datetime
from collections import defaultdict
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class BitcoinTracker:
    """Advanced Bitcoin blockchain tracker with multiple API sources"""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'BlockchainIntelligence/1.0'
        })

        # API endpoints
        self.apis = {
            'blockchain_info': 'https://blockchain.info',
            'blockchair': 'https://api.blockchair.com/bitcoin',
            'blockcypher': 'https://api.blockcypher.com/v1/btc/main',
            'blockstream': 'https://blockstream.info/api',
            'mempool_space': 'https://mempool.space/api'
        }

        # Rate limiting
        self.rate_limits = {
            'blockchain_info': 0.2,  # 5 req/sec
            'blockchair': 0.34,      # 3 req/sec
            'blockcypher': 0.2,      # 5 req/sec
            'blockstream': 0.1,      # 10 req/sec
            'mempool_space': 0.1
        }

        self.last_request = {}
        self.cache = {}

    def _rate_limit(self, api: str):
        """Enforce rate limiting for API calls"""
        if api in self.last_request:
            elapsed = time.time() - self.last_request[api]
            sleep_time = self.rate_limits.get(api, 1) - elapsed
            if sleep_time > 0:
                time.sleep(sleep_time)
        self.last_request[api] = time.time()

    def get_address_info(self, address: str, api: str = 'blockchain_info') -> Dict:
        """Get comprehensive address information"""
        cache_key = f"addr_{address}_{api}"
        if cache_key in self.cache:
            return self.cache[cache_key]

        try:
            if api == 'blockchain_info':
                return self._get_blockchain_info_address(address)
            elif api == 'blockchair':
                return self._get_blockchair_address(address)
            elif api == 'blockcypher':
                return self._get_blockcypher_address(address)
            elif api == 'blockstream':
                return self._get_blockstream_address(address)
            elif api == 'mempool_space':
                return self._get_mempool_address(address)
        except Exception as e:
            logger.error(f"Error fetching address {address} from {api}: {e}")
            # Try fallback API
            if api != 'blockstream':
                return self.get_address_info(address, 'blockstream')
            return {}

    def _get_blockchain_info_address(self, address: str) -> Dict:
        """Get address info from blockchain.info"""
        self._rate_limit('blockchain_info')

        url = f"{self.apis['blockchain_info']}/rawaddr/{address}"
        response = self.session.get(url, timeout=10)
        response.raise_for_status()

        data = response.json()

        result = {
            'address': address,
            'balance': data.get('final_balance', 0) / 1e8,  # Convert satoshi to BTC
            'total_received': data.get('total_received', 0) / 1e8,
            'total_sent': data.get('total_sent', 0) / 1e8,
            'tx_count': data.get('n_tx', 0),
            'transactions': [],
            'api_source': 'blockchain_info'
        }

        # Process transactions
        for tx in data.get('txs', []):
            result['transactions'].append({
                'hash': tx.get('hash'),
                'time': datetime.fromtimestamp(tx.get('time', 0)),
                'block_height': tx.get('block_height'),
                'inputs': [{'address': inp.get('prev_out', {}).get('addr'),
                           'value': inp.get('prev_out', {}).get('value', 0) / 1e8}
                          for inp in tx.get('inputs', [])],
                'outputs': [{'address': out.get('addr'),
                            'value': out.get('value', 0) / 1e8}
                           for out in tx.get('out', [])]
            })

        self.cache[f"addr_{address}_blockchain_info"] = result
        return result

    def _get_blockchair_address(self, address: str) -> Dict:
        """Get address info from blockchair"""
        self._rate_limit('blockchair')

        url = f"{self.apis['blockchair']}/dashboards/address/{address}"
        response = self.session.get(url, timeout=10)
        response.raise_for_status()

        data = response.json()['data'][address]
        addr_data = data['address']

        result = {
            'address': address,
            'balance': addr_data.get('balance', 0) / 1e8,
            'total_received': addr_data.get('received', 0) / 1e8,
            'total_sent': addr_data.get('spent', 0) / 1e8,
            'tx_count': addr_data.get('transaction_count', 0),
            'first_seen': addr_data.get('first_seen_receiving'),
            'last_seen': addr_data.get('last_seen_receiving'),
            'transactions': [],
            'api_source': 'blockchair'
        }

        # Process transactions
        for tx_hash, tx in data.get('transactions', {}).items():
            result['transactions'].append({
                'hash': tx_hash,
                'time': datetime.fromisoformat(tx.get('time', '').replace('Z', '+00:00')) if tx.get('time') else None,
                'block_height': tx.get('block_id'),
                'balance_change': tx.get('balance_change', 0) / 1e8
            })

        self.cache[f"addr_{address}_blockchair"] = result
        return result

    def _get_blockcypher_address(self, address: str) -> Dict:
        """Get address info from blockcypher"""
        self._rate_limit('blockcypher')

        url = f"{self.apis['blockcypher']}/addrs/{address}/full"
        response = self.session.get(url, timeout=10)
        response.raise_for_status()

        data = response.json()

        result = {
            'address': address,
            'balance': data.get('final_balance', 0) / 1e8,
            'total_received': data.get('total_received', 0) / 1e8,
            'total_sent': data.get('total_sent', 0) / 1e8,
            'tx_count': data.get('n_tx', 0),
            'unconfirmed_balance': data.get('unconfirmed_balance', 0) / 1e8,
            'transactions': [],
            'api_source': 'blockcypher'
        }

        # Process transactions
        for tx in data.get('txs', []):
            result['transactions'].append({
                'hash': tx.get('hash'),
                'time': datetime.fromisoformat(tx.get('received', '').replace('Z', '+00:00')) if tx.get('received') else None,
                'block_height': tx.get('block_height'),
                'confirmations': tx.get('confirmations', 0),
                'inputs': [{'address': inp.get('addresses', [None])[0] if inp.get('addresses') else None,
                           'value': inp.get('output_value', 0) / 1e8}
                          for inp in tx.get('inputs', [])],
                'outputs': [{'address': out.get('addresses', [None])[0] if out.get('addresses') else None,
                            'value': out.get('value', 0) / 1e8}
                           for out in tx.get('outputs', [])]
            })

        self.cache[f"addr_{address}_blockcypher"] = result
        return result

    def _get_blockstream_address(self, address: str) -> Dict:
        """Get address info from blockstream"""
        self._rate_limit('blockstream')

        # Get basic address info
        url = f"{self.apis['blockstream']}/address/{address}"
        response = self.session.get(url, timeout=10)
        response.raise_for_status()

        data = response.json()

        result = {
            'address': address,
            'balance': (data.get('chain_stats', {}).get('funded_txo_sum', 0) -
                       data.get('chain_stats', {}).get('spent_txo_sum', 0)) / 1e8,
            'total_received': data.get('chain_stats', {}).get('funded_txo_sum', 0) / 1e8,
            'total_sent': data.get('chain_stats', {}).get('spent_txo_sum', 0) / 1e8,
            'tx_count': data.get('chain_stats', {}).get('tx_count', 0),
            'transactions': [],
            'api_source': 'blockstream'
        }

        # Get transactions
        tx_url = f"{self.apis['blockstream']}/address/{address}/txs"
        tx_response = self.session.get(tx_url, timeout=10)
        if tx_response.status_code == 200:
            txs = tx_response.json()
            for tx in txs:
                result['transactions'].append({
                    'hash': tx.get('txid'),
                    'time': datetime.fromtimestamp(tx.get('status', {}).get('block_time', 0)) if tx.get('status', {}).get('block_time') else None,
                    'block_height': tx.get('status', {}).get('block_height'),
                    'confirmed': tx.get('status', {}).get('confirmed', False)
                })

        self.cache[f"addr_{address}_blockstream"] = result
        return result

    def _get_mempool_address(self, address: str) -> Dict:
        """Get address info from mempool.space"""
        self._rate_limit('mempool_space')

        url = f"{self.apis['mempool_space']}/address/{address}"
        response = self.session.get(url, timeout=10)
        response.raise_for_status()

        data = response.json()

        result = {
            'address': address,
            'balance': (data.get('chain_stats', {}).get('funded_txo_sum', 0) -
                       data.get('chain_stats', {}).get('spent_txo_sum', 0)) / 1e8,
            'total_received': data.get('chain_stats', {}).get('funded_txo_sum', 0) / 1e8,
            'total_sent': data.get('chain_stats', {}).get('spent_txo_sum', 0) / 1e8,
            'tx_count': data.get('chain_stats', {}).get('tx_count', 0),
            'api_source': 'mempool_space'
        }

        self.cache[f"addr_{address}_mempool_space"] = result
        return result

    def get_transaction(self, tx_hash: str, api: str = 'blockchain_info') -> Dict:
        """Get detailed transaction information"""
        cache_key = f"tx_{tx_hash}_{api}"
        if cache_key in self.cache:
            return self.cache[cache_key]

        try:
            if api == 'blockchain_info':
                return self._get_blockchain_info_tx(tx_hash)
            elif api == 'blockcypher':
                return self._get_blockcypher_tx(tx_hash)
            elif api == 'blockstream':
                return self._get_blockstream_tx(tx_hash)
        except Exception as e:
            logger.error(f"Error fetching transaction {tx_hash} from {api}: {e}")
            return {}

    def _get_blockchain_info_tx(self, tx_hash: str) -> Dict:
        """Get transaction from blockchain.info"""
        self._rate_limit('blockchain_info')

        url = f"{self.apis['blockchain_info']}/rawtx/{tx_hash}"
        response = self.session.get(url, timeout=10)
        response.raise_for_status()

        data = response.json()

        return {
            'hash': tx_hash,
            'time': datetime.fromtimestamp(data.get('time', 0)),
            'block_height': data.get('block_height'),
            'size': data.get('size'),
            'fee': data.get('fee', 0) / 1e8,
            'inputs': [{'address': inp.get('prev_out', {}).get('addr'),
                       'value': inp.get('prev_out', {}).get('value', 0) / 1e8,
                       'tx_index': inp.get('prev_out', {}).get('tx_index')}
                      for inp in data.get('inputs', [])],
            'outputs': [{'address': out.get('addr'),
                        'value': out.get('value', 0) / 1e8,
                        'spent': out.get('spent', False)}
                       for out in data.get('out', [])],
            'api_source': 'blockchain_info'
        }

    def _get_blockcypher_tx(self, tx_hash: str) -> Dict:
        """Get transaction from blockcypher"""
        self._rate_limit('blockcypher')

        url = f"{self.apis['blockcypher']}/txs/{tx_hash}"
        response = self.session.get(url, timeout=10)
        response.raise_for_status()

        data = response.json()

        return {
            'hash': tx_hash,
            'time': datetime.fromisoformat(data.get('received', '').replace('Z', '+00:00')) if data.get('received') else None,
            'block_height': data.get('block_height'),
            'confirmations': data.get('confirmations', 0),
            'size': data.get('size'),
            'fee': data.get('fees', 0) / 1e8,
            'inputs': [{'address': inp.get('addresses', [None])[0] if inp.get('addresses') else None,
                       'value': inp.get('output_value', 0) / 1e8}
                      for inp in data.get('inputs', [])],
            'outputs': [{'address': out.get('addresses', [None])[0] if out.get('addresses') else None,
                        'value': out.get('value', 0) / 1e8,
                        'spent': out.get('spent_by') is not None}
                       for out in data.get('outputs', [])],
            'api_source': 'blockcypher'
        }

    def _get_blockstream_tx(self, tx_hash: str) -> Dict:
        """Get transaction from blockstream"""
        self._rate_limit('blockstream')

        url = f"{self.apis['blockstream']}/tx/{tx_hash}"
        response = self.session.get(url, timeout=10)
        response.raise_for_status()

        data = response.json()

        return {
            'hash': tx_hash,
            'time': datetime.fromtimestamp(data.get('status', {}).get('block_time', 0)) if data.get('status', {}).get('block_time') else None,
            'block_height': data.get('status', {}).get('block_height'),
            'confirmed': data.get('status', {}).get('confirmed', False),
            'size': data.get('size'),
            'weight': data.get('weight'),
            'fee': data.get('fee', 0) / 1e8,
            'api_source': 'blockstream'
        }

    def analyze_wallet(self, address: str) -> Dict:
        """Comprehensive wallet analysis"""
        logger.info(f"Analyzing wallet: {address}")

        # Get address info from primary source
        addr_info = self.get_address_info(address)

        analysis = {
            'address': address,
            'balance': addr_info.get('balance', 0),
            'total_received': addr_info.get('total_received', 0),
            'total_sent': addr_info.get('total_sent', 0),
            'tx_count': addr_info.get('tx_count', 0),
            'first_seen': addr_info.get('first_seen'),
            'last_seen': addr_info.get('last_seen'),
            'risk_score': 0,
            'flags': [],
            'patterns': []
        }

        # Analyze transaction patterns
        if addr_info.get('transactions'):
            analysis['patterns'] = self._analyze_tx_patterns(addr_info['transactions'])

        # Calculate risk score
        analysis['risk_score'] = self._calculate_risk_score(analysis)

        return analysis

    def _analyze_tx_patterns(self, transactions: List[Dict]) -> List[str]:
        """Analyze transaction patterns for suspicious behavior"""
        patterns = []

        if not transactions:
            return patterns

        # Check for mixing patterns (many inputs, many outputs)
        for tx in transactions:
            if len(tx.get('inputs', [])) > 10 and len(tx.get('outputs', [])) > 10:
                patterns.append('mixing_service_pattern')
                break

        # Check for peel chain (sequential transactions with decreasing amounts)
        values = [tx.get('balance_change', 0) for tx in transactions if 'balance_change' in tx]
        if len(values) > 5:
            decreasing = all(values[i] >= values[i+1] for i in range(len(values)-1))
            if decreasing:
                patterns.append('peel_chain_pattern')

        # Check for rapid transactions
        times = [tx['time'] for tx in transactions if tx.get('time')]
        if len(times) > 2:
            time_diffs = [(times[i+1] - times[i]).total_seconds() for i in range(len(times)-1)]
            if any(diff < 60 for diff in time_diffs):  # Transactions within 1 minute
                patterns.append('rapid_transaction_pattern')

        return list(set(patterns))

    def _calculate_risk_score(self, analysis: Dict) -> float:
        """Calculate risk score based on wallet analysis"""
        score = 0.0

        # High transaction volume
        if analysis['tx_count'] > 1000:
            score += 2.0
        elif analysis['tx_count'] > 100:
            score += 1.0

        # Pattern-based scoring
        if 'mixing_service_pattern' in analysis['patterns']:
            score += 5.0
        if 'peel_chain_pattern' in analysis['patterns']:
            score += 3.0
        if 'rapid_transaction_pattern' in analysis['patterns']:
            score += 2.0

        # Large balance
        if analysis['balance'] > 100:
            score += 1.0
        elif analysis['balance'] > 1000:
            score += 2.0

        return min(score, 10.0)  # Cap at 10

    def trace_funds(self, address: str, max_hops: int = 5, min_amount: float = 0.01) -> Dict:
        """Trace fund flow from an address"""
        logger.info(f"Tracing funds from {address} for {max_hops} hops")

        visited = set()
        flow_graph = {
            'nodes': [],
            'edges': [],
            'hops': []
        }

        def trace_recursive(addr: str, hop: int, path: List[str]):
            if hop > max_hops or addr in visited:
                return

            visited.add(addr)
            addr_info = self.get_address_info(addr)

            flow_graph['nodes'].append({
                'address': addr,
                'balance': addr_info.get('balance', 0),
                'hop': hop,
                'path': path
            })

            # Process transactions
            for tx in addr_info.get('transactions', [])[:50]:  # Limit to 50 most recent
                for output in tx.get('outputs', []):
                    out_addr = output.get('address')
                    value = output.get('value', 0)

                    if out_addr and out_addr != addr and value >= min_amount:
                        flow_graph['edges'].append({
                            'from': addr,
                            'to': out_addr,
                            'value': value,
                            'tx_hash': tx.get('hash'),
                            'time': tx.get('time')
                        })

                        if hop < max_hops:
                            trace_recursive(out_addr, hop + 1, path + [addr])

        trace_recursive(address, 0, [])

        return flow_graph

    def get_utxos(self, address: str) -> List[Dict]:
        """Get unspent transaction outputs for an address"""
        logger.info(f"Getting UTXOs for {address}")

        try:
            self._rate_limit('blockcypher')
            url = f"{self.apis['blockcypher']}/addrs/{address}?unspentOnly=true"
            response = self.session.get(url, timeout=10)
            response.raise_for_status()

            data = response.json()
            utxos = []

            for tx_ref in data.get('txrefs', []):
                utxos.append({
                    'tx_hash': tx_ref.get('tx_hash'),
                    'output_index': tx_ref.get('tx_output_n'),
                    'value': tx_ref.get('value', 0) / 1e8,
                    'confirmations': tx_ref.get('confirmations', 0),
                    'block_height': tx_ref.get('block_height')
                })

            return utxos
        except Exception as e:
            logger.error(f"Error getting UTXOs: {e}")
            return []

    def cluster_addresses(self, seed_address: str, depth: int = 2) -> Set[str]:
        """Cluster related addresses using common input heuristic"""
        logger.info(f"Clustering addresses from {seed_address}")

        cluster = set([seed_address])
        to_process = [seed_address]
        processed = set()

        for _ in range(depth):
            if not to_process:
                break

            current_batch = to_process[:10]  # Process in batches
            to_process = to_process[10:]

            for addr in current_batch:
                if addr in processed:
                    continue

                processed.add(addr)
                addr_info = self.get_address_info(addr)

                # Find addresses that appear together in transaction inputs
                for tx in addr_info.get('transactions', [])[:20]:
                    input_addrs = [inp.get('address') for inp in tx.get('inputs', [])
                                  if inp.get('address')]

                    if len(input_addrs) > 1 and addr in input_addrs:
                        for inp_addr in input_addrs:
                            if inp_addr not in cluster:
                                cluster.add(inp_addr)
                                to_process.append(inp_addr)

        return cluster
