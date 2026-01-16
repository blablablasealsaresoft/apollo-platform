"""
Exchange Monitor - Track deposits/withdrawals to major exchanges
Monitor 50+ cryptocurrency exchanges
"""

import logging
from typing import Dict, List, Set, Optional
from datetime import datetime, timedelta
from collections import defaultdict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ExchangeMonitor:
    """Monitor cryptocurrency exchange wallets and activity"""

    def __init__(self, bitcoin_tracker=None, ethereum_tracker=None, multi_chain_tracker=None):
        self.bitcoin_tracker = bitcoin_tracker
        self.ethereum_tracker = ethereum_tracker
        self.multi_chain_tracker = multi_chain_tracker

        # Known exchange wallet addresses (examples - in production would have real addresses)
        self.exchange_wallets = {
            'binance': {
                'name': 'Binance',
                'btc_wallets': [
                    'bc1qm34lsc65zpw79lxes69zkqmk6ee3ewf0j77s3h',
                    '1NDyJtNTjmwk5xPNhjgAMu4HDHigtobu1s',
                    '34xp4vRoCGJym3xR7yCVPFHoCNxv4Twseo'
                ],
                'eth_wallets': [
                    '0x28C6c06298d514Db089934071355E5743bf21d60',
                    '0x21a31Ee1afC51d94C2eFcCAa2092aD1028285549',
                    '0xDFd5293D8e347dFe59E90eFd55b2956a1343963d'
                ],
                'deposit_patterns': ['many_inputs', 'consolidation'],
                'withdrawal_patterns': ['peeling']
            },
            'coinbase': {
                'name': 'Coinbase',
                'btc_wallets': [
                    'bc1qgdjqv0av3q56jvd82tkdjpy7gdp9ut8tlqmgrpmv24sq90ecnvqqjwvw97',
                    '3Nxwenay9Z8Lc9JBiywExpnEFiLp6Afp8v',
                    '1PoSMiB3wgvS8h8g5tCb6F7KX9PfPPvvnb'
                ],
                'eth_wallets': [
                    '0x71660c4005BA85c37ccec55d0C4493E66Fe775d3',
                    '0x503828976D22510aad0201ac7EC88293211D23Da',
                    '0xddfAbCdc4D8FfC6d5beaf154f18B778f892A0740'
                ],
                'deposit_patterns': ['consolidation'],
                'withdrawal_patterns': ['batched']
            },
            'kraken': {
                'name': 'Kraken',
                'btc_wallets': [
                    'bc1qjasf9z3h7w3jpdnqzwm35yya6gjc3zdjtx6wg8',
                    '3QzYvaRFY6bakFBW4YBRrzmwzTnfZcaA6E',
                    '1Kr6QSydW9bFQG1mXiPNNu6WpJGmUa9i1g'
                ],
                'eth_wallets': [
                    '0x2910543Af39abA0Cd09dBb2D50200b3E800A63D2',
                    '0x0A869d79a7052C7f1b55a8EbAbbEa3420F0D1E13',
                    '0x267be1C1D684F78cb4F6a176C4911b741E4Ffdc0'
                ],
                'deposit_patterns': ['consolidation'],
                'withdrawal_patterns': ['batched']
            },
            'huobi': {
                'name': 'Huobi',
                'btc_wallets': [
                    'bc1qjh0akslml59uuczddqu0y4p7c2j7j98ae2vfll',
                    '3PH1nwWmvqmT5PCqFmkc5aKLoYPkJy5Cke',
                    '1HuobiNj4w1A2rqqWZfgzK4fFyT3PwB2L9'
                ],
                'eth_wallets': [
                    '0x5C985E89DDe482eFE97ea9f1950aD149Eb73829B',
                    '0xAB5C66752a9e8167967685F1450532fB96d5d24f',
                    '0x6748F50f686bfbcA6Fe8ad62b22228b87F31ff2b'
                ],
                'deposit_patterns': ['consolidation'],
                'withdrawal_patterns': ['batched']
            },
            'okx': {
                'name': 'OKX (OKEx)',
                'btc_wallets': [
                    'bc1qjdhtlqq5p40j9hvgfk2y4e0wj8xt5k6wzvuyyy',
                    '3M219KR5vEneNb47ewrPfWyb5jQ2DjxRP6',
                    '1OKEx...example'
                ],
                'eth_wallets': [
                    '0x236B6d0ebFF8C5FcA03C4e4a706D33466BF3D3f4',
                    '0x98EC059Dc3aDFBdd63429454aEB0c990FBA4A128',
                    '0x59FaE149a8F8D89fFc7e0b71C0fD3D4C8C5C1c65'
                ],
                'deposit_patterns': ['consolidation'],
                'withdrawal_patterns': ['peeling']
            },
            'gate_io': {
                'name': 'Gate.io',
                'btc_wallets': [],
                'eth_wallets': [
                    '0x1C4b70a3968436B9A0a9cf5205c787eb81Bb558c',
                    '0x0D0707963952f2fBA59dD06f2b425ace40b492Fe'
                ],
                'deposit_patterns': ['consolidation'],
                'withdrawal_patterns': ['batched']
            },
            'bybit': {
                'name': 'Bybit',
                'btc_wallets': [],
                'eth_wallets': [
                    '0xF89d7b9c864f589bbF53a82105107622B35EaA40',
                    '0x1Db92e2EeBC8E0c075a02BeA49a2935BcD2dFCAb'
                ],
                'deposit_patterns': ['consolidation'],
                'withdrawal_patterns': ['batched']
            },
            'bitfinex': {
                'name': 'Bitfinex',
                'btc_wallets': [
                    'bc1qgdjqv0av3q56jvd82tkdjpy7gdp9ut8tlqmgrpmv24sq90ecnvqqjwvw97',
                    '3D2oetdNuZUqQHPJmcMDDHYoqkyNVsFk9r'
                ],
                'eth_wallets': [
                    '0x77134cbC06cB00b66F4c7e623D5fdBF6777635EC',
                    '0x1151314c646Ce4E0eFD76d1aF4760aE66a9Fe30F'
                ],
                'deposit_patterns': ['consolidation'],
                'withdrawal_patterns': ['batched']
            },
            'kucoin': {
                'name': 'KuCoin',
                'btc_wallets': [],
                'eth_wallets': [
                    '0x2B5634C42055806a59e9107ED44D43c426E58258',
                    '0xcAD621da75a66c7A8f4FF86D30A2bF981Bfc8FdD'
                ],
                'deposit_patterns': ['consolidation'],
                'withdrawal_patterns': ['batched']
            },
            'gemini': {
                'name': 'Gemini',
                'btc_wallets': [
                    'bc1qrwqgm4e842heua3s2n2692a66hdlcgfpuq2c0u'
                ],
                'eth_wallets': [
                    '0xd24400ae8BfEBb18cA49Be86258a3C749cf46853',
                    '0x5f65f7b609678448494De4C87521CdF6cEf1e932'
                ],
                'deposit_patterns': ['consolidation'],
                'withdrawal_patterns': ['batched']
            },
            'bitstamp': {
                'name': 'Bitstamp',
                'btc_wallets': [
                    '34xp4vRoCGJym3xR7yCVPFHoCNxv4Twseo'
                ],
                'eth_wallets': [
                    '0x1522900b6dafaC587D499A862861C0869BE6e428',
                    '0x9a755332D874c893111207b0b220Ce8d71E93928'
                ],
                'deposit_patterns': ['consolidation'],
                'withdrawal_patterns': ['batched']
            }
        }

        # Additional exchanges (names only, would need wallet addresses)
        self.additional_exchanges = [
            'Bittrex', 'Poloniex', 'Crypto.com', 'FTX (defunct)', 'Bithumb',
            'Upbit', 'Coincheck', 'Bitflyer', 'Liquid', 'Bitso',
            'Mercado Bitcoin', 'Luno', 'Paxful', 'LocalBitcoins', 'Bisq',
            'Uniswap', 'SushiSwap', 'PancakeSwap', 'Curve', '1inch',
            'dYdX', 'GMX', 'Balancer', 'Bancor', 'Kyber Network',
            'Loopring', 'ZKSwap', 'Matcha', 'Paraswap', 'Zerion',
            'Voyager (defunct)', 'Celsius (defunct)', 'BlockFi (defunct)',
            'Nexo', 'Wirex', 'Binance.US', 'Coinbase Pro', 'Kraken Pro',
            'OKCoin', 'Bitpanda', 'Bitvavo', 'BTC Markets', 'CoinSpot',
            'Independent Reserve', 'CoinJar', 'Swyftx', 'Digital Surge'
        ]

        self.monitoring_cache = {}

    def identify_exchange(self, address: str, blockchain: str = 'bitcoin') -> Optional[Dict]:
        """Identify if an address belongs to a known exchange"""
        address_lower = address.lower()

        for exchange_id, exchange_data in self.exchange_wallets.items():
            wallets = []

            if blockchain == 'bitcoin':
                wallets = [w.lower() for w in exchange_data.get('btc_wallets', [])]
            elif blockchain == 'ethereum':
                wallets = [w.lower() for w in exchange_data.get('eth_wallets', [])]

            if address_lower in wallets:
                return {
                    'exchange_id': exchange_id,
                    'exchange_name': exchange_data['name'],
                    'blockchain': blockchain,
                    'confidence': 1.0
                }

        # Partial match based on patterns (lower confidence)
        # This is a simplified heuristic
        return None

    def detect_deposit(self, transaction: Dict, blockchain: str = 'bitcoin') -> Optional[Dict]:
        """Detect if a transaction is a deposit to an exchange"""
        deposit_info = None

        if blockchain == 'bitcoin':
            for output in transaction.get('outputs', []):
                to_addr = output.get('address')
                exchange = self.identify_exchange(to_addr, 'bitcoin')

                if exchange:
                    deposit_info = {
                        'type': 'deposit',
                        'exchange': exchange['exchange_name'],
                        'amount': output.get('value', 0),
                        'address': to_addr,
                        'tx_hash': transaction.get('hash'),
                        'time': transaction.get('time')
                    }
                    break

        elif blockchain == 'ethereum':
            to_addr = transaction.get('to')
            exchange = self.identify_exchange(to_addr, 'ethereum')

            if exchange:
                deposit_info = {
                    'type': 'deposit',
                    'exchange': exchange['exchange_name'],
                    'amount': transaction.get('value', 0),
                    'address': to_addr,
                    'tx_hash': transaction.get('hash'),
                    'time': transaction.get('time')
                }

        return deposit_info

    def detect_withdrawal(self, transaction: Dict, blockchain: str = 'bitcoin') -> Optional[Dict]:
        """Detect if a transaction is a withdrawal from an exchange"""
        withdrawal_info = None

        if blockchain == 'bitcoin':
            for inp in transaction.get('inputs', []):
                from_addr = inp.get('address')
                exchange = self.identify_exchange(from_addr, 'bitcoin')

                if exchange:
                    withdrawal_info = {
                        'type': 'withdrawal',
                        'exchange': exchange['exchange_name'],
                        'amount': sum(out.get('value', 0) for out in transaction.get('outputs', [])),
                        'address': from_addr,
                        'tx_hash': transaction.get('hash'),
                        'time': transaction.get('time')
                    }
                    break

        elif blockchain == 'ethereum':
            from_addr = transaction.get('from')
            exchange = self.identify_exchange(from_addr, 'ethereum')

            if exchange:
                withdrawal_info = {
                    'type': 'withdrawal',
                    'exchange': exchange['exchange_name'],
                    'amount': transaction.get('value', 0),
                    'address': from_addr,
                    'tx_hash': transaction.get('hash'),
                    'time': transaction.get('time')
                }

        return withdrawal_info

    def track_exchange_activity(self, address: str, blockchain: str = 'bitcoin') -> Dict:
        """Track all exchange interactions for an address"""
        logger.info(f"Tracking exchange activity for {address} on {blockchain}")

        activity = {
            'address': address,
            'blockchain': blockchain,
            'deposits': [],
            'withdrawals': [],
            'exchanges_used': set(),
            'total_deposited': 0,
            'total_withdrawn': 0,
            'first_exchange_interaction': None,
            'last_exchange_interaction': None
        }

        # Get transaction history
        transactions = []
        if blockchain == 'bitcoin' and self.bitcoin_tracker:
            addr_info = self.bitcoin_tracker.get_address_info(address)
            transactions = addr_info.get('transactions', [])
        elif blockchain == 'ethereum' and self.ethereum_tracker:
            addr_info = self.ethereum_tracker.get_address_info(address)
            transactions = addr_info.get('transactions', [])

        # Analyze each transaction
        for tx in transactions:
            # Check for deposit
            deposit = self.detect_deposit(tx, blockchain)
            if deposit:
                activity['deposits'].append(deposit)
                activity['exchanges_used'].add(deposit['exchange'])
                activity['total_deposited'] += deposit['amount']

                if not activity['first_exchange_interaction'] or deposit['time'] < activity['first_exchange_interaction']:
                    activity['first_exchange_interaction'] = deposit['time']
                if not activity['last_exchange_interaction'] or deposit['time'] > activity['last_exchange_interaction']:
                    activity['last_exchange_interaction'] = deposit['time']

            # Check for withdrawal
            withdrawal = self.detect_withdrawal(tx, blockchain)
            if withdrawal:
                activity['withdrawals'].append(withdrawal)
                activity['exchanges_used'].add(withdrawal['exchange'])
                activity['total_withdrawn'] += withdrawal['amount']

                if not activity['first_exchange_interaction'] or withdrawal['time'] < activity['first_exchange_interaction']:
                    activity['first_exchange_interaction'] = withdrawal['time']
                if not activity['last_exchange_interaction'] or withdrawal['time'] > activity['last_exchange_interaction']:
                    activity['last_exchange_interaction'] = withdrawal['time']

        activity['exchanges_used'] = list(activity['exchanges_used'])
        activity['exchange_count'] = len(activity['exchanges_used'])

        return activity

    def monitor_exchange_wallet(self, exchange_id: str, blockchain: str = 'bitcoin',
                               hours: int = 24) -> Dict:
        """Monitor recent activity on exchange wallets"""
        logger.info(f"Monitoring {exchange_id} {blockchain} wallets for last {hours} hours")

        if exchange_id not in self.exchange_wallets:
            return {'error': f'Unknown exchange: {exchange_id}'}

        exchange_data = self.exchange_wallets[exchange_id]
        wallets = exchange_data.get('btc_wallets' if blockchain == 'bitcoin' else 'eth_wallets', [])

        activity = {
            'exchange': exchange_data['name'],
            'blockchain': blockchain,
            'wallets_monitored': len(wallets),
            'time_window_hours': hours,
            'deposits': [],
            'withdrawals': [],
            'total_deposit_volume': 0,
            'total_withdrawal_volume': 0,
            'unique_addresses': set()
        }

        cutoff_time = datetime.now() - timedelta(hours=hours)

        for wallet in wallets[:5]:  # Limit to first 5 wallets for performance
            try:
                transactions = []

                if blockchain == 'bitcoin' and self.bitcoin_tracker:
                    addr_info = self.bitcoin_tracker.get_address_info(wallet)
                    transactions = addr_info.get('transactions', [])
                elif blockchain == 'ethereum' and self.ethereum_tracker:
                    addr_info = self.ethereum_tracker.get_address_info(wallet)
                    transactions = addr_info.get('transactions', [])

                # Filter by time window
                for tx in transactions:
                    tx_time = tx.get('time')
                    if not tx_time or tx_time < cutoff_time:
                        continue

                    # Detect deposits
                    deposit = self.detect_deposit(tx, blockchain)
                    if deposit:
                        activity['deposits'].append(deposit)
                        activity['total_deposit_volume'] += deposit['amount']
                        if 'from' in tx:
                            activity['unique_addresses'].add(tx['from'])

                    # Detect withdrawals
                    withdrawal = self.detect_withdrawal(tx, blockchain)
                    if withdrawal:
                        activity['withdrawals'].append(withdrawal)
                        activity['total_withdrawal_volume'] += withdrawal['amount']
                        if 'to' in tx:
                            activity['unique_addresses'].add(tx['to'])

            except Exception as e:
                logger.error(f"Error monitoring wallet {wallet}: {e}")

        activity['unique_addresses'] = len(activity['unique_addresses'])
        activity['deposit_count'] = len(activity['deposits'])
        activity['withdrawal_count'] = len(activity['withdrawals'])

        return activity

    def cluster_exchange_wallets(self, exchange_id: str) -> Dict:
        """Cluster all known wallets for an exchange"""
        if exchange_id not in self.exchange_wallets:
            return {'error': f'Unknown exchange: {exchange_id}'}

        exchange_data = self.exchange_wallets[exchange_id]

        cluster = {
            'exchange': exchange_data['name'],
            'btc_wallets': exchange_data.get('btc_wallets', []),
            'eth_wallets': exchange_data.get('eth_wallets', []),
            'total_wallets': len(exchange_data.get('btc_wallets', [])) + len(exchange_data.get('eth_wallets', [])),
            'deposit_patterns': exchange_data.get('deposit_patterns', []),
            'withdrawal_patterns': exchange_data.get('withdrawal_patterns', [])
        }

        return cluster

    def detect_exchange_hopping(self, address: str, blockchain: str = 'bitcoin') -> Dict:
        """Detect if an address is hopping between exchanges"""
        activity = self.track_exchange_activity(address, blockchain)

        analysis = {
            'address': address,
            'is_exchange_hopping': False,
            'hop_count': 0,
            'hop_sequence': [],
            'risk_score': 0.0
        }

        if activity['exchange_count'] > 1:
            # Sort by time
            all_interactions = activity['deposits'] + activity['withdrawals']
            sorted_interactions = sorted(all_interactions, key=lambda x: x.get('time', datetime.now()))

            # Track exchange sequence
            prev_exchange = None
            for interaction in sorted_interactions:
                current_exchange = interaction['exchange']

                if prev_exchange and prev_exchange != current_exchange:
                    analysis['hop_count'] += 1
                    analysis['hop_sequence'].append({
                        'from': prev_exchange,
                        'to': current_exchange,
                        'time': interaction['time']
                    })

                prev_exchange = current_exchange

        if analysis['hop_count'] >= 2:
            analysis['is_exchange_hopping'] = True
            analysis['risk_score'] = min(analysis['hop_count'] * 2.0, 10.0)

        return analysis

    def get_all_exchanges(self) -> List[Dict]:
        """Get list of all monitored exchanges"""
        exchanges = []

        for exchange_id, data in self.exchange_wallets.items():
            exchanges.append({
                'id': exchange_id,
                'name': data['name'],
                'btc_wallet_count': len(data.get('btc_wallets', [])),
                'eth_wallet_count': len(data.get('eth_wallets', []))
            })

        # Add additional exchanges
        for exchange_name in self.additional_exchanges:
            exchanges.append({
                'id': exchange_name.lower().replace(' ', '_'),
                'name': exchange_name,
                'btc_wallet_count': 0,
                'eth_wallet_count': 0,
                'status': 'monitored_name_only'
            })

        return exchanges

    def generate_exchange_report(self, exchange_id: str, hours: int = 24) -> str:
        """Generate human-readable report for exchange activity"""
        btc_activity = self.monitor_exchange_wallet(exchange_id, 'bitcoin', hours)
        eth_activity = self.monitor_exchange_wallet(exchange_id, 'ethereum', hours)

        report = []
        report.append("=" * 80)
        report.append(f"EXCHANGE ACTIVITY REPORT: {exchange_id.upper()}")
        report.append("=" * 80)
        report.append(f"Time Window: Last {hours} hours")
        report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        # Bitcoin activity
        report.append("\n--- BITCOIN NETWORK ---")
        report.append(f"Wallets Monitored: {btc_activity.get('wallets_monitored', 0)}")
        report.append(f"Deposits: {btc_activity.get('deposit_count', 0)}")
        report.append(f"Withdrawals: {btc_activity.get('withdrawal_count', 0)}")
        report.append(f"Total Deposit Volume: {btc_activity.get('total_deposit_volume', 0):.8f} BTC")
        report.append(f"Total Withdrawal Volume: {btc_activity.get('total_withdrawal_volume', 0):.8f} BTC")
        report.append(f"Unique Addresses: {btc_activity.get('unique_addresses', 0)}")

        # Ethereum activity
        report.append("\n--- ETHEREUM NETWORK ---")
        report.append(f"Wallets Monitored: {eth_activity.get('wallets_monitored', 0)}")
        report.append(f"Deposits: {eth_activity.get('deposit_count', 0)}")
        report.append(f"Withdrawals: {eth_activity.get('withdrawal_count', 0)}")
        report.append(f"Total Deposit Volume: {eth_activity.get('total_deposit_volume', 0):.8f} ETH")
        report.append(f"Total Withdrawal Volume: {eth_activity.get('total_withdrawal_volume', 0):.8f} ETH")
        report.append(f"Unique Addresses: {eth_activity.get('unique_addresses', 0)}")

        report.append("\n" + "=" * 80)

        return "\n".join(report)
