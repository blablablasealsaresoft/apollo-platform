"""
OneCoin Specific Tracker
Track OneCoin-related blockchain activity and criminal network mapping
"""

import logging
from typing import Dict, List, Set, Optional
from datetime import datetime, timedelta
from collections import defaultdict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class OneCoinTracker:
    """
    Specialized tracker for OneCoin fraud investigation
    Tracks known OneCoin wallets, fund distribution, and victim payments
    """

    def __init__(self, bitcoin_tracker=None, ethereum_tracker=None, multi_chain_tracker=None):
        self.bitcoin_tracker = bitcoin_tracker
        self.ethereum_tracker = ethereum_tracker
        self.multi_chain_tracker = multi_chain_tracker

        # Known OneCoin-related wallets (examples - would need real data)
        self.onecoin_wallets = {
            'btc': {
                'main_wallets': [
                    # Known primary OneCoin BTC wallets
                    '1OneCoin...example1',
                    'bc1q...onecoin2',
                    '3OneCoin...example3'
                ],
                'distribution_wallets': [
                    # Wallets used for distributing funds
                ],
                'cashout_wallets': [
                    # Wallets used for cashing out
                ]
            },
            'eth': {
                'main_wallets': [
                    # Known OneCoin ETH wallets
                    '0x...onecoin1',
                    '0x...onecoin2'
                ],
                'token_contracts': [
                    # OneCoin-related token contracts
                ]
            }
        }

        # Known OneCoin operators and associates
        self.known_operators = {
            'ruja_ignatova': {
                'name': 'Ruja Ignatova',
                'role': 'Founder',
                'status': 'Fugitive (FBI Most Wanted)',
                'known_wallets': [],
                'aliases': ['Cryptoqueen']
            },
            'konstantin_ignatov': {
                'name': 'Konstantin Ignatov',
                'role': 'Co-founder',
                'status': 'Arrested 2019',
                'known_wallets': []
            },
            'sebastian_greenwood': {
                'name': 'Sebastian Greenwood',
                'role': 'Co-founder',
                'status': 'Arrested 2018',
                'known_wallets': []
            },
            'mark_scott': {
                'name': 'Mark Scott',
                'role': 'Lawyer (Money Laundering)',
                'status': 'Convicted 2019',
                'known_wallets': []
            }
        }

        # Victim payment patterns
        self.victim_patterns = {
            'small_payments': [],  # <$1000
            'medium_payments': [], # $1000-$10000
            'large_payments': []   # >$10000
        }

        # Criminal network connections
        self.network_graph = {
            'nodes': [],
            'edges': [],
            'clusters': {}
        }

    def identify_onecoin_wallet(self, address: str, blockchain: str = 'bitcoin') -> Optional[Dict]:
        """Identify if a wallet is associated with OneCoin"""
        address_lower = address.lower()

        if blockchain == 'bitcoin':
            wallet_lists = self.onecoin_wallets['btc']
        elif blockchain == 'ethereum':
            wallet_lists = self.onecoin_wallets['eth']
        else:
            return None

        # Check each category
        for category, wallets in wallet_lists.items():
            if any(address_lower in w.lower() for w in wallets):
                return {
                    'is_onecoin': True,
                    'category': category,
                    'blockchain': blockchain,
                    'confidence': 1.0
                }

        return None

    def track_onecoin_funds(self, seed_address: str, blockchain: str = 'bitcoin',
                           max_hops: int = 10) -> Dict:
        """
        Track OneCoin fund flow from a known wallet

        This traces where OneCoin funds went - victims, exchanges, other wallets
        """
        logger.info(f"Tracking OneCoin funds from {seed_address}")

        tracking = {
            'seed_address': seed_address,
            'blockchain': blockchain,
            'fund_flows': [],
            'victim_addresses': [],
            'exchange_deposits': [],
            'mixing_service_usage': [],
            'total_amount_tracked': 0,
            'unique_recipients': set(),
            'suspicious_patterns': []
        }

        # Use appropriate tracker
        if blockchain == 'bitcoin' and self.bitcoin_tracker:
            flow = self.bitcoin_tracker.trace_funds(seed_address, max_hops=max_hops)

            for edge in flow.get('edges', []):
                tracking['fund_flows'].append({
                    'from': edge.get('from'),
                    'to': edge.get('to'),
                    'amount': edge.get('value'),
                    'tx_hash': edge.get('tx_hash'),
                    'time': edge.get('time')
                })

                tracking['unique_recipients'].add(edge.get('to'))
                tracking['total_amount_tracked'] += edge.get('value', 0)

        elif blockchain == 'ethereum' and self.ethereum_tracker:
            # Similar tracking for Ethereum
            pass

        tracking['unique_recipients'] = len(tracking['unique_recipients'])

        # Analyze patterns
        tracking['analysis'] = self._analyze_onecoin_patterns(tracking)

        return tracking

    def _analyze_onecoin_patterns(self, tracking: Dict) -> Dict:
        """Analyze patterns specific to OneCoin fraud"""
        analysis = {
            'fraud_indicators': [],
            'victim_count_estimate': 0,
            'total_fraud_amount': tracking.get('total_amount_tracked', 0),
            'risk_score': 10.0  # OneCoin is confirmed fraud, max risk
        }

        # Pattern 1: Many small outgoing payments (victims)
        small_payments = [f for f in tracking['fund_flows']
                         if 0.01 <= f.get('amount', 0) <= 1.0]

        if len(small_payments) > 10:
            analysis['fraud_indicators'].append('multiple_victim_payments')
            analysis['victim_count_estimate'] = len(small_payments)

        # Pattern 2: Large consolidation transactions
        large_payments = [f for f in tracking['fund_flows']
                         if f.get('amount', 0) > 10.0]

        if large_payments:
            analysis['fraud_indicators'].append('large_consolidation_detected')

        # Pattern 3: Rapid fund movement
        if tracking['fund_flows']:
            times = [f.get('time') for f in tracking['fund_flows'] if f.get('time')]
            if times and len(times) > 1:
                time_diffs = [(times[i+1] - times[i]).total_seconds()
                             for i in range(len(times)-1)]
                if any(diff < 3600 for diff in time_diffs):  # Less than 1 hour
                    analysis['fraud_indicators'].append('rapid_fund_movement')

        return analysis

    def map_criminal_network(self, seed_addresses: List[str]) -> Dict:
        """
        Map the criminal network associated with OneCoin

        Args:
            seed_addresses: List of known OneCoin addresses to start from
        """
        logger.info(f"Mapping OneCoin criminal network from {len(seed_addresses)} seed addresses")

        network = {
            'seed_addresses': seed_addresses,
            'entities': [],
            'connections': [],
            'clusters': {},
            'total_wallets': 0,
            'total_transactions': 0,
            'estimated_total_fraud': 0
        }

        # Track all related addresses
        all_addresses = set(seed_addresses)
        processed = set()

        for seed_addr in seed_addresses:
            if seed_addr in processed:
                continue

            # Get related addresses
            if self.bitcoin_tracker:
                cluster = self.bitcoin_tracker.cluster_addresses(seed_addr, depth=2)
                all_addresses.update(cluster)

        # Map entities
        for addr in all_addresses:
            entity = {
                'address': addr,
                'type': 'wallet',
                'is_onecoin': bool(self.identify_onecoin_wallet(addr)),
                'connections': []
            }

            network['entities'].append(entity)

        network['total_wallets'] = len(all_addresses)

        # Analyze the network
        network['analysis'] = self._analyze_network_structure(network)

        return network

    def _analyze_network_structure(self, network: Dict) -> Dict:
        """Analyze the structure of the criminal network"""
        analysis = {
            'network_size': network['total_wallets'],
            'central_nodes': [],
            'peripheral_nodes': [],
            'network_density': 0.0,
            'money_laundering_indicators': []
        }

        # Identify central nodes (high connectivity)
        entity_connections = defaultdict(int)

        for connection in network.get('connections', []):
            entity_connections[connection.get('from')] += 1
            entity_connections[connection.get('to')] += 1

        # Top 10 most connected
        sorted_entities = sorted(entity_connections.items(),
                                key=lambda x: x[1], reverse=True)

        analysis['central_nodes'] = [
            {'address': addr, 'connections': count}
            for addr, count in sorted_entities[:10]
        ]

        return analysis

    def identify_victim_payments(self, onecoin_address: str, blockchain: str = 'bitcoin') -> List[Dict]:
        """
        Identify likely victim payments from a OneCoin wallet

        Victims typically received small amounts as "returns" on their investment
        """
        logger.info(f"Identifying victim payments from {onecoin_address}")

        victims = []

        if blockchain == 'bitcoin' and self.bitcoin_tracker:
            addr_info = self.bitcoin_tracker.get_address_info(onecoin_address)

            for tx in addr_info.get('transactions', []):
                # Look for outgoing transactions
                for output in tx.get('outputs', []):
                    recipient = output.get('address')
                    amount = output.get('value', 0)

                    # Victim payment patterns:
                    # 1. Small amounts (0.01 - 5.0 BTC)
                    # 2. Round numbers (psychological effect)
                    # 3. Multiple payments to same address

                    if 0.01 <= amount <= 5.0 and recipient != onecoin_address:
                        victims.append({
                            'victim_address': recipient,
                            'amount': amount,
                            'tx_hash': tx.get('hash'),
                            'time': tx.get('time'),
                            'payment_type': self._classify_payment_amount(amount)
                        })

        # Group by recipient
        victim_summary = defaultdict(list)
        for victim in victims:
            victim_summary[victim['victim_address']].append(victim)

        # Create summary
        victim_list = []
        for addr, payments in victim_summary.items():
            total_received = sum(p['amount'] for p in payments)
            victim_list.append({
                'address': addr,
                'total_received': total_received,
                'payment_count': len(payments),
                'first_payment': min(p['time'] for p in payments if p.get('time')),
                'last_payment': max(p['time'] for p in payments if p.get('time')),
                'payments': payments
            })

        return victim_list

    def _classify_payment_amount(self, amount: float) -> str:
        """Classify victim payment by amount"""
        if amount < 0.1:
            return 'micro'
        elif amount < 1.0:
            return 'small'
        elif amount < 5.0:
            return 'medium'
        else:
            return 'large'

    def track_cashout_operations(self, addresses: List[str]) -> Dict:
        """
        Track how OneCoin operators cashed out funds

        Looks for:
        - Exchange deposits
        - P2P sales
        - Mixing services
        - Overseas transfers
        """
        logger.info(f"Tracking cashout operations for {len(addresses)} addresses")

        cashout = {
            'addresses_analyzed': len(addresses),
            'exchange_deposits': [],
            'mixer_usage': [],
            'p2p_transactions': [],
            'total_cashed_out': 0,
            'cashout_methods': defaultdict(float)
        }

        for address in addresses:
            if self.bitcoin_tracker:
                addr_info = self.bitcoin_tracker.get_address_info(address)

                for tx in addr_info.get('transactions', []):
                    # Check for exchange deposits
                    for output in tx.get('outputs', []):
                        to_addr = output.get('address')
                        amount = output.get('value', 0)

                        # This would check against known exchange addresses
                        # For now, simplified detection

                        if self._is_likely_exchange(to_addr):
                            cashout['exchange_deposits'].append({
                                'from': address,
                                'to': to_addr,
                                'amount': amount,
                                'tx_hash': tx.get('hash'),
                                'time': tx.get('time')
                            })

                            cashout['total_cashed_out'] += amount
                            cashout['cashout_methods']['exchange'] += amount

        return cashout

    def _is_likely_exchange(self, address: str) -> bool:
        """Heuristic to detect exchange addresses"""
        # Simplified - would use actual exchange wallet database
        # Exchanges often have addresses starting with specific patterns
        # or have very high transaction counts

        return False  # Placeholder

    def generate_investigation_report(self, case_data: Dict) -> str:
        """Generate comprehensive investigation report"""
        report = []
        report.append("=" * 80)
        report.append("ONECOIN FRAUD INVESTIGATION REPORT")
        report.append("=" * 80)
        report.append(f"\nGenerated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Case ID: {case_data.get('case_id', 'N/A')}")

        # Executive Summary
        report.append("\n--- EXECUTIVE SUMMARY ---")
        report.append("OneCoin was a fraudulent cryptocurrency scheme that defrauded")
        report.append("investors of billions of dollars worldwide between 2014-2017.")
        report.append("\nKey Figures:")
        report.append("  - Estimated Total Fraud: $4+ Billion USD")
        report.append("  - Victims: 3+ Million worldwide")
        report.append("  - Main Perpetrator: Ruja Ignatova (Fugitive - FBI Most Wanted)")

        # Wallet Analysis
        if 'wallets_tracked' in case_data:
            report.append("\n--- WALLET ANALYSIS ---")
            report.append(f"Wallets Tracked: {case_data['wallets_tracked']}")
            report.append(f"Total Transactions: {case_data.get('total_transactions', 0)}")
            report.append(f"Total Amount Traced: {case_data.get('total_amount', 0):.8f} BTC")

        # Victim Analysis
        if 'victims' in case_data:
            report.append("\n--- VICTIM ANALYSIS ---")
            victims = case_data['victims']
            report.append(f"Identified Victim Addresses: {len(victims)}")

            total_victim_funds = sum(v.get('total_received', 0) for v in victims)
            report.append(f"Total Paid to Victims: {total_victim_funds:.8f} BTC")
            report.append("\nTop 10 Victim Payments:")

            sorted_victims = sorted(victims, key=lambda x: x.get('total_received', 0), reverse=True)
            for i, victim in enumerate(sorted_victims[:10], 1):
                report.append(f"  {i}. {victim['address'][:16]}... - {victim['total_received']:.8f} BTC")

        # Criminal Network
        if 'network' in case_data:
            report.append("\n--- CRIMINAL NETWORK ---")
            network = case_data['network']
            report.append(f"Network Size: {network.get('total_wallets', 0)} wallets")
            report.append(f"Total Connections: {network.get('total_transactions', 0)}")

        # Cashout Analysis
        if 'cashout' in case_data:
            report.append("\n--- CASHOUT ANALYSIS ---")
            cashout = case_data['cashout']
            report.append(f"Exchange Deposits: {len(cashout.get('exchange_deposits', []))}")
            report.append(f"Total Cashed Out: {cashout.get('total_cashed_out', 0):.8f} BTC")

            if cashout.get('cashout_methods'):
                report.append("\nCashout Methods:")
                for method, amount in cashout['cashout_methods'].items():
                    report.append(f"  - {method.capitalize()}: {amount:.8f} BTC")

        # Recommendations
        report.append("\n--- RECOMMENDATIONS ---")
        report.append("1. Continue monitoring identified wallet addresses for activity")
        report.append("2. Coordinate with law enforcement agencies internationally")
        report.append("3. Track exchange deposits for potential asset recovery")
        report.append("4. Monitor for new wallet clusters linked to known addresses")
        report.append("5. Share intelligence with other victims and investigators")

        # References
        report.append("\n--- REFERENCES ---")
        report.append("- FBI Most Wanted: Ruja Ignatova")
        report.append("- DOJ Press Releases: OneCoin prosecutions")
        report.append("- BBC Podcast: 'The Missing Cryptoqueen'")

        report.append("\n" + "=" * 80)

        return "\n".join(report)

    def get_known_operators(self) -> List[Dict]:
        """Get list of known OneCoin operators"""
        return [
            {
                'id': op_id,
                **op_data
            }
            for op_id, op_data in self.known_operators.items()
        ]

    def estimate_total_fraud(self) -> Dict:
        """Estimate total fraud amount"""
        return {
            'estimated_total_usd': 4000000000,  # $4 billion
            'estimated_btc': 0,  # Would calculate based on tracked wallets
            'victims_worldwide': 3000000,  # 3+ million
            'countries_affected': 175,
            'time_period': '2014-2017',
            'status': 'Ongoing investigation',
            'notes': 'OneCoin never had a real blockchain'
        }
