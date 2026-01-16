"""
Transaction Tracer - Multi-hop Fund Flow Analysis
Advanced transaction tracing with mixing service detection
"""

import logging
from typing import Dict, List, Set, Optional, Tuple
from datetime import datetime, timedelta
from collections import defaultdict, deque
import json

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class TransactionTracer:
    """Advanced multi-hop transaction tracer with flow visualization"""

    def __init__(self, bitcoin_tracker=None, ethereum_tracker=None, multi_chain_tracker=None):
        self.bitcoin_tracker = bitcoin_tracker
        self.ethereum_tracker = ethereum_tracker
        self.multi_chain_tracker = multi_chain_tracker

        # Known mixing services and exchanges
        self.mixing_services = {
            # Bitcoin mixers
            'bc1q...mixer1': 'Wasabi Wallet',
            'bc1q...mixer2': 'Samourai Whirlpool',
            '1...mixer3': 'ChipMixer',
            # Ethereum mixers
            '0x...tornado1': 'Tornado Cash',
            '0x...tornado2': 'Tornado Cash 2'
        }

        self.known_exchanges = {
            # Bitcoin
            '1...binance': 'Binance',
            '3...coinbase': 'Coinbase',
            'bc1q...kraken': 'Kraken',
            # Ethereum
            '0x...binance_eth': 'Binance',
            '0x...coinbase_eth': 'Coinbase'
        }

        self.trace_cache = {}

    def trace_bitcoin_funds(self, address: str, direction: str = 'forward',
                           max_hops: int = 5, min_amount: float = 0.001,
                           time_limit: Optional[timedelta] = None) -> Dict:
        """
        Trace Bitcoin fund flow

        Args:
            address: Starting address
            direction: 'forward' (where funds go) or 'backward' (where funds came from)
            max_hops: Maximum number of hops to trace
            min_amount: Minimum transaction amount to follow (BTC)
            time_limit: Only trace transactions within this time window
        """
        logger.info(f"Tracing Bitcoin funds {direction} from {address}, max {max_hops} hops")

        trace = {
            'start_address': address,
            'direction': direction,
            'nodes': [],
            'edges': [],
            'paths': [],
            'mixing_services_detected': [],
            'exchanges_detected': [],
            'total_hops': 0,
            'total_amount_traced': 0,
            'flags': []
        }

        visited = set()
        queue = deque([(address, 0, [], 0)])  # (address, hop, path, cumulative_amount)

        while queue:
            current_addr, hop, path, cumulative_amt = queue.popleft()

            if hop > max_hops or current_addr in visited:
                continue

            visited.add(current_addr)

            # Add node
            trace['nodes'].append({
                'address': current_addr,
                'hop': hop,
                'type': self._identify_address_type(current_addr),
                'cumulative_amount': cumulative_amt
            })

            # Get transactions
            if not self.bitcoin_tracker:
                continue

            try:
                addr_info = self.bitcoin_tracker.get_address_info(current_addr)

                for tx in addr_info.get('transactions', [])[:100]:
                    tx_hash = tx.get('hash')
                    tx_time = tx.get('time')

                    # Apply time filter
                    if time_limit and tx_time:
                        if abs((datetime.now() - tx_time).total_seconds()) > time_limit.total_seconds():
                            continue

                    # Forward tracing: follow outputs
                    if direction == 'forward':
                        for output in tx.get('outputs', []):
                            out_addr = output.get('address')
                            value = output.get('value', 0)

                            if out_addr and out_addr != current_addr and value >= min_amount:
                                # Add edge
                                trace['edges'].append({
                                    'from': current_addr,
                                    'to': out_addr,
                                    'amount': value,
                                    'tx_hash': tx_hash,
                                    'time': tx_time,
                                    'hop': hop
                                })

                                new_path = path + [current_addr]
                                new_amount = cumulative_amt + value

                                # Check for mixing/exchange
                                self._check_suspicious_entity(out_addr, trace)

                                if hop < max_hops:
                                    queue.append((out_addr, hop + 1, new_path, new_amount))

                                # Record complete path
                                if hop == max_hops - 1:
                                    trace['paths'].append({
                                        'path': new_path + [out_addr],
                                        'total_amount': new_amount,
                                        'hops': hop + 1
                                    })

                    # Backward tracing: follow inputs
                    else:
                        for input_data in tx.get('inputs', []):
                            in_addr = input_data.get('address')
                            value = input_data.get('value', 0)

                            if in_addr and in_addr != current_addr and value >= min_amount:
                                trace['edges'].append({
                                    'from': in_addr,
                                    'to': current_addr,
                                    'amount': value,
                                    'tx_hash': tx_hash,
                                    'time': tx_time,
                                    'hop': hop
                                })

                                new_path = path + [current_addr]
                                new_amount = cumulative_amt + value

                                self._check_suspicious_entity(in_addr, trace)

                                if hop < max_hops:
                                    queue.append((in_addr, hop + 1, new_path, new_amount))

            except Exception as e:
                logger.error(f"Error tracing {current_addr}: {e}")

        # Calculate statistics
        trace['total_hops'] = max([node['hop'] for node in trace['nodes']]) if trace['nodes'] else 0
        trace['total_amount_traced'] = sum([edge['amount'] for edge in trace['edges']])
        trace['unique_addresses'] = len(visited)

        # Analyze patterns
        trace['analysis'] = self._analyze_trace_patterns(trace)

        return trace

    def trace_ethereum_funds(self, address: str, direction: str = 'forward',
                            max_hops: int = 3, min_amount: float = 0.01,
                            include_tokens: bool = True) -> Dict:
        """
        Trace Ethereum fund flow including token transfers

        Args:
            address: Starting address
            direction: 'forward' or 'backward'
            max_hops: Maximum hops to trace
            min_amount: Minimum ETH amount
            include_tokens: Include ERC-20 token transfers
        """
        logger.info(f"Tracing Ethereum funds {direction} from {address}")

        trace = {
            'start_address': address,
            'direction': direction,
            'nodes': [],
            'edges': [],
            'token_transfers': [],
            'contract_interactions': [],
            'defi_protocols': set(),
            'mixing_services_detected': [],
            'exchanges_detected': [],
            'flags': []
        }

        visited = set()
        queue = deque([(address, 0, [])])

        while queue:
            current_addr, hop, path = queue.popleft()

            if hop > max_hops or current_addr in visited:
                continue

            visited.add(current_addr)

            trace['nodes'].append({
                'address': current_addr,
                'hop': hop,
                'type': self._identify_address_type(current_addr)
            })

            if not self.ethereum_tracker:
                continue

            try:
                addr_info = self.ethereum_tracker.get_address_info(current_addr)

                # Trace ETH transfers
                for tx in addr_info.get('transactions', [])[:50]:
                    tx_hash = tx.get('hash')
                    from_addr = tx.get('from')
                    to_addr = tx.get('to')
                    value = tx.get('value', 0)

                    if value < min_amount:
                        continue

                    # Check for contract interaction
                    if to_addr:
                        contract_info = self.ethereum_tracker.analyze_smart_contract(to_addr)
                        if contract_info.get('verified'):
                            trace['contract_interactions'].append({
                                'address': to_addr,
                                'name': contract_info.get('name'),
                                'tx_hash': tx_hash
                            })

                    if direction == 'forward' and from_addr == current_addr and to_addr:
                        trace['edges'].append({
                            'from': from_addr,
                            'to': to_addr,
                            'amount': value,
                            'type': 'ETH',
                            'tx_hash': tx_hash,
                            'hop': hop
                        })

                        self._check_suspicious_entity(to_addr, trace)

                        if hop < max_hops:
                            queue.append((to_addr, hop + 1, path + [current_addr]))

                    elif direction == 'backward' and to_addr == current_addr and from_addr:
                        trace['edges'].append({
                            'from': from_addr,
                            'to': to_addr,
                            'amount': value,
                            'type': 'ETH',
                            'tx_hash': tx_hash,
                            'hop': hop
                        })

                        self._check_suspicious_entity(from_addr, trace)

                        if hop < max_hops:
                            queue.append((from_addr, hop + 1, path + [current_addr]))

                # Trace token transfers
                if include_tokens:
                    for token_tx in addr_info.get('token_transfers', [])[:30]:
                        trace['token_transfers'].append({
                            'from': token_tx.get('from'),
                            'to': token_tx.get('to'),
                            'token': token_tx.get('token_symbol'),
                            'amount': token_tx.get('value'),
                            'tx_hash': token_tx.get('hash')
                        })

            except Exception as e:
                logger.error(f"Error tracing Ethereum {current_addr}: {e}")

        trace['defi_protocols'] = list(trace['defi_protocols'])
        trace['unique_addresses'] = len(visited)
        trace['analysis'] = self._analyze_trace_patterns(trace)

        return trace

    def _identify_address_type(self, address: str) -> str:
        """Identify the type of address (exchange, mixer, contract, etc.)"""
        # Check known mixing services
        for pattern, name in self.mixing_services.items():
            if pattern in address:
                return 'mixer'

        # Check known exchanges
        for pattern, name in self.known_exchanges.items():
            if pattern in address:
                return 'exchange'

        # Check address format for type
        if address.startswith('0x'):
            # Ethereum address
            if len(address) == 42:
                return 'ethereum_address'
        elif address.startswith('bc1'):
            return 'bitcoin_bech32'
        elif address.startswith('3'):
            return 'bitcoin_p2sh'
        elif address.startswith('1'):
            return 'bitcoin_p2pkh'

        return 'unknown'

    def _check_suspicious_entity(self, address: str, trace: Dict):
        """Check if address belongs to a mixer or exchange"""
        for pattern, name in self.mixing_services.items():
            if pattern in address:
                if name not in trace['mixing_services_detected']:
                    trace['mixing_services_detected'].append(name)
                    trace['flags'].append(f'mixer_detected:{name}')

        for pattern, name in self.known_exchanges.items():
            if pattern in address:
                if name not in trace['exchanges_detected']:
                    trace['exchanges_detected'].append(name)

    def _analyze_trace_patterns(self, trace: Dict) -> Dict:
        """Analyze patterns in the trace for suspicious activity"""
        analysis = {
            'risk_score': 0.0,
            'patterns_detected': [],
            'recommendations': []
        }

        # Pattern 1: Mixing service usage
        if trace.get('mixing_services_detected'):
            analysis['patterns_detected'].append('mixing_service_usage')
            analysis['risk_score'] += 5.0
            analysis['recommendations'].append('High priority: Funds passed through mixing service')

        # Pattern 2: Multiple exchange hops
        if len(trace.get('exchanges_detected', [])) > 1:
            analysis['patterns_detected'].append('exchange_hopping')
            analysis['risk_score'] += 2.0

        # Pattern 3: Rapid splitting
        edges_by_hop = defaultdict(list)
        for edge in trace.get('edges', []):
            edges_by_hop[edge['hop']].append(edge)

        for hop, edges in edges_by_hop.items():
            unique_destinations = set(edge['to'] for edge in edges)
            if len(unique_destinations) > 10:
                analysis['patterns_detected'].append(f'rapid_splitting_hop_{hop}')
                analysis['risk_score'] += 1.5

        # Pattern 4: Peel chain
        if self._detect_peel_chain(trace):
            analysis['patterns_detected'].append('peel_chain')
            analysis['risk_score'] += 3.0

        # Pattern 5: Round-trip detection
        if self._detect_round_trip(trace):
            analysis['patterns_detected'].append('round_trip')
            analysis['risk_score'] += 2.0

        # Normalize risk score
        analysis['risk_score'] = min(analysis['risk_score'], 10.0)

        return analysis

    def _detect_peel_chain(self, trace: Dict) -> bool:
        """Detect peel chain pattern in transaction trace"""
        edges = trace.get('edges', [])

        if len(edges) < 3:
            return False

        # Sort edges by hop
        sorted_edges = sorted(edges, key=lambda x: x['hop'])

        # Check for decreasing amounts pattern
        for i in range(len(sorted_edges) - 2):
            amounts = [sorted_edges[i]['amount'],
                      sorted_edges[i+1]['amount'],
                      sorted_edges[i+2]['amount']]

            # Peel chain: consistently decreasing amounts
            if amounts[0] > amounts[1] > amounts[2]:
                # Check if decrease is significant
                if amounts[1] < amounts[0] * 0.9 and amounts[2] < amounts[1] * 0.9:
                    return True

        return False

    def _detect_round_trip(self, trace: Dict) -> bool:
        """Detect if funds return to original address"""
        start_addr = trace.get('start_address')
        nodes = trace.get('nodes', [])

        # Check if start address appears again at a later hop
        for node in nodes:
            if node['address'] == start_addr and node['hop'] > 0:
                return True

        return False

    def visualize_flow(self, trace: Dict, output_format: str = 'json') -> str:
        """
        Generate visualization data for the transaction flow

        Args:
            trace: Trace result dictionary
            output_format: 'json', 'dot', or 'cytoscape'
        """
        if output_format == 'json':
            return json.dumps(trace, indent=2, default=str)

        elif output_format == 'dot':
            # GraphViz DOT format
            dot = 'digraph TransactionFlow {\n'
            dot += '  rankdir=LR;\n'
            dot += '  node [shape=box];\n'

            # Add nodes
            for node in trace.get('nodes', []):
                addr = node['address']
                label = f"{addr[:8]}...{addr[-6:]}"
                color = 'red' if node['type'] == 'mixer' else 'blue' if node['type'] == 'exchange' else 'black'
                dot += f'  "{addr}" [label="{label}\\nHop {node["hop"]}", color={color}];\n'

            # Add edges
            for edge in trace.get('edges', []):
                dot += f'  "{edge["from"]}" -> "{edge["to"]}" [label="{edge["amount"]:.4f}"];\n'

            dot += '}\n'
            return dot

        elif output_format == 'cytoscape':
            # Cytoscape.js format
            cytoscape_data = {
                'nodes': [
                    {
                        'data': {
                            'id': node['address'],
                            'label': f"{node['address'][:8]}...{node['address'][-6:]}",
                            'hop': node['hop'],
                            'type': node['type']
                        }
                    }
                    for node in trace.get('nodes', [])
                ],
                'edges': [
                    {
                        'data': {
                            'id': f"{edge['from']}_{edge['to']}",
                            'source': edge['from'],
                            'target': edge['to'],
                            'amount': edge['amount'],
                            'label': f"{edge['amount']:.4f}"
                        }
                    }
                    for edge in trace.get('edges', [])
                ]
            }
            return json.dumps(cytoscape_data, indent=2)

        return json.dumps(trace, indent=2, default=str)

    def find_common_paths(self, traces: List[Dict]) -> Dict:
        """Find common paths across multiple traces"""
        logger.info(f"Finding common paths across {len(traces)} traces")

        common_paths = {
            'common_addresses': set(),
            'common_edges': [],
            'intersection_points': []
        }

        if len(traces) < 2:
            return common_paths

        # Find common addresses
        addr_sets = [set(node['address'] for node in trace.get('nodes', [])) for trace in traces]
        common_paths['common_addresses'] = set.intersection(*addr_sets)

        # Find common edges (same from->to pairs)
        edge_counters = defaultdict(int)
        for trace in traces:
            for edge in trace.get('edges', []):
                edge_key = (edge['from'], edge['to'])
                edge_counters[edge_key] += 1

        # Edges that appear in multiple traces
        for edge_key, count in edge_counters.items():
            if count > 1:
                common_paths['common_edges'].append({
                    'from': edge_key[0],
                    'to': edge_key[1],
                    'appearances': count
                })

        return common_paths

    def generate_report(self, trace: Dict) -> str:
        """Generate human-readable report of the trace"""
        report = []
        report.append("=" * 80)
        report.append("TRANSACTION TRACE REPORT")
        report.append("=" * 80)
        report.append(f"\nStart Address: {trace['start_address']}")
        report.append(f"Direction: {trace['direction']}")
        report.append(f"Unique Addresses: {trace.get('unique_addresses', 0)}")
        report.append(f"Total Hops: {trace.get('total_hops', 0)}")

        if 'total_amount_traced' in trace:
            report.append(f"Total Amount Traced: {trace['total_amount_traced']:.8f} BTC")

        # Suspicious entities
        if trace.get('mixing_services_detected'):
            report.append("\n⚠ MIXING SERVICES DETECTED:")
            for mixer in trace['mixing_services_detected']:
                report.append(f"  - {mixer}")

        if trace.get('exchanges_detected'):
            report.append("\nExchanges Detected:")
            for exchange in trace['exchanges_detected']:
                report.append(f"  - {exchange}")

        # Analysis
        analysis = trace.get('analysis', {})
        if analysis:
            report.append(f"\nRisk Score: {analysis.get('risk_score', 0):.1f}/10.0")

            if analysis.get('patterns_detected'):
                report.append("\nPatterns Detected:")
                for pattern in analysis['patterns_detected']:
                    report.append(f"  - {pattern}")

            if analysis.get('recommendations'):
                report.append("\nRecommendations:")
                for rec in analysis['recommendations']:
                    report.append(f"  - {rec}")

        # Paths
        if trace.get('paths'):
            report.append(f"\nTop Paths (showing first 5):")
            for i, path_info in enumerate(trace['paths'][:5], 1):
                path = path_info['path']
                report.append(f"\n  Path {i}:")
                report.append(f"    Hops: {path_info['hops']}")
                if 'total_amount' in path_info:
                    report.append(f"    Amount: {path_info['total_amount']:.8f}")
                report.append(f"    Route: {' -> '.join([addr[:8] + '...' for addr in path])}")

        report.append("\n" + "=" * 80)

        return "\n".join(report)
