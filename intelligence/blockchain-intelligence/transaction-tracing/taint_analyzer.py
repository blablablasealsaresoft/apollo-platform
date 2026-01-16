"""
Taint Analysis Engine
Advanced taint tracking using poison and haircut algorithms
"""

import asyncio
import logging
from typing import Dict, List, Set, Optional, Tuple, Any
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict, deque
import networkx as nx
from enum import Enum


class TaintMethod(Enum):
    """Taint calculation methods"""
    POISON = "poison"  # All outputs tainted if any input is tainted
    HAIRCUT = "haircut"  # Proportional taint based on amount
    FIFO = "fifo"  # First-in-first-out
    LIFO = "lifo"  # Last-in-first-out


class TaintSource(Enum):
    """Sources of taint"""
    THEFT = "theft"
    RANSOMWARE = "ransomware"
    DARKNET = "darknet"
    SANCTIONED = "sanctioned"
    MIXER = "mixer"
    SCAM = "scam"
    HACK = "hack"
    TERRORIST = "terrorist"


@dataclass
class TaintScore:
    """Taint score for an address or transaction"""
    address: str
    total_taint: float  # 0.0 to 1.0
    taint_sources: Dict[TaintSource, float]
    clean_amount: float
    tainted_amount: float
    calculation_method: TaintMethod
    confidence: float
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TaintPath:
    """Path of taint propagation"""
    source_address: str
    target_address: str
    path: List[str]
    initial_taint: float
    final_taint: float
    hops: int
    taint_dilution: float


class TaintAnalyzer:
    """
    Advanced taint analysis engine

    Features:
    - Poison algorithm (binary taint)
    - Haircut algorithm (proportional taint)
    - FIFO/LIFO tracking
    - Multi-source taint tracking
    - Taint propagation analysis
    - Clean/dirty fund separation
    """

    def __init__(self, method: TaintMethod = TaintMethod.HAIRCUT):
        """
        Initialize taint analyzer

        Args:
            method: Default taint calculation method
        """
        self.method = method
        self.logger = logging.getLogger(__name__)

        # Taint sources (address -> taint score)
        self.taint_sources: Dict[str, TaintScore] = {}

        # Cache for calculated taints
        self.taint_cache: Dict[Tuple[str, TaintMethod], TaintScore] = {}

        # Statistics
        self.stats = {
            'addresses_analyzed': 0,
            'taint_sources_tracked': 0,
            'propagations_calculated': 0
        }

    def add_taint_source(
        self,
        address: str,
        taint_type: TaintSource,
        amount: float,
        confidence: float = 1.0
    ):
        """
        Add a taint source

        Args:
            address: Tainted address
            taint_type: Type of taint
            amount: Amount of tainted funds
            confidence: Confidence in taint (0-1)
        """
        if address not in self.taint_sources:
            self.taint_sources[address] = TaintScore(
                address=address,
                total_taint=1.0,
                taint_sources={taint_type: 1.0},
                clean_amount=0.0,
                tainted_amount=amount,
                calculation_method=self.method,
                confidence=confidence
            )
        else:
            # Update existing taint
            existing = self.taint_sources[address]
            existing.taint_sources[taint_type] = 1.0
            existing.tainted_amount += amount
            existing.total_taint = 1.0

        self.stats['taint_sources_tracked'] += 1

    async def analyze(
        self,
        address: str,
        transaction_graph: nx.DiGraph,
        method: Optional[TaintMethod] = None
    ) -> TaintScore:
        """
        Analyze taint for an address

        Args:
            address: Address to analyze
            transaction_graph: Transaction graph
            method: Taint calculation method (uses default if None)

        Returns:
            TaintScore for the address
        """
        method = method or self.method
        cache_key = (address, method)

        # Check cache
        if cache_key in self.taint_cache:
            return self.taint_cache[cache_key]

        self.stats['addresses_analyzed'] += 1

        # Calculate taint based on method
        if method == TaintMethod.POISON:
            taint_score = await self._calculate_poison_taint(address, transaction_graph)
        elif method == TaintMethod.HAIRCUT:
            taint_score = await self._calculate_haircut_taint(address, transaction_graph)
        elif method == TaintMethod.FIFO:
            taint_score = await self._calculate_fifo_taint(address, transaction_graph)
        elif method == TaintMethod.LIFO:
            taint_score = await self._calculate_lifo_taint(address, transaction_graph)
        else:
            taint_score = TaintScore(
                address=address,
                total_taint=0.0,
                taint_sources={},
                clean_amount=0.0,
                tainted_amount=0.0,
                calculation_method=method,
                confidence=0.0
            )

        # Cache result
        self.taint_cache[cache_key] = taint_score

        return taint_score

    async def _calculate_poison_taint(
        self,
        address: str,
        graph: nx.DiGraph
    ) -> TaintScore:
        """
        Calculate taint using poison algorithm
        If any input is tainted, all outputs are 100% tainted
        """
        # Check if address is a direct taint source
        if address in self.taint_sources:
            return self.taint_sources[address]

        # Find all paths from taint sources to this address
        is_tainted = False
        taint_sources_found = {}
        total_amount = 0.0

        for source_addr, source_taint in self.taint_sources.items():
            try:
                if nx.has_path(graph, source_addr, address):
                    is_tainted = True
                    # Merge taint sources
                    for taint_type, score in source_taint.taint_sources.items():
                        if taint_type in taint_sources_found:
                            taint_sources_found[taint_type] = max(
                                taint_sources_found[taint_type],
                                score
                            )
                        else:
                            taint_sources_found[taint_type] = score
            except nx.NetworkXNoPath:
                continue

        # Calculate total amount
        for _, _, data in graph.in_edges(address, data=True):
            total_amount += data.get('amount', 0)

        return TaintScore(
            address=address,
            total_taint=1.0 if is_tainted else 0.0,
            taint_sources=taint_sources_found,
            clean_amount=0.0 if is_tainted else total_amount,
            tainted_amount=total_amount if is_tainted else 0.0,
            calculation_method=TaintMethod.POISON,
            confidence=0.9 if is_tainted else 1.0
        )

    async def _calculate_haircut_taint(
        self,
        address: str,
        graph: nx.DiGraph
    ) -> TaintScore:
        """
        Calculate taint using haircut algorithm
        Taint is proportional to the ratio of tainted to total inputs
        """
        # Check if address is a direct taint source
        if address in self.taint_sources:
            return self.taint_sources[address]

        total_taint = 0.0
        taint_sources_found = defaultdict(float)
        total_input_amount = 0.0
        tainted_input_amount = 0.0

        # Analyze each input
        for predecessor in graph.predecessors(address):
            edge_data = graph.get_edge_data(predecessor, address)
            input_amount = edge_data.get('amount', 0)
            total_input_amount += input_amount

            # Get taint of predecessor
            pred_taint = await self.analyze(predecessor, graph, TaintMethod.HAIRCUT)

            # Calculate tainted portion of this input
            input_tainted_amount = input_amount * pred_taint.total_taint
            tainted_input_amount += input_tainted_amount

            # Propagate taint sources proportionally
            for taint_type, score in pred_taint.taint_sources.items():
                taint_sources_found[taint_type] += score * (input_amount / max(total_input_amount, 1))

        # Calculate overall taint ratio
        if total_input_amount > 0:
            total_taint = tainted_input_amount / total_input_amount
        else:
            total_taint = 0.0

        return TaintScore(
            address=address,
            total_taint=min(total_taint, 1.0),
            taint_sources=dict(taint_sources_found),
            clean_amount=total_input_amount - tainted_input_amount,
            tainted_amount=tainted_input_amount,
            calculation_method=TaintMethod.HAIRCUT,
            confidence=0.85
        )

    async def _calculate_fifo_taint(
        self,
        address: str,
        graph: nx.DiGraph
    ) -> TaintScore:
        """
        Calculate taint using FIFO (first-in-first-out)
        Assumes oldest inputs are spent first
        """
        if address in self.taint_sources:
            return self.taint_sources[address]

        # Get all inputs sorted by timestamp
        inputs = []
        for predecessor in graph.predecessors(address):
            edge_data = graph.get_edge_data(predecessor, address)
            inputs.append({
                'address': predecessor,
                'amount': edge_data.get('amount', 0),
                'timestamp': edge_data.get('timestamp', datetime.min),
                'taint': await self.analyze(predecessor, graph, TaintMethod.FIFO)
            })

        # Sort by timestamp (oldest first)
        inputs.sort(key=lambda x: x['timestamp'])

        # Get all outputs sorted by timestamp
        outputs = []
        for successor in graph.successors(address):
            edge_data = graph.get_edge_data(address, successor)
            outputs.append({
                'address': successor,
                'amount': edge_data.get('amount', 0),
                'timestamp': edge_data.get('timestamp', datetime.min)
            })

        outputs.sort(key=lambda x: x['timestamp'])

        # Match inputs to outputs in FIFO order
        remaining_inputs = inputs.copy()
        total_tainted = 0.0
        total_clean = 0.0
        taint_sources_found = defaultdict(float)

        for output in outputs:
            output_amount = output['amount']
            remaining_output = output_amount

            while remaining_output > 0 and remaining_inputs:
                input_entry = remaining_inputs[0]
                input_amount = input_entry['amount']
                input_taint = input_entry['taint']

                # Take from this input
                taken = min(remaining_output, input_amount)

                # Calculate taint
                tainted_portion = taken * input_taint.total_taint
                clean_portion = taken * (1 - input_taint.total_taint)

                total_tainted += tainted_portion
                total_clean += clean_portion

                # Track taint sources
                for taint_type, score in input_taint.taint_sources.items():
                    taint_sources_found[taint_type] += score * (taken / output_amount)

                # Update remaining
                remaining_output -= taken
                input_entry['amount'] -= taken

                if input_entry['amount'] <= 0:
                    remaining_inputs.pop(0)

        # Calculate overall taint
        total_amount = total_tainted + total_clean
        taint_ratio = total_tainted / total_amount if total_amount > 0 else 0.0

        return TaintScore(
            address=address,
            total_taint=taint_ratio,
            taint_sources=dict(taint_sources_found),
            clean_amount=total_clean,
            tainted_amount=total_tainted,
            calculation_method=TaintMethod.FIFO,
            confidence=0.8
        )

    async def _calculate_lifo_taint(
        self,
        address: str,
        graph: nx.DiGraph
    ) -> TaintScore:
        """
        Calculate taint using LIFO (last-in-first-out)
        Assumes newest inputs are spent first
        """
        # Similar to FIFO but reverse the sort order
        if address in self.taint_sources:
            return self.taint_sources[address]

        # Get all inputs sorted by timestamp (newest first for LIFO)
        inputs = []
        for predecessor in graph.predecessors(address):
            edge_data = graph.get_edge_data(predecessor, address)
            inputs.append({
                'address': predecessor,
                'amount': edge_data.get('amount', 0),
                'timestamp': edge_data.get('timestamp', datetime.min),
                'taint': await self.analyze(predecessor, graph, TaintMethod.LIFO)
            })

        # Sort by timestamp (newest first for LIFO)
        inputs.sort(key=lambda x: x['timestamp'], reverse=True)

        # Rest is similar to FIFO
        outputs = []
        for successor in graph.successors(address):
            edge_data = graph.get_edge_data(address, successor)
            outputs.append({
                'address': successor,
                'amount': edge_data.get('amount', 0),
                'timestamp': edge_data.get('timestamp', datetime.min)
            })

        outputs.sort(key=lambda x: x['timestamp'])

        remaining_inputs = inputs.copy()
        total_tainted = 0.0
        total_clean = 0.0
        taint_sources_found = defaultdict(float)

        for output in outputs:
            output_amount = output['amount']
            remaining_output = output_amount

            while remaining_output > 0 and remaining_inputs:
                input_entry = remaining_inputs[0]
                input_amount = input_entry['amount']
                input_taint = input_entry['taint']

                taken = min(remaining_output, input_amount)

                tainted_portion = taken * input_taint.total_taint
                clean_portion = taken * (1 - input_taint.total_taint)

                total_tainted += tainted_portion
                total_clean += clean_portion

                for taint_type, score in input_taint.taint_sources.items():
                    taint_sources_found[taint_type] += score * (taken / output_amount)

                remaining_output -= taken
                input_entry['amount'] -= taken

                if input_entry['amount'] <= 0:
                    remaining_inputs.pop(0)

        total_amount = total_tainted + total_clean
        taint_ratio = total_tainted / total_amount if total_amount > 0 else 0.0

        return TaintScore(
            address=address,
            total_taint=taint_ratio,
            taint_sources=dict(taint_sources_found),
            clean_amount=total_clean,
            tainted_amount=total_tainted,
            calculation_method=TaintMethod.LIFO,
            confidence=0.8
        )

    async def trace_taint_propagation(
        self,
        source_address: str,
        graph: nx.DiGraph,
        max_hops: int = 10,
        min_taint: float = 0.01
    ) -> List[TaintPath]:
        """
        Trace how taint propagates from source

        Args:
            source_address: Tainted source address
            graph: Transaction graph
            max_hops: Maximum propagation hops
            min_taint: Minimum taint to track

        Returns:
            List of taint propagation paths
        """
        self.stats['propagations_calculated'] += 1

        paths = []

        # BFS from source
        queue = deque([(source_address, [source_address], 1.0, 0)])
        visited = set()

        while queue:
            current, path, current_taint, hop = queue.popleft()

            if hop >= max_hops or current_taint < min_taint:
                continue

            if current in visited:
                continue

            visited.add(current)

            # Get successors
            for successor in graph.successors(current):
                # Calculate taint at successor
                succ_taint = await self.analyze(successor, graph, self.method)

                if succ_taint.total_taint >= min_taint:
                    new_path = path + [successor]

                    # Create taint path
                    taint_path = TaintPath(
                        source_address=source_address,
                        target_address=successor,
                        path=new_path,
                        initial_taint=1.0,
                        final_taint=succ_taint.total_taint,
                        hops=len(new_path) - 1,
                        taint_dilution=1.0 - succ_taint.total_taint
                    )

                    paths.append(taint_path)

                    # Continue propagation
                    queue.append((successor, new_path, succ_taint.total_taint, hop + 1))

        return paths

    def compare_methods(
        self,
        address: str,
        graph: nx.DiGraph
    ) -> Dict[TaintMethod, TaintScore]:
        """
        Compare taint scores using different methods

        Args:
            address: Address to analyze
            graph: Transaction graph

        Returns:
            Dictionary of method -> taint score
        """
        results = {}

        for method in TaintMethod:
            score = asyncio.run(self.analyze(address, graph, method))
            results[method] = score

        return results

    def get_risk_category(self, taint_score: TaintScore) -> str:
        """
        Categorize risk based on taint score

        Args:
            taint_score: Taint score to categorize

        Returns:
            Risk category string
        """
        if taint_score.total_taint >= 0.75:
            return "CRITICAL"
        elif taint_score.total_taint >= 0.50:
            return "HIGH"
        elif taint_score.total_taint >= 0.25:
            return "MEDIUM"
        elif taint_score.total_taint >= 0.10:
            return "LOW"
        else:
            return "MINIMAL"

    def get_statistics(self) -> Dict[str, Any]:
        """Get analyzer statistics"""
        return self.stats.copy()

    def clear_cache(self):
        """Clear taint calculation cache"""
        self.taint_cache.clear()


# Example usage
async def main():
    """Example usage of TaintAnalyzer"""
    # Create analyzer
    analyzer = TaintAnalyzer(method=TaintMethod.HAIRCUT)

    # Add taint sources
    analyzer.add_taint_source(
        address="source_addr_1",
        taint_type=TaintSource.HACK,
        amount=100.0,
        confidence=0.95
    )

    # Create sample graph
    graph = nx.DiGraph()
    graph.add_edge("source_addr_1", "intermediate_1", amount=50.0)
    graph.add_edge("source_addr_1", "intermediate_2", amount=50.0)
    graph.add_edge("intermediate_1", "target", amount=30.0)
    graph.add_edge("intermediate_2", "target", amount=40.0)

    # Analyze taint
    taint_score = await analyzer.analyze("target", graph)

    print(f"Taint Analysis for 'target':")
    print(f"  Total taint: {taint_score.total_taint:.2%}")
    print(f"  Tainted amount: {taint_score.tainted_amount:.2f}")
    print(f"  Clean amount: {taint_score.clean_amount:.2f}")
    print(f"  Risk category: {analyzer.get_risk_category(taint_score)}")
    print(f"  Taint sources: {taint_score.taint_sources}")

    # Trace propagation
    paths = await analyzer.trace_taint_propagation("source_addr_1", graph)
    print(f"\nTaint propagation paths: {len(paths)}")
    for path in paths:
        print(f"  {' -> '.join(path.path)}")
        print(f"    Final taint: {path.final_taint:.2%}")

    # Compare methods
    comparison = analyzer.compare_methods("target", graph)
    print(f"\nMethod comparison:")
    for method, score in comparison.items():
        print(f"  {method.value}: {score.total_taint:.2%}")


if __name__ == "__main__":
    asyncio.run(main())
