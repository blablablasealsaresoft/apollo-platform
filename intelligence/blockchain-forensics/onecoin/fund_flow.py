"""
Fund Flow Analyzer for OneCoin Investigation

Tracks and visualizes the flow of OneCoin funds through the blockchain ecosystem.
"""

import asyncio
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
import logging

logger = logging.getLogger(__name__)


@dataclass
class FundFlow:
    """Represents a flow of funds"""

    source_address: str
    destination_address: str
    amount: float
    amount_usd: float
    timestamp: datetime
    hops: int  # Number of intermediate addresses
    path: List[str]  # Complete path from source to destination
    tags: List[str] = field(default_factory=list)


class FundFlowAnalyzer:
    """
    Analyzes fund flows in the OneCoin network

    Tracks how money moves from victims through the network
    to eventual cash-out points (exchanges, mixers, etc.)
    """

    def __init__(self, db_manager, api_manager, graph_client):
        self.db = db_manager
        self.api = api_manager
        self.graph = graph_client

        logger.info("Fund Flow Analyzer initialized")

    async def trace_fund_flow(
        self,
        source_address: str,
        blockchain: str = "btc",
        max_hops: int = 10,
        min_amount_usd: float = 1000
    ) -> List[FundFlow]:
        """
        Trace the flow of funds from a source address

        Args:
            source_address: Starting address
            blockchain: Blockchain type
            max_hops: Maximum number of hops to follow
            min_amount_usd: Minimum amount to trace

        Returns:
            List of fund flows
        """
        logger.info(f"Tracing fund flow from {source_address}")

        flows = []
        visited = set()

        # BFS to explore fund flows
        queue = [(source_address, [], 0, 0)]  # (address, path, hops, total_amount)

        while queue:
            current_addr, path, hops, total_amount = queue.pop(0)

            if hops > max_hops or current_addr in visited:
                continue

            visited.add(current_addr)

            # Get outgoing transactions
            txs = await self.api.get_address_transactions(current_addr, blockchain)

            for tx in txs:
                if tx["from_address"] != current_addr:
                    continue

                amount_usd = tx.get("amount_usd", 0)
                if amount_usd < min_amount_usd:
                    continue

                to_addr = tx["to_address"]
                new_path = path + [current_addr]

                # Check if this is a terminal point (exchange, mixer, etc.)
                is_terminal = await self._is_terminal_address(to_addr)

                if is_terminal or hops == max_hops:
                    # Create fund flow record
                    flow = FundFlow(
                        source_address=source_address,
                        destination_address=to_addr,
                        amount=tx["amount"],
                        amount_usd=amount_usd,
                        timestamp=tx["timestamp"],
                        hops=hops + 1,
                        path=new_path + [to_addr],
                    )

                    # Tag the flow
                    flow.tags = await self._tag_flow(flow)

                    flows.append(flow)
                else:
                    # Continue tracing
                    queue.append((to_addr, new_path, hops + 1, total_amount + amount_usd))

        logger.info(f"Found {len(flows)} fund flows from {source_address}")
        return flows

    async def analyze_flow_patterns(
        self,
        flows: List[FundFlow]
    ) -> Dict:
        """
        Analyze patterns in fund flows

        Identifies common patterns like:
        - Splitting (one source to many destinations)
        - Layering (multiple intermediate hops)
        - Integration (consolidation at exchanges)
        """
        analysis = {
            "total_flows": len(flows),
            "total_amount_usd": sum(f.amount_usd for f in flows),
            "average_hops": sum(f.hops for f in flows) / len(flows) if flows else 0,
            "patterns": [],
            "destinations": {},
            "timeline": [],
        }

        # Analyze destination types
        for flow in flows:
            dest_type = await self._classify_destination(flow.destination_address)
            analysis["destinations"][dest_type] = \
                analysis["destinations"].get(dest_type, 0) + 1

        # Detect patterns
        if analysis["average_hops"] > 5:
            analysis["patterns"].append("complex_layering")

        # Check for splitting patterns
        source_counts = {}
        for flow in flows:
            source_counts[flow.source_address] = \
                source_counts.get(flow.source_address, 0) + 1

        for source, count in source_counts.items():
            if count > 10:
                analysis["patterns"].append(f"splitting_from_{source}")

        # Timeline analysis
        flows_by_date = {}
        for flow in flows:
            date_key = flow.timestamp.date().isoformat()
            if date_key not in flows_by_date:
                flows_by_date[date_key] = []
            flows_by_date[date_key].append(flow)

        analysis["timeline"] = [
            {
                "date": date,
                "flow_count": len(flows),
                "total_amount": sum(f.amount_usd for f in flows),
            }
            for date, flows in sorted(flows_by_date.items())
        ]

        return analysis

    async def generate_sankey_diagram_data(
        self,
        flows: List[FundFlow]
    ) -> Dict:
        """
        Generate data for Sankey diagram visualization

        Shows flow of funds from sources through intermediaries to destinations
        """
        nodes = []
        links = []
        node_indices = {}

        def get_node_index(address: str, label: Optional[str] = None) -> int:
            if address not in node_indices:
                node_indices[address] = len(nodes)
                nodes.append({
                    "id": address,
                    "label": label or address[:8] + "...",
                })
            return node_indices[address]

        # Process each flow
        for flow in flows:
            path = flow.path

            for i in range(len(path) - 1):
                source_idx = get_node_index(path[i])
                target_idx = get_node_index(path[i + 1])

                # Add link
                links.append({
                    "source": source_idx,
                    "target": target_idx,
                    "value": flow.amount_usd,
                    "timestamp": flow.timestamp.isoformat(),
                })

        return {
            "nodes": nodes,
            "links": links,
        }

    async def identify_consolidation_points(
        self,
        flows: List[FundFlow]
    ) -> List[Dict]:
        """
        Identify addresses where funds consolidate

        These are often exchange deposit addresses or collection points
        """
        # Count incoming flows per address
        incoming_counts = {}
        incoming_amounts = {}

        for flow in flows:
            dest = flow.destination_address
            incoming_counts[dest] = incoming_counts.get(dest, 0) + 1
            incoming_amounts[dest] = incoming_amounts.get(dest, 0) + flow.amount_usd

        # Filter for significant consolidation points
        consolidation_points = []

        for address, count in incoming_counts.items():
            if count >= 5:  # At least 5 incoming flows
                point = {
                    "address": address,
                    "incoming_flow_count": count,
                    "total_amount_usd": incoming_amounts[address],
                    "average_amount_usd": incoming_amounts[address] / count,
                    "type": await self._classify_destination(address),
                }
                consolidation_points.append(point)

        # Sort by total amount
        consolidation_points.sort(key=lambda x: x["total_amount_usd"], reverse=True)

        return consolidation_points

    async def calculate_recovery_potential(
        self,
        flows: List[FundFlow]
    ) -> Dict:
        """
        Calculate potential for fund recovery

        Estimates which funds might be recoverable based on where they ended up
        """
        recovery = {
            "total_traced": sum(f.amount_usd for f in flows),
            "at_exchanges": 0.0,
            "in_mixers": 0.0,
            "in_transit": 0.0,
            "unknown": 0.0,
            "potentially_recoverable": 0.0,
            "by_exchange": {},
        }

        for flow in flows:
            dest_type = await self._classify_destination(flow.destination_address)

            if dest_type.startswith("exchange:"):
                exchange_name = dest_type.split(":")[1]
                recovery["at_exchanges"] += flow.amount_usd
                recovery["by_exchange"][exchange_name] = \
                    recovery["by_exchange"].get(exchange_name, 0) + flow.amount_usd
            elif dest_type == "mixer":
                recovery["in_mixers"] += flow.amount_usd
            elif dest_type == "unknown":
                recovery["unknown"] += flow.amount_usd
            else:
                recovery["in_transit"] += flow.amount_usd

        # Funds at regulated exchanges are potentially recoverable
        recovery["potentially_recoverable"] = recovery["at_exchanges"]

        return recovery

    # Private helper methods

    async def _is_terminal_address(self, address: str) -> bool:
        """Check if address is a terminal point (exchange, mixer, etc.)"""
        # Check if it's an exchange
        from ..config import KNOWN_EXCHANGES
        for exchange_addresses in KNOWN_EXCHANGES.values():
            if address in exchange_addresses:
                return True

        # Check if it's a mixer
        from ..config import KNOWN_MIXERS
        for mixer_addresses in KNOWN_MIXERS.values():
            if address in mixer_addresses:
                return True

        return False

    async def _tag_flow(self, flow: FundFlow) -> List[str]:
        """Tag a fund flow with relevant labels"""
        tags = []

        # Tag by number of hops
        if flow.hops == 1:
            tags.append("direct")
        elif flow.hops <= 3:
            tags.append("short_path")
        elif flow.hops <= 6:
            tags.append("medium_path")
        else:
            tags.append("long_path")

        # Tag by amount
        if flow.amount_usd > 1_000_000:
            tags.append("very_high_value")
        elif flow.amount_usd > 100_000:
            tags.append("high_value")
        elif flow.amount_usd > 10_000:
            tags.append("medium_value")
        else:
            tags.append("low_value")

        # Tag by destination type
        dest_type = await self._classify_destination(flow.destination_address)
        tags.append(f"dest:{dest_type}")

        return tags

    async def _classify_destination(self, address: str) -> str:
        """Classify destination address type"""
        # Check if it's an exchange
        from ..config import KNOWN_EXCHANGES
        for exchange_name, exchange_addresses in KNOWN_EXCHANGES.items():
            if address in exchange_addresses:
                return f"exchange:{exchange_name}"

        # Check if it's a mixer
        from ..config import KNOWN_MIXERS
        for mixer_type, mixer_addresses in KNOWN_MIXERS.items():
            if address in mixer_addresses:
                return "mixer"

        # Check if it's ransomware
        from ..config import KNOWN_RANSOMWARE
        for ransomware_type, ransomware_addresses in KNOWN_RANSOMWARE.items():
            if address in ransomware_addresses:
                return f"ransomware:{ransomware_type}"

        return "unknown"
