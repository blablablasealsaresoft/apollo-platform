"""
OneCoin Tracker - Main tracking system for OneCoin fraud investigation

This module coordinates the tracking of OneCoin-related cryptocurrency movements,
focusing on identifying and following funds stolen in the $4 billion fraud.
"""

import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
import logging

logger = logging.getLogger(__name__)


@dataclass
class OneCoinTransaction:
    """OneCoin-related transaction"""

    txid: str
    blockchain: str  # btc, eth, etc.
    timestamp: datetime
    from_address: str
    to_address: str
    amount: float
    amount_usd: float
    confidence_score: float  # 0-1, likelihood this is OneCoin related
    tags: List[str] = field(default_factory=list)
    metadata: Dict = field(default_factory=dict)


@dataclass
class OneCoinWallet:
    """Suspected OneCoin wallet"""

    address: str
    blockchain: str
    first_seen: datetime
    last_activity: datetime
    total_received: float
    total_sent: float
    balance: float
    confidence_score: float
    owner_type: str  # ruja, associate, victim, exchange, unknown
    owner_name: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    connected_wallets: List[str] = field(default_factory=list)


@dataclass
class OneCoinCluster:
    """Cluster of related OneCoin wallets"""

    cluster_id: str
    wallets: List[str]
    owner_type: str
    owner_name: Optional[str]
    total_value: float
    total_transactions: int
    first_activity: datetime
    last_activity: datetime


class OneCoinTracker:
    """
    Main OneCoin tracking system

    Coordinates all OneCoin investigation activities:
    - Wallet identification
    - Transaction tracking
    - Fund flow analysis
    - Exchange monitoring
    - Timeline reconstruction
    """

    def __init__(self, db_manager, api_manager, neo4j_client):
        self.db = db_manager
        self.api = api_manager
        self.graph = neo4j_client

        # Known OneCoin addresses (to be expanded through investigation)
        self.known_onecoin_addresses: Set[str] = set()
        self.known_ruja_addresses: Set[str] = set()

        # Tracked wallets
        self.tracked_wallets: Dict[str, OneCoinWallet] = {}

        # Investigation cache
        self.investigation_cache: Dict[str, any] = {}

        logger.info("OneCoin Tracker initialized")

    async def initialize_known_addresses(self):
        """Load known OneCoin and Ruja Ignatova addresses"""
        # Load from database
        known_addresses = await self.db.get_known_onecoin_addresses()
        self.known_onecoin_addresses.update(known_addresses)

        ruja_addresses = await self.db.get_ruja_ignatova_addresses()
        self.known_ruja_addresses.update(ruja_addresses)

        logger.info(
            f"Loaded {len(self.known_onecoin_addresses)} OneCoin addresses, "
            f"{len(self.known_ruja_addresses)} Ruja addresses"
        )

    async def track_address(
        self, address: str, blockchain: str = "btc", depth: int = 3
    ) -> Dict:
        """
        Track an address and its connections

        Args:
            address: Wallet address to track
            blockchain: Blockchain type (btc, eth, etc.)
            depth: How many hops to follow

        Returns:
            Tracking results including all connected addresses
        """
        logger.info(f"Tracking {blockchain} address: {address} (depth={depth})")

        results = {
            "address": address,
            "blockchain": blockchain,
            "transactions": [],
            "connected_addresses": set(),
            "suspicious_patterns": [],
            "exchange_deposits": [],
            "onecoin_confidence": 0.0,
        }

        try:
            # Get all transactions for this address
            transactions = await self.api.get_address_transactions(address, blockchain)
            results["transactions"] = transactions

            # Analyze transactions for OneCoin patterns
            patterns = await self._analyze_transaction_patterns(transactions)
            results["suspicious_patterns"] = patterns

            # Calculate OneCoin confidence score
            confidence = await self._calculate_onecoin_confidence(
                address, transactions, patterns
            )
            results["onecoin_confidence"] = confidence

            # Find connected addresses
            for tx in transactions:
                if tx.get("from_address") != address:
                    results["connected_addresses"].add(tx.get("from_address"))
                if tx.get("to_address") != address:
                    results["connected_addresses"].add(tx.get("to_address"))

            # Check for exchange deposits
            exchange_deposits = await self._check_exchange_deposits(transactions)
            results["exchange_deposits"] = exchange_deposits

            # Store in database
            await self.db.store_tracking_result(results)

            # Update graph database
            await self._update_graph_relationships(address, results)

            # Recursively track connected addresses if depth > 0
            if depth > 0:
                for connected_addr in list(results["connected_addresses"])[:10]:  # Limit to prevent explosion
                    sub_results = await self.track_address(
                        connected_addr, blockchain, depth - 1
                    )
                    results["connected_addresses"].update(
                        sub_results["connected_addresses"]
                    )

            return results

        except Exception as e:
            logger.error(f"Error tracking address {address}: {e}")
            return results

    async def identify_ruja_wallets(
        self,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None
    ) -> List[OneCoinWallet]:
        """
        Identify wallets likely controlled by Ruja Ignatova

        Uses multiple heuristics:
        - Large amounts (> $1M)
        - Timing (2014-2017 OneCoin peak)
        - Connection to known associates
        - Movement to luxury goods/real estate
        """
        logger.info("Identifying potential Ruja Ignatova wallets")

        if not start_date:
            start_date = datetime(2014, 1, 1)
        if not end_date:
            end_date = datetime(2017, 10, 1)  # When she disappeared

        candidates = []

        # Query high-value transactions in the timeframe
        high_value_txs = await self.db.query_high_value_transactions(
            start_date, end_date, min_amount_usd=1_000_000
        )

        for tx in high_value_txs:
            # Check if connected to known OneCoin addresses
            from_addr = tx.get("from_address")
            to_addr = tx.get("to_address")

            if from_addr in self.known_onecoin_addresses or \
               to_addr in self.known_onecoin_addresses:

                # Get wallet details
                wallet = await self._analyze_wallet(from_addr, tx.get("blockchain"))

                # Calculate likelihood this is Ruja's wallet
                ruja_score = await self._calculate_ruja_likelihood(wallet, tx)

                if ruja_score > 0.7:  # High confidence
                    wallet.confidence_score = ruja_score
                    wallet.owner_type = "ruja"
                    wallet.owner_name = "Ruja Ignatova (suspected)"
                    candidates.append(wallet)

        logger.info(f"Identified {len(candidates)} potential Ruja wallets")
        return candidates

    async def trace_victim_payments(self, victim_address: str) -> Dict:
        """
        Trace payments from a OneCoin victim to identify where funds went

        Args:
            victim_address: Address of OneCoin victim

        Returns:
            Complete trace of victim funds
        """
        logger.info(f"Tracing victim payments from {victim_address}")

        trace = {
            "victim_address": victim_address,
            "total_invested": 0.0,
            "payment_path": [],
            "final_destinations": [],
            "cashed_out_at": [],
        }

        # Get all outgoing transactions from victim
        victim_txs = await self.api.get_address_transactions(victim_address)

        for tx in victim_txs:
            if tx.get("from_address") == victim_address:
                trace["total_invested"] += tx.get("amount_usd", 0)

                # Follow the path
                path = await self._trace_transaction_path(
                    tx.get("to_address"),
                    tx.get("blockchain"),
                    max_hops=10
                )
                trace["payment_path"].append(path)

                # Check if it reached an exchange
                for hop in path:
                    if hop.get("is_exchange"):
                        trace["cashed_out_at"].append({
                            "exchange": hop.get("exchange_name"),
                            "amount": hop.get("amount_usd"),
                            "timestamp": hop.get("timestamp"),
                        })

        return trace

    async def detect_laundering_paths(
        self,
        source_address: str,
        min_amount: float = 100000
    ) -> List[Dict]:
        """
        Detect money laundering patterns from a source address

        Looks for:
        - Rapid splitting across multiple addresses
        - Use of mixers/tumblers
        - Complex multi-hop paths
        - Final consolidation at exchanges
        """
        logger.info(f"Detecting laundering paths from {source_address}")

        paths = []

        # Get outgoing transactions
        transactions = await self.api.get_address_transactions(source_address)

        for tx in transactions:
            if tx.get("amount_usd", 0) < min_amount:
                continue

            # Analyze the path this transaction takes
            path_analysis = await self._analyze_laundering_path(
                tx.get("txid"),
                tx.get("to_address"),
                tx.get("blockchain")
            )

            if path_analysis.get("is_suspicious"):
                paths.append(path_analysis)

        return paths

    async def generate_investigation_report(
        self,
        addresses: List[str],
        include_timeline: bool = True,
        include_network_graph: bool = True
    ) -> Dict:
        """
        Generate comprehensive investigation report

        Args:
            addresses: List of addresses to investigate
            include_timeline: Include timeline reconstruction
            include_network_graph: Include network relationship graph

        Returns:
            Complete investigation report
        """
        logger.info(f"Generating investigation report for {len(addresses)} addresses")

        report = {
            "generated_at": datetime.utcnow().isoformat(),
            "addresses_analyzed": len(addresses),
            "total_value_tracked": 0.0,
            "total_transactions": 0,
            "high_confidence_wallets": [],
            "exchange_cashouts": [],
            "suspicious_patterns": [],
            "timeline": [],
            "network_graph": None,
        }

        # Analyze each address
        for address in addresses:
            result = await self.track_address(address)
            report["total_transactions"] += len(result.get("transactions", []))

            if result.get("onecoin_confidence", 0) > 0.7:
                report["high_confidence_wallets"].append(address)

        # Generate timeline if requested
        if include_timeline:
            report["timeline"] = await self._reconstruct_timeline(addresses)

        # Generate network graph if requested
        if include_network_graph:
            report["network_graph"] = await self._generate_network_graph(addresses)

        return report

    # Private helper methods

    async def _analyze_transaction_patterns(self, transactions: List[Dict]) -> List[str]:
        """Analyze transactions for suspicious patterns"""
        patterns = []

        if not transactions:
            return patterns

        # Check for rapid splitting
        if len(transactions) > 10:
            time_span = (transactions[-1]["timestamp"] - transactions[0]["timestamp"]).total_seconds()
            if time_span < 3600:  # Less than 1 hour
                patterns.append("rapid_splitting")

        # Check for round amounts (common in fraud)
        round_amounts = sum(1 for tx in transactions if tx.get("amount", 0) % 1 == 0)
        if round_amounts / len(transactions) > 0.7:
            patterns.append("round_amounts")

        # Check for mixer usage
        for tx in transactions:
            if await self._is_mixer_address(tx.get("to_address")):
                patterns.append("mixer_usage")
                break

        return patterns

    async def _calculate_onecoin_confidence(
        self,
        address: str,
        transactions: List[Dict],
        patterns: List[str]
    ) -> float:
        """Calculate confidence score that address is OneCoin related"""
        confidence = 0.0

        # Direct connection to known OneCoin address
        if address in self.known_onecoin_addresses:
            return 1.0

        # Check transactions to/from known addresses
        connected_count = 0
        for tx in transactions:
            if tx.get("from_address") in self.known_onecoin_addresses or \
               tx.get("to_address") in self.known_onecoin_addresses:
                connected_count += 1

        if connected_count > 0:
            confidence += min(0.5, connected_count * 0.1)

        # Suspicious patterns
        confidence += len(patterns) * 0.1

        # High value (OneCoin moved billions)
        total_value = sum(tx.get("amount_usd", 0) for tx in transactions)
        if total_value > 1_000_000:
            confidence += 0.2

        return min(1.0, confidence)

    async def _check_exchange_deposits(self, transactions: List[Dict]) -> List[Dict]:
        """Check if any transactions are deposits to exchanges"""
        deposits = []

        for tx in transactions:
            exchange = await self._identify_exchange(tx.get("to_address"))
            if exchange:
                deposits.append({
                    "txid": tx.get("txid"),
                    "exchange": exchange,
                    "amount": tx.get("amount"),
                    "amount_usd": tx.get("amount_usd"),
                    "timestamp": tx.get("timestamp"),
                })

        return deposits

    async def _update_graph_relationships(self, address: str, results: Dict):
        """Update Neo4j graph with address relationships"""
        # Create address node
        await self.graph.create_address_node(address, results)

        # Create transaction relationships
        for tx in results.get("transactions", []):
            await self.graph.create_transaction_relationship(
                tx.get("from_address"),
                tx.get("to_address"),
                tx
            )

    async def _analyze_wallet(self, address: str, blockchain: str) -> OneCoinWallet:
        """Analyze a wallet and create OneCoinWallet object"""
        transactions = await self.api.get_address_transactions(address, blockchain)

        total_received = sum(
            tx.get("amount", 0)
            for tx in transactions
            if tx.get("to_address") == address
        )
        total_sent = sum(
            tx.get("amount", 0)
            for tx in transactions
            if tx.get("from_address") == address
        )

        return OneCoinWallet(
            address=address,
            blockchain=blockchain,
            first_seen=min(tx.get("timestamp") for tx in transactions) if transactions else datetime.utcnow(),
            last_activity=max(tx.get("timestamp") for tx in transactions) if transactions else datetime.utcnow(),
            total_received=total_received,
            total_sent=total_sent,
            balance=total_received - total_sent,
            confidence_score=0.0,
            owner_type="unknown",
        )

    async def _calculate_ruja_likelihood(
        self,
        wallet: OneCoinWallet,
        transaction: Dict
    ) -> float:
        """Calculate likelihood that wallet belongs to Ruja Ignatova"""
        score = 0.0

        # Very high value suggests top-level control
        if wallet.balance > 10_000_000:  # > $10M
            score += 0.4

        # Activity in 2014-2017 timeframe
        if wallet.first_seen.year >= 2014 and wallet.last_activity.year <= 2017:
            score += 0.2

        # Connected to known Ruja addresses
        for known_addr in self.known_ruja_addresses:
            if known_addr in wallet.connected_wallets:
                score += 0.3
                break

        # Pattern: large incoming, distributed outgoing (boss pattern)
        if wallet.total_received > wallet.total_sent * 0.9:
            score += 0.1

        return min(1.0, score)

    async def _trace_transaction_path(
        self,
        address: str,
        blockchain: str,
        max_hops: int = 10
    ) -> List[Dict]:
        """Trace the path of transactions from an address"""
        path = []
        current_address = address

        for hop in range(max_hops):
            # Get transactions from current address
            txs = await self.api.get_address_transactions(current_address, blockchain)

            if not txs:
                break

            # Take the largest outgoing transaction
            outgoing = [tx for tx in txs if tx.get("from_address") == current_address]
            if not outgoing:
                break

            largest_tx = max(outgoing, key=lambda x: x.get("amount_usd", 0))

            # Check if it's an exchange
            exchange = await self._identify_exchange(largest_tx.get("to_address"))

            path.append({
                "hop": hop,
                "address": largest_tx.get("to_address"),
                "amount": largest_tx.get("amount"),
                "amount_usd": largest_tx.get("amount_usd"),
                "timestamp": largest_tx.get("timestamp"),
                "is_exchange": exchange is not None,
                "exchange_name": exchange,
            })

            # Stop if we hit an exchange
            if exchange:
                break

            current_address = largest_tx.get("to_address")

        return path

    async def _analyze_laundering_path(
        self,
        txid: str,
        address: str,
        blockchain: str
    ) -> Dict:
        """Analyze a transaction path for money laundering indicators"""
        analysis = {
            "txid": txid,
            "is_suspicious": False,
            "indicators": [],
            "risk_score": 0,
        }

        # Trace the path
        path = await self._trace_transaction_path(address, blockchain)

        # Check for laundering indicators

        # 1. Multiple hops before exchange
        if len(path) > 5:
            analysis["indicators"].append("multiple_hops")
            analysis["risk_score"] += 20

        # 2. Mixer usage
        for hop in path:
            if await self._is_mixer_address(hop.get("address")):
                analysis["indicators"].append("mixer_usage")
                analysis["risk_score"] += 40

        # 3. Rapid movement (all hops within 24 hours)
        if path:
            time_span = (path[-1]["timestamp"] - path[0]["timestamp"]).total_seconds()
            if time_span < 86400:  # 24 hours
                analysis["indicators"].append("rapid_movement")
                analysis["risk_score"] += 15

        # 4. Amount splitting
        amounts = [hop.get("amount", 0) for hop in path]
        if len(set(amounts)) > len(amounts) * 0.8:  # Highly varied amounts
            analysis["indicators"].append("amount_splitting")
            analysis["risk_score"] += 10

        analysis["is_suspicious"] = analysis["risk_score"] > 50

        return analysis

    async def _reconstruct_timeline(self, addresses: List[str]) -> List[Dict]:
        """Reconstruct timeline of events for addresses"""
        all_transactions = []

        for address in addresses:
            txs = await self.api.get_address_transactions(address)
            all_transactions.extend(txs)

        # Sort by timestamp
        all_transactions.sort(key=lambda x: x.get("timestamp", datetime.min))

        timeline = []
        for tx in all_transactions:
            timeline.append({
                "timestamp": tx.get("timestamp").isoformat(),
                "event": "transaction",
                "from": tx.get("from_address"),
                "to": tx.get("to_address"),
                "amount_usd": tx.get("amount_usd"),
                "txid": tx.get("txid"),
            })

        return timeline

    async def _generate_network_graph(self, addresses: List[str]) -> Dict:
        """Generate network graph data for visualization"""
        nodes = []
        edges = []

        for address in addresses:
            # Add address as node
            wallet = await self._analyze_wallet(address, "btc")  # Default to BTC

            nodes.append({
                "id": address,
                "type": wallet.owner_type,
                "balance": wallet.balance,
                "total_received": wallet.total_received,
            })

            # Get transactions to create edges
            txs = await self.api.get_address_transactions(address)

            for tx in txs:
                edges.append({
                    "from": tx.get("from_address"),
                    "to": tx.get("to_address"),
                    "amount": tx.get("amount_usd"),
                    "timestamp": tx.get("timestamp").isoformat(),
                })

        return {
            "nodes": nodes,
            "edges": edges,
        }

    async def _is_mixer_address(self, address: str) -> bool:
        """Check if address is a known mixer"""
        # Check against known mixer addresses
        from ..config import KNOWN_MIXERS

        for mixer_type, addresses in KNOWN_MIXERS.items():
            if address in addresses:
                return True

        return False

    async def _identify_exchange(self, address: str) -> Optional[str]:
        """Identify if address belongs to an exchange"""
        from ..config import KNOWN_EXCHANGES

        for exchange_name, addresses in KNOWN_EXCHANGES.items():
            if address in addresses:
                return exchange_name

        return None
