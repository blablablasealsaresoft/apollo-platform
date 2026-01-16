"""
Ruja Ignatova Wallet Identifier

Advanced heuristics for identifying wallets controlled by Ruja Ignatova
and her close associates in the OneCoin fraud operation.
"""

import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)


@dataclass
class WalletSignature:
    """Behavioral signature of a wallet"""

    avg_transaction_size: float
    transaction_frequency: float  # transactions per day
    active_hours: List[int]  # hours of day when active (0-23)
    preferred_amounts: List[float]  # common transaction amounts
    geographic_indicators: List[str]  # inferred locations
    counterparty_types: Dict[str, int]  # types of addresses interacted with


class RujaWalletIdentifier:
    """
    Identifies wallets likely controlled by Ruja Ignatova

    Uses multiple identification techniques:
    - Behavioral fingerprinting
    - Network analysis
    - Timing analysis
    - Amount patterns
    - Geographic indicators
    - Associate connections
    """

    def __init__(self, db_manager, api_manager, graph_client):
        self.db = db_manager
        self.api = api_manager
        self.graph = graph_client

        # Known Ruja characteristics (from investigations)
        self.ruja_characteristics = {
            "preferred_exchanges": ["binance", "bitstamp", "kraken"],
            "active_period": (datetime(2014, 1, 1), datetime(2017, 10, 1)),
            "typical_amounts": [50000, 100000, 250000, 500000, 1000000],  # USD
            "known_associates": self._load_known_associates(),
            "luxury_purchases": self._load_luxury_indicators(),
        }

        logger.info("Ruja Wallet Identifier initialized")

    def _load_known_associates(self) -> List[str]:
        """Load known Ruja Ignatova associates"""
        return [
            "konstantin_ignatov",  # Brother
            "sebastian_greenwood",  # Co-founder
            "mark_scott",  # Lawyer
            "gilbert_armenta",  # Lawyer
            "irina_dilkinska",  # Legal/compliance
        ]

    def _load_luxury_indicators(self) -> Dict[str, List[str]]:
        """Load addresses associated with luxury purchases"""
        return {
            "real_estate": [],  # Addresses of luxury real estate dealers
            "jewelry": [],  # High-end jewelry stores
            "yachts": [],  # Yacht dealers
            "private_aviation": [],  # Private jet services
        }

    async def identify_ruja_wallets(
        self,
        candidate_addresses: Optional[List[str]] = None,
        min_confidence: float = 0.7
    ) -> List[Dict]:
        """
        Identify wallets likely controlled by Ruja Ignatova

        Args:
            candidate_addresses: Specific addresses to analyze (or None for broad search)
            min_confidence: Minimum confidence score to return

        Returns:
            List of identified wallets with confidence scores
        """
        logger.info(f"Identifying Ruja wallets (min_confidence={min_confidence})")

        identified_wallets = []

        # If no candidates provided, find high-value wallets in timeframe
        if not candidate_addresses:
            candidate_addresses = await self._find_candidate_wallets()

        # Analyze each candidate
        for address in candidate_addresses:
            analysis = await self.analyze_wallet(address)

            if analysis["ruja_confidence"] >= min_confidence:
                identified_wallets.append({
                    "address": address,
                    "confidence": analysis["ruja_confidence"],
                    "indicators": analysis["indicators"],
                    "total_value": analysis["total_value"],
                    "first_activity": analysis["first_activity"],
                    "last_activity": analysis["last_activity"],
                })

        # Sort by confidence
        identified_wallets.sort(key=lambda x: x["confidence"], reverse=True)

        logger.info(f"Identified {len(identified_wallets)} potential Ruja wallets")
        return identified_wallets

    async def analyze_wallet(self, address: str, blockchain: str = "btc") -> Dict:
        """
        Comprehensive analysis of a wallet for Ruja indicators

        Returns detailed analysis with confidence score
        """
        logger.info(f"Analyzing wallet {address} for Ruja indicators")

        analysis = {
            "address": address,
            "blockchain": blockchain,
            "ruja_confidence": 0.0,
            "indicators": [],
            "total_value": 0.0,
            "first_activity": None,
            "last_activity": None,
            "behavioral_signature": None,
            "network_analysis": None,
        }

        try:
            # Get all transactions
            transactions = await self.api.get_address_transactions(address, blockchain)

            if not transactions:
                return analysis

            # Basic metrics
            analysis["first_activity"] = min(tx["timestamp"] for tx in transactions)
            analysis["last_activity"] = max(tx["timestamp"] for tx in transactions)
            analysis["total_value"] = sum(tx.get("amount_usd", 0) for tx in transactions)

            # Generate behavioral signature
            signature = await self._generate_wallet_signature(address, transactions)
            analysis["behavioral_signature"] = signature

            # Calculate confidence based on multiple factors
            confidence_score = 0.0

            # 1. Timeframe analysis (20 points)
            timeframe_score = await self._analyze_timeframe(analysis["first_activity"], analysis["last_activity"])
            if timeframe_score > 0:
                analysis["indicators"].append("active_during_onecoin_peak")
                confidence_score += timeframe_score

            # 2. Transaction patterns (25 points)
            pattern_score = await self._analyze_transaction_patterns(transactions, signature)
            if pattern_score > 0:
                analysis["indicators"].extend(["suspicious_patterns"])
                confidence_score += pattern_score

            # 3. Network connections (30 points)
            network_analysis = await self._analyze_network_connections(address, transactions)
            analysis["network_analysis"] = network_analysis
            if network_analysis["associate_connections"] > 0:
                analysis["indicators"].append("connected_to_associates")
                confidence_score += 30

            # 4. Value analysis (15 points)
            value_score = await self._analyze_value_patterns(transactions)
            if value_score > 0:
                analysis["indicators"].append("high_value_transactions")
                confidence_score += value_score

            # 5. Geographic indicators (10 points)
            geo_score = await self._analyze_geographic_indicators(transactions)
            if geo_score > 0:
                analysis["indicators"].append("geographic_match")
                confidence_score += geo_score

            # Normalize to 0-1
            analysis["ruja_confidence"] = min(1.0, confidence_score / 100)

            return analysis

        except Exception as e:
            logger.error(f"Error analyzing wallet {address}: {e}")
            return analysis

    async def compare_wallets(
        self,
        address1: str,
        address2: str
    ) -> Dict:
        """
        Compare two wallets to determine if likely controlled by same entity

        Returns similarity score and shared characteristics
        """
        logger.info(f"Comparing wallets {address1} and {address2}")

        # Analyze both wallets
        analysis1 = await self.analyze_wallet(address1)
        analysis2 = await self.analyze_wallet(address2)

        sig1 = analysis1["behavioral_signature"]
        sig2 = analysis2["behavioral_signature"]

        similarity = {
            "similarity_score": 0.0,
            "shared_counterparties": [],
            "timing_similarity": 0.0,
            "amount_pattern_similarity": 0.0,
            "likely_same_owner": False,
        }

        if not sig1 or not sig2:
            return similarity

        # Compare behavioral signatures

        # 1. Transaction size similarity
        size_diff = abs(sig1.avg_transaction_size - sig2.avg_transaction_size)
        size_similarity = max(0, 1 - (size_diff / max(sig1.avg_transaction_size, sig2.avg_transaction_size)))
        similarity["similarity_score"] += size_similarity * 30

        # 2. Timing similarity (active hours)
        common_hours = set(sig1.active_hours) & set(sig2.active_hours)
        timing_similarity = len(common_hours) / 24
        similarity["timing_similarity"] = timing_similarity
        similarity["similarity_score"] += timing_similarity * 25

        # 3. Shared counterparties
        # Get transactions for both
        txs1 = await self.api.get_address_transactions(address1)
        txs2 = await self.api.get_address_transactions(address2)

        counterparties1 = set(tx["to_address"] for tx in txs1 if tx["from_address"] == address1)
        counterparties2 = set(tx["to_address"] for tx in txs2 if tx["from_address"] == address2)

        shared = counterparties1 & counterparties2
        similarity["shared_counterparties"] = list(shared)

        if shared:
            similarity["similarity_score"] += min(30, len(shared) * 5)

        # 4. Preferred amounts similarity
        common_amounts = set(sig1.preferred_amounts) & set(sig2.preferred_amounts)
        if common_amounts:
            amount_similarity = len(common_amounts) / max(len(sig1.preferred_amounts), len(sig2.preferred_amounts))
            similarity["amount_pattern_similarity"] = amount_similarity
            similarity["similarity_score"] += amount_similarity * 15

        # Determine if likely same owner
        similarity["likely_same_owner"] = similarity["similarity_score"] > 70

        return similarity

    async def cluster_ruja_wallets(
        self,
        seed_addresses: List[str]
    ) -> Dict:
        """
        Cluster wallets likely all controlled by Ruja Ignatova

        Args:
            seed_addresses: Known or suspected Ruja addresses to start from

        Returns:
            Complete cluster of related wallets
        """
        logger.info(f"Clustering Ruja wallets from {len(seed_addresses)} seed addresses")

        cluster = {
            "seed_addresses": seed_addresses,
            "cluster_members": set(seed_addresses),
            "total_value": 0.0,
            "connections": [],
        }

        # Expand cluster iteratively
        to_explore = list(seed_addresses)
        explored = set()

        while to_explore:
            current_address = to_explore.pop(0)

            if current_address in explored:
                continue

            explored.add(current_address)

            # Get connected addresses
            txs = await self.api.get_address_transactions(current_address)

            for tx in txs:
                connected_addr = tx["to_address"] if tx["from_address"] == current_address else tx["from_address"]

                if connected_addr in explored:
                    continue

                # Check if connected address is similar to seed addresses
                max_similarity = 0.0
                for seed_addr in seed_addresses:
                    comparison = await self.compare_wallets(connected_addr, seed_addr)
                    max_similarity = max(max_similarity, comparison["similarity_score"] / 100)

                if max_similarity > 0.7:  # High similarity
                    cluster["cluster_members"].add(connected_addr)
                    to_explore.append(connected_addr)

                    cluster["connections"].append({
                        "from": current_address,
                        "to": connected_addr,
                        "similarity": max_similarity,
                    })

        # Calculate total value in cluster
        for address in cluster["cluster_members"]:
            analysis = await self.analyze_wallet(address)
            cluster["total_value"] += analysis["total_value"]

        cluster["cluster_members"] = list(cluster["cluster_members"])

        logger.info(
            f"Clustered {len(cluster['cluster_members'])} wallets "
            f"worth ${cluster['total_value']:,.2f}"
        )

        return cluster

    # Private helper methods

    async def _find_candidate_wallets(self) -> List[str]:
        """Find candidate wallets for Ruja identification"""
        # Query database for high-value wallets in OneCoin timeframe
        start_date = self.ruja_characteristics["active_period"][0]
        end_date = self.ruja_characteristics["active_period"][1]

        candidates = await self.db.query_wallets(
            start_date=start_date,
            end_date=end_date,
            min_value_usd=500_000,  # Minimum $500k
            limit=1000
        )

        return [wallet["address"] for wallet in candidates]

    async def _generate_wallet_signature(
        self,
        address: str,
        transactions: List[Dict]
    ) -> WalletSignature:
        """Generate behavioral signature for a wallet"""

        # Calculate average transaction size
        amounts = [tx.get("amount_usd", 0) for tx in transactions]
        avg_amount = sum(amounts) / len(amounts) if amounts else 0

        # Calculate transaction frequency
        if len(transactions) > 1:
            time_span = (transactions[-1]["timestamp"] - transactions[0]["timestamp"]).days
            frequency = len(transactions) / max(time_span, 1)
        else:
            frequency = 0

        # Determine active hours
        active_hours = []
        hour_counts = {}
        for tx in transactions:
            hour = tx["timestamp"].hour
            hour_counts[hour] = hour_counts.get(hour, 0) + 1

        # Top 8 active hours
        active_hours = sorted(hour_counts.keys(), key=lambda h: hour_counts[h], reverse=True)[:8]

        # Find preferred amounts (rounded amounts that appear frequently)
        amount_counts = {}
        for amount in amounts:
            # Round to nearest 10k
            rounded = round(amount / 10000) * 10000
            amount_counts[rounded] = amount_counts.get(rounded, 0) + 1

        preferred_amounts = [
            amt for amt, count in amount_counts.items()
            if count > 2 and amt > 0
        ][:5]

        # Analyze counterparties
        counterparty_types = {}
        for tx in transactions:
            counterparty = tx["to_address"] if tx["from_address"] == address else tx["from_address"]

            # Determine type
            cp_type = await self._classify_address(counterparty)
            counterparty_types[cp_type] = counterparty_types.get(cp_type, 0) + 1

        return WalletSignature(
            avg_transaction_size=avg_amount,
            transaction_frequency=frequency,
            active_hours=active_hours,
            preferred_amounts=preferred_amounts,
            geographic_indicators=[],  # Would need additional data
            counterparty_types=counterparty_types,
        )

    async def _analyze_timeframe(
        self,
        first_activity: datetime,
        last_activity: datetime
    ) -> float:
        """Analyze if wallet activity aligns with Ruja's active period"""
        score = 0.0

        ruja_start, ruja_end = self.ruja_characteristics["active_period"]

        # Active during OneCoin peak
        if first_activity >= ruja_start and first_activity <= ruja_end:
            score += 10

        # Stopped activity around when Ruja disappeared
        if last_activity >= datetime(2017, 9, 1) and last_activity <= datetime(2017, 11, 1):
            score += 10  # Very suspicious

        return score

    async def _analyze_transaction_patterns(
        self,
        transactions: List[Dict],
        signature: WalletSignature
    ) -> float:
        """Analyze transaction patterns for Ruja indicators"""
        score = 0.0

        # High average transaction size
        if signature.avg_transaction_size > 100_000:
            score += 10

        # Preferred amounts match known patterns
        for amount in signature.preferred_amounts:
            if amount in self.ruja_characteristics["typical_amounts"]:
                score += 5

        # High transaction frequency (active trader)
        if signature.transaction_frequency > 1:  # > 1 tx per day
            score += 5

        return min(25, score)

    async def _analyze_network_connections(
        self,
        address: str,
        transactions: List[Dict]
    ) -> Dict:
        """Analyze network connections for associate links"""
        analysis = {
            "associate_connections": 0,
            "exchange_connections": {},
            "mixer_usage": False,
        }

        # Get known associate addresses from database
        associate_addresses = await self.db.get_associate_addresses(
            self.ruja_characteristics["known_associates"]
        )

        # Check transactions for associate connections
        for tx in transactions:
            counterparty = tx["to_address"] if tx["from_address"] == address else tx["from_address"]

            if counterparty in associate_addresses:
                analysis["associate_connections"] += 1

            # Check for exchange
            exchange = await self._identify_exchange(counterparty)
            if exchange:
                analysis["exchange_connections"][exchange] = \
                    analysis["exchange_connections"].get(exchange, 0) + 1

            # Check for mixer
            if await self._is_mixer_address(counterparty):
                analysis["mixer_usage"] = True

        return analysis

    async def _analyze_value_patterns(self, transactions: List[Dict]) -> float:
        """Analyze value patterns"""
        score = 0.0

        total_value = sum(tx.get("amount_usd", 0) for tx in transactions)

        # Very high total value
        if total_value > 10_000_000:  # > $10M
            score += 15
        elif total_value > 1_000_000:  # > $1M
            score += 10
        elif total_value > 100_000:  # > $100k
            score += 5

        return score

    async def _analyze_geographic_indicators(self, transactions: List[Dict]) -> float:
        """Analyze geographic indicators (requires additional data sources)"""
        # This would require IP data, exchange data, etc.
        # Placeholder implementation
        return 0.0

    async def _classify_address(self, address: str) -> str:
        """Classify an address by type"""
        # Check if it's an exchange
        exchange = await self._identify_exchange(address)
        if exchange:
            return f"exchange:{exchange}"

        # Check if it's a mixer
        if await self._is_mixer_address(address):
            return "mixer"

        # Check if it's a known associate
        associate_addresses = await self.db.get_all_associate_addresses()
        if address in associate_addresses:
            return "associate"

        return "unknown"

    async def _identify_exchange(self, address: str) -> Optional[str]:
        """Identify if address belongs to an exchange"""
        from ..config import KNOWN_EXCHANGES

        for exchange_name, addresses in KNOWN_EXCHANGES.items():
            if address in addresses:
                return exchange_name

        return None

    async def _is_mixer_address(self, address: str) -> bool:
        """Check if address is a known mixer"""
        from ..config import KNOWN_MIXERS

        for mixer_type, addresses in KNOWN_MIXERS.items():
            if address in addresses:
                return True

        return False
