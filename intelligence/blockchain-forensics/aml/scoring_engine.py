"""
AML Scoring Engine

Calculates risk scores (0-100) for cryptocurrency addresses based on:
- Transaction patterns
- Connections to known bad actors
- Mixer/tumbler usage
- Exchange interactions
- Volume and velocity
"""

import asyncio
from typing import Dict, List, Optional
from dataclasses import dataclass
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)


@dataclass
class RiskScore:
    """Risk score for an address"""

    address: str
    total_score: int  # 0-100
    risk_level: str  # low, medium, high, critical
    risk_factors: Dict[str, int]  # factor -> score contribution
    red_flags: List[str]
    timestamp: datetime


class AMLScoringEngine:
    """
    AML Scoring Engine

    Calculates comprehensive risk scores for cryptocurrency addresses
    """

    def __init__(self, db_manager, api_manager, config):
        self.db = db_manager
        self.api = api_manager
        self.config = config

        # Risk thresholds
        self.thresholds = {
            "low": 25,
            "medium": 50,
            "high": 75,
            "critical": 90,
        }

        logger.info("AML Scoring Engine initialized")

    async def calculate_risk_score(
        self,
        address: str,
        blockchain: str = "btc"
    ) -> RiskScore:
        """
        Calculate comprehensive risk score for an address

        Score breakdown (0-100):
        - Known bad actors: 40 points
        - Mixer/tumbler usage: 25 points
        - Suspicious patterns: 20 points
        - Volume/velocity: 10 points
        - Other factors: 5 points
        """
        logger.info(f"Calculating AML risk score for {address}")

        risk_factors = {}
        red_flags = []
        total_score = 0

        # Get transactions
        transactions = await self.api.get_address_transactions(address, blockchain)

        if not transactions:
            return RiskScore(
                address=address,
                total_score=0,
                risk_level="unknown",
                risk_factors={},
                red_flags=["no_transaction_data"],
                timestamp=datetime.utcnow(),
            )

        # 1. Known bad actors (40 points)
        bad_actor_score = await self._check_known_bad_actors(address, transactions)
        if bad_actor_score > 0:
            risk_factors["known_bad_actors"] = bad_actor_score
            total_score += bad_actor_score

            if bad_actor_score >= 30:
                red_flags.append("direct_connection_to_criminal_addresses")
            elif bad_actor_score >= 15:
                red_flags.append("indirect_connection_to_criminal_addresses")

        # 2. Mixer/tumbler usage (25 points)
        mixer_score = await self._check_mixer_usage(address, transactions)
        if mixer_score > 0:
            risk_factors["mixer_usage"] = mixer_score
            total_score += mixer_score

            if mixer_score >= 20:
                red_flags.append("heavy_mixer_usage")
            elif mixer_score >= 10:
                red_flags.append("moderate_mixer_usage")

        # 3. Suspicious patterns (20 points)
        pattern_score = await self._analyze_suspicious_patterns(transactions)
        if pattern_score > 0:
            risk_factors["suspicious_patterns"] = pattern_score
            total_score += pattern_score

        # 4. Volume/velocity (10 points)
        volume_score = await self._analyze_volume_velocity(transactions)
        if volume_score > 0:
            risk_factors["high_volume_velocity"] = volume_score
            total_score += volume_score

        # 5. Sanctioned entities (auto-critical)
        sanctioned = await self._check_sanctioned_entities(address)
        if sanctioned:
            total_score = 100
            red_flags.append("sanctioned_entity")
            risk_factors["sanctioned"] = 100

        # 6. Exchange interactions (can reduce score)
        exchange_score = await self._analyze_exchange_usage(transactions)
        if exchange_score < 0:  # Regulated exchanges reduce risk
            risk_factors["regulated_exchange_usage"] = exchange_score
            total_score += exchange_score

        # 7. Age and activity (can reduce score)
        age_score = await self._analyze_address_age(transactions)
        if age_score < 0:  # Older, stable addresses are less risky
            risk_factors["address_age"] = age_score
            total_score += age_score

        # Cap score at 0-100
        total_score = max(0, min(100, total_score))

        # Determine risk level
        if total_score >= self.thresholds["critical"]:
            risk_level = "critical"
        elif total_score >= self.thresholds["high"]:
            risk_level = "high"
        elif total_score >= self.thresholds["medium"]:
            risk_level = "medium"
        else:
            risk_level = "low"

        return RiskScore(
            address=address,
            total_score=total_score,
            risk_level=risk_level,
            risk_factors=risk_factors,
            red_flags=red_flags,
            timestamp=datetime.utcnow(),
        )

    async def batch_score_addresses(
        self,
        addresses: List[str],
        blockchain: str = "btc"
    ) -> Dict[str, RiskScore]:
        """Score multiple addresses in parallel"""
        logger.info(f"Batch scoring {len(addresses)} addresses")

        tasks = [
            self.calculate_risk_score(addr, blockchain)
            for addr in addresses
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        scores = {}
        for addr, result in zip(addresses, results):
            if isinstance(result, Exception):
                logger.error(f"Error scoring {addr}: {result}")
                continue
            scores[addr] = result

        return scores

    async def generate_compliance_report(
        self,
        address: str,
        blockchain: str = "btc"
    ) -> Dict:
        """
        Generate detailed compliance report for an address

        Suitable for regulatory submission
        """
        logger.info(f"Generating compliance report for {address}")

        # Calculate risk score
        risk_score = await self.calculate_risk_score(address, blockchain)

        # Get transaction history
        transactions = await self.api.get_address_transactions(address, blockchain)

        # Analyze counterparties
        counterparties = set()
        high_risk_counterparties = []

        for tx in transactions:
            counterparty = tx["to_address"] if tx["from_address"] == address else tx["from_address"]
            counterparties.add(counterparty)

            # Score counterparty
            cp_score = await self.calculate_risk_score(counterparty, blockchain)
            if cp_score.total_score >= self.thresholds["high"]:
                high_risk_counterparties.append({
                    "address": counterparty,
                    "risk_score": cp_score.total_score,
                    "risk_level": cp_score.risk_level,
                })

        # Calculate total volume
        total_received = sum(
            tx.get("amount_usd", 0)
            for tx in transactions
            if tx["to_address"] == address
        )
        total_sent = sum(
            tx.get("amount_usd", 0)
            for tx in transactions
            if tx["from_address"] == address
        )

        report = {
            "address": address,
            "blockchain": blockchain,
            "report_date": datetime.utcnow().isoformat(),
            "risk_assessment": {
                "total_score": risk_score.total_score,
                "risk_level": risk_score.risk_level,
                "risk_factors": risk_score.risk_factors,
                "red_flags": risk_score.red_flags,
            },
            "transaction_summary": {
                "total_transactions": len(transactions),
                "total_received_usd": total_received,
                "total_sent_usd": total_sent,
                "net_balance_usd": total_received - total_sent,
                "first_transaction": transactions[0]["timestamp"].isoformat() if transactions else None,
                "last_transaction": transactions[-1]["timestamp"].isoformat() if transactions else None,
            },
            "counterparty_analysis": {
                "total_counterparties": len(counterparties),
                "high_risk_counterparties": len(high_risk_counterparties),
                "high_risk_details": high_risk_counterparties[:10],  # Top 10
            },
            "recommendations": self._generate_recommendations(risk_score),
        }

        return report

    # Private helper methods

    async def _check_known_bad_actors(
        self,
        address: str,
        transactions: List[Dict]
    ) -> int:
        """Check connections to known criminal addresses"""
        score = 0

        # Load known bad addresses
        from ..config import KNOWN_RANSOMWARE

        all_bad_addresses = set()
        for ransomware_type, addresses in KNOWN_RANSOMWARE.items():
            all_bad_addresses.update(addresses)

        # Check direct connection
        for tx in transactions:
            counterparty = tx["to_address"] if tx["from_address"] == address else tx["from_address"]

            if counterparty in all_bad_addresses:
                score += 20  # Direct connection

        return min(40, score)

    async def _check_mixer_usage(
        self,
        address: str,
        transactions: List[Dict]
    ) -> int:
        """Check mixer/tumbler usage"""
        score = 0

        from ..config import KNOWN_MIXERS

        mixer_addresses = set()
        for mixer_type, addresses in KNOWN_MIXERS.items():
            mixer_addresses.update(addresses)

        mixer_tx_count = 0
        for tx in transactions:
            counterparty = tx["to_address"] if tx["from_address"] == address else tx["from_address"]

            if counterparty in mixer_addresses:
                mixer_tx_count += 1

        # Score based on mixer usage frequency
        if mixer_tx_count > 0:
            mixer_ratio = mixer_tx_count / len(transactions)
            score = int(mixer_ratio * 25)

        return min(25, score)

    async def _analyze_suspicious_patterns(self, transactions: List[Dict]) -> int:
        """Analyze for suspicious transaction patterns"""
        score = 0

        if not transactions:
            return 0

        # Pattern 1: Rapid transaction velocity
        if len(transactions) > 50:
            time_span = (transactions[-1]["timestamp"] - transactions[0]["timestamp"]).days
            if time_span < 7:  # 50+ transactions in a week
                score += 8

        # Pattern 2: Round amounts (common in fraud)
        round_amounts = sum(
            1 for tx in transactions
            if tx.get("amount", 0) % 1 == 0 and tx.get("amount", 0) > 0
        )
        if round_amounts / len(transactions) > 0.7:  # 70%+ round amounts
            score += 5

        # Pattern 3: Structuring (amounts just below reporting threshold)
        # Common threshold is $10k
        structuring_amounts = sum(
            1 for tx in transactions
            if 9000 <= tx.get("amount_usd", 0) <= 9999
        )
        if structuring_amounts > 3:
            score += 7

        return min(20, score)

    async def _analyze_volume_velocity(self, transactions: List[Dict]) -> int:
        """Analyze transaction volume and velocity"""
        score = 0

        if not transactions:
            return 0

        # Calculate total volume
        total_volume = sum(tx.get("amount_usd", 0) for tx in transactions)

        # Very high volume
        if total_volume > 10_000_000:  # > $10M
            score += 5
        elif total_volume > 1_000_000:  # > $1M
            score += 3

        # High velocity (many transactions in short time)
        if len(transactions) > 100:
            time_span = (transactions[-1]["timestamp"] - transactions[0]["timestamp"]).days
            if time_span > 0:
                tx_per_day = len(transactions) / time_span
                if tx_per_day > 10:  # > 10 tx/day
                    score += 5

        return min(10, score)

    async def _check_sanctioned_entities(self, address: str) -> bool:
        """Check if address is on sanctions list"""
        # In production, integrate with OFAC SDN list, UN sanctions, etc.
        # For now, placeholder
        return False

    async def _analyze_exchange_usage(self, transactions: List[Dict]) -> int:
        """Analyze exchange usage (can reduce score)"""
        from ..config import KNOWN_EXCHANGES

        exchange_addresses = set()
        for exchange_name, addresses in KNOWN_EXCHANGES.items():
            exchange_addresses.update(addresses)

        exchange_tx_count = 0
        for tx in transactions:
            counterparty = tx["to_address"] if tx["from_address"] == address else tx["from_address"]

            if counterparty in exchange_addresses:
                exchange_tx_count += 1

        # Heavy regulated exchange usage reduces risk slightly
        if exchange_tx_count > len(transactions) * 0.5:  # > 50% exchange transactions
            return -5

        return 0

    async def _analyze_address_age(self, transactions: List[Dict]) -> int:
        """Analyze address age (older = less risky, generally)"""
        if not transactions:
            return 0

        first_tx = min(tx["timestamp"] for tx in transactions)
        age_days = (datetime.utcnow() - first_tx).days

        # Very old addresses with consistent activity are less risky
        if age_days > 365 * 3:  # > 3 years
            return -3
        elif age_days > 365:  # > 1 year
            return -1

        return 0

    def _generate_recommendations(self, risk_score: RiskScore) -> List[str]:
        """Generate recommendations based on risk score"""
        recommendations = []

        if risk_score.risk_level == "critical":
            recommendations.extend([
                "IMMEDIATE ACTION REQUIRED: Do not process transactions",
                "File Suspicious Activity Report (SAR)",
                "Freeze account pending investigation",
                "Notify law enforcement",
            ])
        elif risk_score.risk_level == "high":
            recommendations.extend([
                "Enhanced due diligence required",
                "Request source of funds documentation",
                "Monitor closely for suspicious activity",
                "Consider filing SAR",
            ])
        elif risk_score.risk_level == "medium":
            recommendations.extend([
                "Standard due diligence required",
                "Monitor for unusual patterns",
                "Request additional KYC information if needed",
            ])
        else:
            recommendations.extend([
                "Standard monitoring procedures",
                "No immediate action required",
            ])

        return recommendations
