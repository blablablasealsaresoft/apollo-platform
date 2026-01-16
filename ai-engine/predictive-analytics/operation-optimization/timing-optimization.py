"""
Predictive Analytics - Timing Optimization
Apollo Platform v0.1.0

Optimize timing of intervention/arrest for maximum success probability.
Balances evidence collection, flight risk, and operational readiness.
"""

import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class InvestigationState:
    """Current investigation state."""
    evidence_strength: float  # 0-1
    flight_risk: float  # 0-1
    network_activity: float  # 0-1
    resource_availability: float  # 0-1
    legal_readiness: float  # 0-1
    victim_safety: float  # 0-1
    days_since_start: int


class TimingOptimizer:
    """
    Optimize timing of intervention/arrest.

    Factors considered:
    - Evidence strength trajectory
    - Subject flight risk
    - Network activity levels
    - Resource availability
    - Legal requirements
    - Victim safety
    """

    def __init__(self):
        """Initialize timing optimizer."""
        self.factors = [
            'evidence_strength',
            'subject_behavior',
            'network_activity',
            'resource_availability',
            'legal_requirements',
            'victim_safety'
        ]

        self.factor_weights = {
            'evidence_strength': 0.30,
            'flight_risk': 0.25,
            'victim_safety': 0.20,
            'network_activity': 0.15,
            'resource_availability': 0.10
        }

        logger.info("Initialized TimingOptimizer")

    def optimize_intervention_timing(
        self,
        investigation: Dict,
        forecast_days: int = 90
    ) -> Dict:
        """
        Determine optimal time for intervention.

        Args:
            investigation: Investigation details dictionary
            forecast_days: Days to forecast ahead

        Returns:
            Optimization result with recommended timing
        """
        logger.info(f"Optimizing intervention timing for {investigation.get('case_id', 'UNKNOWN')}")

        # Analyze current evidence strength
        evidence_score = self._assess_evidence_strength(investigation)

        # Predict future evidence opportunities
        future_evidence = self._predict_future_evidence(investigation, forecast_days)

        # Assess subject flight risk
        flight_risk = self._assess_flight_risk(investigation)

        # Analyze network activity
        network_activity = self._analyze_network_activity(investigation)

        # Check resource availability
        resources = self._check_resource_availability(investigation)

        # Assess victim safety
        victim_safety = self._assess_victim_safety(investigation)

        # Calculate optimal timing
        optimal_date, alternatives = self._calculate_optimal_date(
            evidence_score,
            future_evidence,
            flight_risk,
            network_activity,
            resources,
            victim_safety,
            forecast_days
        )

        # Calculate success probability
        success_prob = self._predict_success_probability(optimal_date, investigation)

        # Identify risk factors
        risk_factors = self._identify_risk_factors(optimal_date, investigation)

        # Coordination requirements
        coordination = self._identify_coordination_needs(investigation)

        result = {
            'case_id': investigation.get('case_id'),
            'recommended_date': optimal_date['date'].strftime('%Y-%m-%d'),
            'days_from_now': optimal_date['days_from_now'],
            'confidence': optimal_date['confidence'],
            'success_probability': success_prob['success_probability'],
            'risk_factors': risk_factors,
            'alternative_dates': alternatives,
            'coordination_requirements': coordination,
            'current_evidence_strength': evidence_score,
            'current_flight_risk': flight_risk,
            'victim_safety_score': victim_safety,
            'recommended_actions': self._generate_action_plan(optimal_date, investigation)
        }

        logger.info(
            f"Optimal date: {result['recommended_date']}, "
            f"Success probability: {success_prob['success_probability']:.3f}"
        )

        return result

    def _assess_evidence_strength(self, investigation: Dict) -> float:
        """Assess current evidence strength (0-1)."""
        evidence_items = investigation.get('evidence', [])

        if not evidence_items:
            return 0.2

        # Weight different evidence types
        weights = {
            'direct': 1.0,
            'circumstantial': 0.6,
            'forensic': 0.9,
            'witness': 0.7,
            'digital': 0.8
        }

        total_weight = sum(
            weights.get(item.get('type'), 0.5)
            for item in evidence_items
        )

        # Normalize
        max_possible = len(evidence_items) * 1.0
        score = min(total_weight / max_possible, 1.0) if max_possible > 0 else 0

        return score

    def _predict_future_evidence(
        self,
        investigation: Dict,
        forecast_days: int
    ) -> List[Dict]:
        """Predict future evidence collection opportunities."""
        current_evidence = self._assess_evidence_strength(investigation)

        # Model evidence accumulation
        opportunities = []

        for day in range(1, forecast_days + 1):
            # Evidence accumulation rate (diminishing returns)
            accumulation_rate = 0.01 * np.exp(-day / 30)

            # Random evidence events (Poisson process)
            if np.random.random() < 0.1:  # 10% chance per day
                opportunities.append({
                    'day': day,
                    'date': datetime.now() + timedelta(days=day),
                    'type': 'evidence_opportunity',
                    'expected_strength_increase': accumulation_rate,
                    'probability': 0.7
                })

        return opportunities

    def _assess_flight_risk(self, investigation: Dict) -> float:
        """Assess subject flight risk (0-1)."""
        indicators = investigation.get('flight_risk_indicators', {})

        risk_score = 0.0

        # Passport activity
        if indicators.get('passport_activity', False):
            risk_score += 0.3

        # Asset liquidation
        if indicators.get('asset_liquidation', False):
            risk_score += 0.3

        # Communication changes
        if indicators.get('unusual_communication', False):
            risk_score += 0.2

        # Travel bookings
        if indicators.get('travel_bookings', False):
            risk_score += 0.4

        # Foreign connections
        if indicators.get('foreign_connections', False):
            risk_score += 0.2

        return min(risk_score, 1.0)

    def _analyze_network_activity(self, investigation: Dict) -> float:
        """Analyze criminal network activity level (0-1)."""
        activity_data = investigation.get('network_activity', {})

        # Recent activity
        recent_transactions = activity_data.get('recent_transactions', 0)
        recent_communications = activity_data.get('recent_communications', 0)

        # Normalize
        activity_score = min(
            (recent_transactions / 100 + recent_communications / 200) / 2,
            1.0
        )

        return activity_score

    def _check_resource_availability(self, investigation: Dict) -> Dict:
        """Check investigation resource availability."""
        required = investigation.get('resources_required', {})
        available = investigation.get('resources_available', {})

        return {
            'personnel_available': available.get('personnel', 0) >= required.get('personnel', 0),
            'budget_available': available.get('budget', 0) >= required.get('budget', 0),
            'equipment_available': available.get('equipment', 0) >= required.get('equipment', 0),
            'score': sum([
                available.get('personnel', 0) >= required.get('personnel', 0),
                available.get('budget', 0) >= required.get('budget', 0),
                available.get('equipment', 0) >= required.get('equipment', 0)
            ]) / 3
        }

    def _assess_victim_safety(self, investigation: Dict) -> float:
        """Assess victim safety considerations (0-1, higher is safer)."""
        victim_data = investigation.get('victim_safety', {})

        safety_score = 0.5  # Default

        # Immediate danger
        if victim_data.get('immediate_danger', False):
            safety_score = 0.1  # Very unsafe

        # Safe location
        elif victim_data.get('safe_location', False):
            safety_score = 0.9  # Very safe

        # Under protection
        elif victim_data.get('under_protection', False):
            safety_score = 0.8

        return safety_score

    def _calculate_optimal_date(
        self,
        evidence_score: float,
        future_evidence: List[Dict],
        flight_risk: float,
        network_activity: float,
        resources: Dict,
        victim_safety: float,
        forecast_days: int
    ) -> Tuple[Dict, List[Dict]]:
        """Calculate optimal intervention date."""
        scores = []

        for day in range(1, forecast_days + 1):
            date = datetime.now() + timedelta(days=day)

            # Project evidence strength
            projected_evidence = evidence_score + sum(
                opp['expected_strength_increase']
                for opp in future_evidence
                if opp['day'] <= day
            )
            projected_evidence = min(projected_evidence, 1.0)

            # Project flight risk (increases over time)
            projected_flight_risk = min(flight_risk + (day * 0.002), 1.0)

            # Resource availability (assume available in future)
            resource_score = resources['score']

            # Calculate composite score
            score = (
                self.factor_weights['evidence_strength'] * projected_evidence -
                self.factor_weights['flight_risk'] * projected_flight_risk +
                self.factor_weights['network_activity'] * network_activity +
                self.factor_weights['resource_availability'] * resource_score +
                self.factor_weights['victim_safety'] * victim_safety
            )

            # Urgency penalty (prefer sooner if victim safety is low)
            if victim_safety < 0.3:
                score -= (day * 0.01)  # Penalty for delay

            scores.append({
                'day': day,
                'date': date,
                'days_from_now': day,
                'score': score,
                'projected_evidence': projected_evidence,
                'projected_flight_risk': projected_flight_risk,
                'confidence': min(0.9 - (day * 0.005), 0.95)  # Decreases with time
            })

        # Find optimal
        scores.sort(key=lambda x: x['score'], reverse=True)

        optimal = scores[0]
        alternatives = scores[1:4]  # Top 3 alternatives

        return optimal, alternatives

    def _predict_success_probability(
        self,
        date: Dict,
        investigation: Dict
    ) -> Dict:
        """Predict probability of successful operation."""
        # Base probability from evidence strength
        base_prob = date['projected_evidence'] * 0.6

        # Adjust for flight risk
        flight_adjustment = (1 - date['projected_flight_risk']) * 0.2

        # Adjust for confidence
        confidence_adjustment = date['confidence'] * 0.2

        success_probability = base_prob + flight_adjustment + confidence_adjustment

        return {
            'success_probability': float(success_probability),
            'confidence_interval': (
                max(0, success_probability - 0.1),
                min(1, success_probability + 0.1)
            ),
            'key_success_factors': self._identify_success_factors(date, investigation),
            'risk_mitigation': self._recommend_risk_mitigation(date, investigation)
        }

    def _identify_risk_factors(
        self,
        date: Dict,
        investigation: Dict
    ) -> List[Dict]:
        """Identify risk factors for the operation."""
        risks = []

        # High flight risk
        if date['projected_flight_risk'] > 0.7:
            risks.append({
                'type': 'FLIGHT_RISK',
                'severity': 'HIGH',
                'description': 'Subject has high flight risk',
                'mitigation': 'Consider travel restrictions or earlier action'
            })

        # Low evidence strength
        if date['projected_evidence'] < 0.6:
            risks.append({
                'type': 'EVIDENCE_WEAKNESS',
                'severity': 'MEDIUM',
                'description': 'Evidence may not be sufficient',
                'mitigation': 'Continue evidence collection or wait for opportunity'
            })

        return risks

    def _identify_success_factors(
        self,
        date: Dict,
        investigation: Dict
    ) -> List[str]:
        """Identify key success factors."""
        factors = []

        if date['projected_evidence'] > 0.7:
            factors.append("Strong evidence base")

        if date['projected_flight_risk'] < 0.3:
            factors.append("Low flight risk")

        if date['confidence'] > 0.8:
            factors.append("High timing confidence")

        return factors

    def _recommend_risk_mitigation(
        self,
        date: Dict,
        investigation: Dict
    ) -> List[str]:
        """Recommend risk mitigation strategies."""
        mitigations = []

        if date['projected_flight_risk'] > 0.5:
            mitigations.append("Implement travel monitoring")
            mitigations.append("Coordinate with border agencies")

        if date['projected_evidence'] < 0.7:
            mitigations.append("Deploy additional surveillance")
            mitigations.append("Accelerate digital forensics")

        return mitigations

    def _identify_coordination_needs(self, investigation: Dict) -> Dict:
        """Identify inter-agency coordination requirements."""
        return {
            'multi_agency_required': investigation.get('multi_jurisdiction', False),
            'agencies_involved': investigation.get('agencies', []),
            'coordination_timeline': '2-4 weeks',
            'lead_agency': investigation.get('lead_agency', 'PRIMARY')
        }

    def _generate_action_plan(
        self,
        optimal_date: Dict,
        investigation: Dict
    ) -> List[Dict]:
        """Generate action plan leading to intervention."""
        days_to_action = optimal_date['days_from_now']

        plan = []

        # Immediate actions
        plan.append({
            'phase': 'IMMEDIATE',
            'timeframe': '1-7 days',
            'actions': [
                'Intensify surveillance',
                'Complete evidence documentation',
                'Brief team members'
            ]
        })

        # Pre-operation
        if days_to_action > 14:
            plan.append({
                'phase': 'PRE_OPERATION',
                'timeframe': '8-14 days',
                'actions': [
                    'Coordinate with partner agencies',
                    'Finalize operational plans',
                    'Conduct rehearsals'
                ]
            })

        # Final preparation
        plan.append({
            'phase': 'FINAL_PREPARATION',
            'timeframe': f'{max(1, days_to_action-7)}-{days_to_action} days',
            'actions': [
                'Confirm all resources',
                'Final intelligence review',
                'Execute operation'
            ]
        })

        return plan


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    investigation = {
        'case_id': 'CASE-2026-001',
        'evidence': [
            {'type': 'digital', 'strength': 0.8},
            {'type': 'forensic', 'strength': 0.7}
        ],
        'flight_risk_indicators': {
            'passport_activity': True,
            'asset_liquidation': False
        },
        'network_activity': {
            'recent_transactions': 50,
            'recent_communications': 100
        },
        'resources_required': {'personnel': 10, 'budget': 50000},
        'resources_available': {'personnel': 12, 'budget': 75000},
        'victim_safety': {'immediate_danger': False, 'safe_location': True}
    }

    optimizer = TimingOptimizer()
    result = optimizer.optimize_intervention_timing(investigation)

    print(f"Optimal timing: {result['recommended_date']}")
    print(f"Success probability: {result['success_probability']:.3f}")
    print(f"Risk factors: {len(result['risk_factors'])}")
