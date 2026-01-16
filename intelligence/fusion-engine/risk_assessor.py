"""
Risk Assessment System
Advanced threat level calculation and predictive risk modeling
"""

from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
import math


class RiskAssessor:
    """
    Risk Assessment Engine
    Calculates threat levels based on behavioral patterns, network analysis, and threat indicators
    """

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize Risk Assessor

        Args:
            config: Configuration dictionary
        """
        self.high_threshold = config.get('high_threshold', 75)
        self.medium_threshold = config.get('medium_threshold', 50)
        self.low_threshold = config.get('low_threshold', 25)

        # Risk factor weights
        self.risk_weights = {
            'breach_exposure': 0.20,
            'behavioral_patterns': 0.25,
            'network_risk': 0.20,
            'geographic_risk': 0.10,
            'temporal_patterns': 0.15,
            'known_indicators': 0.10
        }

        # Known threat indicators
        self.threat_indicators = {
            'high_risk_domains': [
                'tempmail.com', 'guerrillamail.com', '10minutemail.com',
                'throwaway.email', 'mailinator.com'
            ],
            'high_risk_keywords': [
                'fraud', 'scam', 'hack', 'breach', 'ransom', 'darknet',
                'cryptocurrency', 'laundering', 'phishing'
            ],
            'suspicious_patterns': [
                'multiple_aliases', 'location_hopping', 'rapid_transactions',
                'anonymization_tools', 'tor_usage'
            ]
        }

    def assess_risk(self, profile: Any, correlations: Dict[str, Any]) -> float:
        """
        Calculate overall risk score for an entity

        Args:
            profile: EntityProfile object
            correlations: Correlation results from CorrelationEngine

        Returns:
            Risk score (0-100)
        """
        risk_factors = []

        # 1. Breach Exposure Risk
        breach_risk = self._calculate_breach_risk(profile)
        risk_factors.append(('breach_exposure', breach_risk, self.risk_weights['breach_exposure']))

        # 2. Behavioral Pattern Risk
        behavioral_risk = self._calculate_behavioral_risk(profile)
        risk_factors.append(('behavioral_patterns', behavioral_risk, self.risk_weights['behavioral_patterns']))

        # 3. Network Risk
        network_risk = self._calculate_network_risk(profile, correlations)
        risk_factors.append(('network_risk', network_risk, self.risk_weights['network_risk']))

        # 4. Geographic Risk
        geographic_risk = self._calculate_geographic_risk(profile)
        risk_factors.append(('geographic_risk', geographic_risk, self.risk_weights['geographic_risk']))

        # 5. Temporal Pattern Risk
        temporal_risk = self._calculate_temporal_risk(profile)
        risk_factors.append(('temporal_patterns', temporal_risk, self.risk_weights['temporal_patterns']))

        # 6. Known Threat Indicators
        indicator_risk = self._calculate_indicator_risk(profile)
        risk_factors.append(('known_indicators', indicator_risk, self.risk_weights['known_indicators']))

        # Calculate weighted risk score
        total_risk = sum(risk * weight for _, risk, weight in risk_factors)

        # Normalize to 0-100
        risk_score = total_risk * 100

        # Apply multipliers for critical factors
        if self._has_critical_indicators(profile):
            risk_score *= 1.25  # 25% increase for critical indicators

        # Cap at 100
        risk_score = min(risk_score, 100.0)

        return round(risk_score, 2)

    def _calculate_breach_risk(self, profile: Any) -> float:
        """Calculate risk from data breach exposure"""
        risk = 0.0

        # Count breach-related sources
        breach_sources = [s for s in profile.sources if 'breach' in s.lower()]
        breach_count = len(breach_sources)

        # Risk increases with number of breaches
        if breach_count >= 5:
            risk = 0.9
        elif breach_count >= 3:
            risk = 0.7
        elif breach_count >= 1:
            risk = 0.4
        else:
            risk = 0.1

        # Check for password exposure in attributes
        if 'password' in profile.attributes or 'password_hash' in profile.attributes:
            risk += 0.1

        # Check for sensitive data exposure
        sensitive_attrs = ['ssn', 'credit_card', 'passport', 'license']
        exposed_sensitive = sum(1 for attr in sensitive_attrs if attr in profile.attributes)
        risk += exposed_sensitive * 0.05

        return min(risk, 1.0)

    def _calculate_behavioral_risk(self, profile: Any) -> float:
        """Calculate risk from behavioral patterns"""
        risk = 0.0

        # Check for suspicious patterns in metadata
        patterns = profile.metadata.get('patterns', [])

        for pattern in patterns:
            pattern_type = pattern.get('type', '')
            severity = pattern.get('severity', 'low')

            if pattern_type == 'multiple_aliases':
                if pattern.get('count', 0) >= 5:
                    risk += 0.3
                else:
                    risk += 0.15

            elif pattern_type == 'repeated_breaches':
                risk += 0.25

            elif pattern_type == 'multiple_wallets':
                if pattern.get('count', 0) >= 5:
                    risk += 0.2
                else:
                    risk += 0.1

            elif pattern_type == 'geographic_dispersion':
                if pattern.get('count', 0) >= 5:
                    risk += 0.2

            # Severity-based risk
            if severity == 'high':
                risk += 0.1
            elif severity == 'medium':
                risk += 0.05

        # Check for anonymization indicators
        attrs = profile.attributes
        if 'vpn' in str(attrs).lower() or 'tor' in str(attrs).lower():
            risk += 0.15

        return min(risk, 1.0)

    def _calculate_network_risk(self, profile: Any, correlations: Dict[str, Any]) -> float:
        """Calculate risk from network connections"""
        risk = 0.0

        relationships = profile.relationships

        # High connectivity can indicate central role in network
        if len(relationships) >= 10:
            risk += 0.4
        elif len(relationships) >= 5:
            risk += 0.2
        elif len(relationships) >= 2:
            risk += 0.1

        # Check relationship types
        relationship_types = [r.get('type') for r in relationships]

        # Multiple ownership relationships (wallets, domains, etc.)
        owns_count = relationship_types.count('owns')
        if owns_count >= 3:
            risk += 0.2

        # Check for high-risk relationship partners
        # (This would integrate with external threat feeds in production)
        high_risk_partners = sum(
            1 for r in relationships
            if r.get('score', 0) > 0.8  # Strong connections
        )
        if high_risk_partners >= 3:
            risk += 0.15

        # Cluster analysis
        clusters = correlations.get('clusters', [])
        for cluster in clusters:
            if profile.entity_id in cluster.get('entities', []):
                # Large clusters can indicate organized activity
                if cluster.get('size', 0) >= 5:
                    risk += 0.15
                break

        return min(risk, 1.0)

    def _calculate_geographic_risk(self, profile: Any) -> float:
        """Calculate risk from geographic factors"""
        risk = 0.0

        locations = profile.attributes.get('locations', [])
        if isinstance(locations, str):
            locations = [locations]

        # High-risk countries/regions (OFAC, sanctions, etc.)
        high_risk_countries = [
            'russia', 'iran', 'north korea', 'syria', 'venezuela',
            'crimea', 'belarus', 'myanmar'
        ]

        # Check for presence in high-risk locations
        for location in locations:
            location_lower = str(location).lower()
            for high_risk in high_risk_countries:
                if high_risk in location_lower:
                    risk += 0.3
                    break

        # Multiple disparate locations can indicate evasion
        if len(locations) >= 5:
            risk += 0.2
        elif len(locations) >= 3:
            risk += 0.1

        # Check for known tax havens
        tax_havens = ['cayman', 'panama', 'bermuda', 'bahamas', 'switzerland', 'malta']
        for location in locations:
            location_lower = str(location).lower()
            for haven in tax_havens:
                if haven in location_lower:
                    risk += 0.15
                    break

        return min(risk, 1.0)

    def _calculate_temporal_risk(self, profile: Any) -> float:
        """Calculate risk from temporal patterns"""
        risk = 0.0

        timeline = profile.timeline

        if not timeline:
            return 0.0

        # Recent activity spike
        if len(timeline) >= 10:
            # Check for activity clustering
            recent_cutoff = datetime.now() - timedelta(days=30)
            recent_events = [
                e for e in timeline
                if 'timestamp' in e and self._parse_timestamp(e['timestamp']) > recent_cutoff
            ]

            if len(recent_events) >= 5:
                risk += 0.3  # High recent activity

        # Rapid account creation (multiple accounts in short time)
        creation_events = [
            e for e in timeline
            if 'created' in str(e.get('description', '')).lower()
        ]

        if len(creation_events) >= 3:
            # Check if clustered in time
            timestamps = [self._parse_timestamp(e['timestamp']) for e in creation_events if 'timestamp' in e]
            if timestamps:
                time_span = (max(timestamps) - min(timestamps)).days
                if time_span <= 30:
                    risk += 0.25  # Multiple accounts in short time

        # Dormancy followed by sudden activity
        if len(timeline) >= 5:
            sorted_timeline = sorted(
                timeline,
                key=lambda e: self._parse_timestamp(e.get('timestamp', ''))
            )

            # Check for long gaps
            for i in range(1, len(sorted_timeline)):
                prev_time = self._parse_timestamp(sorted_timeline[i-1].get('timestamp', ''))
                curr_time = self._parse_timestamp(sorted_timeline[i].get('timestamp', ''))

                gap_days = (curr_time - prev_time).days
                if gap_days >= 180:  # 6-month dormancy
                    risk += 0.15
                    break

        return min(risk, 1.0)

    def _calculate_indicator_risk(self, profile: Any) -> float:
        """Calculate risk from known threat indicators"""
        risk = 0.0

        attrs = profile.attributes

        # Check for high-risk email domains
        email = attrs.get('email', '')
        if email:
            domain = email.split('@')[1] if '@' in email else ''
            if any(high_risk in domain for high_risk in self.threat_indicators['high_risk_domains']):
                risk += 0.4

        # Check for high-risk keywords in any attribute
        profile_text = str(attrs).lower()
        keyword_matches = sum(
            1 for keyword in self.threat_indicators['high_risk_keywords']
            if keyword in profile_text
        )
        risk += min(keyword_matches * 0.1, 0.4)

        # Check for cryptocurrency activity (can be legitimate but increases risk)
        if 'wallet' in attrs or 'cryptocurrency' in profile_text:
            risk += 0.15

        # Check for darknet/tor indicators
        if 'onion' in profile_text or 'tor' in profile_text or 'i2p' in profile_text:
            risk += 0.25

        return min(risk, 1.0)

    def _has_critical_indicators(self, profile: Any) -> bool:
        """Check for critical threat indicators"""
        critical_keywords = ['ransomware', 'exploit', 'malware', 'botnet', 'terrorism']

        profile_text = str(profile.attributes).lower()

        return any(keyword in profile_text for keyword in critical_keywords)

    def _parse_timestamp(self, timestamp_str: str) -> datetime:
        """Parse timestamp string to datetime"""
        if isinstance(timestamp_str, datetime):
            return timestamp_str

        try:
            return datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        except Exception:
            return datetime.now()

    def categorize_risk(self, risk_score: float) -> str:
        """
        Categorize risk score into risk levels

        Args:
            risk_score: Risk score (0-100)

        Returns:
            Risk category (CRITICAL, HIGH, MEDIUM, LOW)
        """
        if risk_score >= 90:
            return 'CRITICAL'
        elif risk_score >= self.high_threshold:
            return 'HIGH'
        elif risk_score >= self.medium_threshold:
            return 'MEDIUM'
        elif risk_score >= self.low_threshold:
            return 'LOW'
        else:
            return 'MINIMAL'

    def get_risk_breakdown(self, profile: Any, correlations: Dict[str, Any]) -> Dict[str, Any]:
        """
        Get detailed breakdown of risk calculation

        Args:
            profile: EntityProfile object
            correlations: Correlation results

        Returns:
            Dictionary with detailed risk metrics
        """
        breakdown = {
            'overall_risk': self.assess_risk(profile, correlations),
            'risk_category': '',
            'components': {},
            'threat_indicators': [],
            'recommendations': []
        }

        # Calculate component risks
        breakdown['components']['breach_exposure'] = {
            'score': self._calculate_breach_risk(profile) * 100,
            'weight': self.risk_weights['breach_exposure']
        }
        breakdown['components']['behavioral_patterns'] = {
            'score': self._calculate_behavioral_risk(profile) * 100,
            'weight': self.risk_weights['behavioral_patterns']
        }
        breakdown['components']['network_risk'] = {
            'score': self._calculate_network_risk(profile, correlations) * 100,
            'weight': self.risk_weights['network_risk']
        }
        breakdown['components']['geographic_risk'] = {
            'score': self._calculate_geographic_risk(profile) * 100,
            'weight': self.risk_weights['geographic_risk']
        }
        breakdown['components']['temporal_patterns'] = {
            'score': self._calculate_temporal_risk(profile) * 100,
            'weight': self.risk_weights['temporal_patterns']
        }
        breakdown['components']['known_indicators'] = {
            'score': self._calculate_indicator_risk(profile) * 100,
            'weight': self.risk_weights['known_indicators']
        }

        # Categorize
        breakdown['risk_category'] = self.categorize_risk(breakdown['overall_risk'])

        # Identify specific threat indicators
        breakdown['threat_indicators'] = self._identify_threat_indicators(profile)

        # Generate recommendations
        breakdown['recommendations'] = self._generate_recommendations(
            breakdown['overall_risk'],
            breakdown['components']
        )

        return breakdown

    def _identify_threat_indicators(self, profile: Any) -> List[Dict[str, Any]]:
        """Identify specific threat indicators present"""
        indicators = []

        # Check breach exposure
        breach_sources = [s for s in profile.sources if 'breach' in s.lower()]
        if len(breach_sources) >= 3:
            indicators.append({
                'type': 'breach_exposure',
                'severity': 'high',
                'description': f'Appeared in {len(breach_sources)} data breaches'
            })

        # Check for multiple aliases
        if len(profile.aliases) >= 3:
            indicators.append({
                'type': 'multiple_aliases',
                'severity': 'medium',
                'description': f'Uses {len(profile.aliases)} different aliases'
            })

        # Check for cryptocurrency activity
        attrs_text = str(profile.attributes).lower()
        if 'wallet' in attrs_text or 'cryptocurrency' in attrs_text:
            indicators.append({
                'type': 'cryptocurrency',
                'severity': 'medium',
                'description': 'Cryptocurrency wallet activity detected'
            })

        # Check for anonymization tools
        if 'tor' in attrs_text or 'vpn' in attrs_text:
            indicators.append({
                'type': 'anonymization',
                'severity': 'high',
                'description': 'Use of anonymization tools detected'
            })

        return indicators

    def _generate_recommendations(self, risk_score: float,
                                 components: Dict[str, Any]) -> List[str]:
        """Generate risk mitigation recommendations"""
        recommendations = []

        if risk_score >= 75:
            recommendations.append('URGENT: Immediate investigation recommended')
            recommendations.append('Consider escalation to security team')

        if components.get('breach_exposure', {}).get('score', 0) >= 70:
            recommendations.append('Monitor for credential stuffing attacks')
            recommendations.append('Recommend password reset for associated accounts')

        if components.get('network_risk', {}).get('score', 0) >= 60:
            recommendations.append('Investigate network connections and associates')

        if components.get('behavioral_patterns', {}).get('score', 0) >= 70:
            recommendations.append('Flag for behavioral analysis and monitoring')

        if risk_score >= 50:
            recommendations.append('Enhanced due diligence recommended')

        return recommendations
