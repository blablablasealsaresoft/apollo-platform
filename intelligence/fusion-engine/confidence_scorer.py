"""
Confidence Scoring System
Multi-factor confidence calculation with source reliability and data freshness
"""

from typing import Dict, List, Any
from datetime import datetime, timedelta
import math


class ConfidenceScorer:
    """
    Confidence Scoring Engine
    Calculates confidence scores based on source reliability, freshness, and corroboration
    """

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize Confidence Scorer

        Args:
            config: Configuration dictionary
        """
        self.source_weights = config.get('source_weights', {
            'blockchain': 0.95,
            'breach': 0.85,
            'sherlock': 0.80,
            'socmint': 0.75,
            'osint': 0.70,
            'unknown': 0.50
        })

        self.freshness_decay_days = config.get('freshness_decay_days', 180)
        self.corroboration_bonus = config.get('corroboration_bonus', 0.15)
        self.conflict_penalty = config.get('conflict_penalty', 0.20)

    def calculate_confidence(self, profile: Any,
                            intelligence_sources: List[Any]) -> float:
        """
        Calculate overall confidence score for an entity profile

        Args:
            profile: EntityProfile object
            intelligence_sources: List of IntelligenceSource objects

        Returns:
            Confidence score (0-100)
        """
        scores = []

        # 1. Source Reliability Score
        source_score = self._calculate_source_reliability(intelligence_sources)
        scores.append(('source_reliability', source_score, 0.30))

        # 2. Data Freshness Score
        freshness_score = self._calculate_freshness(intelligence_sources)
        scores.append(('freshness', freshness_score, 0.20))

        # 3. Corroboration Score
        corroboration_score = self._calculate_corroboration(profile, intelligence_sources)
        scores.append(('corroboration', corroboration_score, 0.25))

        # 4. Completeness Score
        completeness_score = self._calculate_completeness(profile)
        scores.append(('completeness', completeness_score, 0.15))

        # 5. Conflict Detection Score
        conflict_score = self._calculate_conflict_penalty(profile, intelligence_sources)
        scores.append(('conflict_penalty', conflict_score, 0.10))

        # Weighted average
        total_score = sum(score * weight for _, score, weight in scores)

        # Normalize to 0-100 scale
        confidence = total_score * 100

        # Apply bonuses and penalties
        if len(intelligence_sources) >= 3:
            confidence += self.corroboration_bonus * 100  # Multi-source bonus

        # Cap at 100
        confidence = min(confidence, 100.0)

        return round(confidence, 2)

    def _calculate_source_reliability(self, sources: List[Any]) -> float:
        """Calculate average source reliability score"""
        if not sources:
            return 0.0

        reliability_scores = []
        for source in sources:
            # Get source type weight
            weight = self.source_weights.get(
                source.source_type,
                self.source_weights.get('unknown', 0.5)
            )

            # Factor in explicit reliability if available
            if hasattr(source, 'reliability') and source.reliability:
                weight = (weight + source.reliability) / 2

            reliability_scores.append(weight)

        return sum(reliability_scores) / len(reliability_scores)

    def _calculate_freshness(self, sources: List[Any]) -> float:
        """
        Calculate data freshness score with exponential decay

        Recent data = higher score
        Old data = lower score (exponential decay)
        """
        if not sources:
            return 0.0

        now = datetime.now()
        freshness_scores = []

        for source in sources:
            # Calculate age in days
            age_days = (now - source.timestamp).days

            # Exponential decay function
            # Score = e^(-age / decay_constant)
            decay_factor = age_days / self.freshness_decay_days
            freshness = math.exp(-decay_factor)

            freshness_scores.append(freshness)

        # Return weighted average (more recent sources have more weight)
        return sum(freshness_scores) / len(freshness_scores)

    def _calculate_corroboration(self, profile: Any,
                                sources: List[Any]) -> float:
        """
        Calculate corroboration score based on multi-source validation

        Multiple independent sources confirming same data = higher confidence
        """
        if not sources:
            return 0.0

        # Count unique source types
        source_types = set(source.source_type for source in sources)
        unique_sources = len(source_types)

        # Base score from number of sources
        if unique_sources >= 4:
            base_score = 1.0
        elif unique_sources == 3:
            base_score = 0.85
        elif unique_sources == 2:
            base_score = 0.65
        else:
            base_score = 0.40

        # Bonus for attribute corroboration
        attribute_corroboration = self._calculate_attribute_corroboration(profile, sources)

        # Weighted combination
        corroboration = (base_score * 0.6) + (attribute_corroboration * 0.4)

        return corroboration

    def _calculate_attribute_corroboration(self, profile: Any,
                                          sources: List[Any]) -> float:
        """Calculate how well attributes are corroborated across sources"""
        if not sources or not profile.attributes:
            return 0.0

        # Track which attributes appear in multiple sources
        attribute_sources = {}

        for source in sources:
            for key in profile.attributes.keys():
                # Check if attribute appears in this source
                if self._attribute_in_source(key, profile.attributes[key], source.data):
                    if key not in attribute_sources:
                        attribute_sources[key] = set()
                    attribute_sources[key].add(source.source_type)

        # Calculate corroboration ratio
        total_attrs = len(profile.attributes)
        corroborated_attrs = sum(
            1 for sources_set in attribute_sources.values()
            if len(sources_set) >= 2
        )

        if total_attrs == 0:
            return 0.0

        return corroborated_attrs / total_attrs

    def _attribute_in_source(self, key: str, value: Any, source_data: Dict[str, Any]) -> bool:
        """Check if attribute appears in source data"""
        def search_recursive(obj, target_value):
            if isinstance(obj, dict):
                if key in obj and obj[key] == target_value:
                    return True
                return any(search_recursive(v, target_value) for v in obj.values())
            elif isinstance(obj, list):
                return any(search_recursive(item, target_value) for item in obj)
            return False

        if isinstance(value, list):
            return any(search_recursive(source_data, v) for v in value)
        else:
            return search_recursive(source_data, value)

    def _calculate_completeness(self, profile: Any) -> float:
        """
        Calculate profile completeness score

        More attributes and relationships = higher completeness
        """
        score = 0.0

        # Essential attributes (higher weight)
        essential_attrs = ['email', 'name', 'phone', 'location']
        present_essential = sum(
            1 for attr in essential_attrs
            if attr in profile.attributes and profile.attributes[attr]
        )
        score += (present_essential / len(essential_attrs)) * 0.4

        # Total attributes (breadth)
        total_attrs = len(profile.attributes)
        if total_attrs >= 10:
            score += 0.3
        elif total_attrs >= 5:
            score += 0.2
        elif total_attrs >= 2:
            score += 0.1

        # Relationships
        if len(profile.relationships) >= 5:
            score += 0.2
        elif len(profile.relationships) >= 2:
            score += 0.1

        # Timeline events
        if len(profile.timeline) >= 10:
            score += 0.1
        elif len(profile.timeline) >= 3:
            score += 0.05

        return min(score, 1.0)

    def _calculate_conflict_penalty(self, profile: Any,
                                   sources: List[Any]) -> float:
        """
        Detect conflicting information and apply penalty

        Conflicting data = lower confidence
        """
        # Start at 1.0 (no penalty)
        score = 1.0

        # Check for conflicting values in attributes
        conflicts = self._detect_conflicts(profile, sources)

        # Apply penalty for each conflict
        penalty_per_conflict = self.conflict_penalty / 5  # Max 5 conflicts matter

        score -= min(len(conflicts) * penalty_per_conflict, self.conflict_penalty)

        return max(score, 0.0)

    def _detect_conflicts(self, profile: Any, sources: List[Any]) -> List[Dict[str, Any]]:
        """Detect conflicting information across sources"""
        conflicts = []

        # Build attribute-source mapping
        attr_values = {}

        for source in sources:
            for key, value in source.data.items():
                if key not in attr_values:
                    attr_values[key] = []
                attr_values[key].append({
                    'value': value,
                    'source': source.source_type,
                    'timestamp': source.timestamp
                })

        # Find conflicts (same attribute, different values)
        for key, values in attr_values.items():
            if len(values) >= 2:
                unique_values = set(str(v['value']) for v in values)
                if len(unique_values) >= 2:
                    # Conflict detected
                    conflicts.append({
                        'attribute': key,
                        'values': list(unique_values),
                        'sources': [v['source'] for v in values]
                    })

        return conflicts

    def calculate_attribute_confidence(self, attribute_name: str,
                                      attribute_value: Any,
                                      sources: List[Any]) -> float:
        """
        Calculate confidence score for a specific attribute

        Args:
            attribute_name: Name of the attribute
            attribute_value: Value of the attribute
            sources: Intelligence sources

        Returns:
            Confidence score (0-100)
        """
        score = 0.0

        # Count sources that confirm this attribute
        confirming_sources = []
        for source in sources:
            if self._attribute_in_source(attribute_name, attribute_value, source.data):
                confirming_sources.append(source)

        if not confirming_sources:
            return 0.0

        # Source reliability
        avg_reliability = sum(
            self.source_weights.get(s.source_type, 0.5)
            for s in confirming_sources
        ) / len(confirming_sources)
        score += avg_reliability * 0.5

        # Multi-source confirmation
        if len(confirming_sources) >= 3:
            score += 0.3
        elif len(confirming_sources) == 2:
            score += 0.2
        else:
            score += 0.1

        # Freshness
        if confirming_sources:
            most_recent = max(confirming_sources, key=lambda s: s.timestamp)
            age_days = (datetime.now() - most_recent.timestamp).days
            freshness = math.exp(-age_days / self.freshness_decay_days)
            score += freshness * 0.2

        return min(score * 100, 100.0)

    def get_confidence_breakdown(self, profile: Any,
                                sources: List[Any]) -> Dict[str, Any]:
        """
        Get detailed breakdown of confidence calculation

        Args:
            profile: EntityProfile object
            sources: Intelligence sources

        Returns:
            Dictionary with detailed confidence metrics
        """
        breakdown = {
            'overall_confidence': self.calculate_confidence(profile, sources),
            'components': {},
            'attribute_confidence': {}
        }

        # Component scores
        breakdown['components']['source_reliability'] = {
            'score': self._calculate_source_reliability(sources) * 100,
            'weight': 0.30
        }
        breakdown['components']['freshness'] = {
            'score': self._calculate_freshness(sources) * 100,
            'weight': 0.20
        }
        breakdown['components']['corroboration'] = {
            'score': self._calculate_corroboration(profile, sources) * 100,
            'weight': 0.25
        }
        breakdown['components']['completeness'] = {
            'score': self._calculate_completeness(profile) * 100,
            'weight': 0.15
        }
        breakdown['components']['conflict_penalty'] = {
            'score': self._calculate_conflict_penalty(profile, sources) * 100,
            'weight': 0.10
        }

        # Per-attribute confidence
        for key, value in profile.attributes.items():
            breakdown['attribute_confidence'][key] = self.calculate_attribute_confidence(
                key, value, sources
            )

        return breakdown
