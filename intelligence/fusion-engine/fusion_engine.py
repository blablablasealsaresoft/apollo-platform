"""
Intelligence Fusion Engine - Core System
Multi-source intelligence correlation, entity resolution, and risk assessment
"""

import json
import logging
from typing import Dict, List, Optional, Any, Set
from datetime import datetime, timedelta
from collections import defaultdict
import asyncio
from dataclasses import dataclass, field, asdict

from entity_resolver import EntityResolver
from correlation_algorithm import CorrelationEngine
from confidence_scorer import ConfidenceScorer
from risk_assessor import RiskAssessor
from timeline_builder import TimelineBuilder
from graph_analyzer import GraphAnalyzer


@dataclass
class IntelligenceSource:
    """Intelligence source metadata"""
    source_id: str
    source_type: str  # sherlock, blockchain, breach, socmint, osint
    reliability: float  # 0.0 - 1.0
    timestamp: datetime
    data: Dict[str, Any]


@dataclass
class EntityProfile:
    """Comprehensive entity profile"""
    entity_id: str
    primary_identifier: str
    entity_type: str  # person, organization, wallet, email, etc.
    attributes: Dict[str, Any] = field(default_factory=dict)
    aliases: Set[str] = field(default_factory=set)
    relationships: List[Dict[str, Any]] = field(default_factory=list)
    timeline: List[Dict[str, Any]] = field(default_factory=list)
    risk_score: float = 0.0
    confidence_score: float = 0.0
    sources: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary with serializable types"""
        result = asdict(self)
        result['aliases'] = list(self.aliases)
        return result


class IntelligenceFusion:
    """
    Advanced Intelligence Fusion Engine
    Correlates multi-source intelligence, resolves entities, and generates comprehensive profiles
    """

    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize Intelligence Fusion Engine

        Args:
            config_path: Path to fusion_rules.yaml configuration
        """
        self.logger = logging.getLogger(__name__)
        self.config = self._load_config(config_path)

        # Initialize sub-engines
        self.entity_resolver = EntityResolver(self.config.get('entity_resolution', {}))
        self.correlation_engine = CorrelationEngine(self.config.get('correlation', {}))
        self.confidence_scorer = ConfidenceScorer(self.config.get('confidence', {}))
        self.risk_assessor = RiskAssessor(self.config.get('risk', {}))
        self.timeline_builder = TimelineBuilder(self.config.get('timeline', {}))
        self.graph_analyzer = GraphAnalyzer(self.config.get('graph', {}))

        # In-memory storage
        self.entities: Dict[str, EntityProfile] = {}
        self.raw_intelligence: List[IntelligenceSource] = []

        self.logger.info("Intelligence Fusion Engine initialized")

    def _load_config(self, config_path: Optional[str]) -> Dict[str, Any]:
        """Load configuration from YAML"""
        if config_path:
            try:
                import yaml
                with open(config_path, 'r') as f:
                    return yaml.safe_load(f)
            except Exception as e:
                self.logger.warning(f"Failed to load config: {e}, using defaults")

        # Default configuration
        return {
            'entity_resolution': {
                'fuzzy_threshold': 0.85,
                'email_exact_match': True,
                'phone_normalize': True
            },
            'correlation': {
                'min_correlation_score': 0.6,
                'time_window_days': 365,
                'max_graph_depth': 3
            },
            'confidence': {
                'source_weights': {
                    'blockchain': 0.95,
                    'breach': 0.85,
                    'sherlock': 0.80,
                    'socmint': 0.75,
                    'osint': 0.70
                },
                'freshness_decay_days': 180
            },
            'risk': {
                'high_threshold': 75,
                'medium_threshold': 50,
                'low_threshold': 25
            },
            'timeline': {
                'max_gap_days': 30,
                'min_events': 2
            },
            'graph': {
                'neo4j_uri': 'bolt://localhost:7687',
                'neo4j_user': 'neo4j',
                'neo4j_password': 'password'
            }
        }

    def ingest_intelligence(self, source_data: Dict[str, Any], source_type: str,
                           reliability: Optional[float] = None) -> str:
        """
        Ingest intelligence from a source

        Args:
            source_data: Raw intelligence data
            source_type: Type of source (sherlock, blockchain, etc.)
            reliability: Optional reliability override

        Returns:
            Source ID
        """
        if reliability is None:
            reliability = self.config['confidence']['source_weights'].get(source_type, 0.5)

        source = IntelligenceSource(
            source_id=f"{source_type}_{len(self.raw_intelligence)}_{datetime.now().timestamp()}",
            source_type=source_type,
            reliability=reliability,
            timestamp=datetime.now(),
            data=source_data
        )

        self.raw_intelligence.append(source)
        self.logger.info(f"Ingested intelligence from {source_type}: {source.source_id}")

        return source.source_id

    def build_profile(self, target: str, sources: Optional[List[str]] = None,
                     deep_analysis: bool = True) -> EntityProfile:
        """
        Build comprehensive intelligence profile for target

        Args:
            target: Primary identifier (email, name, wallet, etc.)
            sources: List of source types to use (None = all)
            deep_analysis: Perform deep correlation and graph analysis

        Returns:
            EntityProfile with comprehensive intelligence
        """
        self.logger.info(f"Building profile for target: {target}")

        # Filter relevant intelligence
        relevant_intel = self._filter_intelligence(target, sources)

        if not relevant_intel:
            self.logger.warning(f"No intelligence found for target: {target}")
            return EntityProfile(
                entity_id=f"entity_{hash(target)}",
                primary_identifier=target,
                entity_type="unknown"
            )

        # Step 1: Entity Resolution
        resolved_entities = self.entity_resolver.resolve_entities(relevant_intel, target)

        # Step 2: Correlation
        correlations = self.correlation_engine.correlate(resolved_entities, relevant_intel)

        # Step 3: Build unified profile
        profile = self._build_unified_profile(target, resolved_entities, correlations, relevant_intel)

        # Step 4: Confidence Scoring
        profile.confidence_score = self.confidence_scorer.calculate_confidence(
            profile, relevant_intel
        )

        # Step 5: Risk Assessment
        profile.risk_score = self.risk_assessor.assess_risk(profile, correlations)

        # Step 6: Timeline Generation
        profile.timeline = self.timeline_builder.build_timeline(profile, relevant_intel)

        # Step 7: Deep Analysis (optional)
        if deep_analysis:
            # Graph analysis
            graph_insights = self.graph_analyzer.analyze_network(profile, correlations)
            profile.metadata['graph_analysis'] = graph_insights

            # Pattern detection
            patterns = self._detect_patterns(profile, relevant_intel)
            profile.metadata['patterns'] = patterns

        # Store profile
        self.entities[profile.entity_id] = profile

        self.logger.info(f"Profile built for {target}: Confidence={profile.confidence_score:.2f}, Risk={profile.risk_score:.2f}")

        return profile

    def _filter_intelligence(self, target: str, sources: Optional[List[str]]) -> List[IntelligenceSource]:
        """Filter intelligence relevant to target"""
        relevant = []

        for intel in self.raw_intelligence:
            # Filter by source type
            if sources and intel.source_type not in sources:
                continue

            # Check if target appears in data
            if self._target_matches(target, intel.data):
                relevant.append(intel)

        return relevant

    def _target_matches(self, target: str, data: Dict[str, Any]) -> bool:
        """Check if target identifier appears in intelligence data"""
        target_lower = target.lower()

        def search_recursive(obj):
            if isinstance(obj, str):
                return target_lower in obj.lower()
            elif isinstance(obj, dict):
                return any(search_recursive(v) for v in obj.values())
            elif isinstance(obj, list):
                return any(search_recursive(item) for item in obj)
            return False

        return search_recursive(data)

    def _build_unified_profile(self, target: str, resolved_entities: List[Dict[str, Any]],
                              correlations: Dict[str, Any],
                              intelligence: List[IntelligenceSource]) -> EntityProfile:
        """Build unified entity profile from resolved entities and correlations"""
        profile = EntityProfile(
            entity_id=f"entity_{hash(target)}_{datetime.now().timestamp()}",
            primary_identifier=target,
            entity_type=self._determine_entity_type(target, resolved_entities)
        )

        # Aggregate attributes from all resolved entities
        all_attributes = defaultdict(set)
        all_aliases = set()
        source_ids = set()

        for entity in resolved_entities:
            # Collect attributes
            for key, value in entity.get('attributes', {}).items():
                if isinstance(value, (list, set)):
                    all_attributes[key].update(value)
                else:
                    all_attributes[key].add(str(value))

            # Collect aliases
            all_aliases.update(entity.get('aliases', []))

            # Track sources
            source_ids.add(entity.get('source_id', 'unknown'))

        # Convert sets to appropriate types
        profile.attributes = {
            key: list(values) if len(values) > 1 else list(values)[0]
            for key, values in all_attributes.items()
        }
        profile.aliases = all_aliases
        profile.sources = list(source_ids)

        # Add relationships from correlations
        profile.relationships = correlations.get('relationships', [])

        # Add metadata
        profile.metadata = {
            'total_sources': len(intelligence),
            'source_types': list(set(i.source_type for i in intelligence)),
            'first_seen': min(i.timestamp for i in intelligence).isoformat(),
            'last_seen': max(i.timestamp for i in intelligence).isoformat(),
            'correlation_count': len(correlations.get('correlations', []))
        }

        return profile

    def _determine_entity_type(self, identifier: str, entities: List[Dict[str, Any]]) -> str:
        """Determine entity type from identifier and resolved entities"""
        # Check identifier pattern
        if '@' in identifier:
            return 'email'
        elif identifier.startswith('0x') or identifier.startswith('bc1'):
            return 'wallet'
        elif identifier.replace('-', '').replace('+', '').replace(' ', '').isdigit():
            return 'phone'

        # Check entity types from resolved data
        types = [e.get('type') for e in entities if e.get('type')]
        if types:
            return max(set(types), key=types.count)

        return 'person'

    def _detect_patterns(self, profile: EntityProfile,
                        intelligence: List[IntelligenceSource]) -> List[Dict[str, Any]]:
        """Detect behavioral and data patterns"""
        patterns = []

        # Pattern 1: Repeated breach appearances
        breach_sources = [i for i in intelligence if i.source_type == 'breach']
        if len(breach_sources) >= 3:
            patterns.append({
                'type': 'repeated_breaches',
                'severity': 'high',
                'count': len(breach_sources),
                'description': f"Appeared in {len(breach_sources)} data breaches"
            })

        # Pattern 2: Multiple cryptocurrency wallets
        wallet_attrs = profile.attributes.get('wallets', [])
        if isinstance(wallet_attrs, list) and len(wallet_attrs) >= 2:
            patterns.append({
                'type': 'multiple_wallets',
                'severity': 'medium',
                'count': len(wallet_attrs),
                'description': f"Controls {len(wallet_attrs)} cryptocurrency wallets"
            })

        # Pattern 3: Geographic dispersion
        locations = profile.attributes.get('locations', [])
        if isinstance(locations, list) and len(locations) >= 3:
            patterns.append({
                'type': 'geographic_dispersion',
                'severity': 'medium',
                'count': len(locations),
                'description': f"Associated with {len(locations)} different locations"
            })

        # Pattern 4: Alias usage
        if len(profile.aliases) >= 3:
            patterns.append({
                'type': 'multiple_aliases',
                'severity': 'high',
                'count': len(profile.aliases),
                'description': f"Uses {len(profile.aliases)} different aliases"
            })

        # Pattern 5: Old account activity
        if profile.metadata.get('first_seen'):
            first_seen = datetime.fromisoformat(profile.metadata['first_seen'])
            age_days = (datetime.now() - first_seen).days
            if age_days > 365 * 5:
                patterns.append({
                    'type': 'long_term_presence',
                    'severity': 'low',
                    'age_years': age_days // 365,
                    'description': f"Digital footprint spans {age_days // 365} years"
                })

        return patterns

    def get_related_entities(self, entity_id: str, max_depth: int = 2) -> List[EntityProfile]:
        """Get entities related to specified entity"""
        if entity_id not in self.entities:
            return []

        related = []
        entity = self.entities[entity_id]

        # Use graph analyzer to find connected entities
        connections = self.graph_analyzer.find_connections(entity, max_depth)

        for conn in connections:
            related_id = conn.get('entity_id')
            if related_id and related_id in self.entities:
                related.append(self.entities[related_id])

        return related

    def generate_intelligence_report(self, entity_id: str,
                                    format: str = 'json') -> str:
        """
        Generate comprehensive intelligence report

        Args:
            entity_id: Entity ID to report on
            format: Output format (json, markdown, html)

        Returns:
            Formatted report
        """
        if entity_id not in self.entities:
            raise ValueError(f"Entity not found: {entity_id}")

        profile = self.entities[entity_id]

        if format == 'json':
            return json.dumps(profile.to_dict(), indent=2, default=str)

        elif format == 'markdown':
            return self._generate_markdown_report(profile)

        elif format == 'html':
            return self._generate_html_report(profile)

        else:
            raise ValueError(f"Unsupported format: {format}")

    def _generate_markdown_report(self, profile: EntityProfile) -> str:
        """Generate markdown intelligence report"""
        report = f"""# Intelligence Report: {profile.primary_identifier}

## Summary
- **Entity Type:** {profile.entity_type}
- **Confidence Score:** {profile.confidence_score:.1f}/100
- **Risk Score:** {profile.risk_score:.1f}/100
- **Sources:** {len(profile.sources)}

## Identifiers
- **Primary:** {profile.primary_identifier}
- **Aliases:** {', '.join(profile.aliases) if profile.aliases else 'None'}

## Attributes
"""
        for key, value in profile.attributes.items():
            if isinstance(value, list):
                report += f"- **{key}:** {', '.join(str(v) for v in value)}\n"
            else:
                report += f"- **{key}:** {value}\n"

        report += f"\n## Relationships ({len(profile.relationships)})\n"
        for rel in profile.relationships[:10]:  # Top 10
            report += f"- {rel.get('type', 'Unknown')}: {rel.get('target', 'N/A')} (Score: {rel.get('score', 0):.2f})\n"

        report += f"\n## Timeline ({len(profile.timeline)} events)\n"
        for event in profile.timeline[:10]:  # Top 10
            report += f"- **{event.get('timestamp', 'Unknown')}:** {event.get('description', 'N/A')}\n"

        if profile.metadata.get('patterns'):
            report += f"\n## Detected Patterns\n"
            for pattern in profile.metadata['patterns']:
                report += f"- [{pattern['severity'].upper()}] {pattern['description']}\n"

        report += f"\n## Metadata\n"
        report += f"- **First Seen:** {profile.metadata.get('first_seen', 'Unknown')}\n"
        report += f"- **Last Seen:** {profile.metadata.get('last_seen', 'Unknown')}\n"
        report += f"- **Source Types:** {', '.join(profile.metadata.get('source_types', []))}\n"

        report += f"\n---\n*Report generated: {datetime.now().isoformat()}*\n"

        return report

    def _generate_html_report(self, profile: EntityProfile) -> str:
        """Generate HTML intelligence report"""
        # Risk color coding
        risk_color = 'red' if profile.risk_score >= 75 else 'orange' if profile.risk_score >= 50 else 'green'

        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Intelligence Report - {profile.primary_identifier}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background: #333; color: white; padding: 20px; }}
        .score {{ display: inline-block; margin: 10px; padding: 10px; border-radius: 5px; }}
        .risk-score {{ background: {risk_color}; color: white; }}
        .section {{ margin: 20px 0; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background: #f2f2f2; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Intelligence Report: {profile.primary_identifier}</h1>
        <div class="score">Confidence: {profile.confidence_score:.1f}/100</div>
        <div class="score risk-score">Risk: {profile.risk_score:.1f}/100</div>
    </div>

    <div class="section">
        <h2>Summary</h2>
        <p><strong>Entity Type:</strong> {profile.entity_type}</p>
        <p><strong>Sources:</strong> {len(profile.sources)}</p>
        <p><strong>Aliases:</strong> {', '.join(profile.aliases) if profile.aliases else 'None'}</p>
    </div>

    <div class="section">
        <h2>Timeline</h2>
        <table>
            <tr><th>Timestamp</th><th>Event</th></tr>
"""
        for event in profile.timeline[:20]:
            html += f"<tr><td>{event.get('timestamp', 'Unknown')[:19]}</td><td>{event.get('description', 'N/A')}</td></tr>\n"

        html += """
        </table>
    </div>

    <div class="section">
        <p><em>Report generated: """ + datetime.now().isoformat() + """</em></p>
    </div>
</body>
</html>
"""
        return html

    def export_graph(self, entity_id: str, output_path: str, format: str = 'gexf'):
        """Export entity relationship graph"""
        if entity_id not in self.entities:
            raise ValueError(f"Entity not found: {entity_id}")

        profile = self.entities[entity_id]
        self.graph_analyzer.export_graph(profile, output_path, format)
        self.logger.info(f"Graph exported to {output_path}")

    def clear_cache(self):
        """Clear all cached intelligence and profiles"""
        self.entities.clear()
        self.raw_intelligence.clear()
        self.logger.info("Cache cleared")


def main():
    """Example usage"""
    logging.basicConfig(level=logging.INFO)

    # Initialize fusion engine
    fusion = IntelligenceFusion()

    # Ingest intelligence from various sources
    fusion.ingest_intelligence({
        'email': 'ruja.ignatova@onecoin.eu',
        'name': 'Ruja Ignatova',
        'aliases': ['Cryptoqueen'],
        'location': 'Bulgaria'
    }, 'osint')

    fusion.ingest_intelligence({
        'email': 'ruja.ignatova@onecoin.eu',
        'breach': 'LinkedIn2021',
        'password_hash': 'sha1:...',
        'phone': '+359...'
    }, 'breach')

    fusion.ingest_intelligence({
        'wallet': '0x742d35Cc6634C0532925a3b8....',
        'owner_email': 'ruja.ignatova@onecoin.eu',
        'transactions': 147,
        'total_volume': '1.2M USD'
    }, 'blockchain')

    # Build comprehensive profile
    profile = fusion.build_profile(
        target='ruja.ignatova@onecoin.eu',
        sources=['osint', 'breach', 'blockchain'],
        deep_analysis=True
    )

    print(f"\n{'='*60}")
    print(f"Intelligence Profile: {profile.primary_identifier}")
    print(f"{'='*60}")
    print(f"Confidence Score: {profile.confidence_score:.1f}/100")
    print(f"Risk Score: {profile.risk_score:.1f}/100")
    print(f"Entity Type: {profile.entity_type}")
    print(f"Sources: {len(profile.sources)}")
    print(f"Relationships: {len(profile.relationships)}")
    print(f"Timeline Events: {len(profile.timeline)}")

    # Generate report
    report = fusion.generate_intelligence_report(profile.entity_id, format='markdown')
    print(f"\n{report}")


if __name__ == '__main__':
    main()
