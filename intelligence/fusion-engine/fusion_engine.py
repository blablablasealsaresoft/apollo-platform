"""
Intelligence Fusion Engine
Aggregates data from all intelligence sources and performs correlation
"""

import asyncio
import logging
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict
from elasticsearch import Elasticsearch

logger = logging.getLogger(__name__)


@dataclass
class IntelligenceEntity:
    """Unified intelligence entity"""
    entity_id: str
    entity_type: str  # person, organization, wallet, domain, ip, etc.
    primary_identifier: str
    aliases: Set[str] = field(default_factory=set)
    attributes: Dict[str, Any] = field(default_factory=dict)
    sources: List[str] = field(default_factory=list)
    confidence_score: float = 0.0
    risk_score: float = 0.0
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class IntelligenceLink:
    """Link between intelligence entities"""
    link_id: str
    from_entity: str
    to_entity: str
    link_type: str  # owns, associated_with, transacted_with, etc.
    confidence_score: float
    evidence: List[Dict] = field(default_factory=list)
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)


@dataclass
class FusedIntelligence:
    """Fused intelligence report"""
    report_id: str
    target: str
    entities: List[IntelligenceEntity]
    links: List[IntelligenceLink]
    timeline: List[Dict]
    risk_assessment: Dict[str, Any]
    recommendations: List[str]
    generated_at: datetime
    sources_used: List[str]
    confidence_score: float


class IntelligenceFusionEngine:
    """
    Fuses intelligence from multiple sources:
    - OSINT (Sherlock, BBOT, etc.)
    - Blockchain intelligence
    - Breach databases
    - Dark web intelligence
    - Social media intelligence
    - Public records
    """

    def __init__(
        self,
        es_client: Optional[Elasticsearch] = None,
        es_hosts: Optional[List[str]] = None
    ):
        """
        Initialize fusion engine

        Args:
            es_client: Elasticsearch client
            es_hosts: Elasticsearch hosts
        """
        if es_client:
            self.es = es_client
        else:
            hosts = es_hosts or ['http://localhost:9200']
            self.es = Elasticsearch(hosts)

        self.fusion_index = 'apollo-fusion-intelligence'
        self._ensure_index()

    def _ensure_index(self):
        """Create Elasticsearch index for fused intelligence"""
        if not self.es.indices.exists(index=self.fusion_index):
            self.es.indices.create(
                index=self.fusion_index,
                body={
                    "settings": {
                        "number_of_shards": 3,
                        "number_of_replicas": 1
                    },
                    "mappings": {
                        "properties": {
                            "report_id": {"type": "keyword"},
                            "target": {"type": "keyword"},
                            "entity_count": {"type": "integer"},
                            "link_count": {"type": "integer"},
                            "confidence_score": {"type": "float"},
                            "risk_score": {"type": "float"},
                            "generated_at": {"type": "date"},
                            "sources_used": {"type": "keyword"},
                            "entities": {"type": "object", "enabled": False},
                            "links": {"type": "object", "enabled": False},
                            "timeline": {"type": "object", "enabled": False}
                        }
                    }
                }
            )

    async def fuse_intelligence(
        self,
        target: str,
        target_type: str = 'person',
        sources: Optional[List[str]] = None
    ) -> FusedIntelligence:
        """
        Fuse intelligence from all sources for a target

        Args:
            target: Target identifier (name, email, wallet, etc.)
            target_type: Type of target
            sources: List of sources to query (None = all)

        Returns:
            FusedIntelligence report
        """
        logger.info(f"Fusing intelligence for target: {target}")

        # Collect data from all sources
        source_data = await self._collect_source_data(target, sources)

        # Extract entities
        entities = await self._extract_entities(source_data, target)

        # Resolve entity identities
        entities = await self._resolve_entities(entities)

        # Find links between entities
        links = await self._find_entity_links(entities, source_data)

        # Generate timeline
        timeline = await self._generate_timeline(source_data)

        # Calculate risk assessment
        risk_assessment = await self._assess_risk(entities, links, source_data)

        # Generate recommendations
        recommendations = await self._generate_recommendations(
            entities, links, risk_assessment
        )

        # Calculate overall confidence
        confidence_score = self._calculate_confidence(entities, links)

        # Create fused report
        report_id = f"{target}_{datetime.now().strftime('%Y%m%d%H%M%S')}"
        fused_report = FusedIntelligence(
            report_id=report_id,
            target=target,
            entities=entities,
            links=links,
            timeline=timeline,
            risk_assessment=risk_assessment,
            recommendations=recommendations,
            generated_at=datetime.now(),
            sources_used=list(source_data.keys()),
            confidence_score=confidence_score
        )

        # Store in Elasticsearch
        await self._store_fused_intelligence(fused_report)

        logger.info(
            f"Intelligence fusion complete: {len(entities)} entities, "
            f"{len(links)} links, confidence: {confidence_score:.2f}"
        )

        return fused_report

    async def _collect_source_data(
        self,
        target: str,
        sources: Optional[List[str]]
    ) -> Dict[str, Any]:
        """Collect data from all intelligence sources"""
        source_data = {}

        # Define all intelligence sources
        all_sources = [
            'sherlock',
            'bbot',
            'blockchain',
            'breach_databases',
            'darkweb',
            'geoint',
            'socmint',
            'public_records'
        ]

        active_sources = sources if sources else all_sources

        # Query each source
        tasks = []
        for source in active_sources:
            if source == 'sherlock':
                tasks.append(self._query_sherlock(target))
            elif source == 'bbot':
                tasks.append(self._query_bbot(target))
            elif source == 'blockchain':
                tasks.append(self._query_blockchain(target))
            elif source == 'breach_databases':
                tasks.append(self._query_breach_db(target))
            elif source == 'darkweb':
                tasks.append(self._query_darkweb(target))
            elif source == 'geoint':
                tasks.append(self._query_geoint(target))
            elif source == 'socmint':
                tasks.append(self._query_socmint(target))
            elif source == 'public_records':
                tasks.append(self._query_public_records(target))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Combine results
        for source, result in zip(active_sources, results):
            if not isinstance(result, Exception) and result:
                source_data[source] = result

        return source_data

    async def _query_sherlock(self, target: str) -> Dict[str, Any]:
        """Query Sherlock results from Elasticsearch"""
        try:
            response = self.es.search(
                index='apollo-sherlock-results',
                body={
                    "query": {
                        "bool": {
                            "must": [
                                {"term": {"username": target}},
                                {"term": {"status": "found"}}
                            ]
                        }
                    },
                    "size": 1000
                }
            )

            return {
                'platforms': [
                    hit['_source']
                    for hit in response['hits']['hits']
                ]
            }
        except:
            return {}

    async def _query_bbot(self, target: str) -> Dict[str, Any]:
        """Query BBOT results"""
        # Placeholder - would query BBOT results from storage
        return {}

    async def _query_blockchain(self, target: str) -> Dict[str, Any]:
        """Query blockchain intelligence"""
        # Placeholder - would query blockchain results from storage
        return {}

    async def _query_breach_db(self, target: str) -> Dict[str, Any]:
        """Query breach database results"""
        # Placeholder - would query breach DB results
        return {}

    async def _query_darkweb(self, target: str) -> Dict[str, Any]:
        """Query dark web intelligence"""
        # Placeholder - would query dark web results
        return {}

    async def _query_geoint(self, target: str) -> Dict[str, Any]:
        """Query geolocation intelligence"""
        # Placeholder - would query geoint results
        return {}

    async def _query_socmint(self, target: str) -> Dict[str, Any]:
        """Query social media intelligence"""
        # Placeholder - would query socmint results
        return {}

    async def _query_public_records(self, target: str) -> Dict[str, Any]:
        """Query public records"""
        # Placeholder - would query public records
        return {}

    async def _extract_entities(
        self,
        source_data: Dict[str, Any],
        target: str
    ) -> List[IntelligenceEntity]:
        """Extract entities from source data"""
        entities = []
        entity_map = {}

        # Extract from Sherlock data
        if 'sherlock' in source_data:
            for platform in source_data['sherlock'].get('platforms', []):
                entity_id = f"social:{platform['platform']}:{platform['username']}"
                if entity_id not in entity_map:
                    entity = IntelligenceEntity(
                        entity_id=entity_id,
                        entity_type='social_media_account',
                        primary_identifier=platform['url'],
                        aliases={platform['username']},
                        attributes={
                            'platform': platform['platform'],
                            'username': platform['username'],
                            'url': platform['url']
                        },
                        sources=['sherlock'],
                        confidence_score=platform.get('confidence_score', 0.0),
                        first_seen=datetime.fromisoformat(platform['timestamp'])
                        if 'timestamp' in platform else None
                    )
                    entity_map[entity_id] = entity
                    entities.append(entity)

        # Extract from other sources...

        return entities

    async def _resolve_entities(
        self,
        entities: List[IntelligenceEntity]
    ) -> List[IntelligenceEntity]:
        """Resolve duplicate entities and merge aliases"""
        # Group entities by type and identifier
        entity_groups = defaultdict(list)

        for entity in entities:
            key = (entity.entity_type, entity.primary_identifier.lower())
            entity_groups[key].append(entity)

        # Merge duplicate entities
        resolved = []
        for group in entity_groups.values():
            if len(group) == 1:
                resolved.append(group[0])
            else:
                # Merge multiple entities
                merged = group[0]
                for entity in group[1:]:
                    merged.aliases.update(entity.aliases)
                    merged.attributes.update(entity.attributes)
                    merged.sources.extend(entity.sources)
                    merged.confidence_score = max(
                        merged.confidence_score,
                        entity.confidence_score
                    )

                resolved.append(merged)

        return resolved

    async def _find_entity_links(
        self,
        entities: List[IntelligenceEntity],
        source_data: Dict[str, Any]
    ) -> List[IntelligenceLink]:
        """Find links between entities"""
        links = []

        # Find links based on shared attributes
        for i, entity1 in enumerate(entities):
            for entity2 in entities[i+1:]:
                # Check for common aliases
                if entity1.aliases & entity2.aliases:
                    links.append(IntelligenceLink(
                        link_id=f"{entity1.entity_id}::{entity2.entity_id}",
                        from_entity=entity1.entity_id,
                        to_entity=entity2.entity_id,
                        link_type='shared_alias',
                        confidence_score=0.8,
                        evidence=[{
                            'type': 'shared_alias',
                            'aliases': list(entity1.aliases & entity2.aliases)
                        }]
                    ))

        return links

    async def _generate_timeline(
        self,
        source_data: Dict[str, Any]
    ) -> List[Dict]:
        """Generate timeline of events"""
        timeline = []

        # Extract timestamped events from all sources
        if 'sherlock' in source_data:
            for platform in source_data['sherlock'].get('platforms', []):
                if 'timestamp' in platform:
                    timeline.append({
                        'timestamp': platform['timestamp'],
                        'source': 'sherlock',
                        'event': f"Account found on {platform['platform']}",
                        'details': platform
                    })

        # Sort by timestamp
        timeline.sort(key=lambda x: x['timestamp'])

        return timeline

    async def _assess_risk(
        self,
        entities: List[IntelligenceEntity],
        links: List[IntelligenceLink],
        source_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Calculate risk assessment"""
        risk_factors = []
        risk_score = 0.0

        # Check for breach data
        if 'breach_databases' in source_data:
            risk_factors.append('Found in breach databases')
            risk_score += 30

        # Check for dark web presence
        if 'darkweb' in source_data:
            risk_factors.append('Dark web activity detected')
            risk_score += 40

        # Check for cryptocurrency activity
        if 'blockchain' in source_data:
            risk_factors.append('Cryptocurrency activity')
            risk_score += 10

        # Normalize risk score
        risk_score = min(risk_score, 100)

        return {
            'risk_score': risk_score,
            'risk_level': self._classify_risk(risk_score),
            'risk_factors': risk_factors
        }

    def _classify_risk(self, score: float) -> str:
        """Classify risk level"""
        if score >= 75:
            return 'critical'
        elif score >= 50:
            return 'high'
        elif score >= 25:
            return 'medium'
        else:
            return 'low'

    async def _generate_recommendations(
        self,
        entities: List[IntelligenceEntity],
        links: List[IntelligenceLink],
        risk_assessment: Dict[str, Any]
    ) -> List[str]:
        """Generate recommendations"""
        recommendations = []

        if risk_assessment['risk_level'] in ['critical', 'high']:
            recommendations.append(
                'Immediate investigation recommended due to high risk score'
            )

        if len(entities) > 20:
            recommendations.append(
                'Large digital footprint detected - consider comprehensive monitoring'
            )

        if len(links) > 10:
            recommendations.append(
                'Multiple entity connections found - investigate relationships'
            )

        return recommendations

    def _calculate_confidence(
        self,
        entities: List[IntelligenceEntity],
        links: List[IntelligenceLink]
    ) -> float:
        """Calculate overall confidence score"""
        if not entities:
            return 0.0

        avg_entity_confidence = sum(
            e.confidence_score for e in entities
        ) / len(entities)

        if links:
            avg_link_confidence = sum(
                l.confidence_score for l in links
            ) / len(links)
            return (avg_entity_confidence + avg_link_confidence) / 2
        else:
            return avg_entity_confidence

    async def _store_fused_intelligence(
        self,
        report: FusedIntelligence
    ):
        """Store fused intelligence in Elasticsearch"""
        from dataclasses import asdict

        doc = {
            'report_id': report.report_id,
            'target': report.target,
            'entity_count': len(report.entities),
            'link_count': len(report.links),
            'confidence_score': report.confidence_score,
            'risk_score': report.risk_assessment.get('risk_score', 0),
            'generated_at': report.generated_at.isoformat(),
            'sources_used': report.sources_used,
            'entities': [asdict(e) for e in report.entities],
            'links': [asdict(l) for l in report.links],
            'timeline': report.timeline,
            'risk_assessment': report.risk_assessment,
            'recommendations': report.recommendations
        }

        self.es.index(
            index=self.fusion_index,
            id=report.report_id,
            body=doc
        )

    async def get_fused_report(
        self,
        report_id: str
    ) -> Optional[FusedIntelligence]:
        """Retrieve a fused intelligence report"""
        try:
            response = self.es.get(
                index=self.fusion_index,
                id=report_id
            )
            # Convert back to FusedIntelligence object
            # Simplified - would need full deserialization
            return response['_source']
        except:
            return None
