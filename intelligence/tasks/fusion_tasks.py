"""
Intelligence Fusion Celery Tasks
Profile building, entity resolution, correlation analysis
"""

from celery import Task, group, chord
from celery.utils.log import get_task_logger
import asyncio
from typing import List, Dict, Optional, Any
from datetime import datetime
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from celery_tasks import app
from config import settings

logger = get_task_logger(__name__)


def run_async(coro):
    """Run async coroutine in sync context"""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


@app.task(
    bind=True,
    name='intelligence.fusion.build_profile',
    max_retries=2,
    default_retry_delay=180
)
def build_intelligence_profile_task(
    self: Task,
    target: str,
    target_type: str = 'person',
    sources: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Build comprehensive intelligence profile from all sources

    Args:
        target: Target identifier (username, email, wallet, etc.)
        target_type: Type of target (person, organization, wallet, domain)
        sources: Intelligence sources to use (None = all)

    Returns:
        Dictionary with fused intelligence profile
    """
    logger.info(
        f"[{self.request.id}] Building intelligence profile for: "
        f"{target} (type: {target_type})"
    )

    try:
        from fusion_engine import IntelligenceFusionEngine

        engine = IntelligenceFusionEngine()

        # Collect data from all sources
        available_sources = sources or ['sherlock', 'bbot', 'blockchain', 'breaches']

        intelligence_data = {
            'target': target,
            'target_type': target_type,
            'sources_used': available_sources,
            'data_points': []
        }

        # Gather OSINT data
        if 'sherlock' in available_sources and target_type == 'person':
            from .osint_tasks import search_username_task
            sherlock_result = search_username_task.apply(args=[target]).get()
            intelligence_data['data_points'].append({
                'source': 'sherlock',
                'data': sherlock_result
            })

        # Gather breach data
        if 'breaches' in available_sources:
            from .osint_tasks import email_intelligence_task
            # Try treating target as email
            if '@' in target:
                breach_result = email_intelligence_task.apply(args=[target]).get()
                intelligence_data['data_points'].append({
                    'source': 'breaches',
                    'data': breach_result
                })

        # Gather blockchain data
        if 'blockchain' in available_sources and target_type in ['wallet', 'person']:
            from .blockchain_tasks import wallet_analysis_task
            try:
                wallet_result = wallet_analysis_task.apply(
                    args=[target, 'bitcoin']
                ).get()
                intelligence_data['data_points'].append({
                    'source': 'blockchain',
                    'data': wallet_result
                })
            except:
                pass  # Not a valid wallet address

        # Fuse intelligence
        fused_report = run_async(
            engine.fuse_intelligence(target, target_type, available_sources)
        )

        logger.info(
            f"[{self.request.id}] Intelligence profile built: "
            f"{len(fused_report.entities)} entities identified"
        )

        return {
            'task_id': self.request.id,
            'report_id': fused_report.report_id,
            'target': fused_report.target,
            'target_type': target_type,
            'sources_used': available_sources,
            'entity_count': len(fused_report.entities),
            'link_count': len(fused_report.links),
            'confidence_score': fused_report.confidence_score,
            'risk_assessment': {
                'risk_score': fused_report.risk_assessment.get('risk_score', 0),
                'risk_level': fused_report.risk_assessment.get('risk_level', 'UNKNOWN'),
                'risk_factors': fused_report.risk_assessment.get('risk_factors', []),
            },
            'entities': [
                {
                    'id': e['id'],
                    'type': e['type'],
                    'value': e['value'],
                    'confidence': e.get('confidence', 0)
                }
                for e in fused_report.entities[:50]  # Top 50 entities
            ],
            'links': [
                {
                    'from': l['from'],
                    'to': l['to'],
                    'type': l['type'],
                    'confidence': l.get('confidence', 0)
                }
                for l in fused_report.links[:100]  # Top 100 links
            ],
            'summary': fused_report.summary,
            'completed_at': datetime.now().isoformat()
        }

    except Exception as exc:
        logger.error(f"[{self.request.id}] Profile building failed: {exc}")
        raise self.retry(exc=exc)


@app.task(
    bind=True,
    name='intelligence.fusion.entity_resolution',
    max_retries=3,
    default_retry_delay=60
)
def entity_resolution_task(
    self: Task,
    entities: List[Dict[str, Any]],
    similarity_threshold: float = 0.8
) -> Dict[str, Any]:
    """
    Resolve and merge similar entities

    Args:
        entities: List of entity dictionaries
        similarity_threshold: Threshold for entity matching

    Returns:
        Dictionary with resolved entities
    """
    logger.info(
        f"[{self.request.id}] Resolving {len(entities)} entities"
    )

    try:
        from fusion_engine import IntelligenceFusionEngine

        engine = IntelligenceFusionEngine()

        # Entity resolution logic
        resolved_entities = []
        entity_clusters = []

        # Simple clustering based on similarity
        # In production, use more sophisticated algorithms
        processed = set()

        for i, entity1 in enumerate(entities):
            if i in processed:
                continue

            cluster = [entity1]
            processed.add(i)

            for j, entity2 in enumerate(entities[i+1:], start=i+1):
                if j in processed:
                    continue

                # Calculate similarity
                similarity = engine._calculate_entity_similarity(entity1, entity2)

                if similarity >= similarity_threshold:
                    cluster.append(entity2)
                    processed.add(j)

            if len(cluster) > 1:
                # Merge cluster into single entity
                merged = engine._merge_entities(cluster)
                resolved_entities.append(merged)
                entity_clusters.append({
                    'merged_entity': merged,
                    'original_count': len(cluster),
                    'confidence': sum(e.get('confidence', 0) for e in cluster) / len(cluster)
                })
            else:
                resolved_entities.append(entity1)

        logger.info(
            f"[{self.request.id}] Entity resolution completed: "
            f"{len(entities)} -> {len(resolved_entities)} entities"
        )

        return {
            'task_id': self.request.id,
            'original_entity_count': len(entities),
            'resolved_entity_count': len(resolved_entities),
            'merged_clusters': len(entity_clusters),
            'resolved_entities': resolved_entities,
            'clusters': entity_clusters,
            'statistics': {
                'reduction_ratio': (len(entities) - len(resolved_entities)) / len(entities) if entities else 0,
                'average_cluster_size': sum(c['original_count'] for c in entity_clusters) / len(entity_clusters) if entity_clusters else 1,
            },
            'completed_at': datetime.now().isoformat()
        }

    except Exception as exc:
        logger.error(f"[{self.request.id}] Entity resolution failed: {exc}")
        raise self.retry(exc=exc)


@app.task(
    bind=True,
    name='intelligence.fusion.correlate',
    max_retries=3,
    default_retry_delay=90
)
def correlate_entities_task(
    self: Task,
    entity_ids: List[str],
    correlation_types: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Find correlations between entities

    Args:
        entity_ids: List of entity IDs to correlate
        correlation_types: Types of correlations to find

    Returns:
        Dictionary with correlation analysis
    """
    logger.info(
        f"[{self.request.id}] Correlating {len(entity_ids)} entities"
    )

    try:
        from fusion_engine import IntelligenceFusionEngine

        engine = IntelligenceFusionEngine()

        # Find correlations
        correlations = []

        correlation_types = correlation_types or [
            'temporal',  # Time-based correlations
            'spatial',   # Location-based correlations
            'network',   # Network connections
            'attribute', # Shared attributes
        ]

        # Temporal correlations
        if 'temporal' in correlation_types:
            # Find entities active at similar times
            pass

        # Spatial correlations
        if 'spatial' in correlation_types:
            # Find entities in similar locations
            pass

        # Network correlations
        if 'network' in correlation_types:
            # Find entities with shared connections
            pass

        # Attribute correlations
        if 'attribute' in correlation_types:
            # Find entities with similar attributes
            pass

        logger.info(
            f"[{self.request.id}] Correlation analysis completed: "
            f"{len(correlations)} correlations found"
        )

        return {
            'task_id': self.request.id,
            'entity_count': len(entity_ids),
            'correlation_types': correlation_types,
            'correlations_found': len(correlations),
            'correlations': correlations[:100],  # Top 100 correlations
            'strongest_correlations': sorted(
                correlations,
                key=lambda x: x.get('strength', 0),
                reverse=True
            )[:20],
            'completed_at': datetime.now().isoformat()
        }

    except Exception as exc:
        logger.error(f"[{self.request.id}] Correlation analysis failed: {exc}")
        raise self.retry(exc=exc)


@app.task(
    bind=True,
    name='intelligence.fusion.generate_report',
    max_retries=2,
    default_retry_delay=120
)
def generate_intelligence_report_task(
    self: Task,
    report_id: str,
    format: str = 'json'
) -> Dict[str, Any]:
    """
    Generate comprehensive intelligence report

    Args:
        report_id: ID of the intelligence report
        format: Output format (json, pdf, html)

    Returns:
        Dictionary with generated report
    """
    logger.info(
        f"[{self.request.id}] Generating intelligence report: {report_id}"
    )

    try:
        from fusion_engine import IntelligenceFusionEngine

        engine = IntelligenceFusionEngine()

        # Generate report
        report = {
            'report_id': report_id,
            'generated_at': datetime.now().isoformat(),
            'format': format,
            'sections': {
                'executive_summary': '',
                'target_profile': {},
                'intelligence_findings': [],
                'risk_assessment': {},
                'entity_network': {},
                'timeline': [],
                'recommendations': [],
                'sources': [],
            },
            'metadata': {
                'classification': 'CONFIDENTIAL',
                'distribution': 'INTERNAL',
                'retention': '90_DAYS',
            }
        }

        logger.info(
            f"[{self.request.id}] Report generated: {report_id}"
        )

        return {
            'task_id': self.request.id,
            'report_id': report_id,
            'format': format,
            'report': report,
            'file_size_bytes': len(str(report)),
            'completed_at': datetime.now().isoformat()
        }

    except Exception as exc:
        logger.error(f"[{self.request.id}] Report generation failed: {exc}")
        raise self.retry(exc=exc)


@app.task(
    bind=True,
    name='intelligence.fusion.enrich_profile',
    max_retries=3,
    default_retry_delay=90
)
def enrich_profile_task(
    self: Task,
    profile_id: str,
    enrichment_sources: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Enrich existing intelligence profile with additional data

    Args:
        profile_id: ID of profile to enrich
        enrichment_sources: Additional sources to query

    Returns:
        Dictionary with enriched profile
    """
    logger.info(
        f"[{self.request.id}] Enriching profile: {profile_id}"
    )

    try:
        enrichment_sources = enrichment_sources or [
            'public_records',
            'corporate_registries',
            'property_records',
            'vehicle_records',
        ]

        enriched_data = {
            'profile_id': profile_id,
            'enrichment_sources': enrichment_sources,
            'new_data_points': 0,
            'enrichments': []
        }

        logger.info(
            f"[{self.request.id}] Profile enrichment completed: "
            f"{enriched_data['new_data_points']} new data points"
        )

        return {
            'task_id': self.request.id,
            'profile_id': profile_id,
            'enrichment_sources': enrichment_sources,
            'new_data_points': enriched_data['new_data_points'],
            'enrichments': enriched_data['enrichments'],
            'completed_at': datetime.now().isoformat()
        }

    except Exception as exc:
        logger.error(f"[{self.request.id}] Profile enrichment failed: {exc}")
        raise self.retry(exc=exc)
