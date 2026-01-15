"""
Celery Tasks for Async Intelligence Processing
Uses RabbitMQ for task queue and Redis for results backend
"""

from celery import Celery, group, chord
from celery.utils.log import get_task_logger
import asyncio
from typing import List, Dict, Optional, Any
from datetime import datetime

# Import intelligence modules
import sys
sys.path.append('.')

logger = get_task_logger(__name__)

# Create Celery app
app = Celery(
    'apollo_intelligence',
    broker='amqp://guest:guest@localhost:5672//',
    backend='redis://localhost:6379/0'
)

# Celery configuration
app.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
    task_track_started=True,
    task_time_limit=3600,  # 1 hour max
    task_soft_time_limit=3000,  # 50 minutes soft limit
    worker_prefetch_multiplier=4,
    worker_max_tasks_per_child=1000,
)


# Helper function to run async tasks
def run_async(coro):
    """Run async coroutine in sync context"""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


# Sherlock Tasks
@app.task(bind=True, name='intelligence.sherlock.search_username')
def search_username_task(self, username: str, platforms: Optional[List[str]] = None):
    """
    Search for username across social media platforms

    Args:
        username: Username to search
        platforms: List of platforms (None = all)

    Returns:
        Dictionary with search results
    """
    logger.info(f"Starting username search for: {username}")

    try:
        from osint_tools.sherlock import SherlockEngine

        engine = SherlockEngine()
        results = run_async(engine.search_username(username, platforms))

        return {
            'task_id': self.request.id,
            'username': username,
            'total_results': len(results),
            'found_count': sum(1 for r in results if r.status == 'found'),
            'results': [
                {
                    'platform': r.platform,
                    'url': r.url,
                    'status': r.status,
                    'confidence_score': r.confidence_score
                }
                for r in results
            ],
            'completed_at': datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Username search failed: {e}")
        raise


@app.task(bind=True, name='intelligence.sherlock.batch_search')
def batch_search_usernames_task(
    self,
    usernames: List[str],
    platforms: Optional[List[str]] = None
):
    """
    Batch search for multiple usernames

    Args:
        usernames: List of usernames
        platforms: List of platforms

    Returns:
        Dictionary with batch results
    """
    logger.info(f"Starting batch search for {len(usernames)} usernames")

    try:
        from osint_tools.sherlock import SherlockEngine, BatchUsernameProcessor

        engine = SherlockEngine()
        processor = BatchUsernameProcessor(engine)
        batch_result = run_async(processor.search_batch(usernames, platforms))

        return {
            'task_id': self.request.id,
            'total_usernames': batch_result.total_usernames,
            'total_platforms': batch_result.total_platforms,
            'found_results': batch_result.found_results,
            'duration_seconds': batch_result.duration_seconds,
            'completed_at': datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Batch search failed: {e}")
        raise


# BBOT Tasks
@app.task(bind=True, name='intelligence.bbot.domain_scan')
def domain_scan_task(
    self,
    domain: str,
    scan_types: Optional[List[str]] = None
):
    """
    Scan domain with BBOT

    Args:
        domain: Domain to scan
        scan_types: Types of scans to perform

    Returns:
        Dictionary with scan results
    """
    logger.info(f"Starting BBOT scan for: {domain}")

    try:
        from osint_tools.bbot import BBOTEngine

        engine = BBOTEngine()
        result = run_async(engine.full_scan(domain, scan_types))

        return {
            'task_id': self.request.id,
            'target': result.target,
            'subdomains_found': result.subdomains_found,
            'ips_found': result.ips_found,
            'ports_found': result.ports_found,
            'technologies_found': result.technologies_found,
            'vulnerabilities_found': result.vulnerabilities_found,
            'duration_seconds': result.duration_seconds,
            'completed_at': datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Domain scan failed: {e}")
        raise


# Blockchain Tasks
@app.task(bind=True, name='intelligence.blockchain.wallet_info')
def wallet_info_task(
    self,
    address: str,
    blockchain: str = 'bitcoin'
):
    """
    Get wallet information

    Args:
        address: Wallet address
        blockchain: Blockchain name

    Returns:
        Dictionary with wallet info
    """
    logger.info(f"Fetching wallet info for: {address} on {blockchain}")

    try:
        from blockchain_intelligence import BlockchainIntelligenceEngine

        engine = BlockchainIntelligenceEngine()
        wallet_info = run_async(engine.get_wallet_info(address, blockchain))

        return {
            'task_id': self.request.id,
            'address': wallet_info.address,
            'blockchain': wallet_info.blockchain,
            'balance': str(wallet_info.balance),
            'total_received': str(wallet_info.total_received),
            'total_sent': str(wallet_info.total_sent),
            'transaction_count': wallet_info.transaction_count,
            'completed_at': datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Wallet info fetch failed: {e}")
        raise


@app.task(bind=True, name='intelligence.blockchain.trace_funds')
def trace_funds_task(
    self,
    address: str,
    blockchain: str = 'bitcoin',
    max_hops: int = 5
):
    """
    Trace cryptocurrency funds

    Args:
        address: Starting address
        blockchain: Blockchain name
        max_hops: Maximum hops

    Returns:
        Dictionary with trace graph
    """
    logger.info(f"Tracing funds from: {address} on {blockchain}")

    try:
        from blockchain_intelligence import BlockchainIntelligenceEngine

        engine = BlockchainIntelligenceEngine()
        trace_result = run_async(
            engine.trace_funds(address, blockchain, max_hops)
        )

        return {
            'task_id': self.request.id,
            'start_address': trace_result['start'],
            'blockchain': trace_result['blockchain'],
            'total_nodes': len(trace_result['nodes']),
            'total_edges': len(trace_result['edges']),
            'completed_at': datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Fund tracing failed: {e}")
        raise


# Intelligence Fusion Tasks
@app.task(bind=True, name='intelligence.fusion.fuse')
def fuse_intelligence_task(
    self,
    target: str,
    target_type: str = 'person',
    sources: Optional[List[str]] = None
):
    """
    Fuse intelligence from all sources

    Args:
        target: Target identifier
        target_type: Type of target
        sources: Sources to use

    Returns:
        Dictionary with fused intelligence
    """
    logger.info(f"Fusing intelligence for target: {target}")

    try:
        from fusion_engine import IntelligenceFusionEngine

        engine = IntelligenceFusionEngine()
        fused_report = run_async(
            engine.fuse_intelligence(target, target_type, sources)
        )

        return {
            'task_id': self.request.id,
            'report_id': fused_report.report_id,
            'target': fused_report.target,
            'entity_count': len(fused_report.entities),
            'link_count': len(fused_report.links),
            'confidence_score': fused_report.confidence_score,
            'risk_score': fused_report.risk_assessment.get('risk_score', 0),
            'completed_at': datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Intelligence fusion failed: {e}")
        raise


# Workflow Tasks (Chaining multiple operations)
@app.task(name='intelligence.workflow.full_investigation')
def full_investigation_workflow(
    target: str,
    investigation_type: str = 'person'
):
    """
    Run full investigation workflow

    Args:
        target: Target to investigate
        investigation_type: Type of investigation

    Returns:
        Task group for monitoring
    """
    logger.info(f"Starting full investigation for: {target}")

    # Create task workflow
    if investigation_type == 'person':
        # Person investigation: username search -> social media -> fusion
        workflow = chord([
            search_username_task.s(target, None),
            # Add more parallel tasks
        ])(fuse_intelligence_task.s(target, 'person'))

        return {
            'workflow_id': workflow.id,
            'target': target,
            'type': investigation_type,
            'status': 'started'
        }

    elif investigation_type == 'domain':
        # Domain investigation: BBOT scan -> fusion
        workflow = chord([
            domain_scan_task.s(target, None),
        ])(fuse_intelligence_task.s(target, 'domain'))

        return {
            'workflow_id': workflow.id,
            'target': target,
            'type': investigation_type,
            'status': 'started'
        }

    elif investigation_type == 'wallet':
        # Wallet investigation: blockchain analysis -> fusion
        workflow = chord([
            wallet_info_task.s(target, 'bitcoin'),
            trace_funds_task.s(target, 'bitcoin', 5),
        ])(fuse_intelligence_task.s(target, 'wallet'))

        return {
            'workflow_id': workflow.id,
            'target': target,
            'type': investigation_type,
            'status': 'started'
        }


# Periodic Tasks
@app.task(name='intelligence.maintenance.cleanup_old_results')
def cleanup_old_results():
    """Clean up old results from Elasticsearch"""
    logger.info("Running maintenance: cleanup old results")

    try:
        from osint_tools.sherlock import SherlockResultsStorage

        storage = SherlockResultsStorage()
        deleted = storage.delete_old_results(days=90)

        logger.info(f"Deleted {deleted} old results")
        return {'deleted': deleted}
    except Exception as e:
        logger.error(f"Cleanup failed: {e}")
        raise


# Beat schedule for periodic tasks
app.conf.beat_schedule = {
    'cleanup-old-results': {
        'task': 'intelligence.maintenance.cleanup_old_results',
        'schedule': 86400.0,  # Run daily
    },
}


if __name__ == '__main__':
    app.start()
