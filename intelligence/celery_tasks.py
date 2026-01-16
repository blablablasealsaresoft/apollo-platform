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
def search_username_task(
    self,
    username: str,
    platforms: Optional[List[str]] = None,
    categories: Optional[List[str]] = None,
    reliable_only: bool = False
):
    """
    Search for username across social media platforms

    Args:
        username: Username to search
        platforms: List of platforms (None = all)
        categories: Platform categories to filter by
        reliable_only: Only search reliable platforms

    Returns:
        Dictionary with search results
    """
    logger.info(f"Starting username search for: {username}")

    try:
        import sys
        import os
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'osint-tools', 'sherlock'))
        from sherlock_engine import SherlockEngine

        engine = SherlockEngine(max_concurrent=50, timeout=15)
        results = run_async(engine.search_username(
            username=username,
            platforms=platforms,
            categories=categories,
            reliable_only=reliable_only
        ))

        found_count = sum(1 for r in results if r.status == 'found')
        not_found_count = sum(1 for r in results if r.status == 'not_found')
        error_count = len(results) - found_count - not_found_count

        # Get found profiles only for response
        found_profiles = [
            {
                'platform': r.platform,
                'url': r.url,
                'status': r.status,
                'confidence_score': r.confidence_score,
                'response_time_ms': r.response_time_ms,
                'category': r.metadata.get('category', 'unknown')
            }
            for r in results
            if r.status == 'found'
        ]

        return {
            'task_id': self.request.id,
            'username': username,
            'total_platforms': len(results),
            'found_count': found_count,
            'not_found_count': not_found_count,
            'error_count': error_count,
            'found_profiles': found_profiles,
            'all_results': [
                {
                    'platform': r.platform,
                    'url': r.url,
                    'status': r.status,
                    'confidence_score': r.confidence_score
                }
                for r in results
            ],
            'statistics': engine.get_statistics(),
            'completed_at': datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Username search failed: {e}")
        raise


@app.task(bind=True, name='intelligence.sherlock.batch_search')
def batch_search_usernames_task(
    self,
    usernames: List[str],
    platforms: Optional[List[str]] = None,
    categories: Optional[List[str]] = None
):
    """
    Batch search for multiple usernames

    Args:
        usernames: List of usernames
        platforms: List of platforms
        categories: Platform categories to filter by

    Returns:
        Dictionary with batch results
    """
    logger.info(f"Starting batch search for {len(usernames)} usernames")

    try:
        import sys
        import os
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'osint-tools', 'sherlock'))
        from sherlock_engine import SherlockEngine
        from batch_processor import BatchUsernameProcessor

        engine = SherlockEngine(max_concurrent=50, timeout=15)
        processor = BatchUsernameProcessor(engine, max_concurrent_usernames=5)

        # For batch, we pass categories via the engine's filter
        async def run_batch():
            results = {}
            for username in usernames:
                search_results = await engine.search_username(
                    username=username,
                    platforms=platforms,
                    categories=categories
                )
                results[username] = search_results
            return results

        results_by_username = run_async(run_batch())

        # Aggregate statistics
        total_found = 0
        total_not_found = 0
        total_errors = 0
        summary_by_username = {}

        for username, results in results_by_username.items():
            found = sum(1 for r in results if r.status == 'found')
            not_found = sum(1 for r in results if r.status == 'not_found')
            errors = len(results) - found - not_found

            total_found += found
            total_not_found += not_found
            total_errors += errors

            summary_by_username[username] = {
                'found': found,
                'not_found': not_found,
                'errors': errors,
                'profiles': [
                    {
                        'platform': r.platform,
                        'url': r.url,
                        'confidence': r.confidence_score
                    }
                    for r in results if r.status == 'found'
                ]
            }

        return {
            'task_id': self.request.id,
            'total_usernames': len(usernames),
            'total_platforms_checked': engine.get_platform_count(),
            'total_found': total_found,
            'total_not_found': total_not_found,
            'total_errors': total_errors,
            'results_by_username': summary_by_username,
            'statistics': engine.get_statistics(),
            'completed_at': datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Batch search failed: {e}")
        raise


@app.task(bind=True, name='intelligence.sherlock.search_variants')
def search_username_variants_task(
    self,
    base_username: str,
    platforms: Optional[List[str]] = None
):
    """
    Search for username variants automatically generated from base username

    Args:
        base_username: Base username to generate variants from
        platforms: List of platforms (None = all)

    Returns:
        Dictionary with results for all variants
    """
    logger.info(f"Starting variant search for base username: {base_username}")

    try:
        import sys
        import os
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'osint-tools', 'sherlock'))
        from sherlock_engine import SherlockEngine
        from batch_processor import BatchUsernameProcessor

        engine = SherlockEngine(max_concurrent=50, timeout=15)
        processor = BatchUsernameProcessor(engine)

        batch_result = run_async(processor.search_username_variants(
            base_username=base_username,
            platforms=platforms
        ))

        return {
            'task_id': self.request.id,
            'base_username': base_username,
            'variants_searched': batch_result.total_usernames,
            'total_found': batch_result.found_results,
            'duration_seconds': batch_result.duration_seconds,
            'results_by_variant': {
                username: [
                    {'platform': r.platform, 'url': r.url, 'confidence': r.confidence_score}
                    for r in results if r.status == 'found'
                ]
                for username, results in batch_result.results_by_username.items()
            },
            'completed_at': datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Variant search failed: {e}")
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


@app.task(bind=True, name='intelligence.bbot.subdomain_enum')
def subdomain_enumeration_task(
    self,
    domain: str,
    sources: Optional[List[str]] = None,
    brute_force: bool = False
):
    """
    Enumerate subdomains for a domain using BBOT

    Args:
        domain: Target domain
        sources: Data sources to use
        brute_force: Enable DNS brute forcing

    Returns:
        Dictionary with subdomain enumeration results
    """
    logger.info(f"Starting subdomain enumeration for: {domain}")

    try:
        import sys
        import os
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'osint-tools', 'bbot'))
        from subdomain_enum import SubdomainEnumerator

        enumerator = SubdomainEnumerator()
        results = run_async(enumerator.enumerate(
            domain=domain,
            sources=sources,
            brute_force=brute_force
        ))

        subdomains = []
        for result in results:
            subdomains.append({
                'subdomain': result.subdomain,
                'ip_addresses': result.ip_addresses,
                'cname': result.cname,
                'is_wildcard': result.is_wildcard
            })

        return {
            'task_id': self.request.id,
            'domain': domain,
            'total_found': len(subdomains),
            'subdomains': subdomains,
            'completed_at': datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Subdomain enumeration failed: {e}")
        raise


@app.task(bind=True, name='intelligence.bbot.port_scan')
def port_scan_task(
    self,
    target: str,
    ports: Optional[List[int]] = None,
    preset: str = 'common'
):
    """
    Scan ports on a target using BBOT port scanner

    Args:
        target: Target IP or hostname
        ports: List of ports to scan
        preset: Port preset (quick, common, web, database, full)

    Returns:
        Dictionary with port scan results
    """
    logger.info(f"Starting port scan for: {target}")

    try:
        import sys
        import os
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'osint-tools', 'bbot'))
        from port_scanner import PortScanner

        scanner = PortScanner()
        results = run_async(scanner.scan(
            target=target,
            ports=ports,
            preset=preset
        ))

        open_ports = []
        for result in results:
            open_ports.append({
                'port': result.port,
                'service': result.service,
                'version': result.version,
                'banner': result.banner
            })

        return {
            'task_id': self.request.id,
            'target': target,
            'preset': preset,
            'total_open': len(open_ports),
            'open_ports': open_ports,
            'completed_at': datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Port scan failed: {e}")
        raise


@app.task(bind=True, name='intelligence.bbot.full_recon')
def full_reconnaissance_task(
    self,
    domain: str,
    preset: str = 'standard'
):
    """
    Perform full BBOT reconnaissance on a domain

    Args:
        domain: Target domain
        preset: Scan preset (passive, safe, standard, aggressive)

    Returns:
        Dictionary with complete reconnaissance results
    """
    logger.info(f"Starting full reconnaissance for: {domain}")

    try:
        import sys
        import os
        # Add redteam path for BBOTManager
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'redteam', 'reconnaissance', 'bbot'))
        from bbot_manager import BBOTManager

        manager = BBOTManager()
        scan = manager.create_scan(
            name=f"Celery Full Recon: {domain}",
            targets=[domain],
            preset=preset
        )

        results = run_async(manager.run_scan_async(scan.scan_id))
        scan_data = scan.to_dict()

        return {
            'task_id': self.request.id,
            'scan_id': scan.scan_id,
            'domain': domain,
            'preset': preset,
            'status': scan.status,
            'statistics': scan.get_statistics(),
            'results': {
                'subdomains': results.get('subdomains', []),
                'ips': results.get('ips', []),
                'ports': results.get('ports', {}),
                'technologies': results.get('technologies', {}),
                'vulnerabilities': results.get('vulnerabilities', [])
            },
            'completed_at': datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Full reconnaissance failed: {e}")
        raise


@app.task(bind=True, name='intelligence.bbot.tech_detection')
def technology_detection_task(
    self,
    target: str
):
    """
    Detect technologies on a target

    Args:
        target: Target domain or URL

    Returns:
        Dictionary with detected technologies
    """
    logger.info(f"Starting technology detection for: {target}")

    try:
        import sys
        import os
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'redteam', 'reconnaissance', 'bbot'))
        from bbot_manager import BBOTManager

        manager = BBOTManager()
        scan = manager.create_scan(
            name=f"Tech Detection: {target}",
            targets=[target],
            modules=['wappalyzer', 'httpx']
        )

        results = run_async(manager.run_scan_async(scan.scan_id))

        technologies = results.get('technologies', {}).get(target, [])

        return {
            'task_id': self.request.id,
            'target': target,
            'total_detected': len(technologies),
            'technologies': technologies,
            'completed_at': datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Technology detection failed: {e}")
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
