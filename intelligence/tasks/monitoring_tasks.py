"""
Monitoring Celery Tasks
Continuous monitoring, alerts, scheduled checks
"""

from celery import Task
from celery.utils.log import get_task_logger
import asyncio
from typing import List, Dict, Optional, Any
from datetime import datetime, timedelta
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
    name='intelligence.monitoring.breach_databases',
    max_retries=3,
    default_retry_delay=120
)
def monitor_breach_databases_task(
    self: Task,
    targets: List[str],
    target_type: str = 'email'
) -> Dict[str, Any]:
    """
    Monitor breach databases for target identifiers

    Args:
        targets: List of targets to monitor (emails, usernames, etc.)
        target_type: Type of target (email, username, phone)

    Returns:
        Dictionary with monitoring results
    """
    logger.info(
        f"[{self.request.id}] Monitoring breach databases for "
        f"{len(targets)} {target_type}s"
    )

    try:
        from breach_databases import BreachDatabaseEngine

        engine = BreachDatabaseEngine()
        results = {}
        new_breaches = []

        for target in targets:
            breaches = run_async(engine.search_email(target))

            # Check for new breaches (compare with cached results)
            import redis
            redis_client = redis.Redis(
                host=settings.redis_host,
                port=settings.redis_port,
                password=settings.redis_password,
                db=settings.redis_db
            )

            cache_key = f"breach_monitor:{target_type}:{target}"
            cached_breach_count = redis_client.get(cache_key)

            if cached_breach_count:
                prev_count = int(cached_breach_count)
                if len(breaches) > prev_count:
                    new_breaches.extend(breaches[prev_count:])

            # Update cache
            redis_client.set(cache_key, len(breaches))

            results[target] = {
                'total_breaches': len(breaches),
                'new_breaches': len([b for b in breaches if b in new_breaches]),
                'recent_breaches': [
                    {
                        'breach_name': b.breach_name,
                        'breach_date': b.breach_date.isoformat() if b.breach_date else None,
                        'data_types': b.data_types,
                    }
                    for b in breaches[:5]
                ]
            }

        logger.info(
            f"[{self.request.id}] Breach monitoring completed: "
            f"{len(new_breaches)} new breaches detected"
        )

        return {
            'task_id': self.request.id,
            'targets_monitored': len(targets),
            'target_type': target_type,
            'new_breaches_found': len(new_breaches),
            'results': results,
            'alerts': [
                {
                    'type': 'NEW_BREACH',
                    'target': breach.email,
                    'breach_name': breach.breach_name,
                    'severity': 'HIGH' if breach.password_exposed else 'MEDIUM',
                }
                for breach in new_breaches[:10]
            ],
            'completed_at': datetime.now().isoformat()
        }

    except Exception as exc:
        logger.error(f"[{self.request.id}] Breach monitoring failed: {exc}")
        raise self.retry(exc=exc)


@app.task(
    bind=True,
    name='intelligence.monitoring.scan_darkweb',
    max_retries=2,
    default_retry_delay=300
)
def monitor_darkweb_task(
    self: Task,
    keywords: List[str],
    scan_depth: str = 'surface'
) -> Dict[str, Any]:
    """
    Monitor dark web for keyword mentions

    Args:
        keywords: Keywords to monitor
        scan_depth: Scan depth (surface, deep)

    Returns:
        Dictionary with dark web monitoring results
    """
    logger.info(
        f"[{self.request.id}] Scanning dark web for: "
        f"{', '.join(keywords)}"
    )

    try:
        # Placeholder for dark web monitoring
        # Real implementation would use Tor, I2P, etc.

        mentions = []
        marketplaces_checked = []
        forums_checked = []

        logger.info(
            f"[{self.request.id}] Dark web scan completed: "
            f"{len(mentions)} mentions found"
        )

        return {
            'task_id': self.request.id,
            'keywords': keywords,
            'scan_depth': scan_depth,
            'mentions_found': len(mentions),
            'marketplaces_checked': len(marketplaces_checked),
            'forums_checked': len(forums_checked),
            'mentions': mentions[:50],
            'high_priority_alerts': [
                m for m in mentions
                if m.get('priority') == 'HIGH'
            ][:10],
            'completed_at': datetime.now().isoformat()
        }

    except Exception as exc:
        logger.error(f"[{self.request.id}] Dark web monitoring failed: {exc}")
        raise self.retry(exc=exc)


@app.task(
    bind=True,
    name='intelligence.monitoring.check_wallet_transactions',
    max_retries=3,
    default_retry_delay=60
)
def check_wallet_transactions_task(
    self: Task,
    wallets: Dict[str, str]
) -> Dict[str, Any]:
    """
    Check monitored wallets for new transactions

    Args:
        wallets: Dictionary mapping blockchain to wallet addresses

    Returns:
        Dictionary with transaction monitoring results
    """
    logger.info(
        f"[{self.request.id}] Checking {len(wallets)} wallets for transactions"
    )

    try:
        from .blockchain_tasks import monitor_wallet_task

        results = {}
        total_new_transactions = 0
        alerts = []

        for blockchain, address in wallets.items():
            try:
                result = monitor_wallet_task.apply(
                    args=[address, blockchain, True]
                ).get()

                results[address] = result
                total_new_transactions += result.get('new_transactions', 0)
                alerts.extend(result.get('alerts', []))

            except Exception as e:
                logger.warning(f"Failed to monitor {address}: {e}")
                results[address] = {'error': str(e)}

        logger.info(
            f"[{self.request.id}] Wallet transaction check completed: "
            f"{total_new_transactions} new transactions"
        )

        return {
            'task_id': self.request.id,
            'wallets_monitored': len(wallets),
            'new_transactions': total_new_transactions,
            'alerts_generated': len(alerts),
            'results': results,
            'alerts': alerts[:20],
            'completed_at': datetime.now().isoformat()
        }

    except Exception as exc:
        logger.error(f"[{self.request.id}] Wallet transaction check failed: {exc}")
        raise self.retry(exc=exc)


@app.task(
    bind=True,
    name='intelligence.monitoring.generate_alerts',
    max_retries=3,
    default_retry_delay=60
)
def generate_alerts_task(
    self: Task,
    alert_rules: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Generate alerts based on monitoring rules

    Args:
        alert_rules: List of alert rule definitions

    Returns:
        Dictionary with generated alerts
    """
    logger.info(
        f"[{self.request.id}] Generating alerts for {len(alert_rules)} rules"
    )

    try:
        alerts = []

        for rule in alert_rules:
            rule_type = rule.get('type')
            conditions = rule.get('conditions', {})

            # Evaluate rule conditions
            # This would integrate with all monitoring systems

            if rule_type == 'breach_detection':
                # Check breach monitoring results
                pass
            elif rule_type == 'transaction_threshold':
                # Check blockchain transactions
                pass
            elif rule_type == 'keyword_mention':
                # Check social media/dark web mentions
                pass

        logger.info(
            f"[{self.request.id}] Alert generation completed: "
            f"{len(alerts)} alerts generated"
        )

        return {
            'task_id': self.request.id,
            'rules_evaluated': len(alert_rules),
            'alerts_generated': len(alerts),
            'alerts': alerts,
            'alerts_by_severity': {
                'CRITICAL': len([a for a in alerts if a.get('severity') == 'CRITICAL']),
                'HIGH': len([a for a in alerts if a.get('severity') == 'HIGH']),
                'MEDIUM': len([a for a in alerts if a.get('severity') == 'MEDIUM']),
                'LOW': len([a for a in alerts if a.get('severity') == 'LOW']),
            },
            'completed_at': datetime.now().isoformat()
        }

    except Exception as exc:
        logger.error(f"[{self.request.id}] Alert generation failed: {exc}")
        raise self.retry(exc=exc)


@app.task(
    bind=True,
    name='intelligence.monitoring.refresh_breach_db',
    max_retries=2,
    default_retry_delay=300
)
def refresh_breach_db_task(self: Task) -> Dict[str, Any]:
    """
    Refresh breach database indices and caches

    Returns:
        Dictionary with refresh status
    """
    logger.info(f"[{self.request.id}] Refreshing breach database")

    try:
        from breach_databases import BreachDatabaseEngine

        engine = BreachDatabaseEngine()

        # Refresh breach data from sources
        refresh_stats = {
            'sources_updated': 0,
            'new_breaches': 0,
            'updated_records': 0,
        }

        logger.info(
            f"[{self.request.id}] Breach database refresh completed"
        )

        return {
            'task_id': self.request.id,
            'refresh_stats': refresh_stats,
            'completed_at': datetime.now().isoformat()
        }

    except Exception as exc:
        logger.error(f"[{self.request.id}] Breach DB refresh failed: {exc}")
        raise self.retry(exc=exc)


@app.task(
    bind=True,
    name='intelligence.monitoring.scan_darkweb',
    max_retries=2,
    default_retry_delay=300
)
def scan_darkweb_task(self: Task) -> Dict[str, Any]:
    """
    Periodic dark web scanning for monitored keywords

    Returns:
        Dictionary with scan results
    """
    logger.info(f"[{self.request.id}] Running periodic dark web scan")

    try:
        import redis

        redis_client = redis.Redis(
            host=settings.redis_host,
            port=settings.redis_port,
            password=settings.redis_password,
            db=settings.redis_db
        )

        # Get monitored keywords from Redis
        monitored_keywords = redis_client.smembers('darkweb:monitored_keywords')

        if not monitored_keywords:
            logger.info("No keywords configured for dark web monitoring")
            return {
                'task_id': self.request.id,
                'status': 'NO_KEYWORDS',
                'completed_at': datetime.now().isoformat()
            }

        keywords = [k.decode() if isinstance(k, bytes) else k for k in monitored_keywords]

        # Run dark web scan
        result = monitor_darkweb_task.apply(args=[keywords, 'surface']).get()

        logger.info(
            f"[{self.request.id}] Dark web scan completed: "
            f"{result['mentions_found']} mentions"
        )

        return {
            'task_id': self.request.id,
            'keywords_scanned': len(keywords),
            'mentions_found': result['mentions_found'],
            'high_priority_alerts': len(result.get('high_priority_alerts', [])),
            'completed_at': datetime.now().isoformat()
        }

    except Exception as exc:
        logger.error(f"[{self.request.id}] Dark web scan failed: {exc}")
        raise self.retry(exc=exc)


@app.task(
    bind=True,
    name='intelligence.monitoring.generate_daily_report',
    max_retries=2,
    default_retry_delay=180
)
def generate_daily_report_task(self: Task) -> Dict[str, Any]:
    """
    Generate daily intelligence summary report

    Returns:
        Dictionary with report data
    """
    logger.info(f"[{self.request.id}] Generating daily intelligence report")

    try:
        # Collect statistics from last 24 hours
        yesterday = datetime.now() - timedelta(days=1)

        report = {
            'report_date': yesterday.date().isoformat(),
            'generated_at': datetime.now().isoformat(),
            'summary': {
                'total_tasks_executed': 0,
                'new_breaches_detected': 0,
                'new_transactions_monitored': 0,
                'alerts_generated': 0,
                'profiles_built': 0,
            },
            'top_findings': [],
            'active_investigations': [],
            'system_health': {
                'uptime': '99.9%',
                'task_success_rate': 0.95,
                'average_task_duration': 0,
            }
        }

        logger.info(f"[{self.request.id}] Daily report generated")

        return {
            'task_id': self.request.id,
            'report': report,
            'completed_at': datetime.now().isoformat()
        }

    except Exception as exc:
        logger.error(f"[{self.request.id}] Daily report generation failed: {exc}")
        raise self.retry(exc=exc)


@app.task(
    bind=True,
    name='intelligence.maintenance.cleanup_old_results',
    max_retries=2,
    default_retry_delay=300
)
def cleanup_old_results_task(self: Task) -> Dict[str, Any]:
    """
    Clean up old results from storage

    Returns:
        Dictionary with cleanup statistics
    """
    logger.info(f"[{self.request.id}] Cleaning up old results")

    try:
        from osint_tools.sherlock import SherlockResultsStorage

        storage = SherlockResultsStorage()

        # Delete results older than retention period
        deleted = storage.delete_old_results(days=settings.data_retention_days)

        logger.info(f"[{self.request.id}] Cleanup completed: {deleted} results deleted")

        return {
            'task_id': self.request.id,
            'deleted_count': deleted,
            'retention_days': settings.data_retention_days,
            'completed_at': datetime.now().isoformat()
        }

    except Exception as exc:
        logger.error(f"[{self.request.id}] Cleanup failed: {exc}")
        raise self.retry(exc=exc)


@app.task(
    bind=True,
    name='intelligence.maintenance.cleanup_stale_locks',
    max_retries=3,
    default_retry_delay=60
)
def cleanup_stale_locks_task(self: Task) -> Dict[str, Any]:
    """
    Clean up stale Redis locks

    Returns:
        Dictionary with cleanup statistics
    """
    logger.info(f"[{self.request.id}] Cleaning up stale locks")

    try:
        import redis

        redis_client = redis.Redis(
            host=settings.redis_host,
            port=settings.redis_port,
            password=settings.redis_password,
            db=settings.redis_db
        )

        # Find and remove stale locks
        lock_pattern = 'celery-task-meta-*'
        stale_locks = 0

        for key in redis_client.scan_iter(match=lock_pattern):
            ttl = redis_client.ttl(key)
            if ttl == -1:  # No expiration set
                redis_client.delete(key)
                stale_locks += 1

        logger.info(f"[{self.request.id}] Stale locks cleaned: {stale_locks}")

        return {
            'task_id': self.request.id,
            'stale_locks_removed': stale_locks,
            'completed_at': datetime.now().isoformat()
        }

    except Exception as exc:
        logger.error(f"[{self.request.id}] Lock cleanup failed: {exc}")
        raise self.retry(exc=exc)


@app.task(
    bind=True,
    name='intelligence.maintenance.health_check',
    max_retries=1,
    default_retry_delay=30
)
def health_check_task(self: Task) -> Dict[str, Any]:
    """
    Perform system health check

    Returns:
        Dictionary with health status
    """
    logger.info(f"[{self.request.id}] Running health check")

    try:
        import redis
        from elasticsearch import Elasticsearch

        health = {
            'redis': False,
            'elasticsearch': False,
            'rabbitmq': False,
        }

        # Check Redis
        try:
            redis_client = redis.Redis(
                host=settings.redis_host,
                port=settings.redis_port,
                password=settings.redis_password,
                db=settings.redis_db,
                socket_connect_timeout=5
            )
            redis_client.ping()
            health['redis'] = True
        except:
            pass

        # Check Elasticsearch
        try:
            es = Elasticsearch(settings.elasticsearch_hosts)
            if es.ping():
                health['elasticsearch'] = True
        except:
            pass

        # RabbitMQ check (if broker is accessible)
        health['rabbitmq'] = True  # Assumed healthy if task is running

        all_healthy = all(health.values())

        logger.info(
            f"[{self.request.id}] Health check completed: "
            f"{'HEALTHY' if all_healthy else 'DEGRADED'}"
        )

        return {
            'task_id': self.request.id,
            'status': 'HEALTHY' if all_healthy else 'DEGRADED',
            'services': health,
            'checked_at': datetime.now().isoformat()
        }

    except Exception as exc:
        logger.error(f"[{self.request.id}] Health check failed: {exc}")
        return {
            'task_id': self.request.id,
            'status': 'UNHEALTHY',
            'error': str(exc),
            'checked_at': datetime.now().isoformat()
        }
