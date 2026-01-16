"""
Celery Task Utilities
Task chaining, grouping, callbacks, error handling
"""

from celery import chain, group, chord, signature
from celery.result import AsyncResult, GroupResult
from celery.exceptions import TimeoutError, Retry
from celery.utils.log import get_task_logger
from typing import List, Dict, Optional, Any, Callable
from datetime import datetime, timedelta
import redis
from functools import wraps

from celery_tasks import app
from config import settings

logger = get_task_logger(__name__)


class TaskChainBuilder:
    """Builder for creating complex task chains"""

    def __init__(self):
        self.tasks = []

    def add_task(self, task_name: str, *args, **kwargs):
        """Add a task to the chain"""
        self.tasks.append(signature(task_name, args=args, kwargs=kwargs))
        return self

    def add_parallel_group(self, task_group: List[tuple]):
        """
        Add a group of parallel tasks

        Args:
            task_group: List of (task_name, args, kwargs) tuples
        """
        parallel_tasks = [
            signature(task_name, args=args, kwargs=kwargs)
            for task_name, args, kwargs in task_group
        ]
        self.tasks.append(group(parallel_tasks))
        return self

    def build(self):
        """Build and return the task chain"""
        if not self.tasks:
            raise ValueError("No tasks added to chain")

        if len(self.tasks) == 1:
            return self.tasks[0]

        return chain(*self.tasks)

    def execute(self):
        """Build and execute the chain"""
        task_chain = self.build()
        return task_chain.apply_async()


class InvestigationWorkflow:
    """Pre-built workflows for common investigation patterns"""

    @staticmethod
    def person_investigation(target: str) -> AsyncResult:
        """
        Complete person investigation workflow

        Args:
            target: Target identifier (username, email, etc.)

        Returns:
            AsyncResult for monitoring
        """
        logger.info(f"Starting person investigation workflow for: {target}")

        workflow = chord([
            # Parallel OSINT collection
            signature('intelligence.osint.username_search', args=[target]),
            signature('intelligence.osint.email_intelligence', args=[target]),
            signature('intelligence.socmint.collect_profiles', args=[target]),
        ])(
            # Then fuse all intelligence
            signature('intelligence.fusion.build_profile', args=[target, 'person'])
        )

        return workflow

    @staticmethod
    def wallet_investigation(address: str, blockchain: str = 'bitcoin') -> AsyncResult:
        """
        Complete wallet investigation workflow

        Args:
            address: Wallet address
            blockchain: Blockchain name

        Returns:
            AsyncResult for monitoring
        """
        logger.info(f"Starting wallet investigation workflow for: {address}")

        workflow = chord([
            # Parallel blockchain analysis
            signature('intelligence.blockchain.wallet_analysis', args=[address, blockchain]),
            signature('intelligence.blockchain.trace_funds', args=[address, blockchain, 5]),
            signature('intelligence.blockchain.identify_mixer', args=[address, blockchain]),
        ])(
            # Then build comprehensive profile
            signature('intelligence.fusion.build_profile', args=[address, 'wallet'])
        )

        return workflow

    @staticmethod
    def domain_investigation(domain: str) -> AsyncResult:
        """
        Complete domain investigation workflow

        Args:
            domain: Target domain

        Returns:
            AsyncResult for monitoring
        """
        logger.info(f"Starting domain investigation workflow for: {domain}")

        workflow = chord([
            # Parallel domain analysis
            signature('intelligence.osint.domain_scan', args=[domain]),
            signature('intelligence.osint.email_intelligence', args=[f'admin@{domain}']),
        ])(
            # Then fuse intelligence
            signature('intelligence.fusion.build_profile', args=[domain, 'domain'])
        )

        return workflow


class TaskLock:
    """Distributed task locking using Redis"""

    def __init__(self, lock_name: str, timeout: int = 300):
        """
        Initialize task lock

        Args:
            lock_name: Name of the lock
            timeout: Lock timeout in seconds
        """
        self.lock_name = f"task_lock:{lock_name}"
        self.timeout = timeout
        self.redis_client = redis.Redis(
            host=settings.redis_host,
            port=settings.redis_port,
            password=settings.redis_password,
            db=settings.redis_db
        )

    def acquire(self, blocking: bool = True, blocking_timeout: Optional[int] = None) -> bool:
        """
        Acquire the lock

        Args:
            blocking: Whether to block until lock is available
            blocking_timeout: Maximum time to wait for lock

        Returns:
            True if lock acquired, False otherwise
        """
        if blocking:
            timeout = blocking_timeout or self.timeout
            return self.redis_client.set(
                self.lock_name,
                datetime.now().isoformat(),
                nx=True,
                ex=self.timeout
            )
        else:
            return self.redis_client.set(
                self.lock_name,
                datetime.now().isoformat(),
                nx=True,
                ex=self.timeout
            )

    def release(self):
        """Release the lock"""
        self.redis_client.delete(self.lock_name)

    def is_locked(self) -> bool:
        """Check if lock is currently held"""
        return self.redis_client.exists(self.lock_name) > 0

    def __enter__(self):
        """Context manager entry"""
        if not self.acquire():
            raise RuntimeError(f"Could not acquire lock: {self.lock_name}")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.release()


def task_with_lock(lock_name: str, timeout: int = 300):
    """
    Decorator to ensure only one instance of a task runs at a time

    Args:
        lock_name: Name of the lock
        timeout: Lock timeout in seconds
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            lock = TaskLock(lock_name, timeout)
            if not lock.acquire(blocking=False):
                logger.warning(f"Task {func.__name__} is already running, skipping")
                return {
                    'status': 'SKIPPED',
                    'reason': 'Task already running',
                    'timestamp': datetime.now().isoformat()
                }

            try:
                return func(*args, **kwargs)
            finally:
                lock.release()

        return wrapper
    return decorator


class TaskResultCache:
    """Cache task results in Redis"""

    def __init__(self, ttl: int = 3600):
        """
        Initialize result cache

        Args:
            ttl: Time to live in seconds
        """
        self.ttl = ttl
        self.redis_client = redis.Redis(
            host=settings.redis_host,
            port=settings.redis_port,
            password=settings.redis_password,
            db=settings.redis_db
        )

    def get(self, key: str) -> Optional[Any]:
        """Get cached result"""
        import json

        cached = self.redis_client.get(f"task_cache:{key}")
        if cached:
            return json.loads(cached)
        return None

    def set(self, key: str, value: Any):
        """Set cached result"""
        import json

        self.redis_client.setex(
            f"task_cache:{key}",
            self.ttl,
            json.dumps(value)
        )

    def delete(self, key: str):
        """Delete cached result"""
        self.redis_client.delete(f"task_cache:{key}")

    def clear_pattern(self, pattern: str):
        """Clear all keys matching pattern"""
        for key in self.redis_client.scan_iter(match=f"task_cache:{pattern}"):
            self.redis_client.delete(key)


def task_with_cache(cache_key_func: Callable, ttl: int = 3600):
    """
    Decorator to cache task results

    Args:
        cache_key_func: Function to generate cache key from task args
        ttl: Cache time to live in seconds
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            cache = TaskResultCache(ttl)
            cache_key = cache_key_func(*args, **kwargs)

            # Check cache
            cached_result = cache.get(cache_key)
            if cached_result:
                logger.info(f"Returning cached result for {func.__name__}")
                return cached_result

            # Execute task
            result = func(*args, **kwargs)

            # Cache result
            cache.set(cache_key, result)

            return result

        return wrapper
    return decorator


class TaskMonitor:
    """Monitor task execution and collect metrics"""

    def __init__(self):
        self.redis_client = redis.Redis(
            host=settings.redis_host,
            port=settings.redis_port,
            password=settings.redis_password,
            db=settings.redis_db
        )

    def record_task_start(self, task_id: str, task_name: str):
        """Record task start"""
        self.redis_client.hset(
            f"task_metrics:{task_id}",
            mapping={
                'task_name': task_name,
                'start_time': datetime.now().isoformat(),
                'status': 'RUNNING'
            }
        )
        self.redis_client.expire(f"task_metrics:{task_id}", 86400)  # 24 hours

    def record_task_success(self, task_id: str, duration: float):
        """Record task success"""
        self.redis_client.hset(
            f"task_metrics:{task_id}",
            mapping={
                'status': 'SUCCESS',
                'end_time': datetime.now().isoformat(),
                'duration': duration
            }
        )

        # Update aggregated metrics
        self.redis_client.incr('task_metrics:total_success')

    def record_task_failure(self, task_id: str, error: str):
        """Record task failure"""
        self.redis_client.hset(
            f"task_metrics:{task_id}",
            mapping={
                'status': 'FAILURE',
                'end_time': datetime.now().isoformat(),
                'error': error
            }
        )

        # Update aggregated metrics
        self.redis_client.incr('task_metrics:total_failure')

    def get_task_metrics(self, task_id: str) -> Dict[str, Any]:
        """Get metrics for a specific task"""
        metrics = self.redis_client.hgetall(f"task_metrics:{task_id}")
        return {
            k.decode() if isinstance(k, bytes) else k: v.decode() if isinstance(v, bytes) else v
            for k, v in metrics.items()
        }

    def get_aggregate_metrics(self) -> Dict[str, Any]:
        """Get aggregate task metrics"""
        total_success = self.redis_client.get('task_metrics:total_success') or 0
        total_failure = self.redis_client.get('task_metrics:total_failure') or 0

        if isinstance(total_success, bytes):
            total_success = int(total_success)
        if isinstance(total_failure, bytes):
            total_failure = int(total_failure)

        total_tasks = total_success + total_failure

        return {
            'total_tasks': total_tasks,
            'total_success': total_success,
            'total_failure': total_failure,
            'success_rate': total_success / total_tasks if total_tasks > 0 else 0
        }


def retry_with_backoff(max_retries: int = 3, base_delay: int = 60):
    """
    Decorator for automatic retry with exponential backoff

    Args:
        max_retries: Maximum number of retries
        base_delay: Base delay in seconds
    """
    def decorator(func):
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            try:
                return func(self, *args, **kwargs)
            except Exception as exc:
                retry_count = self.request.retries
                if retry_count < max_retries:
                    # Exponential backoff: base_delay * 2^retry_count
                    countdown = base_delay * (2 ** retry_count)
                    logger.warning(
                        f"Task {func.__name__} failed, retrying in {countdown}s "
                        f"(attempt {retry_count + 1}/{max_retries})"
                    )
                    raise self.retry(exc=exc, countdown=countdown)
                else:
                    logger.error(
                        f"Task {func.__name__} failed after {max_retries} retries"
                    )
                    raise

        return wrapper
    return decorator


class TaskBatcher:
    """Batch multiple tasks for efficient processing"""

    def __init__(self, task_name: str, batch_size: int = 100):
        """
        Initialize task batcher

        Args:
            task_name: Name of the task to batch
            batch_size: Maximum batch size
        """
        self.task_name = task_name
        self.batch_size = batch_size
        self.batch = []

    def add(self, *args, **kwargs):
        """Add task to batch"""
        self.batch.append((args, kwargs))

        if len(self.batch) >= self.batch_size:
            return self.flush()

        return None

    def flush(self) -> Optional[GroupResult]:
        """Execute all batched tasks"""
        if not self.batch:
            return None

        tasks = [
            signature(self.task_name, args=args, kwargs=kwargs)
            for args, kwargs in self.batch
        ]

        result = group(tasks).apply_async()
        self.batch = []

        return result


def get_task_status(task_id: str) -> Dict[str, Any]:
    """
    Get comprehensive status of a task

    Args:
        task_id: Task ID

    Returns:
        Dictionary with task status
    """
    result = AsyncResult(task_id, app=app)

    status = {
        'task_id': task_id,
        'state': result.state,
        'ready': result.ready(),
        'successful': result.successful() if result.ready() else None,
    }

    if result.ready():
        if result.successful():
            status['result'] = result.result
        else:
            status['error'] = str(result.info)

    return status


def wait_for_tasks(task_ids: List[str], timeout: Optional[int] = None) -> Dict[str, Any]:
    """
    Wait for multiple tasks to complete

    Args:
        task_ids: List of task IDs
        timeout: Maximum time to wait in seconds

    Returns:
        Dictionary with task results
    """
    results = {}
    start_time = datetime.now()

    for task_id in task_ids:
        result = AsyncResult(task_id, app=app)

        try:
            remaining_timeout = None
            if timeout:
                elapsed = (datetime.now() - start_time).total_seconds()
                remaining_timeout = timeout - elapsed
                if remaining_timeout <= 0:
                    raise TimeoutError("Timeout waiting for tasks")

            result.get(timeout=remaining_timeout)
            results[task_id] = {
                'status': 'SUCCESS',
                'result': result.result
            }
        except TimeoutError:
            results[task_id] = {
                'status': 'TIMEOUT',
                'state': result.state
            }
        except Exception as e:
            results[task_id] = {
                'status': 'FAILURE',
                'error': str(e)
            }

    return results


def cancel_task(task_id: str, terminate: bool = False) -> bool:
    """
    Cancel a running task

    Args:
        task_id: Task ID
        terminate: Whether to terminate forcefully

    Returns:
        True if cancelled, False otherwise
    """
    result = AsyncResult(task_id, app=app)

    if terminate:
        result.revoke(terminate=True, signal='SIGKILL')
    else:
        result.revoke()

    return True
