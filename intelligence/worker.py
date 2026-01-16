"""
Celery Worker Configuration and Startup
Handles worker initialization, configuration, and monitoring
"""

import os
import sys
import logging
from celery import Celery
from celery.signals import (
    worker_init,
    worker_ready,
    worker_shutdown,
    task_prerun,
    task_postrun,
    task_failure,
    task_success
)

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from celery_tasks import app
from celery_config import get_celery_config
from config import settings
from task_utils import TaskMonitor

logger = logging.getLogger(__name__)


class WorkerManager:
    """Manages Celery worker lifecycle"""

    def __init__(self):
        self.config = get_celery_config()
        self.monitor = TaskMonitor()
        self.worker_id = None

    def configure_worker(self):
        """Configure worker with settings"""
        app.config_from_object(self.config)

        logger.info(f"Worker configured for environment: {os.getenv('ENVIRONMENT', 'development')}")
        logger.info(f"Broker: {self.config.broker_url}")
        logger.info(f"Result backend: {self.config.result_backend}")
        logger.info(f"Worker concurrency: {self.config.worker_concurrency}")

    def setup_logging(self):
        """Setup worker logging"""
        log_level = getattr(logging, settings.log_level.upper(), logging.INFO)

        logging.basicConfig(
            level=log_level,
            format='[%(asctime)s: %(levelname)s/%(processName)s] %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )

        logger.info("Worker logging configured")

    def register_signal_handlers(self):
        """Register Celery signal handlers"""

        @worker_init.connect
        def on_worker_init(sender=None, **kwargs):
            """Called when worker initializes"""
            logger.info("Worker initializing...")
            self.worker_id = sender

        @worker_ready.connect
        def on_worker_ready(sender=None, **kwargs):
            """Called when worker is ready"""
            logger.info(f"Worker ready: {sender}")
            logger.info("Registered queues: " + ", ".join(self.config.task_queues))

        @worker_shutdown.connect
        def on_worker_shutdown(sender=None, **kwargs):
            """Called when worker shuts down"""
            logger.info(f"Worker shutting down: {sender}")

        @task_prerun.connect
        def on_task_prerun(sender=None, task_id=None, task=None, **kwargs):
            """Called before task execution"""
            logger.debug(f"Task starting: {task.name} [{task_id}]")
            self.monitor.record_task_start(task_id, task.name)

        @task_postrun.connect
        def on_task_postrun(sender=None, task_id=None, task=None, retval=None, **kwargs):
            """Called after task execution"""
            logger.debug(f"Task completed: {task.name} [{task_id}]")

        @task_success.connect
        def on_task_success(sender=None, result=None, **kwargs):
            """Called when task succeeds"""
            task_id = sender.request.id
            task_name = sender.name

            logger.info(f"Task succeeded: {task_name} [{task_id}]")

            # Record metrics
            import time
            start_time = getattr(sender.request, 'start_time', time.time())
            duration = time.time() - start_time
            self.monitor.record_task_success(task_id, duration)

        @task_failure.connect
        def on_task_failure(sender=None, task_id=None, exception=None, **kwargs):
            """Called when task fails"""
            task_name = sender.name if sender else 'unknown'

            logger.error(
                f"Task failed: {task_name} [{task_id}]",
                exc_info=exception
            )

            # Record metrics
            self.monitor.record_task_failure(task_id, str(exception))

        logger.info("Signal handlers registered")

    def start(self, queues=None, concurrency=None, loglevel=None):
        """
        Start the worker

        Args:
            queues: List of queue names to consume from
            concurrency: Number of concurrent workers
            loglevel: Log level (DEBUG, INFO, WARNING, ERROR)
        """
        self.setup_logging()
        self.configure_worker()
        self.register_signal_handlers()

        # Build worker arguments
        worker_args = []

        if queues:
            worker_args.extend(['-Q', ','.join(queues)])

        if concurrency:
            worker_args.extend(['-c', str(concurrency)])

        if loglevel:
            worker_args.extend(['-l', loglevel])

        logger.info(f"Starting worker with args: {' '.join(worker_args)}")

        # Start worker
        app.worker_main(argv=['worker'] + worker_args)


def start_osint_worker():
    """Start worker for OSINT queue"""
    logger.info("Starting OSINT worker")
    manager = WorkerManager()
    manager.start(
        queues=['osint'],
        concurrency=4,
        loglevel='INFO'
    )


def start_blockchain_worker():
    """Start worker for Blockchain queue"""
    logger.info("Starting Blockchain worker")
    manager = WorkerManager()
    manager.start(
        queues=['blockchain'],
        concurrency=2,
        loglevel='INFO'
    )


def start_socmint_worker():
    """Start worker for SOCMINT queue"""
    logger.info("Starting SOCMINT worker")
    manager = WorkerManager()
    manager.start(
        queues=['socmint'],
        concurrency=3,
        loglevel='INFO'
    )


def start_fusion_worker():
    """Start worker for Fusion queue"""
    logger.info("Starting Fusion worker")
    manager = WorkerManager()
    manager.start(
        queues=['fusion'],
        concurrency=2,
        loglevel='INFO'
    )


def start_monitoring_worker():
    """Start worker for Monitoring queue"""
    logger.info("Starting Monitoring worker")
    manager = WorkerManager()
    manager.start(
        queues=['monitoring'],
        concurrency=2,
        loglevel='INFO'
    )


def start_general_worker():
    """Start worker consuming all queues"""
    logger.info("Starting general worker (all queues)")
    manager = WorkerManager()
    manager.start(
        queues=['default', 'osint', 'blockchain', 'socmint', 'fusion', 'monitoring', 'maintenance'],
        concurrency=None,  # Use config default
        loglevel='INFO'
    )


def main():
    """Main entry point for worker"""
    import argparse

    parser = argparse.ArgumentParser(description='Apollo Intelligence Celery Worker')
    parser.add_argument(
        '--queue',
        choices=['osint', 'blockchain', 'socmint', 'fusion', 'monitoring', 'maintenance', 'all'],
        default='all',
        help='Queue to consume from'
    )
    parser.add_argument(
        '--concurrency',
        type=int,
        default=None,
        help='Number of concurrent workers'
    )
    parser.add_argument(
        '--loglevel',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        default='INFO',
        help='Log level'
    )

    args = parser.parse_args()

    manager = WorkerManager()

    if args.queue == 'all':
        queues = ['default', 'osint', 'blockchain', 'socmint', 'fusion', 'monitoring', 'maintenance']
    else:
        queues = [args.queue]

    manager.start(
        queues=queues,
        concurrency=args.concurrency,
        loglevel=args.loglevel
    )


if __name__ == '__main__':
    main()
