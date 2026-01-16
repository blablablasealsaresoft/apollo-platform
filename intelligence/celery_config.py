"""
Celery Configuration for Apollo Intelligence
RabbitMQ broker and Redis result backend with comprehensive settings
"""

from kombu import Queue, Exchange
from celery.schedules import crontab
from datetime import timedelta
import os


class CeleryConfig:
    """Celery configuration class"""

    # Broker Configuration (RabbitMQ)
    broker_url = os.getenv(
        'CELERY_BROKER_URL',
        'amqp://guest:guest@localhost:5672//'
    )
    broker_connection_retry_on_startup = True
    broker_connection_retry = True
    broker_connection_max_retries = 10

    # Result Backend (Redis)
    result_backend = os.getenv(
        'CELERY_RESULT_BACKEND',
        'redis://localhost:6379/0'
    )
    result_backend_transport_options = {
        'master_name': 'mymaster',
        'visibility_timeout': 3600,
        'retry_policy': {
            'timeout': 5.0
        }
    }

    # Serialization
    task_serializer = 'json'
    result_serializer = 'json'
    accept_content = ['json']

    # Timezone & Time
    timezone = 'UTC'
    enable_utc = True

    # Task Configuration
    task_track_started = True
    task_time_limit = 3600  # 1 hour hard limit
    task_soft_time_limit = 3000  # 50 minutes soft limit
    task_acks_late = True  # Acknowledge after task completion
    task_reject_on_worker_lost = True
    task_ignore_result = False
    task_store_errors_even_if_ignored = True

    # Result Backend Configuration
    result_expires = 86400  # Results expire after 24 hours
    result_compression = 'gzip'
    result_extended = True
    result_backend_always_retry = True
    result_backend_max_retries = 10

    # Worker Configuration
    worker_prefetch_multiplier = 4  # Tasks to prefetch per worker
    worker_max_tasks_per_child = 1000  # Restart worker after N tasks
    worker_disable_rate_limits = False
    worker_log_format = '[%(asctime)s: %(levelname)s/%(processName)s] %(message)s'
    worker_task_log_format = (
        '[%(asctime)s: %(levelname)s/%(processName)s] '
        '[%(task_name)s(%(task_id)s)] %(message)s'
    )

    # Performance
    worker_pool = 'prefork'  # Use multiprocessing
    worker_concurrency = os.cpu_count() * 2  # 2 workers per CPU core
    worker_max_memory_per_child = 512000  # 512MB per worker

    # Task Routes - Route tasks to specific queues
    task_routes = {
        # OSINT Tasks
        'intelligence.osint.*': {
            'queue': 'osint',
            'routing_key': 'osint',
        },
        # Blockchain Tasks
        'intelligence.blockchain.*': {
            'queue': 'blockchain',
            'routing_key': 'blockchain',
        },
        # SOCMINT Tasks
        'intelligence.socmint.*': {
            'queue': 'socmint',
            'routing_key': 'socmint',
        },
        # Fusion Tasks
        'intelligence.fusion.*': {
            'queue': 'fusion',
            'routing_key': 'fusion',
        },
        # Monitoring Tasks
        'intelligence.monitoring.*': {
            'queue': 'monitoring',
            'routing_key': 'monitoring',
        },
        # Maintenance Tasks
        'intelligence.maintenance.*': {
            'queue': 'maintenance',
            'routing_key': 'maintenance',
        },
    }

    # Queue Definitions
    task_queues = (
        # Default queue
        Queue('default', Exchange('default'), routing_key='default'),

        # OSINT queue (high priority)
        Queue(
            'osint',
            Exchange('osint', type='topic'),
            routing_key='osint',
            queue_arguments={'x-max-priority': 10}
        ),

        # Blockchain queue
        Queue(
            'blockchain',
            Exchange('blockchain', type='topic'),
            routing_key='blockchain',
            queue_arguments={'x-max-priority': 8}
        ),

        # SOCMINT queue
        Queue(
            'socmint',
            Exchange('socmint', type='topic'),
            routing_key='socmint',
            queue_arguments={'x-max-priority': 7}
        ),

        # Fusion queue (long-running tasks)
        Queue(
            'fusion',
            Exchange('fusion', type='topic'),
            routing_key='fusion',
            queue_arguments={'x-max-priority': 6}
        ),

        # Monitoring queue (periodic tasks)
        Queue(
            'monitoring',
            Exchange('monitoring', type='topic'),
            routing_key='monitoring',
            queue_arguments={'x-max-priority': 5}
        ),

        # Maintenance queue (low priority)
        Queue(
            'maintenance',
            Exchange('maintenance', type='topic'),
            routing_key='maintenance',
            queue_arguments={'x-max-priority': 3}
        ),
    )

    # Task priority
    task_default_priority = 5
    task_inherit_parent_priority = True

    # Rate Limiting
    task_default_rate_limit = '100/m'  # 100 tasks per minute
    task_annotations = {
        'intelligence.osint.username_search': {
            'rate_limit': '50/m',  # 50 username searches per minute
            'time_limit': 300,  # 5 minutes
            'soft_time_limit': 240,  # 4 minutes
        },
        'intelligence.osint.domain_scan': {
            'rate_limit': '10/m',  # 10 domain scans per minute
            'time_limit': 1800,  # 30 minutes
            'soft_time_limit': 1620,  # 27 minutes
        },
        'intelligence.blockchain.wallet_analysis': {
            'rate_limit': '30/m',
            'time_limit': 600,  # 10 minutes
        },
        'intelligence.blockchain.trace_funds': {
            'rate_limit': '5/m',  # Very intensive
            'time_limit': 3600,  # 1 hour
        },
        'intelligence.fusion.build_profile': {
            'rate_limit': '20/m',
            'time_limit': 1800,  # 30 minutes
        },
    }

    # Monitoring & Logging
    worker_send_task_events = True
    task_send_sent_event = True

    # Error Handling
    task_autoretry_for = (Exception,)
    task_retry_backoff = True  # Exponential backoff
    task_retry_backoff_max = 600  # Max 10 minutes
    task_retry_jitter = True  # Add random jitter to retries
    task_max_retries = 3

    # Security
    broker_use_ssl = False  # Set to True in production with certificates
    redis_backend_use_ssl = False

    # Beat Schedule (Periodic Tasks)
    beat_schedule = {
        # Cleanup old results every day at 3 AM
        'cleanup-old-results': {
            'task': 'intelligence.maintenance.cleanup_old_results',
            'schedule': crontab(hour=3, minute=0),
            'options': {'queue': 'maintenance'}
        },

        # Refresh breach database every 6 hours
        'refresh-breach-database': {
            'task': 'intelligence.monitoring.refresh_breach_db',
            'schedule': timedelta(hours=6),
            'options': {'queue': 'monitoring'}
        },

        # Monitor dark web mentions every hour
        'monitor-darkweb': {
            'task': 'intelligence.monitoring.scan_darkweb',
            'schedule': timedelta(hours=1),
            'options': {'queue': 'monitoring'}
        },

        # Check wallet transactions every 30 minutes
        'monitor-wallet-transactions': {
            'task': 'intelligence.monitoring.check_wallet_transactions',
            'schedule': timedelta(minutes=30),
            'options': {'queue': 'monitoring'}
        },

        # Generate daily intelligence report
        'daily-intelligence-report': {
            'task': 'intelligence.monitoring.generate_daily_report',
            'schedule': crontab(hour=8, minute=0),
            'options': {'queue': 'maintenance'}
        },

        # Cleanup stale locks every 15 minutes
        'cleanup-stale-locks': {
            'task': 'intelligence.maintenance.cleanup_stale_locks',
            'schedule': timedelta(minutes=15),
            'options': {'queue': 'maintenance'}
        },

        # Health check every 5 minutes
        'health-check': {
            'task': 'intelligence.maintenance.health_check',
            'schedule': timedelta(minutes=5),
            'options': {'queue': 'maintenance'}
        },
    }

    # Flower Configuration (Monitoring)
    flower_port = 5555
    flower_address = '0.0.0.0'
    flower_url_prefix = ''
    flower_basic_auth = None  # Set to ['user:password'] in production

    # Advanced Settings
    task_always_eager = False  # Set to True for testing (executes synchronously)
    task_eager_propagates = True
    task_remote_tracebacks = True
    task_compression = 'gzip'

    # Database for Beat Scheduler (optional)
    beat_scheduler = 'celery.beat:PersistentScheduler'
    beat_schedule_filename = '/tmp/celerybeat-schedule'

    # Event Settings
    worker_send_task_events = True
    task_send_sent_event = True
    event_queue_expires = 60
    event_queue_ttl = 5
    event_serializer = 'json'

    # Optimization
    broker_pool_limit = 10
    broker_heartbeat = 30
    broker_transport_options = {
        'visibility_timeout': 3600,
        'max_retries': 3,
        'interval_start': 0,
        'interval_step': 0.2,
        'interval_max': 0.5,
    }


# Environment-specific configurations
class DevelopmentConfig(CeleryConfig):
    """Development configuration"""
    worker_concurrency = 4
    task_always_eager = False
    worker_log_level = 'DEBUG'


class ProductionConfig(CeleryConfig):
    """Production configuration"""
    broker_use_ssl = True
    redis_backend_use_ssl = True
    worker_log_level = 'INFO'
    flower_basic_auth = [os.getenv('FLOWER_AUTH', 'admin:changeme')]
    task_always_eager = False

    # Production optimizations
    worker_prefetch_multiplier = 2
    worker_max_tasks_per_child = 5000
    broker_connection_max_retries = 100


class TestingConfig(CeleryConfig):
    """Testing configuration"""
    task_always_eager = True  # Execute synchronously
    task_eager_propagates = True
    broker_url = 'memory://'
    result_backend = 'cache+memory://'
    worker_concurrency = 1


# Get configuration based on environment
def get_celery_config():
    """Get appropriate configuration based on environment"""
    env = os.getenv('ENVIRONMENT', 'development').lower()

    if env == 'production':
        return ProductionConfig()
    elif env == 'testing':
        return TestingConfig()
    else:
        return DevelopmentConfig()


# Export config instance
config = get_celery_config()
