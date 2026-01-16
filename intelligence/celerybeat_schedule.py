"""
Celery Beat Schedule Configuration
Periodic and scheduled tasks for intelligence operations
"""

from celery.schedules import crontab
from datetime import timedelta


class CeleryBeatSchedule:
    """
    Celery Beat periodic task schedule
    Defines when and how often tasks should run
    """

    schedule = {
        # MAINTENANCE TASKS
        # =================

        # Cleanup old results every day at 3 AM UTC
        'cleanup-old-results-daily': {
            'task': 'intelligence.maintenance.cleanup_old_results',
            'schedule': crontab(hour=3, minute=0),
            'options': {
                'queue': 'maintenance',
                'expires': 3600,
            }
        },

        # Cleanup stale locks every 15 minutes
        'cleanup-stale-locks': {
            'task': 'intelligence.maintenance.cleanup_stale_locks',
            'schedule': timedelta(minutes=15),
            'options': {
                'queue': 'maintenance',
                'expires': 600,
            }
        },

        # Health check every 5 minutes
        'health-check': {
            'task': 'intelligence.maintenance.health_check',
            'schedule': timedelta(minutes=5),
            'options': {
                'queue': 'maintenance',
                'expires': 240,
            }
        },

        # MONITORING TASKS
        # ================

        # Refresh breach database every 6 hours
        'refresh-breach-database': {
            'task': 'intelligence.monitoring.refresh_breach_db',
            'schedule': timedelta(hours=6),
            'options': {
                'queue': 'monitoring',
                'expires': 3600,
            }
        },

        # Scan dark web every hour
        'scan-darkweb-hourly': {
            'task': 'intelligence.monitoring.scan_darkweb',
            'schedule': timedelta(hours=1),
            'options': {
                'queue': 'monitoring',
                'expires': 3000,
            }
        },

        # Check monitored wallets every 30 minutes
        'check-wallet-transactions': {
            'task': 'intelligence.monitoring.check_wallet_transactions',
            'schedule': timedelta(minutes=30),
            'args': [{}],  # Empty dict - will load from config
            'options': {
                'queue': 'monitoring',
                'expires': 1500,
            }
        },

        # REPORTING TASKS
        # ===============

        # Generate daily intelligence report at 8 AM UTC
        'daily-intelligence-report': {
            'task': 'intelligence.monitoring.generate_daily_report',
            'schedule': crontab(hour=8, minute=0),
            'options': {
                'queue': 'maintenance',
                'expires': 3600,
            }
        },

        # Generate weekly summary on Mondays at 9 AM
        'weekly-intelligence-summary': {
            'task': 'intelligence.monitoring.generate_daily_report',
            'schedule': crontab(day_of_week=1, hour=9, minute=0),
            'options': {
                'queue': 'maintenance',
                'expires': 7200,
            }
        },

        # BREACH MONITORING
        # =================

        # Monitor VIP email addresses every 2 hours
        'monitor-vip-emails': {
            'task': 'intelligence.monitoring.breach_databases',
            'schedule': timedelta(hours=2),
            'args': [[], 'email'],  # Empty list - will load from config
            'options': {
                'queue': 'monitoring',
                'expires': 3600,
            }
        },

        # BLOCKCHAIN MONITORING
        # =====================

        # Check high-value wallets every 15 minutes
        'monitor-high-value-wallets': {
            'task': 'intelligence.monitoring.check_wallet_transactions',
            'schedule': timedelta(minutes=15),
            'args': [{}],  # Empty dict - will load from config
            'options': {
                'queue': 'monitoring',
                'expires': 600,
            }
        },

        # DATA REFRESH TASKS
        # ==================

        # Refresh cached intelligence profiles daily at 2 AM
        'refresh-intelligence-profiles': {
            'task': 'intelligence.maintenance.cleanup_old_results',
            'schedule': crontab(hour=2, minute=0),
            'options': {
                'queue': 'maintenance',
                'expires': 3600,
            }
        },

        # ALERT GENERATION
        # ================

        # Generate alerts every 10 minutes
        'generate-alerts': {
            'task': 'intelligence.monitoring.generate_alerts',
            'schedule': timedelta(minutes=10),
            'args': [[]],  # Empty list - will load alert rules from config
            'options': {
                'queue': 'monitoring',
                'expires': 480,
            }
        },
    }


# Additional schedule configurations for different environments

class DevelopmentSchedule(CeleryBeatSchedule):
    """Development environment schedule - more frequent checks"""

    schedule = {
        **CeleryBeatSchedule.schedule,

        # Override with more frequent checks for development
        'health-check': {
            'task': 'intelligence.maintenance.health_check',
            'schedule': timedelta(minutes=1),
            'options': {'queue': 'maintenance'}
        },
    }


class ProductionSchedule(CeleryBeatSchedule):
    """Production environment schedule"""

    schedule = {
        **CeleryBeatSchedule.schedule,

        # Additional production-only tasks
        'database-backup': {
            'task': 'intelligence.maintenance.backup_database',
            'schedule': crontab(hour=1, minute=0),
            'options': {
                'queue': 'maintenance',
                'expires': 3600,
            }
        },

        'performance-metrics': {
            'task': 'intelligence.maintenance.collect_performance_metrics',
            'schedule': timedelta(minutes=5),
            'options': {
                'queue': 'maintenance',
                'expires': 240,
            }
        },
    }


def get_beat_schedule():
    """Get appropriate beat schedule based on environment"""
    import os

    env = os.getenv('ENVIRONMENT', 'development').lower()

    if env == 'production':
        return ProductionSchedule.schedule
    elif env == 'development':
        return DevelopmentSchedule.schedule
    else:
        return CeleryBeatSchedule.schedule


# Export the schedule
beat_schedule = get_beat_schedule()
