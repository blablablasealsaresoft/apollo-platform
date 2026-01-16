"""
Celery Tasks Module
All async intelligence processing tasks
"""

from .osint_tasks import (
    search_username_task,
    batch_search_usernames_task,
    domain_scan_task,
    email_intelligence_task,
    phone_intelligence_task,
)

from .blockchain_tasks import (
    wallet_analysis_task,
    trace_funds_task,
    monitor_wallet_task,
    multi_chain_analysis_task,
    identify_mixer_task,
)

from .socmint_tasks import (
    collect_social_profiles_task,
    scrape_social_posts_task,
    map_social_network_task,
    monitor_social_mentions_task,
)

from .fusion_tasks import (
    build_intelligence_profile_task,
    entity_resolution_task,
    correlate_entities_task,
    generate_intelligence_report_task,
)

from .monitoring_tasks import (
    monitor_breach_databases_task,
    monitor_darkweb_task,
    check_wallet_transactions_task,
    generate_alerts_task,
    refresh_breach_db_task,
    scan_darkweb_task,
)

__all__ = [
    # OSINT tasks
    'search_username_task',
    'batch_search_usernames_task',
    'domain_scan_task',
    'email_intelligence_task',
    'phone_intelligence_task',

    # Blockchain tasks
    'wallet_analysis_task',
    'trace_funds_task',
    'monitor_wallet_task',
    'multi_chain_analysis_task',
    'identify_mixer_task',

    # SOCMINT tasks
    'collect_social_profiles_task',
    'scrape_social_posts_task',
    'map_social_network_task',
    'monitor_social_mentions_task',

    # Fusion tasks
    'build_intelligence_profile_task',
    'entity_resolution_task',
    'correlate_entities_task',
    'generate_intelligence_report_task',

    # Monitoring tasks
    'monitor_breach_databases_task',
    'monitor_darkweb_task',
    'check_wallet_transactions_task',
    'generate_alerts_task',
    'refresh_breach_db_task',
    'scan_darkweb_task',
]
