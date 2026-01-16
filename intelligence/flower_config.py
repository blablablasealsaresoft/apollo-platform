"""
Flower Configuration
Real-time monitoring for Celery tasks and workers
"""

import os
from typing import List, Optional


class FlowerConfig:
    """Flower monitoring configuration"""

    # Basic Configuration
    broker_api = os.getenv('CELERY_BROKER_URL', 'amqp://guest:guest@localhost:5672//')
    port = int(os.getenv('FLOWER_PORT', 5555))
    address = os.getenv('FLOWER_ADDRESS', '0.0.0.0')
    url_prefix = os.getenv('FLOWER_URL_PREFIX', '')

    # Authentication
    basic_auth = os.getenv('FLOWER_BASIC_AUTH')  # Format: "user:password"
    auth = os.getenv('FLOWER_AUTH', '')  # Regex for email auth
    oauth2_key = os.getenv('FLOWER_OAUTH2_KEY')
    oauth2_secret = os.getenv('FLOWER_OAUTH2_SECRET')
    oauth2_redirect_uri = os.getenv('FLOWER_OAUTH2_REDIRECT_URI')

    # Security
    certfile = os.getenv('FLOWER_CERTFILE')  # SSL certificate
    keyfile = os.getenv('FLOWER_KEYFILE')    # SSL key

    # Database for persistent state
    db = os.getenv('FLOWER_DB', 'flower.db')
    persistent = True

    # Task monitoring
    max_tasks = int(os.getenv('FLOWER_MAX_TASKS', 10000))
    max_workers = int(os.getenv('FLOWER_MAX_WORKERS', 5000))

    # Auto-refresh
    auto_refresh = True
    purge_offline_workers = int(os.getenv('FLOWER_PURGE_OFFLINE_WORKERS', 60))

    # UI Configuration
    natural_time = True
    enable_events = True

    # Logging
    logging = 'INFO'
    log_file_prefix = os.getenv('FLOWER_LOG_FILE', '/var/log/flower.log')

    # API
    inspect_timeout = float(os.getenv('FLOWER_INSPECT_TIMEOUT', 10000))

    # Custom task columns
    task_columns = [
        'name',
        'uuid',
        'state',
        'args',
        'kwargs',
        'result',
        'received',
        'started',
        'runtime',
        'worker'
    ]


def get_flower_config():
    """Get Flower configuration as dictionary"""
    config = FlowerConfig()

    flower_config = {
        'broker_api': config.broker_api,
        'port': config.port,
        'address': config.address,
        'url_prefix': config.url_prefix,
        'db': config.db,
        'persistent': config.persistent,
        'max_tasks': config.max_tasks,
        'max_workers': config.max_workers,
        'auto_refresh': config.auto_refresh,
        'purge_offline_workers': config.purge_offline_workers,
        'natural_time': config.natural_time,
        'enable_events': config.enable_events,
        'logging': config.logging,
        'inspect_timeout': config.inspect_timeout,
    }

    # Add authentication if configured
    if config.basic_auth:
        flower_config['basic_auth'] = [config.basic_auth]

    if config.auth:
        flower_config['auth'] = config.auth

    # Add SSL if configured
    if config.certfile and config.keyfile:
        flower_config['certfile'] = config.certfile
        flower_config['keyfile'] = config.keyfile

    return flower_config


def start_flower():
    """Start Flower monitoring server"""
    import sys
    from flower.command import FlowerCommand

    config = get_flower_config()

    # Build command line arguments
    args = [
        'flower',
        f'--broker={config["broker_api"]}',
        f'--port={config["port"]}',
        f'--address={config["address"]}',
        f'--db={config["db"]}',
        f'--max_tasks={config["max_tasks"]}',
        f'--persistent={str(config["persistent"]).lower()}',
    ]

    if config.get('basic_auth'):
        args.append(f'--basic_auth={config["basic_auth"][0]}')

    if config.get('url_prefix'):
        args.append(f'--url_prefix={config["url_prefix"]}')

    if config.get('certfile') and config.get('keyfile'):
        args.append(f'--certfile={config["certfile"]}')
        args.append(f'--keyfile={config["keyfile"]}')

    print(f"Starting Flower on {config['address']}:{config['port']}")
    print(f"Dashboard URL: http://{config['address']}:{config['port']}{config['url_prefix']}")

    # Start Flower
    sys.argv = args
    FlowerCommand().execute_from_commandline()


if __name__ == '__main__':
    start_flower()
