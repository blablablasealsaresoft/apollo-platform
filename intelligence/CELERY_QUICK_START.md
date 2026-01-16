# Celery Quick Start Guide

## 5-Minute Setup

### 1. Start Infrastructure

```bash
# Start RabbitMQ
docker run -d --name rabbitmq -p 5672:5672 -p 15672:15672 rabbitmq:3-management

# Start Redis
docker run -d --name redis -p 6379:6379 redis:alpine
```

### 2. Start Worker

```bash
# All queues
celery -A celery_tasks worker -Q default,osint,blockchain,socmint,fusion,monitoring,maintenance -l info

# Or use worker.py
python worker.py --queue all --concurrency 8
```

### 3. Start Beat Scheduler

```bash
celery -A celery_tasks beat -l info
```

### 4. Start Flower (Optional)

```bash
python flower_config.py
# Access at http://localhost:5555
```

## Common Commands

### Execute Tasks

```python
# Python API
from tasks.osint_tasks import search_username_task

# Execute async
result = search_username_task.delay('john_doe')

# Wait for result
data = result.get(timeout=300)
```

### Monitor Tasks

```bash
# List active tasks
celery -A celery_tasks inspect active

# List registered tasks
celery -A celery_tasks inspect registered

# Worker stats
celery -A celery_tasks inspect stats
```

### Workflows

```python
from task_utils import InvestigationWorkflow

# Person investigation
result = InvestigationWorkflow.person_investigation('john_doe')

# Wallet investigation
result = InvestigationWorkflow.wallet_investigation('1A1zP1...', 'bitcoin')

# Domain investigation
result = InvestigationWorkflow.domain_investigation('example.com')
```

## Task Queue Reference

| Queue | Purpose | Priority | Workers |
|-------|---------|----------|---------|
| osint | Username search, domain scan | 10 | 4 |
| blockchain | Wallet analysis, fund tracing | 8 | 2 |
| socmint | Social media intelligence | 7 | 3 |
| fusion | Intelligence fusion | 6 | 2 |
| monitoring | Periodic monitoring | 5 | 2 |
| maintenance | Cleanup, health checks | 3 | 1 |

## Available Tasks

### OSINT
- `intelligence.osint.username_search` - Search username across platforms
- `intelligence.osint.domain_scan` - Scan domain with BBOT
- `intelligence.osint.email_intelligence` - Email breach lookup
- `intelligence.osint.phone_intelligence` - Phone number lookup
- `intelligence.osint.ip_intelligence` - IP geolocation

### Blockchain
- `intelligence.blockchain.wallet_analysis` - Analyze wallet
- `intelligence.blockchain.trace_funds` - Trace cryptocurrency funds
- `intelligence.blockchain.monitor_wallet` - Monitor wallet for transactions
- `intelligence.blockchain.multi_chain_analysis` - Multi-chain analysis
- `intelligence.blockchain.identify_mixer` - Detect mixing services

### SOCMINT
- `intelligence.socmint.collect_profiles` - Collect social profiles
- `intelligence.socmint.scrape_posts` - Scrape social media posts
- `intelligence.socmint.map_network` - Map social network
- `intelligence.socmint.monitor_mentions` - Monitor keyword mentions
- `intelligence.socmint.analyze_behavior` - Behavioral analysis

### Fusion
- `intelligence.fusion.build_profile` - Build intelligence profile
- `intelligence.fusion.entity_resolution` - Resolve entities
- `intelligence.fusion.correlate` - Find correlations
- `intelligence.fusion.generate_report` - Generate report

### Monitoring
- `intelligence.monitoring.breach_databases` - Monitor breaches
- `intelligence.monitoring.scan_darkweb` - Scan dark web
- `intelligence.monitoring.check_wallet_transactions` - Check wallets
- `intelligence.monitoring.generate_alerts` - Generate alerts

## Scheduled Tasks (Celery Beat)

| Task | Schedule | Queue |
|------|----------|-------|
| Cleanup old results | Daily @ 3 AM | maintenance |
| Refresh breach DB | Every 6 hours | monitoring |
| Scan dark web | Every hour | monitoring |
| Check wallets | Every 30 minutes | monitoring |
| Daily report | Daily @ 8 AM | maintenance |
| Health check | Every 5 minutes | maintenance |

## Troubleshooting

### Workers not starting?
```bash
# Check RabbitMQ
telnet localhost 5672

# Check Redis
telnet localhost 6379

# View logs
tail -f /var/log/celery/worker.log
```

### Tasks not executing?
```bash
# List registered tasks
celery -A celery_tasks inspect registered

# Check active workers
celery -A celery_tasks inspect active
```

### High memory usage?
```python
# In celery_config.py - already configured
worker_max_tasks_per_child = 1000  # Restart worker after 1000 tasks
```

## URLs

- **RabbitMQ Management**: http://localhost:15672 (guest/guest)
- **Flower Dashboard**: http://localhost:5555
- **Redis**: localhost:6379

## Environment Variables

```bash
CELERY_BROKER_URL=amqp://guest:guest@localhost:5672//
CELERY_RESULT_BACKEND=redis://localhost:6379/0
ENVIRONMENT=development
REDIS_HOST=localhost
REDIS_PORT=6379
RABBITMQ_HOST=localhost
RABBITMQ_PORT=5672
FLOWER_PORT=5555
```

## Production Deployment

### Systemd Services

```bash
# Copy service files
sudo cp systemd/*.service /etc/systemd/system/

# Enable and start
sudo systemctl enable celery-worker celery-beat flower
sudo systemctl start celery-worker celery-beat flower

# Check status
sudo systemctl status celery-worker
```

### Docker Compose

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f celery-worker

# Scale workers
docker-compose up -d --scale celery-worker=4
```

## More Information

See `README_CELERY.md` for comprehensive documentation.
