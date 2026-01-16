# Apollo Intelligence - Celery Async Task System

Comprehensive asynchronous task processing system for Apollo Intelligence Platform using Celery, RabbitMQ, Redis, and Flower.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                     Apollo Intelligence                      │
│                    Celery Task System                        │
└─────────────────────────────────────────────────────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        │                     │                     │
   ┌────▼────┐          ┌────▼────┐          ┌────▼────┐
   │ RabbitMQ│          │  Redis  │          │ Flower  │
   │ (Broker)│          │(Results)│          │(Monitor)│
   └────┬────┘          └─────────┘          └─────────┘
        │
   ┌────▼──────────────────────────────────────────┐
   │          Task Queues (Priority-Based)          │
   ├────────────┬──────────┬──────────┬────────────┤
   │ OSINT (10) │Block(8)  │SOCMINT(7)│Fusion (6)  │
   └────────────┴──────────┴──────────┴────────────┘
        │
   ┌────▼──────────────────────────────────────────┐
   │              Celery Workers                    │
   │  ┌──────┐  ┌──────┐  ┌──────┐  ┌──────┐     │
   │  │OSINT │  │Block │  │SOCMNT│  │Fusion│     │
   │  │Worker│  │Worker│  │Worker│  │Worker│     │
   │  └──────┘  └──────┘  └──────┘  └──────┘     │
   └────────────────────────────────────────────────┘
```

## Components

### 1. Celery Configuration (`celery_config.py`)

Comprehensive configuration for Celery with RabbitMQ broker and Redis result backend.

**Key Features:**
- Environment-specific configurations (Development, Production, Testing)
- Priority-based task queues
- Rate limiting per task type
- Automatic retry with exponential backoff
- Task time limits and soft limits
- Worker pool configuration

**Queues:**
- `osint` - OSINT operations (Priority: 10)
- `blockchain` - Blockchain analysis (Priority: 8)
- `socmint` - Social media intelligence (Priority: 7)
- `fusion` - Intelligence fusion (Priority: 6)
- `monitoring` - Periodic monitoring (Priority: 5)
- `maintenance` - Cleanup tasks (Priority: 3)

### 2. Task Modules

#### OSINT Tasks (`tasks/osint_tasks.py`)
- `search_username_task` - Username search across 400+ platforms
- `batch_search_usernames_task` - Batch username searches
- `domain_scan_task` - Comprehensive domain scanning with BBOT
- `email_intelligence_task` - Email breach intelligence
- `phone_intelligence_task` - Phone number intelligence
- `ip_intelligence_task` - IP address geolocation and threat intel

#### Blockchain Tasks (`tasks/blockchain_tasks.py`)
- `wallet_analysis_task` - Comprehensive wallet analysis
- `trace_funds_task` - Cryptocurrency fund tracing
- `monitor_wallet_task` - Real-time wallet monitoring
- `multi_chain_analysis_task` - Multi-blockchain analysis
- `identify_mixer_task` - Detect mixing service usage

#### SOCMINT Tasks (`tasks/socmint_tasks.py`)
- `collect_social_profiles_task` - Collect social media profiles
- `scrape_social_posts_task` - Scrape posts from profiles
- `map_social_network_task` - Map social network connections
- `monitor_social_mentions_task` - Monitor keyword mentions
- `analyze_social_behavior_task` - Behavioral pattern analysis
- `extract_social_metadata_task` - Extract profile metadata

#### Fusion Tasks (`tasks/fusion_tasks.py`)
- `build_intelligence_profile_task` - Build comprehensive profiles
- `entity_resolution_task` - Resolve and merge entities
- `correlate_entities_task` - Find entity correlations
- `generate_intelligence_report_task` - Generate reports
- `enrich_profile_task` - Enrich existing profiles

#### Monitoring Tasks (`tasks/monitoring_tasks.py`)
- `monitor_breach_databases_task` - Continuous breach monitoring
- `monitor_darkweb_task` - Dark web scanning
- `check_wallet_transactions_task` - Wallet transaction monitoring
- `generate_alerts_task` - Alert generation
- `refresh_breach_db_task` - Refresh breach databases
- `generate_daily_report_task` - Daily intelligence reports
- `cleanup_old_results_task` - Data cleanup
- `health_check_task` - System health monitoring

### 3. Task Utilities (`task_utils.py`)

Advanced utilities for task management:

**TaskChainBuilder**
```python
from task_utils import TaskChainBuilder

# Build complex task chains
chain = TaskChainBuilder()
chain.add_task('intelligence.osint.username_search', 'target_user')
chain.add_task('intelligence.fusion.build_profile', 'target_user', 'person')
result = chain.execute()
```

**InvestigationWorkflow**
```python
from task_utils import InvestigationWorkflow

# Pre-built workflows
result = InvestigationWorkflow.person_investigation('john_doe')
result = InvestigationWorkflow.wallet_investigation('1A1zP1...', 'bitcoin')
result = InvestigationWorkflow.domain_investigation('example.com')
```

**TaskLock** - Distributed locking
```python
from task_utils import TaskLock

with TaskLock('unique_task_name'):
    # Critical section - only one instance runs
    perform_critical_operation()
```

**TaskResultCache** - Result caching
```python
from task_utils import TaskResultCache

cache = TaskResultCache(ttl=3600)
result = cache.get('username_search:john_doe')
if not result:
    result = perform_search()
    cache.set('username_search:john_doe', result)
```

**TaskMonitor** - Metrics collection
```python
from task_utils import TaskMonitor

monitor = TaskMonitor()
metrics = monitor.get_aggregate_metrics()
print(f"Success rate: {metrics['success_rate']}")
```

### 4. Worker Management (`worker.py`)

Flexible worker configuration and startup.

**Start specific queue workers:**
```bash
# OSINT worker
python worker.py --queue osint --concurrency 4

# Blockchain worker
python worker.py --queue blockchain --concurrency 2

# All queues
python worker.py --queue all --concurrency 8 --loglevel INFO
```

**Programmatic worker management:**
```python
from worker import WorkerManager

manager = WorkerManager()
manager.start(
    queues=['osint', 'blockchain'],
    concurrency=4,
    loglevel='INFO'
)
```

### 5. Flower Monitoring (`flower_config.py`)

Real-time web-based monitoring for Celery.

**Start Flower:**
```bash
python flower_config.py
```

Access dashboard at: `http://localhost:5555`

**Features:**
- Real-time task monitoring
- Worker status and statistics
- Task history and results
- Task rate graphs
- Worker pool size control
- Task revocation

### 6. Beat Scheduler (`celerybeat_schedule.py`)

Periodic task scheduling with Celery Beat.

**Scheduled Tasks:**
- Cleanup old results (daily at 3 AM)
- Refresh breach databases (every 6 hours)
- Dark web scanning (hourly)
- Wallet monitoring (every 30 minutes)
- Daily intelligence reports (8 AM)
- Health checks (every 5 minutes)
- Stale lock cleanup (every 15 minutes)

**Start Beat scheduler:**
```bash
celery -A celery_tasks beat -l info
```

## Installation & Setup

### 1. Install Dependencies

```bash
# Install required packages
pip install celery[redis,msgpack]
pip install redis
pip install flower
pip install kombu
pip install eventlet  # For async I/O
```

### 2. Start Infrastructure

**RabbitMQ:**
```bash
docker run -d --name rabbitmq \
  -p 5672:5672 -p 15672:15672 \
  rabbitmq:3-management
```

**Redis:**
```bash
docker run -d --name redis \
  -p 6379:6379 \
  redis:alpine
```

**Or use Docker Compose:**
```bash
cd /path/to/apollo/intelligence
docker-compose up -d rabbitmq redis
```

### 3. Configure Environment

Create `.env` file:
```bash
# Celery Configuration
CELERY_BROKER_URL=amqp://guest:guest@localhost:5672//
CELERY_RESULT_BACKEND=redis://localhost:6379/0

# Environment
ENVIRONMENT=development

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379

# RabbitMQ
RABBITMQ_HOST=localhost
RABBITMQ_PORT=5672
RABBITMQ_USER=guest
RABBITMQ_PASSWORD=guest

# Flower
FLOWER_PORT=5555
FLOWER_BASIC_AUTH=admin:changeme
```

### 4. Start Workers

**Terminal 1 - OSINT Worker:**
```bash
celery -A celery_tasks worker -Q osint -l info -n osint@%h
```

**Terminal 2 - Blockchain Worker:**
```bash
celery -A celery_tasks worker -Q blockchain -l info -n blockchain@%h
```

**Terminal 3 - General Worker:**
```bash
celery -A celery_tasks worker -Q default,fusion,monitoring -l info -n general@%h
```

**Or use worker.py:**
```bash
python worker.py --queue all --concurrency 8
```

### 5. Start Beat Scheduler

```bash
celery -A celery_tasks beat -l info
```

### 6. Start Flower Monitoring

```bash
python flower_config.py
```

## Usage Examples

### Execute Single Task

```python
from tasks.osint_tasks import search_username_task

# Async execution
result = search_username_task.delay('john_doe')

# Wait for result
data = result.get(timeout=300)
print(f"Found {data['profiles_found']} profiles")
```

### Execute Task with Callback

```python
from celery import chain
from tasks.osint_tasks import search_username_task
from tasks.fusion_tasks import build_intelligence_profile_task

# Chain tasks
workflow = chain(
    search_username_task.s('john_doe'),
    build_intelligence_profile_task.s('john_doe', 'person')
)

result = workflow.apply_async()
```

### Parallel Task Execution

```python
from celery import group
from tasks.osint_tasks import search_username_task

# Execute multiple searches in parallel
job = group(
    search_username_task.s('user1'),
    search_username_task.s('user2'),
    search_username_task.s('user3'),
)

results = job.apply_async()
print(f"Started {len(results)} parallel tasks")
```

### Complex Investigation Workflow

```python
from celery import chord
from tasks.osint_tasks import search_username_task, email_intelligence_task
from tasks.blockchain_tasks import wallet_analysis_task
from tasks.fusion_tasks import build_intelligence_profile_task

# Parallel data collection, then fusion
investigation = chord([
    search_username_task.s('target_user'),
    email_intelligence_task.s('target@email.com'),
    wallet_analysis_task.s('1A1zP1...', 'bitcoin'),
])(
    build_intelligence_profile_task.s('target_user', 'person')
)

result = investigation.apply_async()
```

### Use Pre-built Workflows

```python
from task_utils import InvestigationWorkflow

# Person investigation
result = InvestigationWorkflow.person_investigation('john_doe')

# Wallet investigation
result = InvestigationWorkflow.wallet_investigation(
    '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa',
    'bitcoin'
)

# Domain investigation
result = InvestigationWorkflow.domain_investigation('example.com')

# Monitor result
print(f"Task ID: {result.id}")
print(f"Status: {result.state}")
```

### Task Monitoring

```python
from celery.result import AsyncResult
from task_utils import get_task_status

task_id = 'abc-123-def-456'

# Get task status
status = get_task_status(task_id)
print(f"State: {status['state']}")
print(f"Ready: {status['ready']}")

if status['ready'] and status['successful']:
    print(f"Result: {status['result']}")
```

### Task Cancellation

```python
from task_utils import cancel_task

task_id = 'abc-123-def-456'

# Soft cancel (let task finish current work)
cancel_task(task_id, terminate=False)

# Hard cancel (terminate immediately)
cancel_task(task_id, terminate=True)
```

## Monitoring & Debugging

### Flower Dashboard

Access real-time monitoring at `http://localhost:5555`

**Key Metrics:**
- Active tasks
- Task success/failure rates
- Worker status
- Task execution time
- Queue lengths
- Task history

### Command Line Monitoring

**List active tasks:**
```bash
celery -A celery_tasks inspect active
```

**List registered tasks:**
```bash
celery -A celery_tasks inspect registered
```

**Worker statistics:**
```bash
celery -A celery_tasks inspect stats
```

**Queue status:**
```bash
celery -A celery_tasks inspect active_queues
```

### Task Metrics

```python
from task_utils import TaskMonitor

monitor = TaskMonitor()

# Get aggregate metrics
metrics = monitor.get_aggregate_metrics()
print(f"Total tasks: {metrics['total_tasks']}")
print(f"Success rate: {metrics['success_rate']:.2%}")

# Get specific task metrics
task_metrics = monitor.get_task_metrics('task-id-123')
print(f"Duration: {task_metrics.get('duration')}s")
```

## Task Priority & Rate Limiting

### Task Priority

Tasks are routed to priority queues:

```python
# High priority OSINT task
search_username_task.apply_async(
    args=['john_doe'],
    priority=10
)

# Normal priority
wallet_analysis_task.apply_async(
    args=['1A1zP1...'],
    priority=5
)
```

### Rate Limiting

Rate limits are configured per task type:

- Username search: 50/minute
- Domain scan: 10/minute
- Wallet analysis: 30/minute
- Fund tracing: 5/minute (very intensive)

## Error Handling & Retries

Tasks automatically retry on failure with exponential backoff:

```python
from celery import Task

@app.task(
    bind=True,
    max_retries=3,
    default_retry_delay=60
)
def my_task(self):
    try:
        # Task logic
        pass
    except Exception as exc:
        # Retry with exponential backoff
        raise self.retry(exc=exc)
```

## Performance Tuning

### Worker Concurrency

Adjust based on workload:

```bash
# CPU-intensive tasks
celery -A celery_tasks worker -Q osint --concurrency=4

# I/O-intensive tasks
celery -A celery_tasks worker -Q osint --concurrency=20 -P eventlet
```

### Prefetch Multiplier

Control how many tasks workers prefetch:

```python
# In celery_config.py
worker_prefetch_multiplier = 4  # Prefetch 4 tasks per worker
```

### Task Time Limits

Prevent runaway tasks:

```python
# In celery_config.py
task_time_limit = 3600  # 1 hour hard limit
task_soft_time_limit = 3000  # 50 minute soft limit
```

## Production Deployment

### Systemd Service Files

**celery-worker.service:**
```ini
[Unit]
Description=Apollo Celery Worker
After=network.target rabbitmq.service redis.service

[Service]
Type=forking
User=apollo
Group=apollo
WorkingDirectory=/opt/apollo/intelligence
Environment="PATH=/opt/apollo/venv/bin"
ExecStart=/opt/apollo/venv/bin/celery -A celery_tasks worker \
  -Q default,osint,blockchain,socmint,fusion,monitoring \
  --pidfile=/var/run/celery/worker.pid \
  --logfile=/var/log/celery/worker.log \
  --loglevel=INFO

[Install]
WantedBy=multi-user.target
```

**celery-beat.service:**
```ini
[Unit]
Description=Apollo Celery Beat
After=network.target rabbitmq.service redis.service

[Service]
Type=forking
User=apollo
Group=apollo
WorkingDirectory=/opt/apollo/intelligence
Environment="PATH=/opt/apollo/venv/bin"
ExecStart=/opt/apollo/venv/bin/celery -A celery_tasks beat \
  --pidfile=/var/run/celery/beat.pid \
  --logfile=/var/log/celery/beat.log \
  --loglevel=INFO

[Install]
WantedBy=multi-user.target
```

**flower.service:**
```ini
[Unit]
Description=Apollo Flower Monitoring
After=network.target rabbitmq.service

[Service]
Type=simple
User=apollo
Group=apollo
WorkingDirectory=/opt/apollo/intelligence
Environment="PATH=/opt/apollo/venv/bin"
ExecStart=/opt/apollo/venv/bin/python flower_config.py

[Install]
WantedBy=multi-user.target
```

### Docker Deployment

```dockerfile
# Dockerfile for Celery Worker
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["celery", "-A", "celery_tasks", "worker", "-Q", "all", "-l", "info"]
```

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: celery-worker
spec:
  replicas: 3
  selector:
    matchLabels:
      app: celery-worker
  template:
    metadata:
      labels:
        app: celery-worker
    spec:
      containers:
      - name: worker
        image: apollo-intelligence:latest
        command: ["celery", "-A", "celery_tasks", "worker"]
        env:
        - name: CELERY_BROKER_URL
          value: "amqp://rabbitmq:5672"
        - name: CELERY_RESULT_BACKEND
          value: "redis://redis:6379/0"
```

## Troubleshooting

### Worker Not Starting

Check RabbitMQ and Redis connectivity:
```bash
telnet localhost 5672  # RabbitMQ
telnet localhost 6379  # Redis
```

### Tasks Not Executing

Verify task registration:
```bash
celery -A celery_tasks inspect registered
```

Check worker logs:
```bash
tail -f /var/log/celery/worker.log
```

### High Memory Usage

Restart workers periodically:
```python
# In celery_config.py
worker_max_tasks_per_child = 1000  # Restart after 1000 tasks
```

### Task Timeout Issues

Increase time limits:
```python
# In celery_config.py
task_time_limit = 7200  # 2 hours
task_soft_time_limit = 6600  # 1 hour 50 minutes
```

## Security Considerations

1. **Enable SSL/TLS** for RabbitMQ and Redis in production
2. **Use authentication** for Flower dashboard
3. **Restrict network access** to broker and result backend
4. **Sanitize task inputs** to prevent injection attacks
5. **Limit task privileges** - run workers as non-root user
6. **Monitor task execution** for suspicious activity
7. **Encrypt sensitive data** in task payloads

## Best Practices

1. **Keep tasks idempotent** - tasks should be safely re-runnable
2. **Use task locks** for tasks that shouldn't run concurrently
3. **Set appropriate timeouts** to prevent runaway tasks
4. **Monitor task metrics** to identify bottlenecks
5. **Use task chaining** for complex workflows
6. **Cache results** for expensive operations
7. **Implement proper error handling** and retries
8. **Use priority queues** for urgent tasks
9. **Clean up old results** regularly
10. **Document task dependencies** and requirements

## Support

For issues or questions:
- Check logs in `/var/log/celery/`
- Review Flower dashboard at `http://localhost:5555`
- Inspect worker status: `celery -A celery_tasks inspect stats`

## License

Proprietary - Apollo Intelligence Platform
