# Sherlock OSINT - Quick Start Guide

Get up and running with Sherlock OSINT in 5 minutes!

---

## Installation

### Step 1: Install Dependencies

```bash
cd C:\SECURE_THREAT_INTEL\YoureGunnaHAveToShootMeToStopME\apollo\intelligence\osint-tools\sherlock
pip install -r requirements.txt
```

### Step 2: Verify Installation

```bash
python -c "from sherlock_integration import SherlockOSINT; print('Installation successful!')"
```

---

## Basic Usage

### 1. Python API (Recommended)

```python
from sherlock_async import SherlockAsync
import asyncio

async def main():
    sherlock = SherlockAsync()
    results = await sherlock.search_username_async("john_doe")

    print(f"Found on {results.found_platforms} platforms:")
    for result in results.results:
        if result.exists:
            print(f"  - {result.platform}: {result.url}")

asyncio.run(main())
```

### 2. Command Line

```bash
# Simple search
python sherlock_cli.py john_doe

# Interactive mode
python sherlock_cli.py -i

# Export to JSON
python sherlock_cli.py john_doe -o results.json -f json
```

### 3. REST API

```bash
# Start the API server
python fastapi_endpoints.py

# Search via API (in another terminal)
curl http://localhost:8000/api/search/john_doe

# View API docs
# Open browser to: http://localhost:8000/api/docs
```

---

## Common Use Cases

### Search Specific Platforms

```python
from sherlock_integration import SherlockOSINT

sherlock = SherlockOSINT()
results = sherlock.search_username(
    "username",
    platforms=["GitHub", "Twitter", "LinkedIn"]
)
```

### Search by Category

```python
results = sherlock.search_username(
    "username",
    categories=["social", "development"]
)
```

### Batch Search

```python
usernames = ["user1", "user2", "user3"]
batch_results = sherlock.batch_search(usernames)
```

### High-Confidence Results Only

```python
results = sherlock.search_username(
    "username",
    min_confidence=0.85  # 85%+ confidence only
)
```

---

## Examples

Run the example suite:

```bash
# List all examples
python examples.py --list

# Run specific example
python examples.py 1

# Run all examples
python examples.py
```

---

## Export Results

### JSON Export

```python
sherlock.export_results(results, format='json', output_path='results.json')
```

### CSV Export

```python
sherlock.export_results(results, format='csv', output_path='results.csv')
```

### Markdown Report

```python
sherlock.export_results(results, format='markdown', output_path='report.md')
```

---

## Integration with External Systems

### Elasticsearch

```python
from elasticsearch import Elasticsearch

es = Elasticsearch(['http://localhost:9200'])
sherlock = SherlockOSINT(elasticsearch_client=es)

# Results automatically stored in Elasticsearch
results = sherlock.search_username("username")
```

### Redis Caching

```python
import redis

redis_client = redis.Redis(host='localhost', port=6379)
sherlock = SherlockOSINT(redis_client=redis_client, enable_cache=True)

# First search: slow (fetches from platforms)
results1 = sherlock.search_username("username")

# Second search: fast (loads from cache)
results2 = sherlock.search_username("username")
```

### Neo4j Relationships

```python
from neo4j import GraphDatabase

driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "password"))
sherlock = SherlockOSINT(neo4j_client=driver)

# Relationships automatically created in Neo4j
results = sherlock.search_username("username")
```

---

## Performance Tips

### 1. Use Async for Speed

```python
from sherlock_async import SherlockAsync  # Faster!

sherlock = SherlockAsync(max_concurrent=50)
results = await sherlock.search_username_async("username")
```

### 2. Enable Redis Caching

```python
import redis
redis_client = redis.Redis()
sherlock = SherlockAsync(redis_client=redis_client)
```

### 3. Filter Platforms

```python
# Only check relevant platforms
results = sherlock.search_username(
    "username",
    categories=["social", "development"]  # Faster than all
)
```

---

## Testing

Run the test suite:

```bash
# Run all tests
pytest test_sherlock.py -v

# Run with coverage
pytest test_sherlock.py --cov=. --cov-report=html

# Run async tests only
pytest test_sherlock.py -k "async" -v
```

---

## API Server

### Start Server

```bash
python fastapi_endpoints.py
```

### API Endpoints

- **GET** `/api/health` - Health check
- **POST** `/api/search` - Search username
- **GET** `/api/search/{username}` - Search username (GET)
- **POST** `/api/batch` - Batch search
- **GET** `/api/batch/{job_id}` - Get batch status
- **GET** `/api/platforms` - List platforms
- **GET** `/api/stats` - Get statistics

### API Examples

```bash
# Health check
curl http://localhost:8000/api/health

# Search username
curl -X POST http://localhost:8000/api/search \
  -H "Content-Type: application/json" \
  -d '{"username": "john_doe"}'

# List platforms
curl http://localhost:8000/api/platforms

# Batch search
curl -X POST http://localhost:8000/api/batch \
  -H "Content-Type: application/json" \
  -d '{"usernames": ["user1", "user2", "user3"]}'
```

---

## Troubleshooting

### Import Errors

```bash
# Make sure all dependencies are installed
pip install -r requirements.txt
```

### Timeout Issues

```python
# Increase timeout
sherlock = SherlockOSINT(timeout=30)  # 30 seconds
```

### Too Many Failed Requests

```python
# Reduce concurrent requests
sherlock = SherlockAsync(max_concurrent=20)  # Default: 50
```

### Redis Connection Error

```bash
# Make sure Redis is running
redis-cli ping
# Should return: PONG
```

### Elasticsearch Connection Error

```bash
# Check Elasticsearch is running
curl http://localhost:9200
```

---

## Next Steps

1. **Read the full documentation**: See `README_SHERLOCK.md`
2. **Explore examples**: Run `python examples.py`
3. **Customize platforms**: Edit `platforms_config.json`
4. **Set up integrations**: Configure Elasticsearch, Redis, Neo4j
5. **Deploy API**: Use FastAPI endpoints for production

---

## Support

- Documentation: `README_SHERLOCK.md`
- Examples: `examples.py`
- Tests: `test_sherlock.py`
- API Docs: http://localhost:8000/api/docs (when server running)

---

## Quick Reference

### Python API

```python
from sherlock_async import SherlockAsync
import asyncio

async def search():
    sherlock = SherlockAsync()
    results = await sherlock.search_username_async("username")
    print(f"Found: {results.found_platforms}")

asyncio.run(search())
```

### CLI

```bash
python sherlock_cli.py username
python sherlock_cli.py -i  # Interactive
python sherlock_cli.py username -o output.json -f json
```

### REST API

```bash
python fastapi_endpoints.py
curl http://localhost:8000/api/search/username
```

---

**Happy Hunting! 🔍**
