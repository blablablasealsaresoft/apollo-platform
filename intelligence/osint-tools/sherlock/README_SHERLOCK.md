# Sherlock OSINT - Username Search Engine

![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Status](https://img.shields.io/badge/status-production-brightgreen.svg)

**Production-ready OSINT username search engine for Apollo Intelligence Platform**

Search for usernames across **400+ social media platforms, forums, gaming sites, and online services** with high-performance async capabilities.

---

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
  - [Python API](#python-api)
  - [Command Line](#command-line)
  - [Async Implementation](#async-implementation)
- [Integration](#integration)
- [Platform Coverage](#platform-coverage)
- [Configuration](#configuration)
- [Examples](#examples)
- [Performance](#performance)
- [API Reference](#api-reference)
- [Contributing](#contributing)

---

## Features

### Core Capabilities

- **400+ Platform Support** - Search across social media, forums, gaming, development, and more
- **High-Performance Async** - Check 50+ platforms concurrently with aiohttp
- **Confidence Scoring** - AI-based confidence levels for each match (0.0-1.0)
- **Multiple Detection Methods** - Status codes, error messages, URL patterns
- **Batch Processing** - Search multiple usernames efficiently
- **Smart Caching** - Redis integration for faster repeated searches
- **Rate Limiting** - Respectful delays and concurrent request management
- **Export Formats** - JSON, CSV, Markdown output
- **Progress Tracking** - Real-time progress bars with tqdm
- **Error Recovery** - Automatic retries with exponential backoff

### Integration Points

- **Elasticsearch** - Store search results and historical data
- **Redis** - Cache results for improved performance
- **Neo4j** - Map username relationships across platforms
- **FastAPI** - RESTful API endpoints (see API documentation)

### CLI Features

- **Interactive Mode** - User-friendly command-line interface
- **Batch Search** - Process multiple usernames from file
- **Category Filtering** - Search specific platform categories
- **Colorized Output** - Beautiful terminal output with colorama
- **Statistics** - Detailed search metrics and summaries

---

## Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager
- (Optional) Redis for caching
- (Optional) Elasticsearch for storage
- (Optional) Neo4j for relationship mapping

### Install Dependencies

```bash
cd C:\SECURE_THREAT_INTEL\YoureGunnaHAveToShootMeToStopME\apollo\intelligence\osint-tools\sherlock
pip install -r requirements.txt
```

### Quick Install (Core Only)

```bash
pip install requests aiohttp beautifulsoup4 tqdm colorama tabulate
```

---

## Quick Start

### 1. Python API (Async - Recommended)

```python
from sherlock_async import SherlockAsync
import asyncio

async def search():
    sherlock = SherlockAsync(max_concurrent=50)
    results = await sherlock.search_username_async("ruja_ignatova")

    print(f"Found on {results.found_platforms}/{results.total_platforms} platforms")

    for result in results.results:
        if result.exists:
            print(f"{result.platform}: {result.url} (confidence: {result.confidence:.0%})")

asyncio.run(search())
```

### 2. Python API (Sync)

```python
from sherlock_integration import SherlockOSINT

sherlock = SherlockOSINT()
results = sherlock.search_username("ruja_ignatova")

for result in results.results:
    if result.exists:
        print(f"{result.platform}: {result.url}")
```

### 3. Command Line

```bash
# Simple search
python sherlock_cli.py john_doe

# Interactive mode
python sherlock_cli.py -i

# Batch search
python sherlock_cli.py user1 user2 user3

# Export to JSON
python sherlock_cli.py john_doe -o results.json -f json
```

---

## Usage

### Python API

#### Basic Search

```python
from sherlock_integration import SherlockOSINT

# Initialize
sherlock = SherlockOSINT()

# Search username
results = sherlock.search_username("target_username")

# Access results
print(f"Username: {results.username}")
print(f"Platforms checked: {results.total_platforms}")
print(f"Platforms found: {results.found_platforms}")
print(f"Duration: {results.search_duration:.2f}s")

# Iterate through results
for result in results.results:
    if result.exists:
        print(f"""
        Platform: {result.platform}
        URL: {result.url}
        Confidence: {result.confidence:.0%}
        Category: {result.additional_data.get('category', 'unknown')}
        """)
```

#### Advanced Search with Filters

```python
# Search specific platforms only
results = sherlock.search_username(
    "username",
    platforms=["GitHub", "Twitter", "LinkedIn", "Instagram"]
)

# Search by category
results = sherlock.search_username(
    "username",
    categories=["social", "development", "gaming"]
)

# Set minimum confidence threshold
results = sherlock.search_username(
    "username",
    min_confidence=0.75  # Only return results with 75%+ confidence
)
```

#### Batch Search

```python
usernames = ["user1", "user2", "user3", "user4"]

batch_results = sherlock.batch_search(usernames)

for result in batch_results:
    print(f"{result.username}: {result.found_platforms} platforms found")
```

#### Export Results

```python
# Export to JSON
sherlock.export_results(results, format='json', output_path='results.json')

# Export to CSV
sherlock.export_results(results, format='csv', output_path='results.csv')

# Export to Markdown
sherlock.export_results(results, format='markdown', output_path='report.md')
```

### Async Implementation

```python
from sherlock_async import SherlockAsync
import asyncio

async def main():
    # Initialize async sherlock
    sherlock = SherlockAsync(
        max_concurrent=50,      # Check 50 platforms simultaneously
        rate_limit_delay=0.1    # 100ms delay between batches
    )

    # Search username
    results = await sherlock.search_username_async(
        "username",
        show_progress=True  # Show progress bar
    )

    # Multiple usernames
    usernames = ["user1", "user2", "user3"]
    batch_results = await sherlock.batch_search_async(
        usernames,
        delay_between_searches=1.0  # 1 second between users
    )

    # Get statistics
    stats = sherlock.get_statistics()
    print(f"Success rate: {stats['success_rate']:.1%}")

# Run
asyncio.run(main())
```

### Command Line Interface

#### Basic Usage

```bash
# Search single username
python sherlock_cli.py john_doe

# Search multiple usernames
python sherlock_cli.py user1 user2 user3

# Search from file
python sherlock_cli.py -u usernames.txt
```

#### Advanced Options

```bash
# Filter by platforms
python sherlock_cli.py john_doe -p GitHub Twitter LinkedIn

# Filter by categories
python sherlock_cli.py john_doe -c social gaming development

# Use sync mode (slower but more compatible)
python sherlock_cli.py john_doe --sync

# Set minimum confidence
python sherlock_cli.py john_doe --min-confidence 0.8

# Export results
python sherlock_cli.py john_doe -o report.json -f json
python sherlock_cli.py john_doe -o report.csv -f csv
python sherlock_cli.py john_doe -o report.md -f markdown

# Batch with output directory
python sherlock_cli.py -u users.txt --output-dir results/

# Verbose logging
python sherlock_cli.py john_doe -v
```

#### Interactive Mode

```bash
python sherlock_cli.py -i

# Interactive session:
sherlock> search john_doe
sherlock> ruja_ignatova
sherlock> help
sherlock> exit
```

---

## Integration

### Elasticsearch Integration

```python
from elasticsearch import Elasticsearch
from sherlock_integration import SherlockOSINT

# Connect to Elasticsearch
es = Elasticsearch(['http://localhost:9200'])

# Initialize Sherlock with Elasticsearch
sherlock = SherlockOSINT(elasticsearch_client=es)

# Search - results automatically stored in Elasticsearch
results = sherlock.search_username("username")

# Query stored results
query = {
    "query": {
        "match": {
            "username": "username"
        }
    }
}
es_results = es.search(index="sherlock-results", body=query)
```

### Redis Caching

```python
import redis
from sherlock_integration import SherlockOSINT

# Connect to Redis
redis_client = redis.Redis(host='localhost', port=6379, db=0)

# Initialize Sherlock with Redis caching
sherlock = SherlockOSINT(
    redis_client=redis_client,
    enable_cache=True
)

# First search - fetches from platforms
results1 = sherlock.search_username("username")  # ~30 seconds

# Second search - loads from cache
results2 = sherlock.search_username("username")  # ~0.1 seconds

# Get cache statistics
stats = sherlock.get_statistics()
print(f"Cache hit rate: {stats['cache_hit_rate']:.1%}")
```

### Neo4j Relationship Mapping

```python
from neo4j import GraphDatabase
from sherlock_integration import SherlockOSINT

# Connect to Neo4j
driver = GraphDatabase.driver(
    "bolt://localhost:7687",
    auth=("neo4j", "password")
)

# Initialize Sherlock with Neo4j
sherlock = SherlockOSINT(neo4j_client=driver)

# Search - relationships automatically created
results = sherlock.search_username("username")

# Query Neo4j for relationships
with driver.session() as session:
    result = session.run("""
        MATCH (u:Username {name: $username})-[r:HAS_ACCOUNT_ON]->(p:Platform)
        RETURN u, p, r
    """, username="username")
```

### Full Integration Example

```python
from elasticsearch import Elasticsearch
import redis
from neo4j import GraphDatabase
from sherlock_async import SherlockAsync

# Setup integrations
es = Elasticsearch(['http://localhost:9200'])
redis_client = redis.Redis(host='localhost', port=6379)
neo4j_driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "password"))

# Initialize Sherlock with all integrations
sherlock = SherlockAsync(
    elasticsearch_client=es,
    redis_client=redis_client,
    neo4j_client=neo4j_driver,
    max_concurrent=50
)

# Search - results stored in all systems
import asyncio
results = asyncio.run(sherlock.search_username_async("username"))
```

---

## Platform Coverage

### Categories (400+ Platforms)

| Category | Count | Examples |
|----------|-------|----------|
| **Social Media** | 80+ | Instagram, Twitter, Facebook, TikTok, Snapchat |
| **Development** | 50+ | GitHub, GitLab, BitBucket, StackOverflow, CodePen |
| **Gaming** | 40+ | Steam, Xbox, PlayStation, Twitch, Discord |
| **Professional** | 30+ | LinkedIn, AngelList, Behance, Dribbble |
| **Video** | 25+ | YouTube, Vimeo, DailyMotion, TikTok |
| **Music** | 20+ | Spotify, SoundCloud, BandCamp, MixCloud |
| **Blogging** | 20+ | Medium, WordPress, Blogger, Substack |
| **Photo** | 15+ | Flickr, 500px, Unsplash, VSCO |
| **Forum** | 15+ | Reddit, HackerNews, Lobsters |
| **Others** | 100+ | Shopping, Travel, Finance, Education, etc. |

### Platform Examples

```
Social: Instagram, Twitter, Facebook, TikTok, LinkedIn, Pinterest, Snapchat
Development: GitHub, GitLab, BitBucket, StackOverflow, CodePen, NPM, PyPI
Gaming: Steam, Xbox, Twitch, Discord, Roblox, Minecraft (NameMC)
Professional: LinkedIn, AngelList, Behance, Dribbble, About.me
Music: Spotify, SoundCloud, BandCamp, MixCloud, Last.fm
Video: YouTube, Vimeo, DailyMotion, Twitch
Blogging: Medium, WordPress, Blogger, Tumblr, Substack
Forums: Reddit, HackerNews, Quora, StackOverflow
```

---

## Configuration

### Platform Configuration (platforms_config.json)

```json
{
  "GitHub": {
    "url": "https://github.com/{}",
    "errorType": "status_code",
    "errorCode": 404,
    "category": "development",
    "reliable": true
  },
  "Twitter": {
    "url": "https://twitter.com/{}",
    "errorType": "status_code",
    "errorCode": 404,
    "category": "social",
    "reliable": true
  }
}
```

### Detection Methods

**1. Status Code Detection**
```json
{
  "errorType": "status_code",
  "errorCode": 404
}
```
Returns true if status code is NOT 404.

**2. Error Message Detection**
```json
{
  "errorType": "message",
  "errorMsg": "User not found"
}
```
Returns true if error message is NOT in response.

**3. URL Pattern Detection**
```json
{
  "errorType": "response_url",
  "errorUrl": "/error"
}
```
Returns true if redirected URL does NOT contain "/error".

### Custom Platform Addition

```python
# Add custom platform
sherlock.platforms["CustomSite"] = {
    "url": "https://example.com/users/{}",
    "errorType": "status_code",
    "errorCode": 404,
    "category": "custom",
    "reliable": True
}

# Search with custom platform
results = sherlock.search_username("username")
```

---

## Examples

### Example 1: Investigating Person of Interest

```python
from sherlock_async import SherlockAsync
import asyncio

async def investigate_poi():
    sherlock = SherlockAsync(max_concurrent=50)

    # Known aliases
    aliases = [
        "ruja_ignatova",
        "cryptoqueen",
        "dr_ruja"
    ]

    print("Investigating person of interest...")

    all_platforms = {}

    for alias in aliases:
        print(f"\nSearching alias: {alias}")
        results = await sherlock.search_username_async(alias, show_progress=True)

        for result in results.results:
            if result.exists and result.confidence > 0.7:
                if result.platform not in all_platforms:
                    all_platforms[result.platform] = []
                all_platforms[result.platform].append({
                    'alias': alias,
                    'url': result.url,
                    'confidence': result.confidence
                })

    # Report
    print("\n" + "="*70)
    print("INVESTIGATION REPORT")
    print("="*70)

    for platform, accounts in all_platforms.items():
        print(f"\n{platform}:")
        for account in accounts:
            print(f"  - {account['alias']}: {account['url']} ({account['confidence']:.0%})")

asyncio.run(investigate_poi())
```

### Example 2: Monitoring New Account Creation

```python
from sherlock_integration import SherlockOSINT
import time
import json
from datetime import datetime

def monitor_username(username, interval=3600):
    """
    Monitor username for new account creation

    Args:
        username: Username to monitor
        interval: Check interval in seconds (default: 1 hour)
    """
    sherlock = SherlockOSINT()

    # Initial baseline
    print(f"Establishing baseline for: {username}")
    baseline = sherlock.search_username(username)
    baseline_platforms = {r.platform for r in baseline.results if r.exists}

    print(f"Baseline: {len(baseline_platforms)} platforms")

    # Save baseline
    with open(f"{username}_baseline.json", 'w') as f:
        json.dump(baseline.to_dict(), f, indent=2)

    # Monitoring loop
    print(f"Starting monitoring (checking every {interval}s)...")

    while True:
        time.sleep(interval)

        print(f"\n[{datetime.now()}] Checking for new accounts...")

        current = sherlock.search_username(username)
        current_platforms = {r.platform for r in current.results if r.exists}

        # Detect new platforms
        new_platforms = current_platforms - baseline_platforms

        if new_platforms:
            print(f"ALERT: New accounts detected on {len(new_platforms)} platforms!")

            for platform in new_platforms:
                result = next(r for r in current.results if r.platform == platform)
                print(f"  - {platform}: {result.url}")

                # Send alert (integrate with your alerting system)
                send_alert(username, platform, result.url)

            # Update baseline
            baseline_platforms = current_platforms
        else:
            print("No new accounts detected")

def send_alert(username, platform, url):
    """Send alert to security team"""
    # Implement your alerting logic here
    # Examples: Email, Slack, Discord, SMS, etc.
    print(f"[ALERT] New account: {username} on {platform} - {url}")
```

### Example 3: Category-Based Reconnaissance

```python
from sherlock_async import SherlockAsync
import asyncio

async def category_recon():
    sherlock = SherlockAsync()

    username = "target_user"

    categories = {
        'social': 'Social Media Presence',
        'development': 'Development Activity',
        'gaming': 'Gaming Accounts',
        'professional': 'Professional Profiles',
        'blogging': 'Content Creation'
    }

    print(f"Category-based reconnaissance for: {username}\n")

    for category, description in categories.items():
        print(f"\n{'='*60}")
        print(f"{description} ({category})")
        print('='*60)

        results = await sherlock.search_username_async(
            username,
            categories=[category],
            show_progress=False
        )

        found = [r for r in results.results if r.exists]

        if found:
            print(f"\nFound on {len(found)} platforms:")
            for result in found:
                print(f"  - {result.platform:20s} {result.url}")
        else:
            print("\nNo accounts found in this category")

        await asyncio.sleep(1)  # Respectful delay

asyncio.run(category_recon())
```

### Example 4: Export and Reporting

```python
from sherlock_integration import SherlockOSINT
from datetime import datetime
import os

def generate_report(username):
    """Generate comprehensive OSINT report"""
    sherlock = SherlockOSINT()

    print(f"Generating OSINT report for: {username}")

    # Search
    results = sherlock.search_username(username)

    # Create report directory
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_dir = f"reports/{username}_{timestamp}"
    os.makedirs(report_dir, exist_ok=True)

    # Export in multiple formats
    sherlock.export_results(
        results,
        format='json',
        output_path=f"{report_dir}/results.json"
    )

    sherlock.export_results(
        results,
        format='csv',
        output_path=f"{report_dir}/results.csv"
    )

    sherlock.export_results(
        results,
        format='markdown',
        output_path=f"{report_dir}/report.md"
    )

    # Generate summary
    with open(f"{report_dir}/summary.txt", 'w') as f:
        f.write(f"OSINT Report: {username}\n")
        f.write(f"Generated: {datetime.now()}\n\n")
        f.write(f"Platforms Checked: {results.total_platforms}\n")
        f.write(f"Platforms Found: {results.found_platforms}\n")
        f.write(f"Search Duration: {results.search_duration:.2f}s\n\n")

        found = [r for r in results.results if r.exists]
        f.write("Found Accounts:\n")
        for result in found:
            f.write(f"  - {result.platform}: {result.url}\n")

    print(f"\nReport generated in: {report_dir}/")
    print(f"  - results.json")
    print(f"  - results.csv")
    print(f"  - report.md")
    print(f"  - summary.txt")

# Usage
generate_report("target_username")
```

---

## Performance

### Benchmarks

**Test Configuration:**
- Username: test_user
- Platforms: 400+
- System: Intel i7, 16GB RAM
- Network: 100 Mbps

| Implementation | Duration | Speed | Recommended |
|----------------|----------|-------|-------------|
| **Async** | 12-15s | 30 platforms/sec | ✅ Production |
| **Sync (50 workers)** | 45-60s | 7 platforms/sec | Development |
| **Sync (10 workers)** | 120-150s | 3 platforms/sec | Limited environments |

### Performance Tips

**1. Use Async Implementation**
```python
from sherlock_async import SherlockAsync  # Recommended
sherlock = SherlockAsync(max_concurrent=50)
```

**2. Enable Redis Caching**
```python
import redis
redis_client = redis.Redis()
sherlock = SherlockAsync(redis_client=redis_client)
```

**3. Filter Platforms**
```python
# Only check relevant platforms
results = sherlock.search_username(
    "username",
    categories=["social", "development"]  # Faster than all categories
)
```

**4. Adjust Concurrency**
```python
# For faster connections
sherlock = SherlockAsync(max_concurrent=100)

# For slower/restricted connections
sherlock = SherlockAsync(max_concurrent=20)
```

---

## API Reference

### SherlockOSINT Class

```python
class SherlockOSINT:
    def __init__(self,
                 config_path: Optional[str] = None,
                 timeout: int = 10,
                 max_workers: int = 50,
                 enable_cache: bool = True,
                 elasticsearch_client = None,
                 redis_client = None,
                 neo4j_client = None)

    def search_username(self,
                       username: str,
                       platforms: Optional[List[str]] = None,
                       categories: Optional[List[str]] = None,
                       min_confidence: float = 0.0) -> BatchSearchResult

    def batch_search(self,
                    usernames: List[str],
                    platforms: Optional[List[str]] = None,
                    categories: Optional[List[str]] = None) -> List[BatchSearchResult]

    def export_results(self,
                      batch_result: BatchSearchResult,
                      format: str = 'json',
                      output_path: Optional[str] = None) -> str

    def get_statistics(self) -> Dict

    def close(self)
```

### SherlockAsync Class

```python
class SherlockAsync:
    def __init__(self,
                 config_path: Optional[str] = None,
                 timeout: int = 10,
                 max_concurrent: int = 50,
                 rate_limit_delay: float = 0.1,
                 elasticsearch_client = None,
                 redis_client = None)

    async def search_username_async(self,
                                   username: str,
                                   platforms: Optional[List[str]] = None,
                                   categories: Optional[List[str]] = None,
                                   show_progress: bool = True) -> BatchSearchResult

    async def batch_search_async(self,
                                usernames: List[str],
                                platforms: Optional[List[str]] = None,
                                categories: Optional[List[str]] = None,
                                delay_between_searches: float = 1.0) -> List[BatchSearchResult]

    # Synchronous wrappers
    def search_username(self, *args, **kwargs) -> BatchSearchResult
    def batch_search(self, *args, **kwargs) -> List[BatchSearchResult]

    def get_statistics(self) -> Dict
```

### Data Classes

```python
@dataclass
class SherlockResult:
    username: str
    platform: str
    url: str
    exists: bool
    confidence: float
    response_time: float
    http_status: int
    error_message: Optional[str] = None
    timestamp: str = None
    additional_data: Optional[Dict] = None

@dataclass
class BatchSearchResult:
    username: str
    total_platforms: int
    found_platforms: int
    results: List[SherlockResult]
    search_duration: float
    timestamp: str
```

---

## Contributing

### Adding New Platforms

Edit `platforms_config.json`:

```json
{
  "NewPlatform": {
    "url": "https://newplatform.com/users/{}",
    "errorType": "status_code",
    "errorCode": 404,
    "category": "social",
    "reliable": true
  }
}
```

### Testing

```bash
# Run tests
pytest tests/

# Run with coverage
pytest --cov=. tests/

# Run async tests
pytest -v tests/test_async.py
```

---

## License

MIT License - See LICENSE file for details

---

## Support

For issues, questions, or contributions:
- GitHub Issues: [Report Issue]
- Documentation: [Full Docs]
- Email: support@apollo-intel.local

---

## Acknowledgments

Inspired by the original [Sherlock Project](https://github.com/sherlock-project/sherlock)

Built for the **Apollo Intelligence Platform** by the OSINT development team.

---

**Last Updated:** 2026-01-14
**Version:** 1.0.0
**Status:** Production Ready
