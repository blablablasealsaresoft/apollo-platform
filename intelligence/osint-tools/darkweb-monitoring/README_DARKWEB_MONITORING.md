# Dark Web Monitoring System

## Overview

Comprehensive dark web intelligence gathering and monitoring system for tracking hidden services, marketplaces, forums, paste sites, and Telegram channels.

## Features

### Core Capabilities

- **Tor Search Engine Integration**: Search across Ahmia, OnionLand, DarkSearch, and Torch
- **Marketplace Tracking**: Monitor dark web marketplaces for specific keywords and vendors
- **Forum Scraping**: Automated scraping of dark web forums (Dread, Envoy, etc.)
- **Paste Site Monitoring**: Track Pastebin, Ghostbin, 0bin for credential leaks
- **Telegram Intelligence**: Monitor Telegram channels for dark web activity
- **Onion Crawler**: Automated crawling and content extraction from .onion sites
- **Alert System**: Real-time notifications via webhooks and email
- **Cryptocurrency Tracking**: Extract and track Bitcoin, Ethereum, and Monero addresses

### Intelligence Collection

- Keyword monitoring across all sources
- Entity extraction (emails, IPs, domains)
- Cryptocurrency address detection
- Risk scoring for content
- Relationship mapping
- Historical data tracking

## Components

### 1. darkweb_monitor.py

Main monitoring orchestration system.

```python
from darkweb_monitor import DarkWebMonitor, MonitoringConfig

# Create configuration
config = MonitoringConfig(
    keywords=["onecoin", "ruja ignatova"],
    marketplaces=["alphabay", "darkbay"],
    forums=["dread", "darknetlive"],
    paste_sites=["pastebin", "ghostbin"],
    continuous=False,
    max_depth=3
)

# Initialize monitor
monitor = DarkWebMonitor(config)

# Start monitoring
results = await monitor.start_monitoring()

# Export results
monitor.export_results(format='json', output_file='results.json')
monitor.export_results(format='html', output_file='report.html')

# Get statistics
stats = monitor.get_statistics()
print(f"Total results: {stats['total_results']}")
print(f"High risk: {stats['high_risk_results']}")
```

### 2. onion_crawler.py

Tor hidden service crawler for automated site exploration.

```python
from onion_crawler import OnionCrawler, CrawlConfig
from tor_proxy import TorProxy

# Initialize Tor proxy
tor_proxy = TorProxy()
await tor_proxy.start()

# Create crawler
config = CrawlConfig(
    max_depth=3,
    max_pages=100,
    delay=2.0,
    extract_emails=True,
    extract_crypto=True
)

crawler = OnionCrawler(tor_proxy, config)

# Crawl onion site
pages = await crawler.crawl(
    "http://example.onion",
    max_depth=2,
    max_pages=50
)

# Generate sitemap
sitemap = crawler.generate_sitemap("sitemap.md")

# Export results
crawler.export_results("crawl_results.json")

# Get statistics
stats = crawler.get_statistics()
```

### 3. marketplace_tracker.py

Dark web marketplace monitoring and vendor tracking.

```python
from marketplace_tracker import MarketplaceTracker

tracker = MarketplaceTracker(tor_proxy)

# Track marketplace
results = await tracker.track_marketplace(
    "alphabay",
    keywords=["stolen data", "credentials"],
    categories=["fraud", "digital"]
)

# Get marketplace list
marketplaces = tracker.get_marketplace_list(status="active")

# Track specific vendor
vendor_info = await tracker.track_vendor("alphabay", "VendorName")

# Monitor cryptocurrency transactions
transactions = await tracker.monitor_transactions(
    cryptocurrency="bitcoin",
    addresses=["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"]
)

# Analyze listing
analysis = tracker.analyze_listing(listing)

# Generate report
report = tracker.generate_market_report()
```

### 4. forum_scraper.py

Dark web forum scraping and user tracking.

```python
from forum_scraper import ForumScraper

scraper = ForumScraper(tor_proxy)

# Scrape forum
results = await scraper.scrape_forum(
    "dread",
    keywords=["exploit", "vulnerability"],
    boards=["security", "hacking"],
    max_pages=10
)

# Search threads
threads = await scraper.search_threads(
    "dread",
    keyword="zero-day",
    max_results=50
)

# Track user
user = await scraper.track_user("dread", "username")

# Analyze user activity
analysis = scraper.analyze_user_activity("username")

# Map user relationships
relationships = scraper.map_user_relationships("username", depth=2)

# Get forum list
forums = scraper.get_forum_list(status="active")

# Generate report
report = scraper.generate_forum_report()
```

### 5. paste_monitor.py

Paste site monitoring for leaked credentials and sensitive data.

```python
from paste_monitor import PasteMonitor

monitor = PasteMonitor()

# Monitor paste sites
results = await monitor.monitor(
    keywords=["database dump", "credentials", "@company.com"],
    sites=["pastebin", "ghostbin", "0bin"],
    continuous=True,
    duration=3600  # 1 hour
)

# Search specific paste site
pastes = await monitor.search_pastes(
    keyword="password",
    site="pastebin",
    max_results=100
)

# Generate report
report = monitor.generate_report()

# Export results
monitor.export_results("paste_results.json")
```

### 6. telegram_darkweb.py

Telegram channel monitoring for dark web intelligence.

```python
from telegram_darkweb import TelegramDarkWeb

# Initialize with API credentials
monitor = TelegramDarkWeb(
    api_id="YOUR_API_ID",
    api_hash="YOUR_API_HASH"
)

# Monitor channels
results = await monitor.monitor_channels(
    channels=["@darknet_news", "@marketplace_alerts"],
    keywords=["breach", "leak", "dump"],
    continuous=True
)

# Get channel info
channel_info = await monitor.get_channel_info("@channel_name")

# Search messages
messages = await monitor.search_messages(
    "@channel_name",
    query="exploit",
    limit=100
)

# Get channel history
history = await monitor.get_channel_history(
    "@channel_name",
    days=7
)

# Analyze channel activity
analysis = monitor.analyze_channel_activity("@channel_name")

# Track user across channels
user_data = monitor.track_user("user_id")

# Export messages
monitor.export_messages("telegram_messages.json")
```

### 7. tor_proxy.py

Tor SOCKS5 proxy management for anonymous connectivity.

```python
from tor_proxy import TorProxy

# Initialize proxy
proxy = TorProxy(
    socks_port=9050,
    control_port=9051
)

# Start Tor
await proxy.start()

# Verify connection
is_tor = await proxy.verify_tor_connection()

# Get current exit IP
ip = await proxy.get_current_ip()

# Rotate circuit (new exit node)
await proxy.rotate_circuit()

# Get session for HTTP requests
async with proxy.get_session() as session:
    async with session.get("http://example.onion") as response:
        html = await response.text()

# Get status
status = proxy.get_status()

# Stop Tor
await proxy.stop()
proxy.cleanup()
```

### 8. darkweb_alerts.py

Real-time alerting system with webhook and email support.

```python
from darkweb_alerts import DarkWebAlerts

# Initialize alerts
alerts = DarkWebAlerts(
    webhook_url="https://hooks.slack.com/services/YOUR/WEBHOOK/URL",
    email_config={
        'smtp_host': 'smtp.gmail.com',
        'smtp_port': 587,
        'username': 'your-email@gmail.com',
        'password': 'your-password',
        'from': 'alerts@example.com',
        'to': 'recipient@example.com'
    },
    alert_file="alerts.jsonl"
)

# Send alert
await alerts.send_alert(
    alert_type="high_risk_content",
    severity="critical",
    message="Credential dump found on marketplace",
    result=result_object,
    entities=["admin@company.com"]
)

# Add custom rule
alerts.add_rule(
    rule_name="custom_keyword",
    condition=lambda result: "company_name" in result.content.lower(),
    severity="high"
)

# Get alerts
recent_alerts = alerts.get_alerts(severity="high", limit=10)

# Get statistics
stats = alerts.get_statistics()

# Export alerts
alerts.export_alerts("alert_export.json")
```

## Installation

### Prerequisites

```bash
# Install Tor
# Ubuntu/Debian
sudo apt-get install tor

# macOS
brew install tor

# Windows
# Download from https://www.torproject.org/download/
```

### Python Dependencies

```bash
pip install aiohttp aiohttp-socks asyncio
```

### Telegram API (Optional)

For Telegram monitoring, obtain API credentials:
1. Go to https://my.telegram.org
2. Log in with your phone number
3. Go to "API development tools"
4. Create a new application
5. Copy API ID and API Hash

## Usage Examples

### Basic Monitoring

```python
import asyncio
from darkweb_monitor import DarkWebMonitor

async def main():
    monitor = DarkWebMonitor()

    results = await monitor.start_monitoring(
        keywords=["target_company", "data breach"],
        marketplaces=["alphabay"],
        forums=["dread"],
        continuous=False
    )

    print(f"Found {len(results)} results")
    monitor.export_results(format='html')

asyncio.run(main())
```

### Continuous Monitoring

```python
async def continuous_monitor():
    config = MonitoringConfig(
        keywords=["keyword1", "keyword2"],
        continuous=True,
        interval=3600,  # Check every hour
        enable_alerts=True,
        alert_webhook="https://your-webhook-url"
    )

    monitor = DarkWebMonitor(config)

    # Run for 24 hours
    await monitor.start_monitoring(duration=86400)
```

### Marketplace Intelligence

```python
async def track_marketplace():
    tor_proxy = TorProxy()
    await tor_proxy.start()

    try:
        tracker = MarketplaceTracker(tor_proxy)

        # Track specific marketplace
        results = await tracker.track_marketplace(
            "darkbay",
            keywords=["stolen credentials"],
            categories=["fraud"]
        )

        # Analyze findings
        for result in results:
            if result['risk_score'] >= 80:
                print(f"High risk: {result['title']}")

    finally:
        await tor_proxy.stop()
```

### Credential Leak Detection

```python
async def monitor_leaks():
    paste_monitor = PasteMonitor()

    results = await paste_monitor.monitor(
        keywords=[
            "database dump",
            "@company.com",
            "credentials",
            "password"
        ],
        sites=["pastebin", "ghostbin"],
        continuous=True
    )

    # Check for company emails
    for result in results:
        if result['risk_score'] >= 80:
            print(f"ALERT: {result['title']}")
            print(f"Emails found: {len(result['metadata']['emails_found'])}")
            print(f"Passwords: {result['metadata']['passwords_found']}")
```

### Forum User Tracking

```python
async def track_threat_actor():
    tor_proxy = TorProxy()
    await tor_proxy.start()

    try:
        scraper = ForumScraper(tor_proxy)

        # Track user
        user = await scraper.track_user("dread", "suspected_actor")

        # Analyze activity
        analysis = scraper.analyze_user_activity("suspected_actor")

        # Map relationships
        network = scraper.map_user_relationships("suspected_actor", depth=2)

        print(f"Activity level: {analysis['activity_level']}")
        print(f"Topics: {analysis['topics_of_interest']}")

    finally:
        await tor_proxy.stop()
```

## Alert Configuration

### Slack Webhook

```python
alerts = DarkWebAlerts(
    webhook_url="https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXX"
)
```

### Discord Webhook

```python
alerts = DarkWebAlerts(
    webhook_url="https://discord.com/api/webhooks/WEBHOOK_ID/WEBHOOK_TOKEN"
)
```

### Email Alerts

```python
alerts = DarkWebAlerts(
    email_config={
        'smtp_host': 'smtp.gmail.com',
        'smtp_port': 587,
        'username': 'your-email@gmail.com',
        'password': 'app-specific-password',
        'from': 'darkweb-monitor@company.com',
        'to': 'security-team@company.com'
    }
)
```

## Security Considerations

### Operational Security

1. **Use Tor**: Always use Tor for accessing .onion sites
2. **Rotate Circuits**: Regularly rotate Tor circuits to avoid correlation
3. **No Personal Info**: Never use personal accounts or information
4. **Secure Storage**: Encrypt collected data at rest
5. **Access Control**: Restrict access to monitoring results
6. **Legal Compliance**: Ensure monitoring activities are legal in your jurisdiction

### Best Practices

- Use dedicated infrastructure for dark web monitoring
- Implement rate limiting to avoid detection
- Rotate user agents and delays
- Monitor from multiple exit nodes
- Keep detailed audit logs
- Regular security reviews

### Legal Notice

This tool is for **authorized security research and threat intelligence only**. Users are responsible for:

- Obtaining proper authorization
- Complying with applicable laws
- Following organizational policies
- Respecting privacy and data protection laws

Unauthorized access to computer systems is illegal.

## Database Schema

The system uses SQLite for storage:

```sql
-- Results table
CREATE TABLE results (
    id TEXT PRIMARY KEY,
    timestamp TEXT,
    source TEXT,
    source_type TEXT,
    url TEXT,
    title TEXT,
    content TEXT,
    keywords_found TEXT,
    metadata TEXT,
    risk_score INTEGER,
    entities TEXT,
    crypto_addresses TEXT
);

-- Monitoring sessions
CREATE TABLE monitoring_sessions (
    session_id TEXT PRIMARY KEY,
    start_time TEXT,
    end_time TEXT,
    keywords TEXT,
    results_count INTEGER,
    status TEXT
);

-- Alerts
CREATE TABLE alerts (
    alert_id TEXT PRIMARY KEY,
    timestamp TEXT,
    alert_type TEXT,
    severity TEXT,
    message TEXT,
    result_id TEXT,
    notified INTEGER DEFAULT 0
);
```

## Export Formats

### JSON Export

```json
{
  "metadata": {
    "export_time": "2024-01-15T10:30:00Z",
    "total_results": 42,
    "keywords": ["keyword1", "keyword2"]
  },
  "results": [
    {
      "id": "abc123",
      "timestamp": "2024-01-15T10:25:00Z",
      "source": "Dread",
      "source_type": "forum",
      "url": "http://example.onion/thread/123",
      "title": "Discussion about...",
      "risk_score": 75,
      "keywords_found": ["keyword1"],
      "entities": ["email@example.com"],
      "cryptocurrency_addresses": ["1A1zP1eP..."]
    }
  ]
}
```

### HTML Report

Generates comprehensive HTML report with:
- Summary statistics
- High-risk findings
- Source breakdown
- Timeline visualization
- Entity extraction
- Risk scoring

### CSV Export

Tabular format for analysis in spreadsheet applications.

## Performance Tuning

```python
config = MonitoringConfig(
    max_concurrent=10,  # Parallel requests
    delay=2.0,  # Delay between requests
    timeout=30,  # Request timeout
    circuit_rotation_interval=600,  # Rotate Tor circuit every 10 min
    max_depth=2,  # Crawl depth
    max_pages=100  # Maximum pages per source
)
```

## Troubleshooting

### Tor Connection Issues

```python
# Check Tor status
tor_proxy = TorProxy()
await tor_proxy.start()
is_connected = await tor_proxy.verify_tor_connection()

if not is_connected:
    print("Tor connection failed")
    # Try rotating circuit
    await tor_proxy.rotate_circuit()
```

### Rate Limiting

Increase delays between requests:

```python
config = CrawlConfig(
    delay=5.0,  # 5 seconds between requests
    max_concurrent=3  # Reduce parallel requests
)
```

### Database Locked

If SQLite database is locked:

```python
# Use connection pooling or WAL mode
conn = sqlite3.connect('darkweb_intel.db', check_same_thread=False)
conn.execute('PRAGMA journal_mode=WAL')
```

## Limitations

- Tor network speed limitations
- Some marketplaces require authentication
- CAPTCHA protection on some sites
- Rate limiting by dark web services
- Seizure/downtime of monitored sites
- Telegram API rate limits

## REST API Endpoints (Agent 5 Implementation)

The dark web monitoring system exposes a FastAPI-based REST API for all operations.

### API Base URL

```
http://localhost:8080/api/v1
```

### Dark Web Search

```http
POST /api/v1/darkweb/search
Content-Type: application/json

{
    "query": "cryptocurrency fraud",
    "engines": ["ahmia"],
    "max_results": 50,
    "safe_search": true,
    "include_monitoring": false
}
```

**Response:**
```json
{
    "status": "success",
    "query": "cryptocurrency fraud",
    "total_results": 42,
    "engines_used": ["ahmia"],
    "results": [...],
    "search_time_ms": 1234.5,
    "cached": false
}
```

### Breach Check

```http
POST /api/v1/breach/check
Content-Type: application/json

{
    "query": "test@example.com",
    "query_type": "email",
    "sources": ["hibp", "dehashed"],
    "include_credentials": false
}
```

**Response:**
```json
{
    "status": "success",
    "query": "te***@example.com",
    "query_type": "email",
    "breaches_found": 5,
    "pastes_found": 2,
    "severity": "high",
    "breaches": [...],
    "credentials_count": 3,
    "sources_checked": ["hibp", "dehashed"],
    "checked_at": "2024-01-15T10:30:00Z"
}
```

### Password Check (k-anonymity)

```http
POST /api/v1/breach/check/password
Content-Type: application/json

{
    "password": "test123"
}
```

**Response:**
```json
{
    "compromised": true,
    "exposure_count": 1234567,
    "sha1_prefix": "A94A8",
    "message": "Password found in 1234567 breaches"
}
```

### Get Cached Breach Results

```http
GET /api/v1/breach/results/{query}?query_type=email
```

### Batch Breach Check

```http
POST /api/v1/breach/batch
Content-Type: application/json

{
    "queries": ["user1@example.com", "user2@example.com"],
    "query_type": "email"
}
```

### Paste Site Monitoring

```http
POST /api/v1/paste/monitor
Content-Type: application/json

{
    "keywords": ["database dump", "credentials"],
    "sites": ["pastebin", "github_gist"],
    "duration_seconds": 3600,
    "min_severity": "MEDIUM"
}
```

### Get Paste Alerts

```http
GET /api/v1/paste/alerts?severity=HIGH&limit=100
```

### Get Paste Statistics

```http
GET /api/v1/paste/stats
```

### Get Monitoring Status

```http
GET /api/v1/darkweb/status
```

**Response:**
```json
{
    "tor_status": {
        "is_connected": true,
        "is_tor_verified": true,
        "current_ip": "185.220.101.1",
        "exit_country": "DE"
    },
    "search_stats": {...},
    "breach_stats": {...},
    "paste_stats": {...},
    "active_monitors": 5
}
```

### Tor Circuit Rotation

```http
POST /api/v1/tor/rotate
```

### Get Tor Status

```http
GET /api/v1/tor/status
```

## TimescaleDB Schema

The system uses TimescaleDB for time-series storage with automatic data retention.

### Tables (Hypertables)

```sql
-- Dark web search results
CREATE TABLE darkweb_search_results (
    time TIMESTAMPTZ NOT NULL,
    result_id TEXT NOT NULL,
    query TEXT NOT NULL,
    query_hash TEXT NOT NULL,
    engine TEXT NOT NULL,
    url TEXT NOT NULL,
    title TEXT,
    description TEXT,
    relevance_score FLOAT,
    keywords_matched TEXT[],
    raw_data JSONB,
    PRIMARY KEY (time, result_id)
);

-- Breach check results
CREATE TABLE breach_check_results (
    time TIMESTAMPTZ NOT NULL,
    check_id TEXT NOT NULL,
    query TEXT NOT NULL,
    query_hash TEXT NOT NULL,
    query_type TEXT NOT NULL,
    breaches_found INTEGER DEFAULT 0,
    pastes_found INTEGER DEFAULT 0,
    credentials_count INTEGER DEFAULT 0,
    severity TEXT,
    sources_checked TEXT[],
    breaches_data JSONB,
    raw_data JSONB,
    PRIMARY KEY (time, check_id)
);

-- Paste monitoring results
CREATE TABLE paste_monitoring_results (
    time TIMESTAMPTZ NOT NULL,
    paste_id TEXT NOT NULL,
    site TEXT NOT NULL,
    url TEXT NOT NULL,
    title TEXT,
    author TEXT,
    content_hash TEXT NOT NULL,
    raw_size INTEGER,
    language TEXT,
    paste_type TEXT,
    severity TEXT,
    risk_score INTEGER,
    keywords_matched TEXT[],
    emails_count INTEGER DEFAULT 0,
    passwords_count INTEGER DEFAULT 0,
    crypto_addresses JSONB,
    raw_data JSONB,
    PRIMARY KEY (time, paste_id)
);

-- Dark web alerts
CREATE TABLE darkweb_alerts (
    time TIMESTAMPTZ NOT NULL,
    alert_id TEXT NOT NULL,
    alert_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    source TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    related_id TEXT,
    keywords TEXT[],
    acknowledged BOOLEAN DEFAULT FALSE,
    acknowledged_at TIMESTAMPTZ,
    acknowledged_by TEXT,
    raw_data JSONB,
    PRIMARY KEY (time, alert_id)
);
```

### Continuous Aggregates

```sql
-- Hourly search statistics
CREATE MATERIALIZED VIEW search_stats_hourly AS
SELECT
    time_bucket('1 hour', time) AS bucket,
    engine,
    COUNT(*) as total_results,
    COUNT(DISTINCT query_hash) as unique_queries,
    AVG(relevance_score) as avg_relevance
FROM darkweb_search_results
GROUP BY bucket, engine;

-- Daily breach statistics
CREATE MATERIALIZED VIEW breach_stats_daily AS
SELECT
    time_bucket('1 day', time) AS bucket,
    query_type,
    severity,
    COUNT(*) as total_checks,
    SUM(breaches_found) as total_breaches,
    SUM(credentials_count) as total_credentials
FROM breach_check_results
GROUP BY bucket, query_type, severity;
```

### Data Retention

Automatic retention policies remove data older than 90 days:

```sql
SELECT add_retention_policy('darkweb_search_results', INTERVAL '90 days');
SELECT add_retention_policy('breach_check_results', INTERVAL '90 days');
SELECT add_retention_policy('paste_monitoring_results', INTERVAL '90 days');
SELECT add_retention_policy('darkweb_alerts', INTERVAL '90 days');
```

## Environment Variables

Configure the system with these environment variables:

```bash
# API Keys
HIBP_API_KEY=your_hibp_api_key          # HaveIBeenPwned API key
DEHASHED_API_KEY=your_dehashed_key      # DeHashed API key
DEHASHED_EMAIL=your_dehashed_email      # DeHashed account email
LEAKCHECK_API_KEY=your_leakcheck_key    # LeakCheck API key
DARKSEARCH_API_KEY=your_darksearch_key  # DarkSearch API key
PASTEBIN_API_KEY=your_pastebin_key      # Pastebin Pro API key
GITHUB_TOKEN=your_github_token          # GitHub personal access token

# Tor Configuration
TOR_SOCKS_PORT=9050                     # Tor SOCKS proxy port
TOR_CONTROL_PORT=9051                   # Tor control port

# TimescaleDB
TIMESCALE_HOST=localhost
TIMESCALE_PORT=5432
TIMESCALE_DB=apollo_darkweb
TIMESCALE_USER=apollo
TIMESCALE_PASSWORD=your_password
```

## Future Enhancements

- Machine learning for content classification
- Automated threat actor profiling
- Graph database for relationship mapping
- Real-time streaming alerts
- Integration with SIEM systems
- Automated IOC extraction
- Multi-language support
- Advanced analytics dashboard

## Contributing

This is a production-ready intelligence gathering system. Use responsibly and legally.

## License

For authorized security research and threat intelligence purposes only.

## Support

For issues or questions:
- Check logs in `darkweb_monitor.log`
- Review database for historical data
- Verify Tor connectivity
- Check API credentials (Telegram)
- Review alert configurations

## Acknowledgments

Built for comprehensive dark web intelligence gathering and threat monitoring.
