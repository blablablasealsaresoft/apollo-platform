# Dark Web Monitoring - Quick Start Guide

## 🚀 Fast Setup

### 1. Install Tor

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install tor
sudo systemctl start tor
```

**macOS:**
```bash
brew install tor
brew services start tor
```

**Windows:**
- Download from https://www.torproject.org/download/
- Run installer
- Start Tor Browser or Tor Expert Bundle

### 2. Install Python Dependencies

```bash
pip install -r requirements.txt
```

### 3. Basic Usage

```python
import asyncio
from darkweb_monitor import DarkWebMonitor

async def main():
    monitor = DarkWebMonitor()

    results = await monitor.start_monitoring(
        keywords=["onecoin", "ruja ignatova"],
        marketplaces=["alphabay"],
        forums=["dread"]
    )

    print(f"Found {len(results)} results")
    monitor.export_results(format='html')

asyncio.run(main())
```

## 📋 Common Use Cases

### Monitor for Data Breaches

```python
from darkweb_monitor import DarkWebMonitor, MonitoringConfig

config = MonitoringConfig(
    keywords=["company.com", "database dump", "credentials"],
    paste_sites=["pastebin", "ghostbin"],
    continuous=True,
    interval=1800,  # 30 minutes
    enable_alerts=True
)

monitor = DarkWebMonitor(config)
await monitor.start_monitoring()
```

### Track Threat Actors

```python
from forum_scraper import ForumScraper
from tor_proxy import TorProxy

tor_proxy = TorProxy()
await tor_proxy.start()

scraper = ForumScraper(tor_proxy)

# Track user activity
user = await scraper.track_user("dread", "threat_actor_username")

# Analyze relationships
network = scraper.map_user_relationships("threat_actor_username", depth=2)

await tor_proxy.stop()
```

### Monitor Marketplaces

```python
from marketplace_tracker import MarketplaceTracker
from tor_proxy import TorProxy

tor_proxy = TorProxy()
await tor_proxy.start()

tracker = MarketplaceTracker(tor_proxy)

results = await tracker.track_marketplace(
    "alphabay",
    keywords=["stolen credentials", "database"],
    categories=["fraud", "digital"]
)

await tor_proxy.stop()
```

### Crawl Onion Sites

```python
from onion_crawler import OnionCrawler, CrawlConfig
from tor_proxy import TorProxy

tor_proxy = TorProxy()
await tor_proxy.start()

config = CrawlConfig(
    max_depth=2,
    max_pages=50,
    extract_emails=True,
    extract_crypto=True
)

crawler = OnionCrawler(tor_proxy, config)
pages = await crawler.crawl("http://example.onion")

crawler.generate_sitemap("sitemap.md")
await tor_proxy.stop()
```

## 🔔 Setup Alerts

### Slack Alerts

```python
from darkweb_alerts import DarkWebAlerts

alerts = DarkWebAlerts(
    webhook_url="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
)

# Alerts will be sent automatically when high-risk content is found
```

### Discord Alerts

```python
alerts = DarkWebAlerts(
    webhook_url="https://discord.com/api/webhooks/YOUR_WEBHOOK"
)
```

### Email Alerts

```python
alerts = DarkWebAlerts(
    email_config={
        'smtp_host': 'smtp.gmail.com',
        'smtp_port': 587,
        'username': 'your-email@gmail.com',
        'password': 'app-password',
        'from': 'alerts@company.com',
        'to': 'security@company.com'
    }
)
```

## 📊 Export Results

```python
# JSON export
monitor.export_results(format='json', output_file='results.json')

# HTML report
monitor.export_results(format='html', output_file='report.html')

# CSV export
monitor.export_results(format='csv', output_file='data.csv')
```

## 🔧 Configuration File

Copy `config.example.json` to `config.json` and customize:

```bash
cp config.example.json config.json
nano config.json
```

Key settings:
- `keywords`: Terms to monitor
- `marketplaces`: Which marketplaces to track
- `forums`: Forums to scrape
- `continuous`: Enable continuous monitoring
- `interval`: Check interval in seconds
- `enable_alerts`: Turn on/off alerts

## 🎯 Interactive Examples

Run the example script:

```bash
python example_usage.py
```

This provides an interactive menu with:
1. Basic Monitoring
2. Continuous Monitoring
3. Onion Crawler
4. Marketplace Tracking
5. Forum Scraping
6. Paste Monitoring
7. Telegram Monitoring
8. Comprehensive Monitoring
9. Tor Proxy Management

## ⚠️ Important Notes

### Security
- Always use Tor for accessing .onion sites
- Never use personal accounts
- Encrypt collected data
- Follow legal requirements

### Performance
- Tor is slower than regular internet
- Adjust delays to avoid rate limiting
- Use `circuit_rotation_interval` for anonymity

### Legal
- Ensure you have authorization
- Comply with local laws
- Use for legitimate security research only
- Respect privacy and data protection laws

## 🐛 Troubleshooting

### Tor won't connect
```python
tor_proxy = TorProxy()
await tor_proxy.start()

# Verify connection
is_connected = await tor_proxy.verify_tor_connection()
if not is_connected:
    print("Check if Tor is installed and running")
```

### Database locked
```python
# Use WAL mode
import sqlite3
conn = sqlite3.connect('darkweb_intel.db')
conn.execute('PRAGMA journal_mode=WAL')
```

### Rate limiting
```python
config = CrawlConfig(
    delay=5.0,  # Increase delay
    max_concurrent=2  # Reduce parallel requests
)
```

## 📚 Full Documentation

See `README_DARKWEB_MONITORING.md` for complete documentation.

## 🚨 Support

Check logs for errors:
```bash
cat darkweb_results/darkweb_monitor.log
```

Query database for results:
```bash
sqlite3 darkweb_results/darkweb_intel.db "SELECT * FROM results LIMIT 10;"
```

## 🎓 Learning Resources

1. Start with basic monitoring
2. Test with known .onion sites
3. Configure alerts
4. Set up continuous monitoring
5. Integrate with your security stack

## ⚡ Quick Commands

**Start monitoring now:**
```bash
python -c "import asyncio; from darkweb_monitor import DarkWebMonitor; asyncio.run(DarkWebMonitor().start_monitoring(keywords=['test']))"
```

**Test Tor connection:**
```bash
python -c "import asyncio; from tor_proxy import TorProxy; tor=TorProxy(); asyncio.run(tor.start()); asyncio.run(tor.verify_tor_connection()); asyncio.run(tor.stop())"
```

**View statistics:**
```bash
python -c "from darkweb_monitor import DarkWebMonitor; m=DarkWebMonitor(); print(m.get_statistics())"
```

---

**Built for production threat intelligence. Use responsibly and legally.**
