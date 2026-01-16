# Agent 5: Dark Web Monitoring Implementation

## Overview

Agent 5 has implemented a comprehensive dark web monitoring system with breach checking, paste site monitoring, and API integration for the Apollo Intelligence Platform.

## Components Implemented

### 1. API Endpoints (`/api/v1/`)

**File:** `intelligence/osint-tools/darkweb-monitoring/api_endpoints.py`

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/darkweb/search` | POST | Search dark web via Ahmia.fi |
| `/api/v1/darkweb/status` | GET | Get monitoring system status |
| `/api/v1/breach/check` | POST | Check identifier for breaches |
| `/api/v1/breach/check/password` | POST | Check password exposure (k-anonymity) |
| `/api/v1/breach/results/{query}` | GET | Get cached breach results |
| `/api/v1/breach/batch` | POST | Batch breach checking |
| `/api/v1/paste/monitor` | POST | Monitor paste sites |
| `/api/v1/paste/alerts` | GET | Get paste monitoring alerts |
| `/api/v1/paste/stats` | GET | Get paste monitoring statistics |
| `/api/v1/tor/rotate` | POST | Rotate Tor circuit |
| `/api/v1/tor/status` | GET | Get Tor proxy status |

### 2. TimescaleDB Storage

**File:** `intelligence/osint-tools/darkweb-monitoring/timescale_storage.py`

**Hypertables:**
- `darkweb_search_results` - Dark web search results with time-series indexing
- `breach_check_results` - Breach check results with severity tracking
- `paste_monitoring_results` - Paste site monitoring data
- `darkweb_alerts` - System alerts and notifications

**Features:**
- Automatic data retention (90 days default)
- Continuous aggregates for statistics
- Efficient time-range queries
- Full JSON data storage

### 3. Breach Database Integration

**Files:**
- `intelligence/breach-databases/dehashed.py` - DeHashed API client
- `intelligence/breach-databases/hibp.py` - HaveIBeenPwned API client
- `intelligence/breach-databases/breach_engine.py` - Unified breach search engine

**Capabilities:**
- Email breach checking
- Username lookup
- Domain breach search
- Password exposure check (k-anonymity)
- Credential monitoring
- Multiple source aggregation

### 4. Enhanced Tor Proxy

**File:** `intelligence/osint-tools/darkweb-monitoring/tor_proxy_enhanced.py`

**Features:**
- SOCKS5 proxy with remote DNS
- Automatic circuit rotation
- Connection health monitoring
- Rate limiting
- Session management
- Exit node tracking

### 5. Enhanced Paste Monitoring

**File:** `intelligence/osint-tools/darkweb-monitoring/paste_monitor_enhanced.py`

**Supported Sites:**
- Pastebin (Pro API)
- GitHub Gist
- Rentry
- dpaste
- Ghostbin
- Hastebin

**Detection Patterns:**
- Credentials (email:password combos)
- API keys (AWS, GitHub, Google, Slack)
- Cryptocurrency addresses (BTC, ETH, XMR)
- Credit card numbers
- SSN patterns
- Private keys
- IP addresses and domains
- Onion URLs

## Directory Structure

```
intelligence/
├── osint-tools/
│   └── darkweb-monitoring/
│       ├── __init__.py           # Module exports
│       ├── api_endpoints.py      # FastAPI router
│       ├── timescale_storage.py  # TimescaleDB storage
│       ├── ahmia_search.py       # Dark web search
│       ├── breach_checker.py     # Breach checking
│       ├── paste_monitor.py      # Basic paste monitor
│       ├── paste_monitor_enhanced.py  # Enhanced paste monitor
│       ├── tor_proxy.py          # Basic Tor proxy
│       ├── tor_proxy_enhanced.py # Enhanced Tor proxy
│       ├── requirements.txt      # Dependencies
│       └── README_DARKWEB_MONITORING.md
│
└── breach-databases/
    ├── __init__.py               # Module exports
    ├── breach_engine.py          # Unified breach engine
    ├── dehashed.py               # DeHashed client
    ├── hibp.py                   # HIBP client
    └── requirements.txt          # Dependencies
```

## Environment Variables

```bash
# Breach Database APIs
HIBP_API_KEY=your_hibp_api_key
DEHASHED_API_KEY=your_dehashed_key
DEHASHED_EMAIL=your_dehashed_email
LEAKCHECK_API_KEY=your_leakcheck_key

# Dark Web Search
DARKSEARCH_API_KEY=your_darksearch_key

# Paste Site APIs
PASTEBIN_API_KEY=your_pastebin_pro_key
GITHUB_TOKEN=your_github_token

# Tor Configuration
TOR_SOCKS_PORT=9050
TOR_CONTROL_PORT=9051

# TimescaleDB
TIMESCALE_HOST=localhost
TIMESCALE_PORT=5432
TIMESCALE_DB=apollo_darkweb
TIMESCALE_USER=apollo
TIMESCALE_PASSWORD=your_password
```

## Usage Examples

### Dark Web Search

```python
from intelligence.osint_tools.darkweb_monitoring import AhmiaSearch

search = AhmiaSearch()
results = await search.search(
    query="cryptocurrency fraud",
    max_results=50,
    safe_search=True
)

for result in results:
    print(f"URL: {result.url}")
    print(f"Title: {result.title}")
    print(f"Score: {result.relevance_score}")
```

### Breach Checking

```python
from intelligence.breach_databases import HIBPClient, DeHashedClient

# HIBP Check
hibp = HIBPClient(api_key="your_key")
result = await hibp.check_email_full("user@example.com")
print(f"Breaches: {result.breaches_found}")
print(f"Severity: {result.severity}")

# Password Check (no API key required)
pwd_result = await hibp.check_password("password123")
print(f"Compromised: {pwd_result.compromised}")
print(f"Exposures: {pwd_result.exposure_count}")
```

### Paste Monitoring

```python
from intelligence.osint_tools.darkweb_monitoring import PasteMonitorEnhanced

monitor = PasteMonitorEnhanced(
    pastebin_api_key="your_key",
    github_token="your_token"
)

# Add monitoring rule
monitor.add_monitoring_rule(
    name="Credential Leaks",
    keywords=["password", "credentials"],
    min_severity=PasteSeverity.MEDIUM
)

# Start monitoring
results = await monitor.start_monitoring(
    keywords=["database dump", "leaked"],
    sites=["pastebin", "github_gist"],
    interval=60,
    duration=3600
)
```

### Tor Proxy

```python
from intelligence.osint_tools.darkweb_monitoring import TorProxyEnhanced

proxy = TorProxyEnhanced(
    socks_port=9050,
    auto_rotate_interval=600
)

await proxy.start()

# Make requests through Tor
async with proxy.get_session() as session:
    async with session.get("http://example.onion") as response:
        content = await response.text()

# Rotate circuit
await proxy.rotate_circuit()

# Get status
status = proxy.get_health_status()
print(f"Exit IP: {status['current_ip']}")

await proxy.stop()
```

## API Response Examples

### Dark Web Search Response

```json
{
    "status": "success",
    "query": "cryptocurrency fraud",
    "total_results": 42,
    "engines_used": ["ahmia"],
    "results": [
        {
            "url": "http://example.onion/page",
            "title": "Result Title",
            "description": "Result description...",
            "relevance_score": 85.5,
            "keywords_matched": ["cryptocurrency", "fraud"]
        }
    ],
    "search_time_ms": 1234.5,
    "cached": false
}
```

### Breach Check Response

```json
{
    "status": "success",
    "query": "te***@example.com",
    "query_type": "email",
    "breaches_found": 5,
    "pastes_found": 2,
    "severity": "high",
    "breaches": [
        {
            "name": "Collection1",
            "title": "Collection #1",
            "breach_date": "2019-01-17",
            "pwn_count": 773000000,
            "data_classes": ["Email addresses", "Passwords"]
        }
    ],
    "credentials_count": 3,
    "sources_checked": ["hibp", "dehashed"],
    "checked_at": "2024-01-15T10:30:00Z"
}
```

## Security Considerations

1. **API Keys**: Store all API keys securely in environment variables
2. **Password Checking**: Uses k-anonymity - full password never transmitted
3. **Tor Usage**: Circuit rotation prevents correlation attacks
4. **Data Retention**: Automatic cleanup of old data
5. **Query Masking**: Sensitive queries masked in responses

## Dependencies

See `requirements.txt` files for full dependency lists.

Key dependencies:
- FastAPI for API endpoints
- aiohttp + aiohttp-socks for async HTTP
- asyncpg for TimescaleDB
- stem for Tor control
- beautifulsoup4 for HTML parsing

## Testing

```bash
# Run tests
pytest intelligence/tests/test_darkweb.py -v

# With coverage
pytest --cov=intelligence/osint-tools/darkweb-monitoring tests/
```

## Status

All tasks completed:

- [x] Tor integration with SOCKS proxy and circuit rotation
- [x] Ahmia.fi dark web search API integration
- [x] HaveIBeenPwned API integration
- [x] DeHashed API integration
- [x] Paste site monitoring (Pastebin, GitHub Gist)
- [x] API endpoints (FastAPI)
- [x] TimescaleDB storage
- [x] Updated requirements.txt

## Author

Agent 5 - Dark Web Monitoring Implementation
Date: 2026-01-16
