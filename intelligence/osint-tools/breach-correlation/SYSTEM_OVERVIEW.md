# Breach Database Integration System - Complete Overview

## Agent 6: Breach Database Integration - MISSION COMPLETE

**Location:** `C:\SECURE_THREAT_INTEL\YoureGunnaHAveToShootMeToStopME\apollo\intelligence\osint-tools\breach-correlation\`

## System Capabilities

This is a **comprehensive breach database search and correlation system** that integrates multiple breach databases to provide:

- Multi-source breach database searching (DeHashed 11B+ records, HaveIBeenPwned, Snusbase)
- Cross-breach correlation and pattern analysis
- Credential intelligence extraction
- Continuous breach monitoring with automated alerts
- Password security analysis and risk assessment
- Attack surface mapping and pivot point identification

## Complete File Structure

```
breach-correlation/
├── Core Modules (7 files)
│   ├── breach_search.py              (29.7 KB) - Main search engine
│   ├── dehashed_integration.py       (16.3 KB) - DeHashed API (11B+ records)
│   ├── hibp_integration.py           (16.1 KB) - HaveIBeenPwned API
│   ├── snusbase_integration.py       (17.9 KB) - Snusbase API
│   ├── breach_correlator.py          (21.0 KB) - Cross-breach correlation
│   ├── credential_analyzer.py        (22.4 KB) - Credential intelligence
│   └── breach_monitor.py             (21.4 KB) - Continuous monitoring
│
├── Package Files
│   └── __init__.py                   (1.1 KB)  - Package initialization
│
├── Documentation (3 files)
│   ├── README_BREACH_CORRELATION.md  (21.2 KB) - Complete documentation
│   ├── QUICKSTART.md                 (8.9 KB)  - Quick start guide
│   └── SYSTEM_OVERVIEW.md            (THIS FILE) - System overview
│
├── Configuration & Examples
│   ├── breach_config_template.json   (1.3 KB)  - API configuration template
│   ├── example_usage.py              (15.1 KB) - 9 comprehensive examples
│   ├── test_installation.py          (9.8 KB)  - Installation test suite
│   └── requirements.txt              (288 B)   - Python dependencies
│
└── Total: 15 files, ~200 KB of production code
```

## Core Modules Breakdown

### 1. breach_search.py (Main Search Engine)
**Lines:** ~900 | **Functions:** 25+ | **Classes:** 4

**Purpose:** Central orchestrator for all breach database searches

**Key Features:**
- Unified search interface across all databases
- Concurrent multi-source searching with asyncio
- Automatic result correlation and aggregation
- Built-in caching system
- Export to JSON/CSV/HTML formats
- Search types: email, username, password, phone, IP, domain, hash

**Main Classes:**
- `BreachSearch` - Main search engine
- `SearchResults` - Aggregated results container
- `BreachRecord` - Individual breach record
- `SearchType` - Search type enumeration

**Example:**
```python
searcher = BreachSearch(config_file='breach_config.json')
results = await searcher.search_email("target@example.com")
# Returns: 11B+ records from multiple sources
```

### 2. dehashed_integration.py (DeHashed API)
**Lines:** ~650 | **Database Size:** 11 Billion+ records

**Purpose:** Access DeHashed's comprehensive breach database

**Key Features:**
- Search by: email, username, password, phone, IP, name, address, VIN
- Advanced multi-field queries
- Hash type identification (MD5, SHA1, SHA256, bcrypt, etc.)
- Bulk search capabilities
- Date parsing and breach timeline

**API Endpoints:**
- Email search
- Username search
- Password search
- Phone search
- IP address search
- Name search
- Advanced combined search

**Example:**
```python
dehashed = DeHashedIntegration(email="user@example.com", api_key="key")
results = await dehashed.search_email("target@example.com")
# Returns: All breaches containing this email from 11B+ records
```

### 3. hibp_integration.py (HaveIBeenPwned)
**Lines:** ~600 | **Database:** 13+ Billion accounts

**Purpose:** Check accounts against Troy Hunt's verified breach database

**Key Features:**
- Email breach checking
- Paste monitoring
- Password compromise checking (k-anonymity - secure)
- Domain breach search
- Risk scoring algorithm (0-100)
- Breach statistics and analytics

**Security:**
- Uses k-anonymity for password checking (only sends first 5 chars of hash)
- Never sends full passwords over network
- Respects rate limits (1.5s between requests)

**Example:**
```python
hibp = HaveIBeenPwnedIntegration(api_key="key")
breaches = await hibp.check_email_breaches("target@example.com")
count = await hibp.check_password("password123")  # Secure k-anonymity
# Returns: Breach count without exposing password
```

### 4. snusbase_integration.py (Snusbase)
**Lines:** ~650 | **Special Feature:** Hash cracking

**Purpose:** Access Snusbase breach database with hash lookup

**Key Features:**
- Multi-type searches (email, username, password, hash, IP, name)
- Password hash cracking/lookup
- Wildcard searches (*@domain.com)
- Username enumeration (find all associated data)
- Combo list validation
- Bulk operations

**Unique Capabilities:**
- Crack password hashes (MD5, SHA1, etc.)
- Reverse hash lookup
- Find plaintext from hashes

**Example:**
```python
snusbase = SnusbaseIntegration(api_key="key")
# Crack password hashes
cracked = await snusbase.hash_lookup([
    '5f4dcc3b5aa765d61d8327deb882cf99'  # MD5 hash
])
# Returns: {'5f4dcc3b5aa765d61d8327deb882cf99': 'password'}
```

### 5. breach_correlator.py (Cross-Breach Correlation)
**Lines:** ~700 | **Algorithm:** Graph-based analysis using NetworkX

**Purpose:** Correlate data across multiple breach databases

**Key Features:**
- Password reuse detection across breaches
- Related account discovery
- Credential clustering via graph analysis
- Temporal pattern analysis
- Attack surface mapping
- Pivot point identification

**Analysis Types:**
- Password reuse patterns
- Account relationships
- Identity clustering
- Common password identification
- Username pattern analysis
- Breach timeline reconstruction

**Graph Analysis:**
- Nodes: Emails, usernames, passwords, IPs
- Edges: Relationships from breach records
- Algorithms: Connected components, centrality, clusters

**Example:**
```python
correlator = BreachCorrelator()
results = correlator.correlate_records(all_records)
# Returns: Password reuse, related accounts, credential clusters
```

### 6. credential_analyzer.py (Credential Intelligence)
**Lines:** ~800 | **Patterns:** 20+ detection patterns

**Purpose:** Analyze credentials for patterns, security, and intelligence

**Key Features:**
- Password strength analysis (5 levels)
- Pattern detection (years, keyboard walks, sequential chars)
- Personal information extraction
- Security question identification
- Entropy calculation
- Crack time estimation
- Security recommendations

**Analysis Capabilities:**
- Password composition (uppercase, lowercase, digits, special)
- Length statistics
- Entropy calculation (log2 of character space)
- Crackability assessment (instant to years)
- Pattern recognition (20+ patterns)
- Base word extraction
- Numbering pattern detection

**Patterns Detected:**
- Years (1900-2099)
- Sequential characters (123, abc)
- Keyboard walks (qwerty, asdfgh)
- Repeated characters (aaa, 111)
- Phone numbers
- Dates
- Email addresses in passwords

**Example:**
```python
analyzer = CredentialAnalyzer()
analysis = analyzer.analyze_credentials(records)
# Returns: Strength, patterns, personal info, recommendations
```

### 7. breach_monitor.py (Continuous Monitoring)
**Lines:** ~700 | **Type:** Async continuous monitoring

**Purpose:** Monitor targets for new breaches with automated alerts

**Key Features:**
- Continuous breach monitoring
- Email/webhook notifications
- Customizable check intervals
- Alert severity classification (low/medium/high/critical)
- Historical alert tracking
- Target watchlists
- Custom notification callbacks

**Alert Types:**
- new_breach: New breach discovered
- password_exposed: Password found in breach
- paste_found: Email found in paste

**Notification Methods:**
- Email (SMTP)
- Webhooks (HTTP POST)
- Custom callbacks (Python functions)

**Example:**
```python
monitor = BreachMonitor(breach_search, notification_config)
monitor.add_email_watchlist(['ceo@company.com'], check_interval=3600)
await monitor.start_monitoring()  # Runs continuously
```

## API Integrations

### DeHashed
- **Access:** 11 Billion+ records
- **Cost:** ~$0.0006 per record searched
- **Rate Limit:** 1 request/second
- **Fields:** email, username, password, hash, phone, IP, name, address, VIN
- **Website:** https://dehashed.com

### HaveIBeenPwned (HIBP)
- **Access:** 13+ Billion accounts
- **Cost:** $3.50/month
- **Rate Limit:** 1.5 seconds between requests
- **Fields:** email, domain, password (k-anonymity)
- **Security:** Password checking uses k-anonymity
- **Website:** https://haveibeenpwned.com

### Snusbase
- **Access:** Multiple breach databases
- **Cost:** Subscription-based
- **Rate Limit:** 1 request/second
- **Features:** Hash cracking, combo checking, wildcard search
- **Website:** https://snusbase.com

## Key Algorithms & Technologies

### 1. Password Entropy Calculation
```
Entropy = length × log2(character_space)
- Lowercase only: 26 chars → log2(26) ≈ 4.7 bits per char
- + Uppercase: 52 chars → log2(52) ≈ 5.7 bits per char
- + Digits: 62 chars → log2(62) ≈ 5.95 bits per char
- + Special: 94 chars → log2(94) ≈ 6.55 bits per char

Example: "Password1!"
- Length: 10
- Char space: 62 (lower+upper+digit)
- Entropy: 10 × 5.95 ≈ 59.5 bits
```

### 2. Risk Scoring Algorithm
```python
risk_score = (
    min(breach_count × 5, 40) +           # More breaches = higher risk
    min(verified_breaches × 3, 15) +       # Verified breaches count more
    min(sensitive_breaches × 5, 20) +      # Sensitive data exposure
    min(paste_count × 2, 10) +             # Paste appearances
    critical_data_classes × 5              # Critical data types
)
# Normalized to 0-100 scale
```

### 3. Graph-Based Correlation
```
Uses NetworkX for identity graph construction:
- Nodes: Entities (emails, usernames, passwords, IPs)
- Edges: Co-occurrence in breach records
- Analysis: Connected components → credential clusters
- Metrics: Node centrality, edge weight, cluster density
```

### 4. k-Anonymity Password Checking
```
Secure password checking without revealing password:
1. Hash password: SHA1("password") → 5baa61e4c9b93f...
2. Send only prefix: "5baa6" (first 5 chars)
3. Server returns all hashes starting with "5baa6"
4. Client checks for exact match locally
Result: Password checked securely without transmission
```

## Usage Examples

### Basic Email Search
```python
searcher = BreachSearch(config_file='breach_config.json')
results = await searcher.search_email("target@example.com")
print(f"Found {results.total_records} records from {len(results.sources)} sources")
```

### Multi-Source Correlation
```python
results = await searcher.search_email("target@example.com", correlate=True)
print(f"Password reuse: {results.correlations['password_reuse']['reuse_percentage']:.1f}%")
print(f"Related accounts: {results.correlations['related_accounts']}")
```

### Password Security Check
```python
results = await searcher.search_password("MyPassword123")
if results.total_records > 0:
    print(f"WARNING: Password compromised! Seen {results.total_records} times")
```

### Continuous Monitoring
```python
monitor = BreachMonitor(searcher, notification_config)
monitor.add_email_watchlist(['ceo@company.com'], check_interval=3600)
await monitor.start_monitoring()  # Runs continuously
```

### Hash Cracking
```python
snusbase = SnusbaseIntegration(api_key="key")
cracked = await snusbase.hash_lookup(['5f4dcc3b5aa765d61d8327deb882cf99'])
print(f"Cracked: {cracked}")  # {'5f4dcc...': 'password'}
```

## Installation & Setup

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Configure API Keys
```bash
cp breach_config_template.json breach_config.json
# Edit breach_config.json with your API keys
```

### 3. Test Installation
```bash
python test_installation.py
```

### 4. Run Examples
```bash
python example_usage.py
```

## Security Features

1. **API Key Protection:** Never commits keys to version control
2. **k-Anonymity:** Secure password checking without transmission
3. **Rate Limiting:** Respects API rate limits automatically
4. **Data Encryption:** Supports encrypted storage
5. **Minimal Logging:** Avoids logging sensitive data
6. **Hash Support:** Can work with hashes instead of plaintext

## Performance Optimizations

- **Async I/O:** All network operations are asynchronous
- **Concurrent Searches:** Multiple sources searched simultaneously
- **Caching:** Built-in result caching
- **Rate Limiting:** Automatic compliance with API limits
- **Batch Processing:** Bulk operations for efficiency

## Export Formats

- **JSON:** Machine-readable, complete data
- **CSV:** Spreadsheet-compatible, tabular data
- **HTML:** Human-readable reports with styling

## Use Cases

1. **Security Audits:** Check if company accounts are breached
2. **Incident Response:** Investigate breach exposure
3. **Password Audits:** Assess password security
4. **Threat Intelligence:** Monitor for new breaches
5. **Penetration Testing:** Gather OSINT on targets
6. **Compliance:** Demonstrate breach monitoring

## Legal & Ethical Considerations

- Only use for authorized security research and testing
- Comply with all applicable laws and regulations
- Respect API terms of service
- Obtain proper authorization before testing
- Handle personal data according to privacy laws (GDPR, CCPA)
- Do not use for malicious purposes

## Technical Requirements

- **Python:** 3.7+
- **Dependencies:** aiohttp, networkx
- **Platform:** Cross-platform (Windows, Linux, macOS)
- **Memory:** Minimum 512MB RAM (4GB+ recommended for large datasets)
- **Network:** Internet connection for API access

## Statistics & Metrics

- **Total Code:** ~200 KB
- **Python Modules:** 10 files
- **Functions:** 150+ functions
- **Classes:** 15+ classes
- **Lines of Code:** ~5,000 lines
- **Documentation:** ~50 KB
- **Test Coverage:** Installation test suite included
- **Examples:** 9 comprehensive usage examples

## Quick Reference

### Search Methods
```python
search_email(email)           # Search by email
search_username(username)     # Search by username
search_password(password)     # Check password compromise
search_phone(phone)           # Search by phone
search_ip(ip_address)         # Search by IP
search_domain(domain)         # Search domain breaches
search_hash(hash)             # Crack password hash
multi_search(**kwargs)        # Multi-identifier search
```

### Analysis Methods
```python
correlate_records(records)    # Cross-breach correlation
analyze_credentials(records)  # Credential analysis
calculate_strength(password)  # Password strength
calculate_entropy(password)   # Password entropy
find_pivot_points(records)    # Find investigation pivots
```

### Monitoring Methods
```python
add_target(type, value)       # Add monitoring target
add_email_watchlist(emails)   # Monitor email list
add_domain_watchlist(domains) # Monitor domains
start_monitoring()            # Begin continuous monitoring
get_alerts(filters)           # Retrieve alerts
export_alerts(file)           # Export alert history
```

## Support & Resources

- **Full Documentation:** README_BREACH_CORRELATION.md
- **Quick Start:** QUICKSTART.md
- **Examples:** example_usage.py
- **Tests:** test_installation.py
- **DeHashed Docs:** https://dehashed.com/docs
- **HIBP API Docs:** https://haveibeenpwned.com/API/v3
- **Snusbase Docs:** https://snusbase.com/api

## Version Information

- **Version:** 1.0.0
- **Release Date:** 2026-01-14
- **Status:** Production-ready
- **Agent:** Agent 6 - Breach Database Integration
- **Framework:** Apollo Intelligence Framework

## Deliverables Summary

✓ **breach_search.py** - Main breach search engine with multi-source integration
✓ **dehashed_integration.py** - DeHashed API (11B+ records)
✓ **hibp_integration.py** - HaveIBeenPwned API with k-anonymity
✓ **snusbase_integration.py** - Snusbase API with hash cracking
✓ **breach_correlator.py** - Cross-breach correlation engine
✓ **credential_analyzer.py** - Credential intelligence analyzer
✓ **breach_monitor.py** - Continuous monitoring with alerts
✓ **README_BREACH_CORRELATION.md** - Complete documentation
✓ **QUICKSTART.md** - Quick start guide
✓ **example_usage.py** - 9 comprehensive examples
✓ **test_installation.py** - Installation test suite
✓ **breach_config_template.json** - Configuration template

## Mission Status: COMPLETE

All deliverables successfully built and deployed to:
`C:\SECURE_THREAT_INTEL\YoureGunnaHAveToShootMeToStopME\apollo\intelligence\osint-tools\breach-correlation\`

---

**Apollo Intelligence Framework - Breach Correlation Module v1.0.0**
**Agent 6: Breach Database Integration - Mission Accomplished**
