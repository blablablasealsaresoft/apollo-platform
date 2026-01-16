# Breach Database Integration & Correlation System

Comprehensive breach database search and correlation system integrating multiple breach databases including DeHashed (11B+ records), HaveIBeenPwned, Snusbase, and IntelX.

## Overview

This system provides:
- Multi-source breach database searching
- Cross-breach correlation and pattern analysis
- Credential intelligence extraction
- Continuous breach monitoring with alerts
- Password security analysis
- Attack surface mapping

## Components

### 1. breach_search.py - Main Search Engine

Central orchestrator for all breach database searches with multi-source correlation.

**Features:**
- Unified search interface across all breach databases
- Concurrent multi-source searching
- Automatic result correlation
- Credential analysis
- Result caching
- Export to JSON/CSV/HTML

**Usage:**
```python
from breach_search import BreachSearch

# Initialize with API keys
searcher = BreachSearch(
    dehashed_email="your-email@example.com",
    dehashed_api_key="your-dehashed-key",
    hibp_api_key="your-hibp-key",
    snusbase_api_key="your-snusbase-key"
)

# Search for email
results = await searcher.search_email("target@example.com")

print(f"Found {results.total_records} records")
print(f"Sources: {results.sources}")
print(f"Correlation strength: {results.correlations['correlation_strength']}")

# Search multiple identifiers
multi_results = await searcher.multi_search(
    email="target@example.com",
    username="target_user",
    phone="+1234567890"
)

# Export results
searcher.export_results(results, 'breach_report.html', format='html')
```

**Search Types:**
- Email addresses
- Usernames
- Passwords
- Phone numbers
- IP addresses
- Domains
- Password hashes

### 2. dehashed_integration.py - DeHashed API (11B+ Records)

Access to DeHashed's comprehensive breach database with 11 billion+ records.

**Features:**
- Email/username/password/phone/IP/name search
- Advanced multi-field queries
- Hash type identification
- Bulk search capabilities
- VIN and address search

**Usage:**
```python
from dehashed_integration import DeHashedIntegration

dehashed = DeHashedIntegration(
    email="your-email@example.com",
    api_key="your-api-key"
)

# Email search
results = await dehashed.search_email("target@example.com")

for record in results:
    print(f"Database: {record['database_name']}")
    print(f"Email: {record['email']}")
    print(f"Username: {record['username']}")
    print(f"Password: {record['password']}")
    print(f"Hash: {record['hashed_password']}")

# Advanced search with multiple criteria
results = await dehashed.advanced_search(
    email="target@example.com",
    username="target_user",
    database="LinkedIn"
)

# Bulk search
queries = [
    {'type': 'email', 'value': 'user1@example.com'},
    {'type': 'username', 'value': 'user2'},
    {'type': 'phone', 'value': '+1234567890'}
]
bulk_results = await dehashed.bulk_search(queries)
```

**Searchable Fields:**
- email
- username
- password
- hashed_password
- phone
- ip_address
- name
- address
- vin

### 3. hibp_integration.py - HaveIBeenPwned

Check accounts against Troy Hunt's HaveIBeenPwned breach database.

**Features:**
- Email breach checking
- Paste monitoring
- Password compromise checking (k-anonymity)
- Domain breach search
- Risk scoring
- Breach statistics

**Usage:**
```python
from hibp_integration import HaveIBeenPwnedIntegration

hibp = HaveIBeenPwnedIntegration(api_key="your-api-key")

# Check email breaches
breaches = await hibp.check_email_breaches("target@example.com")

for breach in breaches:
    print(f"Breach: {breach['Name']}")
    print(f"Date: {breach['BreachDate']}")
    print(f"Compromised: {breach['PwnCount']:,} accounts")
    print(f"Data: {', '.join(breach['DataClasses'])}")

# Check password (uses k-anonymity - secure)
password = "MyPassword123"
count = await hibp.check_password(password)
print(f"Password seen {count:,} times in breaches")

# Get comprehensive summary
summary = await hibp.get_breach_summary("target@example.com")
print(f"Risk Score: {summary['risk_score']}/100")
print(f"Total Breaches: {summary['total_breaches']}")
print(f"Sensitive Breaches: {summary['sensitive_breaches']}")
```

**Risk Scoring:**
- Factors: breach count, verified breaches, sensitive breaches, data classes
- Score: 0-100 (higher = more at risk)
- Automated severity classification

### 4. snusbase_integration.py - Snusbase

Access Snusbase breach database with hash lookup and combo checking.

**Features:**
- Multi-type searches (email, username, password, hash, IP, name)
- Password hash cracking
- Wildcard searches
- Username enumeration
- Combo list validation
- Bulk operations

**Usage:**
```python
from snusbase_integration import SnusbaseIntegration

snusbase = SnusbaseIntegration(api_key="your-api-key")

# Email search
results = await snusbase.search_email("target@example.com")

# Hash lookup (crack password hashes)
hashes = [
    '5f4dcc3b5aa765d61d8327deb882cf99',  # password
    '482c811da5d5b4bc6d497ffa98491e38'   # password123
]
cracked = await snusbase.hash_lookup(hashes)
print(f"Cracked passwords: {cracked}")

# Enumerate username (find all associated data)
enum_results = await snusbase.enumerate_username("target_user")
print(f"Associated emails: {enum_results['emails']}")
print(f"Passwords used: {enum_results['passwords']}")
print(f"IP addresses: {enum_results['ip_addresses']}")

# Wildcard search
wildcard_results = await snusbase.wildcard_search(
    pattern="*@company.com",
    search_type="email"
)

# Combo list checking
combos = [
    ("user1@example.com", "password123"),
    ("user2@example.com", "qwerty789")
]
valid_combos = await snusbase.combo_list_check(combos)
```

### 5. breach_correlator.py - Cross-Breach Correlation

Correlate data across multiple breach databases to find patterns and relationships.

**Features:**
- Password reuse detection
- Related account discovery
- Credential clustering
- Temporal pattern analysis
- Attack surface mapping
- Pivot point identification

**Usage:**
```python
from breach_correlator import BreachCorrelator

correlator = BreachCorrelator()

# Correlate breach records
correlation_results = correlator.correlate_records(all_records)

# Password reuse analysis
print(f"Password reuse: {correlation_results['password_reuse']}")
print(f"Reused passwords: {correlation_results['password_reuse']['reused_passwords']}")

# Find related accounts
print(f"Related accounts: {correlation_results['related_accounts']}")

# Credential clusters
for cluster in correlation_results['credential_clusters']:
    print(f"Cluster: {len(cluster['emails'])} emails, {len(cluster['passwords'])} passwords")

# Temporal patterns
temporal = correlation_results['temporal_patterns']
print(f"Earliest breach: {temporal['earliest_breach']}")
print(f"Latest breach: {temporal['latest_breach']}")
print(f"Active period: {temporal['active_period_days']} days")

# Attack surface
attack_surface = correlation_results['attack_surface']
print(f"Entry points: {attack_surface['recon_data']['total_entry_points']}")
print(f"Credential pairs: {attack_surface['credential_pairs_count']}")

# Find pivot points for further investigation
pivots = correlator.find_pivot_points(all_records)
print(f"High-value emails: {pivots['emails']}")
print(f"High-value usernames: {pivots['usernames']}")
```

**Correlation Analysis:**
- Password reuse patterns
- Account relationships
- Identity clustering via graph analysis
- Common password identification
- Username pattern analysis
- Breach timeline reconstruction

### 6. credential_analyzer.py - Credential Intelligence

Analyze credentials for patterns, security weaknesses, and personal information.

**Features:**
- Password strength analysis
- Pattern detection (years, keyboard walks, sequential)
- Personal information extraction
- Security question identification
- Entropy calculation
- Crack time estimation

**Usage:**
```python
from credential_analyzer import CredentialAnalyzer

analyzer = CredentialAnalyzer()

# Comprehensive analysis
analysis = analyzer.analyze_credentials(records)

# Password analysis
pwd_analysis = analysis['password_analysis']
print(f"Average length: {pwd_analysis['length_stats']['average']}")
print(f"Average entropy: {pwd_analysis['average_entropy']}")
print(f"Common passwords: {pwd_analysis['common_percentage']}%")

# Pattern analysis
patterns = analysis['pattern_analysis']
print(f"Years found: {patterns['years_found']}")
print(f"Base words: {patterns['base_words']}")
print(f"Numbering patterns: {patterns['numbering_patterns']}")

# Security analysis
security = analysis['security_analysis']
print(f"Strength distribution: {security['strength_distribution']}")
print(f"Crackability: {security['crackability']}")

# Personal information extraction
personal = analysis['personal_info']
print(f"Names found: {personal['names']}")
print(f"Years: {personal['years']}")
print(f"Phone numbers: {personal['phone_numbers']}")
print(f"Security answers: {personal['security_answers']}")

# Recommendations
for recommendation in analysis['recommendations']:
    print(f"- {recommendation}")
```

**Analysis Capabilities:**
- Password strength classification (5 levels)
- Entropy calculation
- Crack time estimation
- Pattern recognition (20+ patterns)
- Personal data extraction
- Security recommendations

### 7. breach_monitor.py - Continuous Monitoring

Monitor targets for new breaches with automated alerts and notifications.

**Features:**
- Continuous breach monitoring
- Email/webhook notifications
- Customizable check intervals
- Alert severity classification
- Historical alert tracking
- Target watchlists

**Usage:**
```python
from breach_monitor import BreachMonitor
from breach_search import BreachSearch

# Initialize
breach_search = BreachSearch(config_file='breach_config.json')

# Configure notifications
notification_config = {
    'email_enabled': True,
    'from_email': 'alerts@example.com',
    'to_email': 'security@example.com',
    'smtp_host': 'smtp.gmail.com',
    'smtp_port': 587,
    'smtp_username': 'your-email@gmail.com',
    'smtp_password': 'your-password',
    'webhook_url': 'https://your-webhook.com/alerts'
}

monitor = BreachMonitor(
    breach_search=breach_search,
    notification_config=notification_config
)

# Add monitoring targets
monitor.add_email_watchlist([
    'ceo@company.com',
    'admin@company.com',
    'security@company.com'
], check_interval=3600)  # Check every hour

monitor.add_domain_watchlist([
    'company.com',
    'subsidiary.com'
], check_interval=7200)  # Check every 2 hours

# Register custom alert handler
async def custom_handler(alert):
    print(f"ALERT: {alert.message}")
    # Send to SIEM, Slack, etc.

monitor.register_notification_callback(custom_handler)

# Start monitoring (runs continuously)
await monitor.start_monitoring()

# Get statistics
stats = monitor.get_statistics()
print(f"Active targets: {stats['enabled_targets']}")
print(f"Total alerts: {stats['total_alerts']}")
print(f"Critical alerts: {stats['alerts_by_severity']['critical']}")

# Get recent alerts
recent_alerts = monitor.get_alerts(days=7, severity='critical')

# Export alerts
monitor.export_alerts('breach_alerts.json', format='json')
```

**Alert Types:**
- new_breach: New breach discovered
- password_exposed: Password found in breach
- paste_found: Email found in paste

**Severity Levels:**
- low: Minor findings
- medium: Moderate concern
- high: Significant breach
- critical: Sensitive data exposed

## Configuration

### API Keys Configuration File

Create `breach_config.json`:

```json
{
  "dehashed_email": "your-email@example.com",
  "dehashed_api_key": "your-dehashed-api-key",
  "hibp_api_key": "your-hibp-api-key",
  "snusbase_api_key": "your-snusbase-api-key",
  "intelx_api_key": "your-intelx-api-key",
  "leakcheck_api_key": "your-leakcheck-api-key"
}
```

### Obtaining API Keys

**DeHashed:**
- Website: https://dehashed.com
- Pricing: $0.0006 per record searched
- Features: 11B+ records, comprehensive search

**HaveIBeenPwned:**
- Website: https://haveibeenpwned.com/API/Key
- Pricing: $3.50/month
- Features: Verified breach data, password checking

**Snusbase:**
- Website: https://snusbase.com
- Pricing: Subscription-based
- Features: Hash cracking, combo checking

## Integration Examples

### Example 1: Complete Target Investigation

```python
import asyncio
from breach_search import BreachSearch

async def investigate_target(email):
    searcher = BreachSearch(config_file='breach_config.json')

    # Search all databases
    results = await searcher.search_email(email, correlate=True)

    print(f"\n=== Breach Investigation: {email} ===\n")
    print(f"Total Records Found: {results.total_records}")
    print(f"Sources: {', '.join(results.sources)}")
    print(f"Correlation Strength: {results.correlations['correlation_strength']:.2%}")

    # Password reuse
    pwd_reuse = results.correlations['password_reuse']
    print(f"\nPassword Reuse:")
    print(f"  Unique passwords: {pwd_reuse['total_unique_passwords']}")
    print(f"  Reused: {pwd_reuse['reused_passwords']} ({pwd_reuse['reuse_percentage']:.1f}%)")

    # Related accounts
    related = results.correlations['related_accounts']
    print(f"\nRelated Accounts:")
    print(f"  Total emails: {related['total_unique_emails']}")
    print(f"  Total usernames: {related['total_unique_usernames']}")

    # Credential analysis
    creds = results.credential_analysis
    print(f"\nCredential Analysis:")
    print(f"  Average password strength: {creds['security_analysis']['average_score']:.1f}/100")
    print(f"  Common passwords: {creds['password_analysis']['common_percentage']:.1f}%")

    # Export comprehensive report
    searcher.export_results(results, f'{email}_breach_report.html', format='html')

    return results

# Run investigation
asyncio.run(investigate_target("target@example.com"))
```

### Example 2: Domain-Wide Breach Assessment

```python
async def assess_domain(domain):
    searcher = BreachSearch(config_file='breach_config.json')

    # Search for domain breaches
    results = await searcher.search_domain(domain)

    print(f"\n=== Domain Assessment: {domain} ===\n")
    print(f"Breached Services: {results.total_records}")

    # Analyze exposed data types
    data_types = set()
    for record in results.records:
        data_types.update(record.additional_data.get('data_classes', []))

    print(f"\nExposed Data Types:")
    for data_type in sorted(data_types):
        print(f"  - {data_type}")

    # High-value targets (employees in multiple breaches)
    email_counts = {}
    for record in results.records:
        if record.email:
            email_counts[record.email] = email_counts.get(record.email, 0) + 1

    high_value = {k: v for k, v in email_counts.items() if v > 2}
    print(f"\nHigh-Risk Accounts (3+ breaches): {len(high_value)}")

    return results
```

### Example 3: Password Security Audit

```python
async def audit_passwords(records):
    from credential_analyzer import CredentialAnalyzer

    analyzer = CredentialAnalyzer()
    analysis = analyzer.analyze_credentials(records)

    print("\n=== Password Security Audit ===\n")

    # Strength distribution
    print("Strength Distribution:")
    for level, count in analysis['security_analysis']['strength_distribution'].items():
        pct = analysis['security_analysis']['strength_percentages'][level]
        print(f"  {level}: {count} ({pct:.1f}%)")

    # Crackability
    print("\nCrackability:")
    for level, count in analysis['security_analysis']['crackability'].items():
        pct = analysis['security_analysis']['crackability_percentages'][level]
        print(f"  {level}: {count} ({pct:.1f}%)")

    # Recommendations
    print("\nRecommendations:")
    for rec in analysis['recommendations']:
        print(f"  - {rec}")

    return analysis
```

### Example 4: Continuous Monitoring Setup

```python
async def setup_monitoring():
    from breach_monitor import BreachMonitor
    from breach_search import BreachSearch

    # Initialize
    searcher = BreachSearch(config_file='breach_config.json')

    notification_config = {
        'email_enabled': True,
        'from_email': 'alerts@company.com',
        'to_email': 'security-team@company.com',
        'smtp_host': 'smtp.company.com',
        'smtp_port': 587
    }

    monitor = BreachMonitor(searcher, notification_config=notification_config)

    # Add executive team
    executives = [
        'ceo@company.com',
        'cfo@company.com',
        'cto@company.com'
    ]
    monitor.add_email_watchlist(executives, check_interval=1800)  # 30 min

    # Add domain
    monitor.add_domain_watchlist(['company.com'], check_interval=3600)  # 1 hour

    # Custom alert handler
    async def security_team_alert(alert):
        if alert.severity in ['critical', 'high']:
            # Send to Slack, SIEM, etc.
            print(f"CRITICAL ALERT: {alert.message}")

    monitor.register_notification_callback(security_team_alert)

    # Start monitoring
    await monitor.start_monitoring()
```

## Best Practices

### 1. Rate Limiting
All integrations implement rate limiting to comply with API terms:
- DeHashed: 1 request/second
- HIBP: 1.5 seconds between requests
- Snusbase: 1 request/second

### 2. Caching
Use built-in caching to reduce API calls:
```python
# Results are automatically cached
results1 = await searcher.search_email("test@example.com")
results2 = await searcher.search_email("test@example.com")  # From cache
```

### 3. Error Handling
Always handle API errors gracefully:
```python
try:
    results = await searcher.search_email(email)
except ValueError as e:
    print(f"Invalid input: {e}")
except Exception as e:
    print(f"API error: {e}")
```

### 4. Concurrent Searches
Use multi-search for efficiency:
```python
# Instead of sequential searches
results = await searcher.multi_search(
    email="target@example.com",
    username="target_user",
    phone="+1234567890"
)
```

### 5. Data Privacy
Handle sensitive data responsibly:
- Never log full passwords
- Use password hashing when possible
- Secure API key storage
- Encrypt stored results

## Output Formats

### JSON Export
```python
searcher.export_results(results, 'output.json', format='json')
```

### CSV Export
```python
searcher.export_results(results, 'output.csv', format='csv')
```

### HTML Report
```python
searcher.export_results(results, 'output.html', format='html')
```

## Advanced Features

### Graph-Based Correlation
The correlator uses NetworkX to build relationship graphs:
- Nodes: Emails, usernames, passwords, IPs
- Edges: Relationships from same breach record
- Analysis: Connected components, centrality, clusters

### Password Entropy Calculation
```
Entropy = length × log2(character_space)
- Lowercase only: 26 characters
- + Uppercase: 52 characters
- + Digits: 62 characters
- + Special: 94 characters
```

### Risk Scoring Algorithm
```python
risk_score = (
    min(breach_count * 5, 40) +
    min(verified_breaches * 3, 15) +
    min(sensitive_breaches * 5, 20) +
    min(paste_count * 2, 10) +
    critical_data_classes * 5
)
# Normalized to 0-100
```

## Troubleshooting

### API Authentication Errors
```
Error: Invalid credentials
Solution: Verify API keys in config file
```

### Rate Limit Exceeded
```
Error: Rate limit exceeded
Solution: Increase delay between requests or use caching
```

### No Results Found
```
Issue: Search returns empty results
Solution: Try different search terms, check API quotas
```

## Performance Optimization

### Batch Processing
```python
# Process multiple targets efficiently
targets = ['user1@example.com', 'user2@example.com', 'user3@example.com']

async def process_batch(targets):
    tasks = [searcher.search_email(t) for t in targets]
    results = await asyncio.gather(*tasks)
    return results
```

### Selective Correlation
```python
# Skip correlation for simple searches
results = await searcher.search_email(email, correlate=False)
```

## Security Considerations

1. **API Key Protection**: Never commit API keys to version control
2. **Data Retention**: Clear sensitive data after analysis
3. **Access Control**: Restrict access to breach data
4. **Logging**: Minimize logging of sensitive information
5. **Encryption**: Encrypt stored credentials and results

## Legal and Ethical Considerations

- Only use for authorized security research and testing
- Comply with all applicable laws and regulations
- Respect API terms of service
- Obtain proper authorization before testing
- Handle personal data according to privacy laws (GDPR, CCPA, etc.)

## Dependencies

```
aiohttp>=3.8.0
networkx>=2.8.0
```

## License

This tool is for authorized security research and testing only.

## Support

For issues or questions:
1. Check API provider documentation
2. Review error logs
3. Verify API credentials
4. Check rate limits and quotas

## Version History

- v1.0.0 - Initial release with all integrations
  - DeHashed integration (11B+ records)
  - HaveIBeenPwned integration
  - Snusbase integration
  - Cross-breach correlation
  - Credential analysis
  - Continuous monitoring
  - Multi-format export

---

**Apollo Intelligence Framework - Breach Correlation Module**
