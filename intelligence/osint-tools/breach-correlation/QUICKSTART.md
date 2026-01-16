# Breach Correlation System - Quick Start Guide

Get up and running with the breach correlation system in 5 minutes.

## Step 1: Install Dependencies

```bash
pip install -r requirements.txt
```

Required packages:
- `aiohttp` - Async HTTP requests
- `networkx` - Graph-based correlation

## Step 2: Configure API Keys

1. Copy the configuration template:
```bash
cp breach_config_template.json breach_config.json
```

2. Edit `breach_config.json` and add your API keys:
```json
{
  "dehashed_email": "your-email@example.com",
  "dehashed_api_key": "your-dehashed-key",
  "hibp_api_key": "your-hibp-key",
  "snusbase_api_key": "your-snusbase-key"
}
```

### Where to Get API Keys

**DeHashed** (Recommended - 11B+ records)
- Website: https://dehashed.com
- Sign up and get API credentials
- Cost: ~$0.0006 per record searched

**HaveIBeenPwned** (Recommended - Verified breaches)
- Website: https://haveibeenpwned.com/API/Key
- Purchase API key
- Cost: $3.50/month

**Snusbase** (Optional - Hash cracking)
- Website: https://snusbase.com
- Sign up for subscription
- Cost: Varies

## Step 3: Basic Usage

### Search for Email

```python
import asyncio
from breach_search import BreachSearch

async def search():
    # Initialize
    searcher = BreachSearch(config_file='breach_config.json')

    # Search
    results = await searcher.search_email("target@example.com")

    # Display results
    print(f"Found {results.total_records} records")
    for record in results.records[:5]:
        print(f"\nDatabase: {record.database}")
        print(f"Email: {record.email}")
        print(f"Password: {record.password}")

asyncio.run(search())
```

### Search Multiple Sources

```python
async def multi_search():
    searcher = BreachSearch(config_file='breach_config.json')

    results = await searcher.multi_search(
        email="target@example.com",
        username="target_user",
        phone="+1234567890"
    )

    for search_type, data in results.items():
        print(f"{search_type}: {data.total_records} records")

asyncio.run(multi_search())
```

### Check Password Compromise

```python
async def check_password():
    searcher = BreachSearch(config_file='breach_config.json')

    password = "password123"
    results = await searcher.search_password(password)

    if results.total_records > 0:
        print(f"WARNING: Password compromised!")
        print(f"Seen {results.total_records} times")
    else:
        print("Password not found in breaches")

asyncio.run(check_password())
```

## Step 4: Advanced Features

### Correlation Analysis

```python
async def correlate():
    searcher = BreachSearch(config_file='breach_config.json')

    # Enable correlation
    results = await searcher.search_email("target@example.com", correlate=True)

    # Password reuse
    reuse = results.correlations['password_reuse']
    print(f"Password reuse: {reuse['reuse_percentage']:.1f}%")

    # Attack surface
    attack = results.correlations['attack_surface']
    print(f"Entry points: {attack['entry_points']}")

asyncio.run(correlate())
```

### Continuous Monitoring

```python
from breach_monitor import BreachMonitor

async def monitor():
    searcher = BreachSearch(config_file='breach_config.json')
    monitor = BreachMonitor(searcher)

    # Add targets
    monitor.add_email_watchlist([
        'ceo@company.com',
        'admin@company.com'
    ])

    # Start monitoring
    await monitor.start_monitoring()

asyncio.run(monitor())
```

## Step 5: Export Results

### Export to HTML

```python
searcher.export_results(results, 'report.html', format='html')
```

### Export to JSON

```python
searcher.export_results(results, 'data.json', format='json')
```

### Export to CSV

```python
searcher.export_results(results, 'data.csv', format='csv')
```

## Common Use Cases

### Use Case 1: Employee Breach Check

Check if company employees have been breached:

```python
async def check_employees():
    searcher = BreachSearch(config_file='breach_config.json')

    employees = [
        'ceo@company.com',
        'cto@company.com',
        'admin@company.com'
    ]

    for email in employees:
        results = await searcher.search_email(email)
        print(f"{email}: {results.total_records} breaches")

asyncio.run(check_employees())
```

### Use Case 2: Domain Assessment

Assess all breaches for your domain:

```python
async def assess_domain():
    searcher = BreachSearch(config_file='breach_config.json')

    results = await searcher.search_domain("company.com")

    databases = set(r.database for r in results.records)
    print(f"Domain breached in {len(databases)} services")

    for db in databases:
        print(f"  - {db}")

asyncio.run(assess_domain())
```

### Use Case 3: Password Audit

Audit password security:

```python
async def audit_passwords():
    searcher = BreachSearch(config_file='breach_config.json')

    results = await searcher.search_email("target@example.com", correlate=True)

    analysis = results.credential_analysis
    security = analysis['security_analysis']

    print("Password Strength Distribution:")
    for level, count in security['strength_distribution'].items():
        pct = security['strength_percentages'][level]
        print(f"  {level}: {count} ({pct:.1f}%)")

asyncio.run(audit_passwords())
```

### Use Case 4: Real-time Monitoring

Set up automated breach monitoring:

```python
async def setup_monitoring():
    searcher = BreachSearch(config_file='breach_config.json')

    # Configure email alerts
    notification_config = {
        'email_enabled': True,
        'from_email': 'alerts@company.com',
        'to_email': 'security@company.com',
        'smtp_host': 'smtp.gmail.com',
        'smtp_port': 587,
        'smtp_username': 'your-email@gmail.com',
        'smtp_password': 'your-password'
    }

    monitor = BreachMonitor(
        breach_search=searcher,
        notification_config=notification_config
    )

    # Add VIP targets (check every 30 minutes)
    monitor.add_email_watchlist([
        'ceo@company.com',
        'cfo@company.com'
    ], check_interval=1800)

    # Add domain (check every 2 hours)
    monitor.add_domain_watchlist(['company.com'], check_interval=7200)

    # Start monitoring
    await monitor.start_monitoring()

asyncio.run(setup_monitoring())
```

## Running Examples

The system includes comprehensive examples:

```bash
python example_usage.py
```

This runs through all major features including:
- Basic searches
- Multi-source correlation
- Credential analysis
- Password checking
- Domain assessment
- Monitoring setup

## Troubleshooting

### Issue: "Invalid credentials"
**Solution:** Verify API keys in `breach_config.json`

### Issue: "Rate limit exceeded"
**Solution:** Wait between requests or reduce query frequency

### Issue: "No results found"
**Solution:**
- Try different search terms
- Verify API quotas
- Check if email/username actually has breaches

### Issue: "Module not found"
**Solution:** Install dependencies: `pip install -r requirements.txt`

## Best Practices

1. **Start with HIBP**: Free tier available, good for testing
2. **Use DeHashed for comprehensive searches**: 11B+ records
3. **Enable correlation**: Provides valuable intelligence
4. **Cache results**: Built-in caching reduces API calls
5. **Monitor continuously**: Set up automated monitoring for important targets
6. **Export reports**: Generate HTML reports for stakeholders

## Security Notes

- Never commit `breach_config.json` with API keys to version control
- Add to `.gitignore`: `breach_config.json`
- Use environment variables for production deployments
- Encrypt stored results containing sensitive data
- Only use for authorized security testing

## Next Steps

1. Read full documentation: `README_BREACH_CORRELATION.md`
2. Review API integration details in individual module files
3. Set up continuous monitoring for your organization
4. Integrate with your existing security tools

## Support Resources

- **DeHashed Docs**: https://dehashed.com/docs
- **HIBP API Docs**: https://haveibeenpwned.com/API/v3
- **Snusbase Docs**: https://snusbase.com/api

## Quick Reference

### Search Types
- `search_email(email)` - Search by email
- `search_username(username)` - Search by username
- `search_password(password)` - Check password compromise
- `search_phone(phone)` - Search by phone number
- `search_ip(ip_address)` - Search by IP address
- `search_domain(domain)` - Search domain breaches
- `search_hash(hash)` - Crack password hash

### Key Features
- **Multi-source aggregation**: All breach databases in one search
- **Correlation engine**: Find patterns across breaches
- **Credential analysis**: Analyze password security
- **Continuous monitoring**: Automated breach alerts
- **Export options**: JSON, CSV, HTML reports

---

**Get Started Now:** Copy `breach_config_template.json` to `breach_config.json`, add your API keys, and run `python example_usage.py`
