# Public Records Intelligence - Quick Reference

## Installation

```bash
cd public-records
pip install -r requirements.txt
```

## Basic Usage

```python
from public_records import PublicRecords

# Initialize
records = PublicRecords()

# Search
results = records.search(name="John Doe", state="NY")

# Print results
print(f"Found {results['summary']['total_records']} records")
```

## Common Operations

### 1. Person Investigation

```python
results = records.search(
    name="John Doe",
    dob="1980-01-01",
    state="NY",
    record_types=["court", "criminal", "property"]
)
```

### 2. Business Investigation

```python
results = records.search(
    business_name="Acme Corporation",
    state="DE",
    record_types=["business", "government"]
)
```

### 3. Property Search

```python
from property_records import PropertyRecordsSearch

prop = PropertyRecordsSearch({'attom_api_key': 'key'})
history = prop.get_property_history(
    address="123 Main St",
    city="New York",
    state="NY",
    zip_code="10001"
)
```

### 4. Criminal Background

```python
from criminal_records import CriminalRecordsSearch

crim = CriminalRecordsSearch()
background = crim.get_background_check({
    'name': 'John Doe',
    'state': 'FL',
    'dob': '1980-01-01'
})
print(f"Risk: {background['risk_assessment']}")
```

### 5. Offshore Investigation

```python
from offshore_leaks import OffshoreLeaksSearch

offshore = OffshoreLeaksSearch()
profile = offshore.get_offshore_profile('John Doe')
print(f"Entities: {profile['summary']['entities']}")
print(f"Risk: {profile['risk_assessment']}")
```

## Export Options

```python
# JSON
records.export_results(results, 'report.json', format='json')

# HTML
records.export_results(results, 'report.html', format='html')

# CSV
records.export_results(results, 'report.csv', format='csv')
```

## API Keys Required

| Service | Key Name | Required For |
|---------|----------|--------------|
| JudyRecords | `judy_records_api_key` | Court records (740M cases) |
| PACER | `pacer_username`, `pacer_password` | Federal courts |
| ATTOM | `attom_api_key` | Property records |
| OpenCorporates | `opencorporates_token` | Business records (200M+) |
| FEC | `fec_api_key` | Campaign finance |
| ProPublica | `propublica_api_key` | Congress data |

## Configuration Template

```python
config = {
    'court': {
        'judy_records_api_key': 'YOUR_KEY',
        'court_listener_token': 'YOUR_TOKEN',
        'pacer_username': 'USERNAME',
        'pacer_password': 'PASSWORD'
    },
    'property': {
        'attom_api_key': 'YOUR_KEY',
        'zillow_api_key': 'YOUR_KEY'
    },
    'business': {
        'opencorporates_token': 'YOUR_TOKEN'
    },
    'government': {
        'fec_api_key': 'YOUR_KEY',
        'propublica_api_key': 'YOUR_KEY'
    }
}

records = PublicRecords(config)
```

## Record Types

- `court` - Court cases (740M+)
- `criminal` - Criminal records, sex offenders
- `property` - Real estate ownership
- `business` - Corporate registrations (200M+)
- `government` - Contracts, campaign finance
- `offshore` - Panama Papers, Paradise Papers (810K+)

## Data Sources Overview

### Court Records
- **JudyRecords**: 740M court cases
- **CourtListener**: Federal/state opinions
- **PACER**: Federal courts
- **State Courts**: 50 state systems

### Criminal Records
- **NSOPW**: 900K+ sex offenders
- **FBI**: Most Wanted lists
- **BOP**: Federal inmates
- **State DOC**: State corrections

### Property Records
- **ATTOM**: 150M+ properties
- **Zillow**: Valuations
- **County Assessors**: Tax records
- **County Recorders**: Deeds

### Business Records
- **OpenCorporates**: 200M+ companies
- **Secretary of State**: All 50 states
- **SEC EDGAR**: Public companies
- **UCC Filings**: Secured transactions

### Government Records
- **USASpending**: Federal contracts
- **FEC**: Campaign finance
- **Senate LDA**: Lobbying
- **MuckRock**: FOIA requests

### Offshore Leaks
- **Panama Papers**: 214,488 entities
- **Paradise Papers**: 120,000+ entities
- **Pandora Papers**: 29,000+ entities
- **Total**: 810,000+ entities

## Async Usage

```python
import asyncio

async def search_multiple():
    results = await records.search_async(query)
    return results

# Run async
results = asyncio.run(search_multiple())
```

## Error Handling

```python
try:
    results = records.search(name="John Doe", state="NY")
except Exception as e:
    print(f"Search failed: {e}")
```

## Performance Tips

1. **Use specific record types**: Only search what you need
2. **Cache results**: Save to file and reuse
3. **Rate limiting**: Add delays between requests
4. **Async for bulk**: Use async for multiple searches

## Legal Notice

This tool is for legitimate purposes only:
- ✅ Due diligence, background checks, investigations
- ❌ Stalking, harassment, illegal purposes

Comply with FCRA, privacy laws, and terms of service.

## Support

- Full documentation: `README_PUBLIC_RECORDS.md`
- Examples: `example_usage.py`
- Data sources: See `__init__.py`

## Quick Test

```python
# Test without API keys (limited results)
from public_records import PublicRecords

records = PublicRecords()
results = records.search(name="John Doe", state="NY")
print(f"System working: {results['summary']['total_records']} records")
```

---

**Agent 16: Public Records Intelligence**
Version 1.0.0
