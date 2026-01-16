# Public Records Intelligence System

Comprehensive public records search system for OSINT investigations. Aggregates data from court records, criminal databases, property records, business registrations, government contracts, and offshore leaks.

## Overview

This system provides unified access to multiple public record databases:

- **Court Records**: 740M+ cases (JudyRecords, CourtListener, PACER)
- **Criminal Records**: State/federal databases, sex offender registry, inmate search
- **Property Records**: Ownership, transactions, tax assessments, mortgages
- **Business Records**: 200M+ companies (OpenCorporates, Secretary of State)
- **Government Records**: Contracts, campaign finance, lobbying, FOIA
- **Offshore Leaks**: 810K+ entities (Panama Papers, Paradise Papers, Pandora Papers)

## Components

### 1. Main Search Engine (`public_records.py`)

Orchestrates searches across all record types.

```python
from public_records import PublicRecords

# Initialize with API keys
config = {
    'court': {
        'judy_records_api_key': 'your_key',
        'pacer_username': 'username',
        'pacer_password': 'password'
    },
    'business': {
        'opencorporates_token': 'your_token'
    },
    'government': {
        'fec_api_key': 'your_key'
    }
}

records = PublicRecords(config)

# Search all record types
results = records.search(
    name="John Doe",
    state="NY",
    record_types=["court", "criminal", "property"]
)

print(f"Total records found: {results['summary']['total_records']}")
print(f"Risk indicators: {results['summary']['risk_indicators']}")

# Export results
records.export_results(results, 'report.json', format='json')
records.export_results(results, 'report.html', format='html')
```

### 2. Court Records (`court_records.py`)

Search 740 million court cases across federal and state systems.

**Data Sources:**
- **JudyRecords**: 740M court cases (civil, criminal, traffic, family)
- **CourtListener**: Federal and state court opinions
- **PACER**: Federal court system (district, bankruptcy, appellate)
- **State Courts**: Individual state court systems

```python
from court_records import CourtRecordsSearch

court_search = CourtRecordsSearch({
    'judy_records_api_key': 'your_key',
    'court_listener_token': 'your_token',
    'pacer_username': 'username',
    'pacer_password': 'password'
})

query = {
    'name': 'John Doe',
    'state': 'NY'
}

results = asyncio.run(court_search.search_async(query))

for record in results:
    print(f"Case: {record['case_number']}")
    print(f"Court: {record['court']}")
    print(f"Type: {record['case_type']}")
    print(f"Status: {record['status']}")

# Get specific case details
details = court_search.get_case_details('20-cv-12345', 'SDNY')

# Track case for updates
court_search.track_case_docket('20-cv-12345', 'SDNY')
```

**Features:**
- Civil and criminal case search
- Case docket tracking
- Court opinion search
- Federal and state integration
- Case detail extraction

### 3. Criminal Records (`criminal_records.py`)

Search criminal databases, sex offender registries, and inmate records.

**Data Sources:**
- **National Sex Offender Registry**: 900K+ registered offenders
- **FBI Most Wanted**: Ten Most Wanted, terrorists
- **US Marshals Most Wanted**: Fugitives
- **Federal Bureau of Prisons**: Inmate locator
- **State DOC**: 50 state corrections departments

```python
from criminal_records import CriminalRecordsSearch

criminal_search = CriminalRecordsSearch()

query = {
    'name': 'John Doe',
    'state': 'FL',
    'dob': '1980-01-01'
}

results = asyncio.run(criminal_search.search_async(query))

for record in results:
    print(f"Source: {record['source']}")
    print(f"Severity: {record['severity']}")
    print(f"Offenses: {record.get('offenses', [])}")

# Comprehensive background check
background = criminal_search.get_background_check(query)
print(f"Risk Assessment: {background['risk_assessment']}")
print(f"Sex Offender: {background['summary']['sex_offender']}")
print(f"Federal Custody: {background['summary']['federal_custody']}")
print(f"Most Wanted: {background['summary']['most_wanted']}")
```

**Features:**
- Sex offender registry search
- Federal inmate locator
- State DOC searches
- Most wanted lists
- Risk assessment
- Background check compilation

### 4. Property Records (`property_records.py`)

Search property ownership, transactions, and tax records.

**Data Sources:**
- **ATTOM Data**: 150M+ properties nationwide
- **Zillow**: Property valuations and history
- **County Assessors**: Tax assessments
- **County Recorders**: Deed and mortgage records
- **NYC ACRIS**: New York City property records

```python
from property_records import PropertyRecordsSearch

property_search = PropertyRecordsSearch({
    'attom_api_key': 'your_key',
    'zillow_api_key': 'your_key'
})

# Search by owner name
query = {
    'name': 'John Doe',
    'state': 'NY'
}

results = asyncio.run(property_search.search_async(query))

for record in results:
    print(f"Address: {record['address']}")
    print(f"Owner: {record['owner']['name']}")
    print(f"Value: ${record['assessment']['market_value']}")
    print(f"Last Sale: ${record['sale']['last_sale_price']}")

# Complete property history
history = property_search.get_property_history(
    address="123 Main Street",
    city="New York",
    state="NY",
    zip_code="10001"
)

print(f"Ownership History: {history['ownership_history']}")
print(f"Value History: {history['value_history']}")
print(f"Timeline: {history['timeline']}")
```

**Features:**
- Owner name search
- Address-based search
- Property tax records
- Deed records
- Mortgage records
- Transaction history
- Value assessments

### 5. Business Records (`business_records.py`)

Search corporate registrations, filings, and business licenses.

**Data Sources:**
- **OpenCorporates**: 200M+ companies worldwide
- **Secretary of State**: All 50 states business registrations
- **SEC EDGAR**: Public company filings
- **UCC Filings**: Secured transactions
- **DBA Registrations**: Fictitious business names

```python
from business_records import BusinessRecordsSearch

business_search = BusinessRecordsSearch({
    'opencorporates_token': 'your_token'
})

query = {
    'business_name': 'Acme Corporation',
    'state': 'DE'
}

results = asyncio.run(business_search.search_async(query))

for record in results:
    print(f"Company: {record['name']}")
    print(f"Jurisdiction: {record['jurisdiction']}")
    print(f"Status: {record['status']}")
    print(f"Incorporation: {record['incorporation_date']}")

# Company profile
profile = business_search.get_company_profile('Tesla Inc', 'DE')
print(f"Jurisdictions: {profile['jurisdictions']}")
print(f"Registrations: {profile['registrations']}")

# Get company officers
officers = asyncio.run(
    business_search.get_company_officers('5200726', 'us_de')
)
for officer in officers:
    print(f"{officer['name']} - {officer['position']}")
```

**Features:**
- Multi-jurisdiction search
- Secretary of State filings
- Corporate officer lookup
- SEC public company data
- UCC filing search
- Business license lookup

### 6. Government Records (`government_records.py`)

Search government contracts, campaign finance, and lobbying records.

**Data Sources:**
- **USASpending.gov**: Federal contracts and spending
- **FEC**: Campaign contributions and candidates
- **Senate LDA**: Lobbying disclosures
- **MuckRock**: FOIA requests
- **Public salary databases**: Federal and state employees

```python
from government_records import GovernmentRecordsSearch

gov_search = GovernmentRecordsSearch({
    'fec_api_key': 'your_key',
    'propublica_api_key': 'your_key'
})

# Search government contracts
query = {
    'business_name': 'Lockheed Martin'
}

results = asyncio.run(gov_search.search_async(query))

for record in results:
    if 'award_amount' in record:
        print(f"Contract: ${record['award_amount']:,.2f}")
        print(f"Agency: {record['awarding_agency']}")
    if 'contribution_amount' in record:
        print(f"Contribution: ${record['contribution_amount']}")
        print(f"Recipient: {record['recipient_committee']}")

# Government profile
profile = gov_search.get_government_profile('John Doe')
print(f"Government Contracts: {profile['summary']['government_contracts']}")
print(f"Campaign Contributions: {profile['summary']['campaign_contributions']}")
print(f"Lobbying Activities: {profile['summary']['lobbying_activities']}")

# Congressional record
congress = asyncio.run(gov_search.get_congressional_record('Bernie Sanders'))
print(f"Position: {congress['current_position']}")
```

**Features:**
- Federal contract search
- Campaign finance tracking
- Lobbying disclosure search
- FOIA request database
- Public salary lookup
- Congressional voting records

### 7. Offshore Leaks (`offshore_leaks.py`)

Search ICIJ offshore databases for hidden assets and entities.

**Data Sources:**
- **Panama Papers** (2016): 214,488 entities
- **Paradise Papers** (2017): 120,000+ entities
- **Pandora Papers** (2021): 29,000+ entities
- **Offshore Leaks** (2013): 130,000+ entities
- **Bahamas Leaks** (2016): 175,000+ entities
- **Malta Files**, **Mauritius Leaks**

**Total: 810,000+ offshore entities**

```python
from offshore_leaks import OffshoreLeaksSearch

offshore_search = OffshoreLeaksSearch()

query = {
    'name': 'John Doe'
}

results = asyncio.run(offshore_search.search_async(query))

for record in results:
    print(f"Type: {record['type']}")  # entity, officer, intermediary
    print(f"Name: {record['name']}")
    print(f"Jurisdiction: {record.get('jurisdiction', 'N/A')}")
    print(f"Data Source: {record['data_source']}")  # Panama, Paradise, etc.

# Offshore profile
profile = offshore_search.get_offshore_profile('Vladimir Putin')
print(f"Risk Assessment: {profile['risk_assessment']}")
print(f"Entities: {profile['summary']['entities']}")
print(f"Officer Positions: {profile['summary']['officer_positions']}")
print(f"Jurisdictions: {profile['summary']['jurisdictions']}")

# Entity details with connections
details = asyncio.run(
    offshore_search.get_entity_details('10000001')
)
print(f"Officers: {details['officers']}")
print(f"Connections: {details['connections']}")

# Jurisdiction risk analysis
risk = offshore_search.analyze_jurisdiction_risk('BVI')
print(f"Risk Level: {risk['risk_level']}")
print(f"Secrecy Haven: {risk['is_secrecy_haven']}")
```

**Features:**
- Entity search (companies, trusts, foundations)
- Officer/shareholder search
- Intermediary search (law firms, banks)
- Connection mapping
- Jurisdiction risk analysis
- Network visualization data

## Installation

```bash
# Install dependencies
pip install aiohttp beautifulsoup4 lxml

# Optional dependencies for specific features
pip install pandas  # For data analysis
pip install matplotlib  # For visualization
```

## Configuration

Create a configuration file with API keys:

```python
config = {
    'court': {
        'judy_records_api_key': 'your_key',
        'court_listener_token': 'your_token',
        'pacer_username': 'username',
        'pacer_password': 'password'
    },
    'criminal': {
        # Most criminal databases don't require API keys
    },
    'property': {
        'attom_api_key': 'your_key',
        'zillow_api_key': 'your_key',
        'realtor_api_key': 'your_key'
    },
    'business': {
        'opencorporates_token': 'your_token'
    },
    'government': {
        'fec_api_key': 'your_key',
        'propublica_api_key': 'your_key'
    },
    'offshore': {
        # ICIJ database is public, no API key needed
    }
}
```

## API Keys

### Required for Full Functionality

1. **JudyRecords** - Court records access
   - Website: https://www.judyrecords.com
   - Coverage: 740M+ court cases

2. **PACER** - Federal court system
   - Website: https://pacer.uscourts.gov
   - Cost: $0.10 per page (free up to $30/quarter)

3. **ATTOM Data** - Property records
   - Website: https://api.developer.attomdata.com
   - Pricing: Varies by volume

4. **OpenCorporates** - Business records
   - Website: https://opencorporates.com/api
   - Free tier available

5. **FEC** - Campaign finance
   - Website: https://api.open.fec.gov
   - Free with registration

6. **ProPublica** - Congress data
   - Website: https://www.propublica.org/datastore/api
   - Free with registration

### Free/Public Access

- CourtListener (free)
- ICIJ Offshore Leaks (free)
- State court systems (free)
- Sex offender registry (free)
- BOP inmate locator (free)
- Secretary of State websites (free)
- USASpending.gov (free)

## Complete Example

```python
from public_records import PublicRecords

# Initialize
records = PublicRecords(config)

# Comprehensive person investigation
results = records.search(
    name="John Doe",
    dob="1980-01-01",
    city="New York",
    state="NY",
    record_types=[
        'court',
        'criminal',
        'property',
        'business',
        'government',
        'offshore'
    ]
)

# Analyze results
print(f"\n{'='*60}")
print("COMPREHENSIVE PUBLIC RECORDS REPORT")
print(f"{'='*60}\n")

print(f"Subject: {results['query']['name']}")
print(f"Search Date: {results['timestamp']}")
print(f"Total Records: {results['summary']['total_records']}")
print(f"Execution Time: {results['execution_time']:.2f}s\n")

print("Records by Type:")
for record_type, count in results['summary']['records_by_type'].items():
    print(f"  {record_type.title()}: {count}")

if results['summary']['risk_indicators']:
    print(f"\nRISK INDICATORS:")
    for indicator in results['summary']['risk_indicators']:
        severity = indicator['severity'].upper()
        print(f"  [{severity}] {indicator['type']}: {indicator['count']} records")

# Detailed record breakdown
print(f"\n{'='*60}")
print("DETAILED RECORDS")
print(f"{'='*60}\n")

# Court records
if 'court' in results['records']:
    print(f"Court Records ({len(results['records']['court'])}):")
    for record in results['records']['court'][:5]:
        print(f"  - Case {record['case_number']} ({record['court']})")
        print(f"    Status: {record['status']}")
        print(f"    URL: {record['url']}\n")

# Criminal records
if 'criminal' in results['records']:
    print(f"Criminal Records ({len(results['records']['criminal'])}):")
    for record in results['records']['criminal'][:5]:
        print(f"  - {record['source']} [{record['severity']}]")
        print(f"    Name: {record.get('name', 'N/A')}")
        print(f"    URL: {record['url']}\n")

# Property records
if 'property' in results['records']:
    print(f"Property Records ({len(results['records']['property'])}):")
    for record in results['records']['property'][:5]:
        if 'address' in record:
            addr = record['address']
            print(f"  - {addr.get('street')}, {addr.get('city')}, {addr.get('state')}")
        if 'assessment' in record:
            print(f"    Value: ${record['assessment'].get('market_value', 'N/A')}")
        print(f"    URL: {record['url']}\n")

# Business records
if 'business' in results['records']:
    print(f"Business Records ({len(results['records']['business'])}):")
    for record in results['records']['business'][:5]:
        print(f"  - {record['name']} ({record['jurisdiction']})")
        print(f"    Status: {record['status']}")
        print(f"    URL: {record['url']}\n")

# Government records
if 'government' in results['records']:
    print(f"Government Records ({len(results['records']['government'])}):")
    for record in results['records']['government'][:5]:
        print(f"  - {record['source']}")
        if 'award_amount' in record:
            print(f"    Contract: ${record['award_amount']:,.2f}")
        if 'contribution_amount' in record:
            print(f"    Contribution: ${record['contribution_amount']:,.2f}")
        print(f"    URL: {record['url']}\n")

# Offshore records
if 'offshore' in results['records']:
    print(f"Offshore Records ({len(results['records']['offshore'])}):")
    for record in results['records']['offshore'][:5]:
        print(f"  - {record['name']} ({record['type']})")
        print(f"    Jurisdiction: {record.get('jurisdiction', 'N/A')}")
        print(f"    Source: {record['data_source']}")
        print(f"    URL: {record['url']}\n")

# Export reports
records.export_results(results, 'full_report.json', format='json')
records.export_results(results, 'full_report.html', format='html')
records.export_results(results, 'full_report.csv', format='csv')

print(f"\nReports exported to:")
print(f"  - full_report.json")
print(f"  - full_report.html")
print(f"  - full_report.csv")
```

## Advanced Usage

### Asynchronous Searches

```python
import asyncio
from public_records import PublicRecords

async def main():
    records = PublicRecords(config)

    # Create multiple search queries
    queries = [
        {'name': 'John Doe', 'state': 'NY'},
        {'name': 'Jane Smith', 'state': 'CA'},
        {'business_name': 'Acme Corp', 'state': 'DE'}
    ]

    # Run searches concurrently
    tasks = [records.search_async(query) for query in queries]
    results = await asyncio.gather(*tasks)

    for result in results:
        print(f"Results for {result['query']}: {result['summary']['total_records']} records")

asyncio.run(main())
```

### Custom Record Filters

```python
# Search specific record types only
results = records.search(
    name="John Doe",
    state="NY",
    record_types=['criminal', 'offshore']  # Only search these
)

# Filter by date range
results = records.search(
    name="John Doe",
    state="NY",
    date_from="2020-01-01",
    date_to="2023-12-31"
)
```

### Risk Assessment

```python
def assess_person_risk(name, state):
    records = PublicRecords(config)
    results = records.search(name=name, state=state)

    risk_score = 0
    risk_factors = []

    # Criminal records
    if results['records'].get('criminal'):
        risk_score += 50
        risk_factors.append('Criminal records found')

    # Offshore entities
    if results['records'].get('offshore'):
        risk_score += 30
        risk_factors.append('Offshore entities found')

    # Multiple court cases
    if len(results['records'].get('court', [])) > 5:
        risk_score += 20
        risk_factors.append('Multiple court cases')

    return {
        'risk_score': risk_score,
        'risk_level': 'HIGH' if risk_score > 50 else 'MEDIUM' if risk_score > 20 else 'LOW',
        'risk_factors': risk_factors,
        'total_records': results['summary']['total_records']
    }

risk = assess_person_risk('John Doe', 'NY')
print(f"Risk Level: {risk['risk_level']} ({risk['risk_score']})")
print(f"Factors: {', '.join(risk['risk_factors'])}")
```

## Legal and Ethical Considerations

### Legal Use Only

This tool is designed for legitimate purposes only:

✅ **Permitted Uses:**
- Background checks for employment
- Due diligence for business transactions
- Legal investigations
- Journalism and research
- Compliance and risk assessment
- Asset recovery
- Fraud prevention

❌ **Prohibited Uses:**
- Stalking or harassment
- Identity theft
- Discrimination
- Unauthorized surveillance
- Privacy violations
- Illegal purposes

### Compliance

- **FCRA**: If used for employment, credit, insurance, or tenant screening, must comply with Fair Credit Reporting Act
- **Privacy Laws**: Respect state and federal privacy laws
- **Terms of Service**: Comply with all data source terms of service
- **Data Protection**: Handle personal data responsibly

### Best Practices

1. **Purpose Limitation**: Only collect data necessary for legitimate purpose
2. **Data Minimization**: Don't collect more than needed
3. **Security**: Protect collected data appropriately
4. **Retention**: Don't keep data longer than necessary
5. **Accuracy**: Verify information before making decisions
6. **Transparency**: Be clear about how data is used
7. **Rights**: Respect individual data rights

## Troubleshooting

### API Rate Limits

```python
# Implement rate limiting
import time

def search_with_rate_limit(queries):
    results = []
    for query in queries:
        result = records.search(**query)
        results.append(result)
        time.sleep(1)  # Wait 1 second between requests
    return results
```

### Handling Errors

```python
try:
    results = records.search(name="John Doe", state="NY")
except Exception as e:
    print(f"Search error: {e}")
    # Log error, retry, or use cached data
```

### Missing API Keys

```python
# Check for missing configuration
is_valid, errors = records.validate_query(query)
if not is_valid:
    print(f"Query validation errors: {errors}")
```

## Performance Optimization

### Caching Results

```python
import json
import hashlib

def cached_search(query):
    # Create cache key from query
    cache_key = hashlib.md5(json.dumps(query, sort_keys=True).encode()).hexdigest()
    cache_file = f"cache/{cache_key}.json"

    # Check cache
    if os.path.exists(cache_file):
        with open(cache_file, 'r') as f:
            return json.load(f)

    # Perform search
    results = records.search(**query)

    # Save to cache
    with open(cache_file, 'w') as f:
        json.dump(results, f)

    return results
```

### Parallel Searches

```python
from concurrent.futures import ThreadPoolExecutor

def parallel_search(queries):
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(records.search, **query) for query in queries]
        return [f.result() for f in futures]
```

## Support and Resources

### Data Sources

- JudyRecords: https://www.judyrecords.com
- CourtListener: https://www.courtlistener.com
- PACER: https://pacer.uscourts.gov
- OpenCorporates: https://opencorporates.com
- ICIJ: https://www.icij.org/investigations/
- FEC: https://www.fec.gov
- USASpending: https://www.usaspending.gov

### Documentation

- ATTOM API: https://api.developer.attomdata.com/docs
- FEC API: https://api.open.fec.gov/developers/
- OpenCorporates API: https://api.opencorporates.com/documentation
- ProPublica Congress: https://projects.propublica.org/api-docs/congress-api/

## License

This tool is provided for legitimate investigative purposes only. Users are responsible for compliance with all applicable laws and regulations.

## Version History

- **v1.0.0** (2026-01): Initial release
  - Court records search
  - Criminal records search
  - Property records search
  - Business records search
  - Government records search
  - Offshore leaks search
  - Unified search interface
  - Export functionality

---

**Built for Apollo Intelligence Framework**
Agent 16: Public Records Intelligence
