# People Search & Background Intelligence System

Comprehensive people search and background check OSINT toolkit for identity resolution, contact discovery, and public records research.

## Overview

This suite provides advanced people search capabilities combining multiple data sources, APIs, and web scraping techniques to build comprehensive profiles on individuals.

## Components

### 1. people_search.py - Main People Search Engine

Unified search interface aggregating multiple data sources.

**Features:**
- Multi-source people search
- Name, email, phone, address searches
- Relative and associate discovery
- Deep web search integration
- Confidence scoring
- Profile merging and deduplication

**Usage:**
```python
from people_search import PeopleSearch

async with PeopleSearch(config) as search:
    profile = await search.investigate(
        name="John Doe",
        location="New York, NY",
        email="john@example.com",
        deep_search=True
    )

    print(search.export_report(profile, format='text'))

    # Save JSON report
    with open('report.json', 'w') as f:
        f.write(search.export_report(profile, format='json'))
```

**PersonProfile Structure:**
- Basic Information (name, age, DOB)
- Contact Information (addresses, phones, emails)
- Relationships (relatives, associates)
- Social Profiles
- Employment & Education
- Public Records (voter, property, court, criminal)
- Confidence Score (0-100)

### 2. spokeo_integration.py - Spokeo API Integration

Commercial people search API with comprehensive reports.

**Features:**
- Name search with location filtering
- Reverse phone lookup
- Email address search
- Address lookup
- Background reports
- Social media profiles
- Wealth indicators

**Usage:**
```python
from spokeo_integration import SpokeoIntegration

async with SpokeoIntegration(api_key) as spokeo:
    # Search by name
    profiles = await spokeo.search_person(
        first_name="John",
        last_name="Doe",
        city="New York",
        state="NY",
        age_min=30,
        age_max=40
    )

    # Reverse phone lookup
    profile = await spokeo.reverse_phone_lookup("5551234567")

    # Email search
    profile = await spokeo.email_search("john@example.com")

    # Get full report
    full_report = await spokeo.get_full_report(spokeo_id)
```

**API Key Required:** https://www.spokeo.com/api

### 3. pipl_integration.py - Pipl Deep Web Search

Identity resolution across deep web sources.

**Features:**
- Deep web people search
- Identity resolution
- Contact aggregation
- Professional background
- Social media discovery
- Username correlation
- Multi-factor matching

**Usage:**
```python
from pipl_integration import PiplIntegration

async with PiplIntegration(api_key) as pipl:
    # Comprehensive search
    person = await pipl.comprehensive_search(
        name="John Doe",
        email="john@example.com",
        phone="+1-555-123-4567",
        location={'city': 'New York', 'state': 'NY', 'country': 'US'},
        minimum_probability=0.7
    )

    print(pipl.export_person(person, format='text'))

    # Get best contact info
    primary_email = pipl.get_primary_email(person)
    primary_phone = pipl.get_primary_phone(person)
```

**API Key Required:** https://pipl.com/api

### 4. truepeoplesearch.py - Free People Search

Web scraper for TruePeopleSearch.com (no API key required).

**Features:**
- Name search
- Address history
- Phone number lookup
- Relatives discovery
- Associates finding
- No cost, no API key

**Usage:**
```python
from truepeoplesearch import TruePeopleSearch

async with TruePeopleSearch(rate_limit=2.0) as tps:
    # Search by name
    results = await tps.search_by_name(
        first_name="John",
        last_name="Doe",
        city="New York",
        state="NY"
    )

    # Get full profiles
    for result in results:
        if result.profile_url:
            full_profile = await tps.get_full_profile(result.profile_url)
            print(tps.export_profile(full_profile, format='text'))

    # Reverse phone lookup
    profile = await tps.search_by_phone("555-123-4567")

    # Comprehensive search (auto-fetches full profiles)
    profiles = await tps.comprehensive_search(
        name="John Doe",
        location="New York, NY"
    )
```

**Note:** Web scraping - respect rate limits and robots.txt

### 5. background_checker.py - Background Checks

Comprehensive background investigation system.

**Features:**
- Criminal record search
- Court case lookup (state, county, federal)
- Property records
- Business affiliations
- Sex offender registry
- Bankruptcy records
- Liens and judgments
- Risk scoring

**Usage:**
```python
from background_checker import BackgroundChecker

async with BackgroundChecker(config) as checker:
    report = await checker.comprehensive_check(
        name="John Doe",
        dob="1980-01-01",
        state="NY",
        county="New York"
    )

    print(checker.export_report(report, format='text'))

    print(f"Risk Score: {report.risk_score}/100")
    print(f"Completeness: {report.completeness_score}%")

    # Access specific records
    for crime in report.criminal_records:
        print(f"[{crime.severity}] {crime.offense}")

    for case in report.court_cases:
        print(f"[{case.case_type}] {case.case_number}")
```

**Record Types:**
- Criminal Records (felonies, misdemeanors)
- Court Cases (criminal, civil, family, probate)
- Property Records (ownership, value, tax)
- Business Affiliations (owner, officer, agent)
- Sex Offender Registry
- Bankruptcy Records
- Liens & Judgments

### 6. voter_records.py - Voter Registration

Voter registration and history lookup.

**Features:**
- Voter registration search
- Party affiliation
- Voting history (elections participated)
- Registration address
- Precinct and district info
- Multi-state support

**Usage:**
```python
from voter_records import VoterRecordsSearch

async with VoterRecordsSearch() as vrs:
    # Search voter registration
    records = await vrs.search_voter(
        first_name="John",
        last_name="Doe",
        state="NY",
        county="New York"
    )

    for record in records:
        print(vrs.export_record(record, format='text'))

        # Analyze voting patterns
        analysis = vrs.analyze_voting_pattern(record)
        print(f"Engagement: {analysis['voter_engagement']}")

    # Verify registration
    verified = await vrs.verify_registration(
        name="John Doe",
        address="123 Main St",
        state="NY"
    )

    # Find all voters at address
    voters = await vrs.search_by_address(
        address="123 Main St",
        city="New York",
        state="NY"
    )
```

**Supported States:** All 50 states + DC (varies by state portal availability)

### 7. social_profile_aggregator.py - Social Media Aggregation

Cross-platform social media profile discovery and correlation.

**Features:**
- 50+ platform support
- Username enumeration
- Profile correlation
- Contact information extraction
- Network visualization
- Activity aggregation

**Usage:**
```python
from social_profile_aggregator import SocialProfileAggregator

async with SocialProfileAggregator() as spa:
    # Search by username
    network = await spa.search_username("johndoe")

    print(spa.export_network(network, format='text'))
    print(f"Found on {network.platforms_found} platforms")

    # Search by name (generates potential usernames)
    network = await spa.search_name("John Doe")

    # Generate network visualization
    graph = spa.generate_network_graph(network)

    # Correlate profiles
    correlations = await spa.correlate_profiles(network.profiles)
```

**Supported Platforms:**
- Social Media: Twitter, Facebook, Instagram, LinkedIn, TikTok, Snapchat
- Professional: GitHub, GitLab, Stack Overflow, Kaggle
- Content: YouTube, Medium, Twitch, Vimeo
- Gaming: Steam, Xbox, PlayStation, Discord
- Financial: Cash App, Venmo, Patreon
- And 30+ more platforms

## Installation

### Requirements

```bash
pip install aiohttp beautifulsoup4 lxml
```

### Optional Dependencies

```bash
# For enhanced parsing
pip install html5lib

# For network visualization
pip install networkx matplotlib

# For PDF reports
pip install reportlab
```

## Configuration

Create a configuration file `config.json`:

```json
{
  "spokeo_api_key": "your_spokeo_key",
  "pipl_api_key": "your_pipl_key",
  "hunter_api_key": "your_hunter_key",
  "numverify_api_key": "your_numverify_key",
  "rate_limits": {
    "spokeo": 1.0,
    "pipl": 1.0,
    "truepeoplesearch": 2.0
  },
  "enable_cache": true,
  "cache_ttl": 3600
}
```

## Complete Investigation Example

```python
import asyncio
from people_search import PeopleSearch
from spokeo_integration import SpokeoIntegration
from pipl_integration import PiplIntegration
from truepeoplesearch import TruePeopleSearch
from background_checker import BackgroundChecker
from voter_records import VoterRecordsSearch
from social_profile_aggregator import SocialProfileAggregator
import json

async def comprehensive_investigation(name, location=None, email=None, phone=None):
    """
    Perform comprehensive people investigation using all tools
    """
    config = json.load(open('config.json'))

    results = {
        'name': name,
        'people_search': None,
        'spokeo': None,
        'pipl': None,
        'truepeoplesearch': None,
        'background': None,
        'voter': None,
        'social': None
    }

    # 1. Main people search (aggregated)
    async with PeopleSearch(config) as ps:
        results['people_search'] = await ps.investigate(
            name=name,
            location=location,
            email=email,
            phone=phone,
            deep_search=True
        )

    # 2. Spokeo search
    if config.get('spokeo_api_key'):
        async with SpokeoIntegration(config['spokeo_api_key']) as spokeo:
            name_parts = name.split()
            profiles = await spokeo.search_person(
                first_name=name_parts[0],
                last_name=name_parts[-1]
            )
            results['spokeo'] = profiles[0] if profiles else None

    # 3. Pipl deep search
    if config.get('pipl_api_key'):
        async with PiplIntegration(config['pipl_api_key']) as pipl:
            results['pipl'] = await pipl.comprehensive_search(
                name=name,
                email=email,
                phone=phone
            )

    # 4. TruePeopleSearch (free)
    async with TruePeopleSearch() as tps:
        tps_results = await tps.comprehensive_search(name, location)
        results['truepeoplesearch'] = tps_results[0] if tps_results else None

    # 5. Background check
    async with BackgroundChecker(config) as bc:
        # Extract state from location
        state = location.split(',')[-1].strip() if location else None
        results['background'] = await bc.comprehensive_check(
            name=name,
            state=state
        )

    # 6. Voter records
    async with VoterRecordsSearch() as vrs:
        name_parts = name.split()
        if len(name_parts) >= 2 and state:
            voter_records = await vrs.search_voter(
                first_name=name_parts[0],
                last_name=name_parts[-1],
                state=state
            )
            results['voter'] = voter_records[0] if voter_records else None

    # 7. Social media aggregation
    async with SocialProfileAggregator() as spa:
        results['social'] = await spa.search_name(name)

    return results

async def main():
    # Perform investigation
    results = await comprehensive_investigation(
        name="John Doe",
        location="New York, NY",
        email="john.doe@example.com",
        phone="555-123-4567"
    )

    # Generate comprehensive report
    print("="*80)
    print("COMPREHENSIVE PEOPLE SEARCH REPORT")
    print("="*80)

    # Main search results
    if results['people_search']:
        ps = PeopleSearch()
        print(ps.export_report(results['people_search'], format='text'))

    # Background check
    if results['background']:
        bc = BackgroundChecker()
        print(bc.export_report(results['background'], format='text'))

    # Voter registration
    if results['voter']:
        vrs = VoterRecordsSearch()
        print(vrs.export_record(results['voter'], format='text'))

    # Social media
    if results['social']:
        spa = SocialProfileAggregator()
        print(spa.export_network(results['social'], format='text'))

    # Save complete results
    with open('comprehensive_report.json', 'w') as f:
        json.dump({
            'people_search': results['people_search'].to_dict() if results['people_search'] else None,
            'spokeo': results['spokeo'].__dict__ if results['spokeo'] else None,
            'pipl': results['pipl'].__dict__ if results['pipl'] else None,
            'background': results['background'].__dict__ if results['background'] else None,
            'social': json.loads(spa.export_network(results['social'])) if results['social'] else None
        }, f, indent=2, default=str)

if __name__ == "__main__":
    asyncio.run(main())
```

## Legal & Ethical Considerations

### Legal Compliance

1. **Fair Credit Reporting Act (FCRA)**: Background checks for employment, credit, housing require FCRA compliance
2. **State Laws**: Many states have specific privacy laws (CCPA, GDPR, etc.)
3. **Terms of Service**: Respect platform ToS and API usage limits
4. **Data Protection**: Handle personal information securely

### Ethical Use

- Only use for legitimate purposes (security research, due diligence, skip tracing)
- Obtain proper authorization before investigations
- Do not use for stalking, harassment, or discrimination
- Respect privacy and data protection laws
- Securely store and dispose of collected data

### Prohibited Uses

- Stalking or harassment
- Identity theft
- Unauthorized surveillance
- Discrimination (employment, housing, credit)
- Violation of restraining orders
- Any illegal activity

## Data Sources

### Free/Public Sources
- TruePeopleSearch.com
- FastPeopleSearch.com
- Voter registration databases (state-specific)
- Court records (PACER, state courts)
- Property records (county assessors)
- Business registries (Secretary of State)
- Social media platforms

### Commercial APIs
- Spokeo (https://www.spokeo.com/api)
- Pipl (https://pipl.com/api)
- Hunter.io (https://hunter.io/api)
- Numverify (https://numverify.com/)

### Government Sources
- PACER (Federal courts): https://pacer.uscourts.gov/
- NSOPW (Sex offender registry): https://www.nsopw.gov/
- State voter registration portals
- County property records
- State business registries

## Advanced Features

### 1. Batch Processing

```python
# Process multiple subjects
subjects = [
    {"name": "John Doe", "location": "New York, NY"},
    {"name": "Jane Smith", "location": "Los Angeles, CA"},
]

for subject in subjects:
    results = await comprehensive_investigation(**subject)
    # Save results
```

### 2. Automated Monitoring

```python
# Monitor for changes in records
import schedule

async def monitor_person(name):
    current = await comprehensive_investigation(name)
    # Compare with previous results
    # Alert on changes

schedule.every().day.at("09:00").do(lambda: asyncio.run(monitor_person("John Doe")))
```

### 3. Export Formats

```python
# JSON
report_json = search.export_report(profile, format='json')

# Plain text
report_text = search.export_report(profile, format='text')

# HTML (with styling)
report_html = search.export_report(profile, format='html')
```

## Performance Optimization

### Caching

```python
# Enable caching to reduce duplicate requests
config = {
    'enable_cache': True,
    'cache_ttl': 3600,  # 1 hour
    'cache_backend': 'redis'  # or 'memory'
}
```

### Parallel Processing

```python
# All modules use asyncio for parallel requests
# Example: searching 50 platforms simultaneously
async with SocialProfileAggregator() as spa:
    network = await spa.search_username("johndoe")
    # Checks all 50+ platforms in parallel
```

### Rate Limiting

```python
# Automatic rate limiting
tps = TruePeopleSearch(rate_limit=2.0)  # 2 seconds between requests

# API rate limits respected automatically
spokeo = SpokeoIntegration(api_key, rate_limit_delay=1.0)
```

## Troubleshooting

### Common Issues

**1. API Authentication Errors**
```python
# Verify API keys are correct
# Check API quota/credits
# Ensure proper API plan
```

**2. Scraping Failures**
```python
# Website structure changed - update parsers
# Rate limit exceeded - increase delay
# Blocked IP - use proxies/rotation
```

**3. No Results Found**
```python
# Try different name variations
# Expand search to more states
# Use partial matching
# Try related names (maiden, aliases)
```

## Security Best Practices

1. **API Key Protection**
   - Never commit API keys to version control
   - Use environment variables or secure vaults
   - Rotate keys regularly

2. **Data Encryption**
   - Encrypt stored reports
   - Use HTTPS for all API calls
   - Secure database connections

3. **Access Control**
   - Implement user authentication
   - Log all searches
   - Audit trail for compliance

4. **Data Retention**
   - Implement retention policies
   - Secure deletion procedures
   - Comply with data protection laws

## Contributing

When adding new data sources:

1. Follow existing code structure
2. Implement async/await patterns
3. Add comprehensive error handling
4. Include rate limiting
5. Document API requirements
6. Add usage examples
7. Update this README

## License

This tool is for educational and authorized security research only. Users are responsible for compliance with all applicable laws and regulations.

## Support

For issues, questions, or contributions:
- Review code documentation
- Check example usage
- Verify API credentials
- Test with known data first

---

**WARNING**: This is a powerful OSINT tool. Use responsibly and legally. Always obtain proper authorization before investigating individuals.
