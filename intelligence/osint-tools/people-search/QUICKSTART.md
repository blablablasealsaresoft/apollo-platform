# Quick Start Guide - People Search & Background Intelligence

Get started with the people search system in 5 minutes.

## Installation

### 1. Install Dependencies

```bash
cd C:\SECURE_THREAT_INTEL\YoureGunnaHAveToShootMeToStopME\apollo\intelligence\osint-tools\people-search

pip install -r requirements.txt
```

### 2. Configure API Keys (Optional)

```bash
# Copy example config
cp config.example.json config.json

# Edit config.json and add your API keys
# Note: Most features work without API keys using free sources
```

## Basic Usage

### Example 1: Simple Name Search (Free)

```python
import asyncio
from people_search import PeopleSearch

async def search_person():
    async with PeopleSearch() as search:
        profile = await search.investigate(
            name="John Doe",
            location="New York, NY"
        )

        print(f"Found: {profile.name}")
        print(f"Confidence: {profile.confidence_score}/100")
        print(f"Addresses: {len(profile.addresses)}")
        print(f"Phones: {len(profile.phone_numbers)}")

asyncio.run(search_person())
```

### Example 2: Reverse Phone Lookup

```python
from truepeoplesearch import TruePeopleSearch

async def lookup_phone():
    async with TruePeopleSearch() as tps:
        profile = await tps.search_by_phone("555-123-4567")

        if profile:
            print(f"Name: {profile.name}")
            print(f"Address: {profile.current_address}")
            print(f"Relatives: {', '.join(profile.relatives)}")

asyncio.run(lookup_phone())
```

### Example 3: Social Media Search

```python
from social_profile_aggregator import SocialProfileAggregator

async def find_socials():
    async with SocialProfileAggregator() as spa:
        network = await spa.search_username("johndoe")

        print(f"Found on {network.platforms_found} platforms:")
        for profile in network.profiles:
            print(f"  - {profile.platform}: {profile.url}")

asyncio.run(find_socials())
```

### Example 4: Background Check

```python
from background_checker import BackgroundChecker

async def background_check():
    async with BackgroundChecker() as checker:
        report = await checker.comprehensive_check(
            name="John Doe",
            state="NY"
        )

        print(f"Risk Score: {report.risk_score}/100")
        print(f"Criminal Records: {len(report.criminal_records)}")
        print(f"Court Cases: {len(report.court_cases)}")

asyncio.run(background_check())
```

## Running Examples

The package includes comprehensive examples:

```bash
# Run all examples
python example_usage.py

# Run specific example (1-10)
python example_usage.py 1  # Basic search
python example_usage.py 9  # Comprehensive investigation
```

## API Keys (Optional but Recommended)

### Free Options (No API Key Required)
- TruePeopleSearch
- Voter records (state-specific)
- Social media scraping

### Paid APIs (Better Results)

1. **Spokeo** - $19.95/month
   - Get key: https://www.spokeo.com/api
   - Add to config: `"spokeo_api_key": "your_key"`

2. **Pipl** - Pay per search
   - Get key: https://pipl.com/api
   - Add to config: `"pipl_api_key": "your_key"`

3. **Hunter.io** - Free tier available
   - Get key: https://hunter.io/api
   - Add to config: `"hunter_api_key": "your_key"`

## Common Use Cases

### 1. Find Contact Information

```python
from people_search import PeopleSearch

async with PeopleSearch() as search:
    profile = await search.investigate(name="John Doe", location="New York, NY")

    # Extract contact info
    emails = profile.email_addresses
    phones = [p['number'] for p in profile.phone_numbers]
    addresses = [a['full_address'] for a in profile.addresses]
```

### 2. Verify Identity

```python
from people_search import PeopleSearch

async with PeopleSearch() as search:
    profile = await search.investigate(
        name="John Doe",
        email="john@example.com",
        phone="555-123-4567"
    )

    # Check confidence
    if profile.confidence_score > 80:
        print("High confidence match!")
```

### 3. Find Relatives

```python
from truepeoplesearch import TruePeopleSearch

async with TruePeopleSearch() as tps:
    results = await tps.search_by_name("John", "Doe", state="NY")

    for result in results:
        full = await tps.get_full_profile(result.profile_url)
        print(f"Relatives: {', '.join(full.relatives)}")
```

### 4. Social Media OSINT

```python
from social_profile_aggregator import SocialProfileAggregator

async with SocialProfileAggregator() as spa:
    # Search by username
    network = await spa.search_username("johndoe")

    # Search by name
    network2 = await spa.search_name("John Doe")

    # Generate visualization
    graph = spa.generate_network_graph(network)
```

## Output Formats

All modules support multiple output formats:

```python
# JSON
json_report = search.export_report(profile, format='json')
with open('report.json', 'w') as f:
    f.write(json_report)

# Text
text_report = search.export_report(profile, format='text')
print(text_report)

# HTML
html_report = search.export_report(profile, format='html')
with open('report.html', 'w') as f:
    f.write(html_report)
```

## Rate Limiting

Respect rate limits to avoid being blocked:

```python
# Set rate limit (seconds between requests)
tps = TruePeopleSearch(rate_limit=2.0)  # 2 seconds

# Automatic rate limiting is built into all modules
```

## Best Practices

1. **Always use context managers** (async with)
   ```python
   async with PeopleSearch() as search:
       # Your code here
   ```

2. **Handle exceptions**
   ```python
   try:
       profile = await search.investigate(name="John Doe")
   except Exception as e:
       print(f"Search failed: {e}")
   ```

3. **Check confidence scores**
   ```python
   if profile.confidence_score > 70:
       # High confidence - likely correct
   else:
       # Low confidence - verify manually
   ```

4. **Use deep search for comprehensive results**
   ```python
   profile = await search.investigate(
       name="John Doe",
       deep_search=True  # More thorough but slower
   )
   ```

5. **Cache results to reduce duplicate searches**
   ```python
   # Enable caching in config.json
   {
       "enable_cache": true,
       "cache_ttl": 3600
   }
   ```

## Troubleshooting

### No Results Found
- Try different name spellings
- Add more identifiers (email, phone, location)
- Use `deep_search=True`
- Check multiple states

### API Errors
- Verify API key is correct
- Check API quota/credits
- Ensure proper API plan

### Slow Performance
- Enable caching
- Use specific platforms instead of all
- Reduce `deep_search` scope
- Implement parallel searches

### Being Blocked
- Increase rate limits
- Use proxy rotation
- Add random delays
- Rotate user agents

## Legal Reminder

Always ensure:
- You have authorization to search
- Comply with all applicable laws
- Respect privacy and data protection
- Use for legitimate purposes only
- Maintain secure storage of data

## Next Steps

- Read the full [README_PEOPLE_SEARCH.md](README_PEOPLE_SEARCH.md)
- Explore [example_usage.py](example_usage.py)
- Configure API keys for better results
- Customize search parameters
- Build your own integrations

## Support

For issues or questions:
1. Check example code
2. Review module docstrings
3. Verify API credentials
4. Test with known data

Happy investigating!
