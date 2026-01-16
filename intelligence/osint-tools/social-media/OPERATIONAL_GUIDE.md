# SOCMINT - Operational Guide

## Quick Start

### Installation

```bash
cd C:\SECURE_THREAT_INTEL\YoureGunnaHAveToShootMeToStopME\apollo\intelligence\osint-tools\social-media
pip install -r requirements.txt
```

### Basic Usage

```python
from socmint_orchestrator import SOCMINT

# Initialize
socmint = SOCMINT()

# Collect intelligence
profile = socmint.build_profile(
    username="target_user",
    platforms=["twitter", "facebook", "instagram"],
    deep_scan=True
)

# Review results
print(f"Risk Score: {profile.risk_score}")
print(f"Platforms: {profile.platforms}")
```

## File Structure

```
social-media/
├── Core System
│   ├── socmint_orchestrator.py     (11.2 KB) - Main engine
│   ├── platform_aggregator.py      (15.6 KB) - Cross-platform unification
│   └── __init__.py                 (0.9 KB)  - Package initialization
│
├── Platform Collectors
│   ├── twitter_intel.py            (15.4 KB) - Twitter/X intelligence
│   ├── facebook_intel.py           (16.3 KB) - Facebook intelligence
│   ├── instagram_intel.py          (16.3 KB) - Instagram intelligence
│   ├── linkedin_intel.py           (18.0 KB) - LinkedIn intelligence
│   ├── tiktok_intel.py             (15.0 KB) - TikTok intelligence
│   ├── reddit_intel.py             (15.5 KB) - Reddit intelligence
│   ├── telegram_intel.py           (14.8 KB) - Telegram intelligence
│   └── discord_intel.py            (17.8 KB) - Discord intelligence
│
├── Documentation
│   ├── README_SOCMINT.md           (18.6 KB) - Full documentation
│   └── OPERATIONAL_GUIDE.md        (This file)
│
├── Examples & Testing
│   ├── example_usage.py            (11.3 KB) - Usage examples
│   └── test_socmint.py             (6.8 KB)  - Test suite
│
└── Configuration
    └── requirements.txt             (1.2 KB)  - Dependencies

Total: 13 Python files, 2 documentation files, 1 config file
Combined code: ~176 KB
```

## Operational Scenarios

### Scenario 1: Person of Interest (POI) Investigation

**Objective:** Build comprehensive profile on suspect

```python
from socmint_orchestrator import SOCMINT

socmint = SOCMINT()

# Full spectrum collection
poi_profile = socmint.build_profile(
    username="suspect_username",
    platforms=None,  # Search ALL platforms
    deep_scan=True   # Enable network analysis
)

# Risk assessment
if poi_profile.risk_score > 0.7:
    print("⚠️ HIGH RISK - Escalate to supervisor")

# Export for analysis
report = socmint.export_profile(poi_profile, format='html')
with open(f'POI_{poi_profile.username}_report.html', 'w') as f:
    f.write(report)
```

### Scenario 2: Network Mapping

**Objective:** Map connections between suspects

```python
# Collect profiles for both suspects
suspect1 = socmint.build_profile("suspect1", deep_scan=True)
suspect2 = socmint.build_profile("suspect2", deep_scan=True)

# Analyze connections
connections = socmint.find_connections("suspect1", "suspect2")

print(f"Connection Score: {connections['connection_score']}")
print(f"Shared Platforms: {connections['shared_platforms']}")
print(f"Mutual Contacts: {len(connections['mutual_followers'])}")

# Map network
for connection in connections['mutual_across_platforms']:
    print(f"  - {connection['username']} on {connection['platforms']}")
```

### Scenario 3: Location-Based Surveillance

**Objective:** Monitor activity at specific location

```python
# Monitor location (e.g., protest site, event)
activity = socmint.monitor_location(
    latitude=40.7580,    # Times Square
    longitude=-73.9855,
    radius_km=0.5,
    platforms=["twitter", "instagram", "facebook"]
)

# Analyze detected activity
for platform, data in activity.items():
    posts = data.get('posts', []) + data.get('tweets', [])
    print(f"{platform}: {len(posts)} posts detected")

    # Extract user information
    for post in posts[:10]:  # Top 10
        print(f"  User: {post.get('author')}")
        print(f"  Content: {post.get('text', '')[:100]}...")
```

### Scenario 4: Hashtag Campaign Monitoring

**Objective:** Track hashtag across platforms

```python
# Monitor campaign hashtag
campaign = socmint.track_hashtag(
    hashtag="OperationName",
    platforms=["twitter", "instagram", "tiktok"]
)

# Identify top contributors
for platform, data in campaign.items():
    print(f"\n{platform.upper()}:")
    print(f"  Total Posts: {data.get('post_count', 0)}")

    # Extract top users
    if 'top_creators' in data:
        for creator in data['top_creators'][:5]:
            print(f"  - {creator['username']}: {creator['posts']} posts")
```

### Scenario 5: Deep Dive on Single Platform

**Objective:** Detailed analysis of one platform

```python
from twitter_intel import TwitterIntel

twitter = TwitterIntel()

# Deep collection
profile = twitter.collect_profile("target", deep_scan=True)

# Analyze network
print(f"Followers: {len(profile['network']['followers'])}")
print(f"Following: {len(profile['network']['following'])}")
print(f"Influential Followers: {profile['network']['influential_followers'][:5]}")

# Analyze content
for pattern in profile['activity_patterns']['posting_hours'].items():
    hour, count = pattern
    print(f"  {hour}:00 - {count} tweets")

# Sentiment analysis
sentiment = profile['activity_patterns']['content_analysis']
print(f"Positive: {sentiment['positive_tweets']}")
print(f"Negative: {sentiment['negative_tweets']}")
```

## Command Cheat Sheet

### Profile Collection
```python
# Basic profile
profile = socmint.build_profile("username")

# Deep scan with network analysis
profile = socmint.build_profile("username", deep_scan=True)

# Specific platforms only
profile = socmint.build_profile("username", platforms=["twitter", "instagram"])
```

### Search Operations
```python
# Username search across all platforms
results = socmint.search_username("username")

# Hashtag tracking
hashtag_data = socmint.track_hashtag("hashtag")

# Location monitoring
location_data = socmint.monitor_location(lat, lon, radius_km=1.0)
```

### Connection Analysis
```python
# Find connections between users
connections = socmint.find_connections("user1", "user2")
```

### Export Operations
```python
# JSON export
json_data = socmint.export_profile(profile, format='json')

# HTML report
html_report = socmint.export_profile(profile, format='html')

# CSV export
csv_data = socmint.export_profile(profile, format='csv')
```

### Statistics
```python
# Get collection statistics
stats = socmint.get_statistics()
print(stats)
```

## Platform-Specific Operations

### Twitter
```python
from twitter_intel import TwitterIntel
twitter = TwitterIntel()

# Profile + tweets
profile = twitter.collect_profile("username", deep_scan=True)

# Track hashtag
hashtag_data = twitter.track_hashtag("hashtag", limit=100)

# Location search
tweets = twitter.search_location(40.7128, -74.0060, radius_km=5.0)
```

### Instagram
```python
from instagram_intel import InstagramIntel
instagram = InstagramIntel()

# Profile + posts + stories
profile = instagram.collect_profile("username", deep_scan=True)

# Hashtag tracking
hashtag_data = instagram.track_hashtag("hashtag", limit=100)

# Story analysis
stories = instagram.analyze_story("username")
```

### LinkedIn
```python
from linkedin_intel import LinkedInIntel
linkedin = LinkedInIntel()

# Professional profile
profile = linkedin.collect_profile("username", deep_scan=True)

# Search people
results = linkedin.search_people("keyword", filters={'location': 'NYC'})

# Company analysis
company = linkedin.analyze_company("CompanyName")
```

### Reddit
```python
from reddit_intel import RedditIntel
reddit = RedditIntel()

# User profile + history
profile = reddit.collect_profile("username", deep_scan=True)

# Track subreddit
subreddit_data = reddit.track_subreddit("subreddit_name", limit=100)

# Search posts
results = reddit.search_posts("keyword", subreddit="specific_sub")
```

### TikTok
```python
from tiktok_intel import TikTokIntel
tiktok = TikTokIntel()

# User profile + videos
profile = tiktok.collect_profile("username", deep_scan=True)

# Discover trends
trends = tiktok.discover_trends("US")

# Sound analysis
sound_data = tiktok.analyze_sound("sound_id")
```

### Telegram
```python
from telegram_intel import TelegramIntel
telegram = TelegramIntel()

# Monitor channel
channel = telegram.monitor_channel("channel_id", limit=500)

# Monitor group
group = telegram.monitor_group("group_id")

# Track mentions
mentions = telegram.track_user_mentions("username")
```

### Discord
```python
from discord_intel import DiscordIntel
discord = DiscordIntel()

# Scrape server
server = discord.scrape_server("server_id")

# User profile
profile = discord.collect_profile("user#1234", deep_scan=True)

# Search servers
results = discord.search_servers("keyword")
```

## Best Practices

### 1. Rate Limiting
```python
import time

# Add delays between requests
for username in target_list:
    profile = socmint.build_profile(username)
    time.sleep(5)  # 5-second delay
```

### 2. Error Handling
```python
try:
    profile = socmint.build_profile("username")
except Exception as e:
    print(f"Collection failed: {e}")
    # Log error, retry, or escalate
```

### 3. Data Storage
```python
import json
from datetime import datetime

# Save with timestamp
filename = f"profile_{username}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
with open(filename, 'w') as f:
    json.dump(profile, f, indent=2, default=str)
```

### 4. Incremental Collection
```python
# Collect platforms separately to handle failures
platforms = ["twitter", "facebook", "instagram", "linkedin"]
results = {}

for platform in platforms:
    try:
        data = socmint.build_profile("username", platforms=[platform])
        results[platform] = data
    except Exception as e:
        print(f"{platform} failed: {e}")
        continue
```

### 5. Batch Processing
```python
# Process multiple targets
targets = ["user1", "user2", "user3"]
profiles = {}

for target in targets:
    print(f"Processing {target}...")
    profiles[target] = socmint.build_profile(target, deep_scan=True)
    time.sleep(10)  # Rate limiting

# Export batch results
with open('batch_results.json', 'w') as f:
    json.dump(profiles, f, indent=2, default=str)
```

## Troubleshooting

### Issue: Import Errors
```python
# Solution: Ensure all dependencies installed
pip install -r requirements.txt
```

### Issue: API Authentication Failures
```python
# Solution: Configure API credentials
config = {
    'twitter': {'bearer_token': 'your_token'},
    'facebook': {'access_token': 'your_token'}
}
socmint = SOCMINT(config)
```

### Issue: Rate Limiting
```python
# Solution: Implement exponential backoff
import time

retries = 3
for attempt in range(retries):
    try:
        profile = socmint.build_profile("username")
        break
    except Exception as e:
        if attempt < retries - 1:
            wait = 2 ** attempt  # Exponential backoff
            time.sleep(wait)
```

### Issue: No Data Returned
```python
# Check if username exists
results = socmint.search_username("username")
for platform, data in results.items():
    if data.get('exists'):
        print(f"Found on {platform}")
```

## Security Checklist

- [ ] API credentials stored securely (not in code)
- [ ] Collected data encrypted at rest
- [ ] Access logs maintained
- [ ] Data retention policy followed
- [ ] Classification markings applied
- [ ] Only authorized personnel have access
- [ ] Regular security audits conducted

## Performance Tips

1. **Use parallel collection** - Build profiles across platforms simultaneously
2. **Implement caching** - Cache frequently accessed profiles
3. **Limit deep scans** - Only use when necessary
4. **Filter platforms** - Only query relevant platforms
5. **Batch operations** - Process multiple targets together

## Reporting Templates

### Executive Summary
```
TARGET: [username]
RISK SCORE: [score]/1.0
PLATFORMS: [count] active
KEY FINDINGS:
- [Finding 1]
- [Finding 2]
- [Finding 3]
RECOMMENDATION: [action]
```

### Detailed Report
```
SOCMINT INTELLIGENCE REPORT

Target Identification:
- Primary Username: [username]
- Alternate Names: [list]
- Active Platforms: [list]

Metrics:
- Total Followers: [count]
- Total Posts: [count]
- Engagement Rate: [rate]

Network Analysis:
- Key Connections: [list]
- Influential Contacts: [list]
- Cross-Platform Connections: [count]

Risk Assessment:
- Risk Score: [score]
- Risk Factors: [list]
- Recommendation: [action]
```

## Next Steps

After successful deployment:

1. Configure API credentials for production platforms
2. Integrate with case management system
3. Set up automated monitoring for high-value targets
4. Train analysts on operational procedures
5. Establish data retention and disposal procedures

---

**CLASSIFICATION: SENSITIVE**

This operational guide is for authorized intelligence personnel only.
