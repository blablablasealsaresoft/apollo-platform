# SOCMINT - Social Media Intelligence Collection System

Comprehensive social media intelligence (SOCMINT) collection and analysis framework supporting multiple platforms with cross-platform correlation and unified profile building.

## Overview

This SOCMINT framework provides advanced intelligence collection capabilities across major social media platforms including Twitter/X, Facebook, Instagram, LinkedIn, TikTok, Reddit, Telegram, and Discord. The system aggregates data from multiple sources to build comprehensive target profiles with relationship mapping, activity analysis, and behavioral patterns.

## Architecture

```
social-media/
├── socmint_orchestrator.py     # Main SOCMINT engine
├── twitter_intel.py             # Twitter/X intelligence
├── facebook_intel.py            # Facebook intelligence
├── instagram_intel.py           # Instagram intelligence
├── linkedin_intel.py            # LinkedIn intelligence
├── tiktok_intel.py             # TikTok intelligence
├── reddit_intel.py             # Reddit intelligence
├── telegram_intel.py           # Telegram intelligence
├── discord_intel.py            # Discord intelligence
├── platform_aggregator.py      # Cross-platform aggregation
└── README_SOCMINT.md           # This file
```

## Components

### 1. SOCMINT Orchestrator (`socmint_orchestrator.py`)

Main intelligence engine that coordinates multi-platform collection and aggregation.

**Features:**
- Multi-platform profile building
- Parallel data collection
- Cross-platform correlation
- Risk score calculation
- Export to multiple formats (JSON, HTML, CSV)

**Example Usage:**
```python
from socmint_orchestrator import SOCMINT

# Initialize orchestrator
socmint = SOCMINT()

# Build comprehensive profile
profile = socmint.build_profile(
    username="target_user",
    platforms=["twitter", "facebook", "instagram", "linkedin"],
    deep_scan=True
)

# Access results
print(f"Risk Score: {profile.risk_score}")
print(f"Platforms: {len(profile.platforms)}")
print(f"Timeline Events: {len(profile.timeline)}")

# Export results
json_data = socmint.export_profile(profile, format='json')
html_report = socmint.export_profile(profile, format='html')
```

**Key Methods:**
- `build_profile(username, platforms, deep_scan)` - Build unified profile
- `track_hashtag(hashtag, platforms)` - Track hashtag across platforms
- `monitor_location(lat, lon, radius_km)` - Monitor location-based activity
- `find_connections(user1, user2)` - Find connections between users
- `search_username(username)` - Search username across all platforms

### 2. Twitter Intelligence (`twitter_intel.py`)

Collects Twitter/X profile data, tweets, followers, and performs sentiment analysis.

**Features:**
- Profile scraping
- Tweet collection and analysis
- Follower/following network mapping
- Hashtag tracking
- Geolocation extraction
- Sentiment analysis
- Activity pattern detection

**Example Usage:**
```python
from twitter_intel import TwitterIntel

twitter = TwitterIntel()

# Collect profile with deep scan
profile = twitter.collect_profile("target_user", deep_scan=True)

# Access data
print(f"Tweets: {len(profile['tweets'])}")
print(f"Influence Score: {profile['metrics']['influence_score']}")
print(f"Network: {profile['network']['follower_count']} followers")

# Track hashtag
hashtag_data = twitter.track_hashtag("cybersecurity", limit=100)
print(f"Tweets with #{hashtag_data['hashtag']}: {hashtag_data['tweet_count']}")

# Search by location
location_tweets = twitter.search_location(40.7128, -74.0060, radius_km=5.0)
```

### 3. Facebook Intelligence (`facebook_intel.py`)

Extracts Facebook profiles, friend networks, posts, and location data.

**Features:**
- Profile extraction
- Friend network mapping
- Post collection
- Photo/video extraction
- Location tracking (check-ins)
- Event monitoring
- Group discovery
- Page analysis

**Example Usage:**
```python
from facebook_intel import FacebookIntel

facebook = FacebookIntel()

# Collect profile
profile = facebook.collect_profile("target_user", deep_scan=True)

# Access data
print(f"Posts: {len(profile['posts'])}")
print(f"Friends: {len(profile['friends'])}")
print(f"Check-ins: {len(profile['check_ins'])}")
print(f"Social Score: {profile['metrics']['social_score']:.2f}")

# Monitor location
location_data = facebook.search_location(40.7128, -74.0060, radius_km=10.0)

# Search groups
groups = facebook.search_groups("cybersecurity")
```

### 4. Instagram Intelligence (`instagram_intel.py`)

Collects Instagram profiles, posts, stories, and performs image analysis.

**Features:**
- Profile data extraction
- Post/story collection
- Follower/following analysis
- Hashtag tracking
- Location extraction
- Tagged post collection
- Content analysis
- Engagement metrics

**Example Usage:**
```python
from instagram_intel import InstagramIntel

instagram = InstagramIntel()

# Collect profile
profile = instagram.collect_profile("target_user", deep_scan=True)

# Access data
print(f"Posts: {len(profile['posts'])}")
print(f"Followers: {len(profile['followers'])}")
print(f"Influence Score: {profile['metrics']['influence_score']:.2f}")

# Analyze content patterns
content_analysis = profile['content_analysis']
print(f"Top hashtags: {content_analysis['hashtag_frequency']}")

# Track hashtag
hashtag_data = instagram.track_hashtag("travel", limit=100)
```

### 5. LinkedIn Intelligence (`linkedin_intel.py`)

Extracts professional profiles, work history, skills, and connections.

**Features:**
- Professional profile extraction
- Connection mapping
- Work history analysis
- Education background
- Skills and endorsements
- Certifications tracking
- Recommendations collection
- Company analysis

**Example Usage:**
```python
from linkedin_intel import LinkedInIntel

linkedin = LinkedInIntel()

# Collect professional profile
profile = linkedin.collect_profile("john-doe", deep_scan=True)

# Access data
print(f"Experience: {len(profile['experience'])} positions")
print(f"Skills: {len(profile['skills'])}")
print(f"Connections: {profile['metrics']['total_connections']}")
print(f"Professional Score: {profile['metrics']['professional_score']:.2f}")

# Search people
results = linkedin.search_people(
    "security analyst",
    filters={'location': 'New York', 'industry': 'Cybersecurity'}
)

# Analyze company
company_data = linkedin.analyze_company("TechCorp")
```

### 6. TikTok Intelligence (`tiktok_intel.py`)

Collects TikTok videos, user profiles, and tracks trending content.

**Features:**
- Video collection
- User profile extraction
- Follower/following analysis
- Hashtag tracking
- Trending content discovery
- Sound/music analysis
- Engagement metrics
- Virality scoring

**Example Usage:**
```python
from tiktok_intel import TikTokIntel

tiktok = TikTokIntel()

# Collect profile
profile = tiktok.collect_profile("target_user", deep_scan=True)

# Access data
print(f"Videos: {len(profile['videos'])}")
print(f"Virality Score: {profile['metrics']['virality_score']:.2f}")

# Track hashtag
hashtag_data = tiktok.track_hashtag("fyp", limit=100)
print(f"Total views: {hashtag_data['view_count']:,}")

# Discover trends
trends = tiktok.discover_trends("US")
print(f"Top trend: {trends[0]['name']}")
```

### 7. Reddit Intelligence (`reddit_intel.py`)

Extracts Reddit user activity, subreddit participation, and behavioral patterns.

**Features:**
- User history extraction
- Post and comment collection
- Subreddit tracking
- Karma analysis
- Activity pattern detection
- Content sentiment analysis
- Behavioral profiling
- Topic analysis

**Example Usage:**
```python
from reddit_intel import RedditIntel

reddit = RedditIntel()

# Collect user profile
profile = reddit.collect_profile("target_user", deep_scan=True)

# Access data
print(f"Posts: {len(profile['posts'])}")
print(f"Comments: {len(profile['comments'])}")
print(f"Karma: {profile['metrics']['total_karma']}")
print(f"Activity Score: {profile['metrics']['activity_score']:.2f}")

# Track subreddit
subreddit_data = reddit.track_subreddit("cybersecurity", limit=100)

# Search posts
results = reddit.search_posts("security breach", subreddit="netsec")
```

### 8. Telegram Intelligence (`telegram_intel.py`)

Monitors Telegram channels, groups, and collects message intelligence.

**Features:**
- Channel monitoring
- Group tracking
- Message collection
- User enumeration
- Member analysis
- Content analysis
- Posting frequency tracking
- Influence scoring

**Example Usage:**
```python
from telegram_intel import TelegramIntel

telegram = TelegramIntel()

# Monitor channel
channel = telegram.monitor_channel("example_channel", limit=500)

# Access data
print(f"Members: {channel['info']['member_count']:,}")
print(f"Messages: {len(channel['messages'])}")
print(f"Influence Score: {channel['metrics']['influence_score']:.2f}")

# Monitor group
group = telegram.monitor_group("example_group")

# Track mentions
mentions = telegram.track_user_mentions("username")
```

### 9. Discord Intelligence (`discord_intel.py`)

Scrapes Discord servers, messages, and tracks user relationships.

**Features:**
- Server discovery and scraping
- Message collection
- User tracking
- Relationship mapping
- Channel analysis
- Member enumeration
- Activity monitoring
- Role analysis

**Example Usage:**
```python
from discord_intel import DiscordIntel

discord = DiscordIntel()

# Scrape server
server = discord.scrape_server("123456789")

# Access data
print(f"Members: {server['metrics']['total_members']}")
print(f"Messages: {server['metrics']['total_messages_collected']}")
print(f"Activity Score: {server['metrics']['activity_score']:.2f}")

# Collect user profile
profile = discord.collect_profile("user#1234", deep_scan=True)

# Search servers
results = discord.search_servers("gaming")
```

### 10. Platform Aggregator (`platform_aggregator.py`)

Unifies and correlates data from multiple platforms.

**Features:**
- Cross-platform profile unification
- Relationship mapping
- Activity timeline building
- Connection discovery
- Pattern analysis
- Consistency scoring
- Report generation

**Example Usage:**
```python
from platform_aggregator import PlatformAggregator

aggregator = PlatformAggregator()

# Unify profile data
unified = aggregator.unify_profile(platform_data)

# Map relationships
relationships = aggregator.map_relationships(platform_data)

# Build timeline
timeline = aggregator.build_timeline(platform_data)

# Find connections between users
connections = aggregator.find_connections(profile1_data, profile2_data)
print(f"Connection Score: {connections['connection_score']}")

# Export report
report = aggregator.export_unified_report(unified, format='json')
```

## Configuration

Each platform collector accepts a configuration dictionary:

```python
config = {
    'twitter': {
        'api_key': 'your_api_key',
        'api_secret': 'your_api_secret',
        'bearer_token': 'your_bearer_token',
        'max_tweets': 200,
        'max_followers': 1000
    },
    'facebook': {
        'access_token': 'your_access_token',
        'app_id': 'your_app_id',
        'app_secret': 'your_app_secret'
    },
    'instagram': {
        'access_token': 'your_access_token',
        'client_id': 'your_client_id'
    },
    'linkedin': {
        'access_token': 'your_access_token',
        'client_id': 'your_client_id'
    },
    'telegram': {
        'api_id': 'your_api_id',
        'api_hash': 'your_api_hash',
        'phone': 'your_phone_number'
    },
    'discord': {
        'bot_token': 'your_bot_token'
    },
    'reddit': {
        'client_id': 'your_client_id',
        'client_secret': 'your_client_secret'
    }
}

socmint = SOCMINT(config)
```

## Data Structures

### TargetProfile

```python
{
    'username': str,
    'platforms': {
        'twitter': {...},
        'facebook': {...},
        # ... other platforms
    },
    'unified_data': {
        'names': [...],
        'usernames': {...},
        'locations': [...],
        'total_followers': int,
        'total_posts': int,
        'platforms_present': [...],
        'verified_platforms': [...]
    },
    'relationships': {
        'followers': [...],
        'following': [...],
        'mutual_across_platforms': [...]
    },
    'timeline': [
        {
            'platform': str,
            'type': str,
            'timestamp': str,
            'content': str,
            'engagement': {...}
        }
    ],
    'risk_score': float,
    'collection_timestamp': str,
    'metadata': {...}
}
```

## Metrics and Scoring

### Risk Score (0.0 - 1.0)
Calculated based on:
- Multiple platform presence (0.1)
- High follower count (0.15)
- High posting frequency (0.1)
- Location sharing (0.15)
- Multiple identities (0.2)

### Influence Score (0 - 100)
Platform-specific scoring based on:
- Follower count (40%)
- Engagement rate (30%)
- Verification status (30%)

### Activity Score (0 - 100)
Measures user activity level:
- Post frequency (30-40%)
- Engagement (30%)
- Platform presence (30-40%)

## Use Cases

### 1. Person of Interest Investigation
```python
# Build comprehensive profile
profile = socmint.build_profile(
    username="target",
    platforms=None,  # Search all platforms
    deep_scan=True
)

# Analyze risk
if profile.risk_score > 0.7:
    print("HIGH RISK TARGET")

# Review timeline
for event in profile.timeline[:10]:
    print(f"{event['timestamp']}: {event['content']}")
```

### 2. Network Mapping
```python
# Find connections between suspects
connections = socmint.find_connections("suspect1", "suspect2")

if connections['connection_score'] > 50:
    print("Strong connection detected")
    print(f"Shared platforms: {connections['shared_platforms']}")
    print(f"Mutual contacts: {len(connections['mutual_followers'])}")
```

### 3. Location-Based Monitoring
```python
# Monitor activity at specific location
activity = socmint.monitor_location(
    latitude=40.7128,
    longitude=-74.0060,
    radius_km=2.0,
    platforms=["twitter", "instagram", "facebook"]
)

# Analyze location intelligence
for platform, data in activity.items():
    print(f"{platform}: {len(data.get('posts', []))} posts found")
```

### 4. Hashtag Campaign Tracking
```python
# Track hashtag across platforms
campaign = socmint.track_hashtag(
    hashtag="OperationXYZ",
    platforms=["twitter", "instagram", "tiktok"]
)

# Identify top contributors
for platform, data in campaign.items():
    print(f"{platform}: {data['post_count']} posts")
```

## Export Formats

### JSON Export
```python
json_data = socmint.export_profile(profile, format='json')
with open('profile.json', 'w') as f:
    f.write(json_data)
```

### HTML Report
```python
html_report = socmint.export_profile(profile, format='html')
with open('report.html', 'w') as f:
    f.write(html_report)
```

### CSV Export
```python
csv_data = socmint.export_profile(profile, format='csv')
with open('profile.csv', 'w') as f:
    f.write(csv_data)
```

## Privacy and Legal Considerations

**IMPORTANT:** This framework is designed for legitimate intelligence and investigation purposes only.

- Always comply with applicable laws and regulations
- Respect platform Terms of Service
- Obtain proper authorization before conducting investigations
- Protect personally identifiable information (PII)
- Follow data retention and privacy policies
- Use responsibly and ethically

## API Rate Limiting

The framework implements rate limiting to avoid API restrictions:

- Twitter: 450 requests per 15-minute window
- Facebook: 200 calls per hour per user
- Instagram: 200 requests per hour
- LinkedIn: Throttling based on API tier
- Reddit: 60 requests per minute

Configure delays and limits in platform-specific configs.

## Dependencies

```bash
pip install requests
pip install beautifulsoup4
pip install selenium
pip install aiohttp
pip install python-telegram-bot
pip install discord.py
pip install praw  # Reddit
pip install tweepy  # Twitter
pip install instaloader  # Instagram
pip install linkedin-api
```

## Performance Optimization

### Parallel Collection
```python
# Collect from multiple platforms simultaneously
profile = socmint.build_profile(
    username="target",
    platforms=["twitter", "facebook", "instagram", "linkedin"]
)
# Uses ThreadPoolExecutor for parallel execution
```

### Caching
```python
# Implement caching to reduce API calls
from functools import lru_cache

@lru_cache(maxsize=100)
def cached_profile(username):
    return socmint.build_profile(username)
```

## Troubleshooting

### Common Issues

**Authentication Errors:**
- Verify API credentials in config
- Check token expiration
- Ensure proper OAuth flow completion

**Rate Limiting:**
- Implement exponential backoff
- Reduce collection limits
- Use multiple API keys/tokens

**Data Collection Failures:**
- Handle private/protected accounts
- Verify target username exists
- Check platform API status

## Statistics and Monitoring

```python
# Get collection statistics
stats = socmint.get_statistics()
print(f"Profiles collected: {stats['profiles_collected']}")
print(f"Posts collected: {stats['posts_collected']}")
print(f"Platforms queried: {stats['platforms_queried']}")
```

## Advanced Features

### Custom Analysis Pipelines
```python
# Implement custom analysis
def custom_analyzer(profile):
    # Your analysis logic
    pass

# Apply to collected profiles
profile = socmint.build_profile("target")
results = custom_analyzer(profile)
```

### Integration with Other Tools
```python
# Export to other OSINT tools
maltego_data = convert_to_maltego(profile)
i2_analyst_data = convert_to_i2(profile)
```

## Security Notes

- Store API credentials securely (environment variables, key vaults)
- Encrypt collected intelligence data
- Implement access controls
- Maintain audit logs
- Follow classification guidelines
- Secure data transmission (TLS/SSL)

## Future Enhancements

- Machine learning for behavioral analysis
- Image recognition and facial analysis
- Natural language processing for content analysis
- Real-time monitoring capabilities
- Advanced network visualization
- Automated threat scoring
- Integration with threat intelligence feeds

## Support and Documentation

For detailed API documentation and additional examples, refer to individual module docstrings.

## Version

SOCMINT Framework v1.0.0

## License

Restricted Use - Authorized Personnel Only

---

**CLASSIFICATION: SENSITIVE**

This system contains advanced intelligence collection capabilities and should only be operated by authorized personnel with proper training and authorization.
