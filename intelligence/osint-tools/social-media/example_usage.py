#!/usr/bin/env python3
"""
SOCMINT Framework - Example Usage
Demonstrates comprehensive social media intelligence collection
"""

import json
from datetime import datetime
from socmint_orchestrator import SOCMINT
from platform_aggregator import PlatformAggregator


def example_comprehensive_profile():
    """Example: Build comprehensive cross-platform profile"""
    print("=" * 60)
    print("EXAMPLE 1: Comprehensive Profile Collection")
    print("=" * 60)

    # Initialize SOCMINT
    socmint = SOCMINT()

    # Build comprehensive profile across all platforms
    profile = socmint.build_profile(
        username="target_user",
        platforms=["twitter", "facebook", "instagram", "linkedin"],
        deep_scan=True
    )

    # Display results
    print(f"\nTarget: {profile.username}")
    print(f"Risk Score: {profile.risk_score}")
    print(f"Platforms Found: {len(profile.platforms)}")
    print(f"Timeline Events: {len(profile.timeline)}")
    print(f"Total Followers: {profile.unified_data.get('total_followers', 0):,}")
    print(f"Total Posts: {profile.unified_data.get('total_posts', 0):,}")

    # Display platform breakdown
    print("\nPlatform Breakdown:")
    for platform_name, platform_data in profile.platforms.items():
        if 'error' not in platform_data:
            print(f"  - {platform_name.upper()}: ✓ Active")
        else:
            print(f"  - {platform_name.upper()}: ✗ Error")

    # Display relationships
    print(f"\nRelationships:")
    print(f"  Followers: {len(profile.relationships.get('followers', []))}")
    print(f"  Following: {len(profile.relationships.get('following', []))}")
    print(f"  Mutual Connections: {len(profile.relationships.get('mutual_across_platforms', []))}")

    # Export to JSON
    json_export = socmint.export_profile(profile, format='json')
    with open('profile_export.json', 'w') as f:
        f.write(json_export)
    print("\n✓ Profile exported to profile_export.json")

    return profile


def example_hashtag_tracking():
    """Example: Track hashtag across platforms"""
    print("\n" + "=" * 60)
    print("EXAMPLE 2: Hashtag Tracking")
    print("=" * 60)

    socmint = SOCMINT()

    # Track hashtag across multiple platforms
    hashtag_data = socmint.track_hashtag(
        hashtag="cybersecurity",
        platforms=["twitter", "instagram", "tiktok"]
    )

    print(f"\nHashtag: #cybersecurity")
    print("\nPlatform Activity:")
    for platform, data in hashtag_data.items():
        if 'post_count' in data:
            print(f"  {platform.upper()}:")
            print(f"    Posts: {data.get('post_count', 0)}")
            print(f"    Total Views: {data.get('view_count', 0):,}")
        elif 'tweet_count' in data:
            print(f"  {platform.upper()}:")
            print(f"    Tweets: {data.get('tweet_count', 0)}")


def example_location_monitoring():
    """Example: Monitor location-based activity"""
    print("\n" + "=" * 60)
    print("EXAMPLE 3: Location-Based Monitoring")
    print("=" * 60)

    socmint = SOCMINT()

    # Monitor activity at specific location (Times Square, NYC)
    location_data = socmint.monitor_location(
        latitude=40.7580,
        longitude=-73.9855,
        radius_km=1.0,
        platforms=["twitter", "instagram", "facebook"]
    )

    print(f"\nLocation: Times Square, NYC")
    print(f"Radius: 1.0 km")
    print("\nActivity Detected:")
    for platform, data in location_data.items():
        posts = data.get('posts', []) + data.get('tweets', []) + data.get('check_ins', [])
        print(f"  {platform.upper()}: {len(posts)} items")


def example_connection_analysis():
    """Example: Find connections between two users"""
    print("\n" + "=" * 60)
    print("EXAMPLE 4: Connection Analysis")
    print("=" * 60)

    socmint = SOCMINT()

    # Find connections between two targets
    connections = socmint.find_connections("user1", "user2")

    print(f"\nAnalyzing connection between 'user1' and 'user2'")
    print(f"\nConnection Score: {connections.get('connection_score', 0):.1f}/100")
    print(f"Shared Platforms: {connections.get('shared_platforms', [])}")
    print(f"Mutual Followers: {len(connections.get('mutual_followers', []))}")
    print(f"Common Locations: {len(connections.get('common_locations', []))}")

    if connections.get('connection_score', 0) > 50:
        print("\n⚠️  STRONG CONNECTION DETECTED")
    else:
        print("\nℹ️  Weak or no connection detected")


def example_username_search():
    """Example: Search username across all platforms"""
    print("\n" + "=" * 60)
    print("EXAMPLE 5: Username Availability Search")
    print("=" * 60)

    socmint = SOCMINT()

    # Search for username across all platforms
    results = socmint.search_username("johndoe")

    print(f"\nSearching for username: 'johndoe'")
    print("\nPlatform Availability:")
    for platform, data in results.items():
        if data.get('exists'):
            print(f"  ✓ {platform.upper()}: Found - {data.get('url', '')}")
        else:
            print(f"  ✗ {platform.upper()}: Not found")


def example_platform_specific():
    """Example: Platform-specific intelligence"""
    print("\n" + "=" * 60)
    print("EXAMPLE 6: Platform-Specific Intelligence")
    print("=" * 60)

    # Twitter Intelligence
    from twitter_intel import TwitterIntel
    twitter = TwitterIntel()

    print("\n--- Twitter Intelligence ---")
    twitter_profile = twitter.collect_profile("target_user", deep_scan=True)
    print(f"Tweets collected: {len(twitter_profile['tweets'])}")
    print(f"Influence Score: {twitter_profile['metrics']['influence_score']:.2f}")

    # Instagram Intelligence
    from instagram_intel import InstagramIntel
    instagram = InstagramIntel()

    print("\n--- Instagram Intelligence ---")
    instagram_profile = instagram.collect_profile("target_user", deep_scan=True)
    print(f"Posts collected: {len(instagram_profile['posts'])}")
    print(f"Engagement Rate: {instagram_profile['metrics']['engagement_rate']:.2f}%")

    # LinkedIn Intelligence
    from linkedin_intel import LinkedInIntel
    linkedin = LinkedInIntel()

    print("\n--- LinkedIn Intelligence ---")
    linkedin_profile = linkedin.collect_profile("john-doe", deep_scan=True)
    print(f"Work Experience: {len(linkedin_profile['experience'])} positions")
    print(f"Professional Score: {linkedin_profile['metrics']['professional_score']:.2f}")

    # Reddit Intelligence
    from reddit_intel import RedditIntel
    reddit = RedditIntel()

    print("\n--- Reddit Intelligence ---")
    reddit_profile = reddit.collect_profile("target_user", deep_scan=True)
    print(f"Posts: {reddit_profile['metrics']['total_posts']}")
    print(f"Comments: {reddit_profile['metrics']['total_comments']}")
    print(f"Karma: {reddit_profile['metrics']['total_karma']}")


def example_cross_platform_aggregation():
    """Example: Cross-platform data aggregation"""
    print("\n" + "=" * 60)
    print("EXAMPLE 7: Cross-Platform Aggregation")
    print("=" * 60)

    # Simulate platform data
    platform_data = {
        'twitter': {
            'profile': {
                'username': 'johndoe',
                'display_name': 'John Doe',
                'location': 'New York, NY',
                'followers_count': 1500,
                'verified': True
            },
            'tweets': []
        },
        'instagram': {
            'profile': {
                'username': 'johndoe',
                'full_name': 'John Doe',
                'biography': 'Photographer & traveler',
                'followers_count': 3000,
                'location': 'New York'
            },
            'posts': []
        },
        'linkedin': {
            'profile': {
                'public_identifier': 'johndoe',
                'first_name': 'John',
                'last_name': 'Doe',
                'headline': 'Cybersecurity Professional',
                'location': {'city': 'New York', 'state': 'NY'},
                'connections_count': 500
            },
            'experience': []
        }
    }

    aggregator = PlatformAggregator()

    # Unify profile data
    unified = aggregator.unify_profile(platform_data)

    print("\n--- Unified Profile ---")
    print(f"Names: {unified['names']}")
    print(f"Usernames: {unified['usernames']}")
    print(f"Platforms Present: {unified['platforms_present']}")
    print(f"Total Followers: {unified['total_followers']:,}")
    print(f"Verified Platforms: {unified['verified_platforms']}")
    print(f"Cross-Platform Consistency: {unified['metadata']['cross_platform_consistency']:.2%}")

    # Map relationships
    relationships = aggregator.map_relationships(platform_data)
    print(f"\n--- Relationships ---")
    print(f"Total Connections Mapped: {len(relationships['followers']) + len(relationships['following'])}")


def example_export_formats():
    """Example: Export in different formats"""
    print("\n" + "=" * 60)
    print("EXAMPLE 8: Export Formats")
    print("=" * 60)

    socmint = SOCMINT()

    # Build profile
    profile = socmint.build_profile(
        username="target_user",
        platforms=["twitter", "instagram"],
        deep_scan=False
    )

    # Export to JSON
    json_data = socmint.export_profile(profile, format='json')
    print("\n✓ JSON export generated")

    # Export to HTML
    html_data = socmint.export_profile(profile, format='html')
    with open('report.html', 'w') as f:
        f.write(html_data)
    print("✓ HTML report generated: report.html")

    # Export to CSV
    csv_data = socmint.export_profile(profile, format='csv')
    with open('report.csv', 'w') as f:
        f.write(csv_data)
    print("✓ CSV export generated: report.csv")


def example_statistics():
    """Example: Collection statistics"""
    print("\n" + "=" * 60)
    print("EXAMPLE 9: Collection Statistics")
    print("=" * 60)

    socmint = SOCMINT()

    # Collect multiple profiles
    for username in ["user1", "user2", "user3"]:
        socmint.build_profile(username, platforms=["twitter", "instagram"])

    # Get statistics
    stats = socmint.get_statistics()

    print("\n--- Collection Statistics ---")
    print(f"Profiles Collected: {stats['profiles_collected']}")
    print(f"Posts Collected: {stats['posts_collected']}")
    print(f"Relationships Mapped: {stats['relationships_mapped']}")
    print(f"Platforms Queried: {stats['platforms_queried']}")


def main():
    """Run all examples"""
    print("\n" + "=" * 60)
    print("SOCMINT FRAMEWORK - COMPREHENSIVE EXAMPLES")
    print("Social Media Intelligence Collection System")
    print("=" * 60)

    try:
        # Run examples
        example_comprehensive_profile()
        example_hashtag_tracking()
        example_location_monitoring()
        example_connection_analysis()
        example_username_search()
        example_platform_specific()
        example_cross_platform_aggregation()
        example_export_formats()
        example_statistics()

        print("\n" + "=" * 60)
        print("ALL EXAMPLES COMPLETED SUCCESSFULLY")
        print("=" * 60)

    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    main()
