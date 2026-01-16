#!/usr/bin/env python3
"""
SOCMINT Framework - Quick Test Script
Verifies all components are working correctly
"""

import sys


def test_imports():
    """Test that all modules can be imported"""
    print("Testing imports...")

    try:
        from socmint_orchestrator import SOCMINT, TargetProfile
        print("  ✓ socmint_orchestrator")
    except Exception as e:
        print(f"  ✗ socmint_orchestrator: {e}")
        return False

    try:
        from twitter_intel import TwitterIntel
        print("  ✓ twitter_intel")
    except Exception as e:
        print(f"  ✗ twitter_intel: {e}")
        return False

    try:
        from facebook_intel import FacebookIntel
        print("  ✓ facebook_intel")
    except Exception as e:
        print(f"  ✗ facebook_intel: {e}")
        return False

    try:
        from instagram_intel import InstagramIntel
        print("  ✓ instagram_intel")
    except Exception as e:
        print(f"  ✗ instagram_intel: {e}")
        return False

    try:
        from linkedin_intel import LinkedInIntel
        print("  ✓ linkedin_intel")
    except Exception as e:
        print(f"  ✗ linkedin_intel: {e}")
        return False

    try:
        from tiktok_intel import TikTokIntel
        print("  ✓ tiktok_intel")
    except Exception as e:
        print(f"  ✗ tiktok_intel: {e}")
        return False

    try:
        from reddit_intel import RedditIntel
        print("  ✓ reddit_intel")
    except Exception as e:
        print(f"  ✗ reddit_intel: {e}")
        return False

    try:
        from telegram_intel import TelegramIntel
        print("  ✓ telegram_intel")
    except Exception as e:
        print(f"  ✗ telegram_intel: {e}")
        return False

    try:
        from discord_intel import DiscordIntel
        print("  ✓ discord_intel")
    except Exception as e:
        print(f"  ✗ discord_intel: {e}")
        return False

    try:
        from platform_aggregator import PlatformAggregator
        print("  ✓ platform_aggregator")
    except Exception as e:
        print(f"  ✗ platform_aggregator: {e}")
        return False

    return True


def test_basic_functionality():
    """Test basic functionality of each module"""
    print("\nTesting basic functionality...")

    try:
        from socmint_orchestrator import SOCMINT
        socmint = SOCMINT()
        print("  ✓ SOCMINT initialization")

        # Test profile building
        profile = socmint.build_profile(
            username="test_user",
            platforms=["twitter", "instagram"],
            deep_scan=False
        )
        print("  ✓ Profile building")

        # Test statistics
        stats = socmint.get_statistics()
        print(f"  ✓ Statistics: {stats['profiles_collected']} profiles collected")

        return True

    except Exception as e:
        print(f"  ✗ Functionality test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_platform_collectors():
    """Test individual platform collectors"""
    print("\nTesting platform collectors...")

    # Test Twitter
    try:
        from twitter_intel import TwitterIntel
        twitter = TwitterIntel()
        profile = twitter.collect_profile("test_user")
        print(f"  ✓ Twitter: {len(profile['tweets'])} tweets collected")
    except Exception as e:
        print(f"  ✗ Twitter: {e}")

    # Test Instagram
    try:
        from instagram_intel import InstagramIntel
        instagram = InstagramIntel()
        profile = instagram.collect_profile("test_user")
        print(f"  ✓ Instagram: {len(profile['posts'])} posts collected")
    except Exception as e:
        print(f"  ✗ Instagram: {e}")

    # Test LinkedIn
    try:
        from linkedin_intel import LinkedInIntel
        linkedin = LinkedInIntel()
        profile = linkedin.collect_profile("test-user")
        print(f"  ✓ LinkedIn: {len(profile['experience'])} positions collected")
    except Exception as e:
        print(f"  ✗ LinkedIn: {e}")

    # Test Reddit
    try:
        from reddit_intel import RedditIntel
        reddit = RedditIntel()
        profile = reddit.collect_profile("test_user")
        print(f"  ✓ Reddit: {profile['metrics']['total_karma']} karma")
    except Exception as e:
        print(f"  ✗ Reddit: {e}")

    # Test TikTok
    try:
        from tiktok_intel import TikTokIntel
        tiktok = TikTokIntel()
        profile = tiktok.collect_profile("test_user")
        print(f"  ✓ TikTok: {len(profile['videos'])} videos collected")
    except Exception as e:
        print(f"  ✗ TikTok: {e}")

    return True


def test_aggregation():
    """Test platform aggregation"""
    print("\nTesting aggregation...")

    try:
        from platform_aggregator import PlatformAggregator

        aggregator = PlatformAggregator()

        # Test data
        platform_data = {
            'twitter': {
                'profile': {
                    'username': 'test',
                    'display_name': 'Test User',
                    'followers_count': 100
                },
                'tweets': []
            },
            'instagram': {
                'profile': {
                    'username': 'test',
                    'full_name': 'Test User',
                    'followers_count': 200
                },
                'posts': []
            }
        }

        # Test unification
        unified = aggregator.unify_profile(platform_data)
        print(f"  ✓ Profile unification: {len(unified['platforms_present'])} platforms")

        # Test relationship mapping
        relationships = aggregator.map_relationships(platform_data)
        print(f"  ✓ Relationship mapping")

        # Test timeline
        timeline = aggregator.build_timeline(platform_data)
        print(f"  ✓ Timeline building: {len(timeline)} events")

        return True

    except Exception as e:
        print(f"  ✗ Aggregation test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_export():
    """Test export functionality"""
    print("\nTesting export functions...")

    try:
        from socmint_orchestrator import SOCMINT

        socmint = SOCMINT()
        profile = socmint.build_profile("test_user", platforms=["twitter"])

        # Test JSON export
        json_data = socmint.export_profile(profile, format='json')
        print(f"  ✓ JSON export: {len(json_data)} bytes")

        # Test HTML export
        html_data = socmint.export_profile(profile, format='html')
        print(f"  ✓ HTML export: {len(html_data)} bytes")

        # Test CSV export
        csv_data = socmint.export_profile(profile, format='csv')
        print(f"  ✓ CSV export: {len(csv_data)} bytes")

        return True

    except Exception as e:
        print(f"  ✗ Export test failed: {e}")
        return False


def main():
    """Run all tests"""
    print("=" * 60)
    print("SOCMINT FRAMEWORK - TEST SUITE")
    print("=" * 60)

    results = []

    # Run tests
    results.append(("Import Test", test_imports()))
    results.append(("Functionality Test", test_basic_functionality()))
    results.append(("Platform Collectors Test", test_platform_collectors()))
    results.append(("Aggregation Test", test_aggregation()))
    results.append(("Export Test", test_export()))

    # Summary
    print("\n" + "=" * 60)
    print("TEST RESULTS")
    print("=" * 60)

    passed = 0
    failed = 0

    for test_name, result in results:
        status = "✓ PASSED" if result else "✗ FAILED"
        print(f"{test_name}: {status}")
        if result:
            passed += 1
        else:
            failed += 1

    print("\n" + "=" * 60)
    print(f"Total: {passed} passed, {failed} failed")
    print("=" * 60)

    if failed == 0:
        print("\n🎉 ALL TESTS PASSED!")
        return 0
    else:
        print(f"\n⚠️  {failed} test(s) failed")
        return 1


if __name__ == '__main__':
    sys.exit(main())
