"""
API Orchestrator - Example Usage
Demonstrates various features of the API orchestration system
"""

import asyncio
import logging
from api_orchestrator import APIOrchestrator

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)


async def example_single_api_call():
    """Example: Call a single API"""
    print("\n=== Single API Call ===")

    orchestrator = APIOrchestrator()

    try:
        # Call GitHub API to get user info
        result = await orchestrator.call_api(
            api_id="github",
            endpoint="/users/torvalds",
            method="GET"
        )

        print(f"Result: {result}")

    except Exception as e:
        print(f"Error: {e}")

    finally:
        await orchestrator.close()


async def example_category_search():
    """Example: Search all APIs in a category"""
    print("\n=== Category Search ===")

    orchestrator = APIOrchestrator()

    try:
        # Search social media for a username
        results = await orchestrator.call_apis(
            category="social_media",
            target="elonmusk",
            parallel=True,
            max_concurrent=5
        )

        # Print summary
        successful = sum(1 for r in results.values() if r.get("success"))
        failed = sum(1 for r in results.values() if not r.get("success"))

        print(f"Total APIs called: {len(results)}")
        print(f"Successful: {successful}")
        print(f"Failed: {failed}")

        # Print successful results
        for api_id, result in results.items():
            if result.get("success"):
                print(f"\n{api_id}:")
                print(f"  Status: {result['data'].get('status')}")
                print(f"  Data: {str(result['data'])[:100]}...")

    except Exception as e:
        print(f"Error: {e}")

    finally:
        await orchestrator.close()


async def example_specific_apis():
    """Example: Call specific APIs"""
    print("\n=== Specific APIs ===")

    orchestrator = APIOrchestrator()

    try:
        # Call specific crypto APIs
        api_ids = [
            "coingecko",
            "coinmarketcap",
            "binance",
            "etherscan"
        ]

        results = await orchestrator.call_apis(
            api_ids=api_ids,
            parallel=True
        )

        for api_id, result in results.items():
            status = "Success" if result.get("success") else "Failed"
            print(f"{api_id}: {status}")
            if not result.get("success"):
                print(f"  Error: {result.get('error')}")

    except Exception as e:
        print(f"Error: {e}")

    finally:
        await orchestrator.close()


async def example_with_caching():
    """Example: Demonstrate caching"""
    print("\n=== Caching Example ===")

    orchestrator = APIOrchestrator(enable_caching=True)

    try:
        endpoint = "/users/github"

        # First call (cache miss)
        print("First call (should be cache miss)...")
        result1 = await orchestrator.call_api(
            api_id="github",
            endpoint=endpoint,
            use_cache=True
        )

        # Second call (cache hit)
        print("Second call (should be cache hit)...")
        result2 = await orchestrator.call_api(
            api_id="github",
            endpoint=endpoint,
            use_cache=True
        )

        # Get cache stats
        if orchestrator.cache:
            stats = orchestrator.cache.get_stats()
            print(f"\nCache Statistics:")
            print(f"  Hits: {stats['hits']}")
            print(f"  Misses: {stats['misses']}")
            print(f"  Hit Rate: {stats['hit_rate']:.2%}")

    except Exception as e:
        print(f"Error: {e}")

    finally:
        await orchestrator.close()


async def example_rate_limiting():
    """Example: Demonstrate rate limiting"""
    print("\n=== Rate Limiting Example ===")

    orchestrator = APIOrchestrator()

    try:
        # Make multiple rapid calls to same API
        api_id = "github"
        calls = 5

        print(f"Making {calls} rapid calls to {api_id}...")

        for i in range(calls):
            try:
                result = await orchestrator.call_api(
                    api_id=api_id,
                    endpoint=f"/users/user{i}"
                )
                print(f"  Call {i+1}: Success")

            except Exception as e:
                print(f"  Call {i+1}: {e}")

        # Get rate limiter stats
        stats = orchestrator.rate_limiter.get_stats(api_id)
        if stats:
            print(f"\nRate Limiter Statistics:")
            print(f"  Current tokens: {stats['current_tokens']:.2f}")
            print(f"  Capacity: {stats['capacity']}")
            print(f"  Utilization: {stats['utilization']:.2%}")

    except Exception as e:
        print(f"Error: {e}")

    finally:
        await orchestrator.close()


async def example_analytics():
    """Example: View analytics"""
    print("\n=== Analytics Example ===")

    orchestrator = APIOrchestrator()

    try:
        # Make some API calls
        apis = ["github", "twitter_v2", "reddit"]

        for api_id in apis:
            try:
                await orchestrator.call_api(api_id, "/test")
            except:
                pass  # Ignore errors for this example

        # Get analytics
        all_metrics = orchestrator.analytics.get_all_metrics()

        print("\nAPI Call Metrics:")
        for api_id, metrics in all_metrics.items():
            print(f"\n{api_id}:")
            print(f"  Total calls: {metrics.total_calls}")
            print(f"  Success rate: {metrics.success_rate:.2%}")
            print(f"  Avg duration: {metrics.avg_duration:.3f}s")
            if metrics.total_calls > 0:
                print(f"  P95 duration: {metrics.p95_duration:.3f}s")

        # Get top APIs
        top_apis = orchestrator.analytics.get_top_apis(limit=5, by="calls")
        print("\nTop 5 APIs by calls:")
        for api in top_apis:
            print(f"  {api['api_name']}: {api['total_calls']} calls")

    except Exception as e:
        print(f"Error: {e}")

    finally:
        await orchestrator.close()


async def example_health_monitoring():
    """Example: Monitor system health"""
    print("\n=== Health Monitoring ===")

    orchestrator = APIOrchestrator()

    try:
        # Make some API calls to generate data
        await orchestrator.call_apis(
            category="social_media",
            parallel=True,
            max_concurrent=3
        )

        # Get health status
        health = orchestrator.get_health()

        print(f"System Health:")
        print(f"  Overall: {'Healthy' if health['healthy'] else 'Unhealthy'}")
        print(f"  Total APIs: {health['total_apis']}")
        print(f"  Unhealthy APIs: {health['unhealthy_apis']}")

        if health['unhealthy_apis'] > 0:
            print("\nUnhealthy Circuit Breakers:")
            for name, stats in health['circuit_breakers'].items():
                print(f"  {name}: {stats['state']}")

        # Get detailed stats
        stats = orchestrator.get_stats()

        print(f"\nRegistry Stats:")
        print(f"  Total APIs: {stats['registry']['total_apis']}")
        print(f"  Categories: {stats['registry']['total_categories']}")

        if stats.get('cache'):
            print(f"\nCache Stats:")
            print(f"  Hit rate: {stats['cache']['hit_rate']:.2%}")

    except Exception as e:
        print(f"Error: {e}")

    finally:
        await orchestrator.close()


async def example_registry_search():
    """Example: Search and explore API registry"""
    print("\n=== Registry Search ===")

    orchestrator = APIOrchestrator()

    try:
        # Get all categories
        categories = orchestrator.registry.get_categories()
        print(f"Available categories: {len(categories)}")
        for cat in categories[:5]:  # Show first 5
            print(f"  - {cat}")

        # Search for specific APIs
        search_term = "email"
        results = orchestrator.registry.search_apis(search_term)
        print(f"\nAPIs matching '{search_term}': {len(results)}")
        for api in results[:5]:  # Show first 5
            print(f"  - {api['name']} ({api['id']})")

        # Get APIs in a category
        category = "blockchain_crypto"
        crypto_apis = orchestrator.registry.get_apis_by_category(category)
        print(f"\nAPIs in {category}: {len(crypto_apis)}")
        for api in crypto_apis[:5]:  # Show first 5
            print(f"  - {api['name']}")

        # Get specific API info
        api_id = "twitter_v2"
        api_info = orchestrator.registry.get_api(api_id)
        if api_info:
            print(f"\nAPI Info for {api_id}:")
            print(f"  Name: {api_info['name']}")
            print(f"  Base URL: {api_info['base_url']}")
            print(f"  Auth: {api_info['auth_type']}")
            print(f"  Rate Limit: {api_info['rate_limit']}")

    except Exception as e:
        print(f"Error: {e}")

    finally:
        await orchestrator.close()


async def example_osint_investigation():
    """Example: OSINT investigation workflow"""
    print("\n=== OSINT Investigation ===")

    orchestrator = APIOrchestrator()

    target = "johndoe"

    try:
        print(f"Investigating target: {target}")

        # Phase 1: Social Media Search
        print("\nPhase 1: Searching social media...")
        social_results = await orchestrator.call_apis(
            category="social_media",
            target=target,
            parallel=True,
            max_concurrent=10
        )

        social_found = sum(
            1 for r in social_results.values()
            if r.get("success") and r.get("data")
        )
        print(f"  Found on {social_found} platforms")

        # Phase 2: Email/Phone Validation
        email = f"{target}@example.com"
        print(f"\nPhase 2: Validating email {email}...")

        email_apis = ["hunter", "emailrep", "abstract_email"]
        email_results = await orchestrator.call_apis(
            api_ids=email_apis,
            target=email,
            parallel=True
        )

        email_valid = sum(
            1 for r in email_results.values()
            if r.get("success")
        )
        print(f"  Validated with {email_valid}/{len(email_apis)} services")

        # Phase 3: Public Records
        print(f"\nPhase 3: Checking public records...")
        records_apis = ["fullcontact", "clearbit", "pipl"]
        records_results = await orchestrator.call_apis(
            api_ids=records_apis,
            target=target,
            parallel=True
        )

        records_found = sum(
            1 for r in records_results.values()
            if r.get("success")
        )
        print(f"  Found in {records_found}/{len(records_apis)} databases")

        # Summary
        print(f"\nInvestigation Summary for {target}:")
        print(f"  Social Media: {social_found} profiles")
        print(f"  Email Validation: {email_valid}/{len(email_apis)} confirmed")
        print(f"  Public Records: {records_found}/{len(records_apis)} found")

        # Get investigation metrics
        stats = orchestrator.analytics.get_all_metrics()
        total_calls = sum(m.total_calls for m in stats.values())
        successful_calls = sum(m.successful_calls for m in stats.values())
        avg_duration = sum(m.avg_duration * m.total_calls for m in stats.values()) / total_calls if total_calls > 0 else 0

        print(f"\nPerformance Metrics:")
        print(f"  Total API calls: {total_calls}")
        print(f"  Success rate: {successful_calls/total_calls:.2%}")
        print(f"  Average duration: {avg_duration:.3f}s")

    except Exception as e:
        print(f"Error: {e}")

    finally:
        await orchestrator.close()


async def main():
    """Run all examples"""
    print("=" * 60)
    print("API Orchestrator - Example Usage")
    print("=" * 60)

    examples = [
        ("Single API Call", example_single_api_call),
        ("Category Search", example_category_search),
        ("Specific APIs", example_specific_apis),
        ("Caching", example_with_caching),
        ("Rate Limiting", example_rate_limiting),
        ("Analytics", example_analytics),
        ("Health Monitoring", example_health_monitoring),
        ("Registry Search", example_registry_search),
        ("OSINT Investigation", example_osint_investigation),
    ]

    for name, example_func in examples:
        try:
            await example_func()
        except Exception as e:
            print(f"Example '{name}' failed: {e}")

        print("\n" + "-" * 60)

    print("\nAll examples completed!")


if __name__ == "__main__":
    asyncio.run(main())
