"""
Sherlock OSINT - Example Usage Scripts

Demonstrates various use cases and integration patterns.

Author: Apollo Intelligence Platform
License: MIT
"""

import asyncio
import sys
from pathlib import Path
import json
import time
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from sherlock_integration import SherlockOSINT
from sherlock_async import SherlockAsync


def example_1_basic_search():
    """
    Example 1: Basic Username Search
    """
    print("\n" + "="*70)
    print("EXAMPLE 1: Basic Username Search")
    print("="*70 + "\n")

    # Initialize Sherlock
    sherlock = SherlockOSINT()

    # Search username
    username = "ruja_ignatova"
    print(f"Searching for username: {username}\n")

    results = sherlock.search_username(username)

    # Display results
    print(f"Search completed in {results.search_duration:.2f} seconds")
    print(f"Platforms checked: {results.total_platforms}")
    print(f"Platforms found: {results.found_platforms}\n")

    # Show found accounts
    if results.found_platforms > 0:
        print("Found on platforms:")
        for result in results.results:
            if result.exists:
                print(f"  - {result.platform:20s} {result.url}")

    # Cleanup
    sherlock.close()


def example_2_filtered_search():
    """
    Example 2: Filtered Search (Specific Platforms & Categories)
    """
    print("\n" + "="*70)
    print("EXAMPLE 2: Filtered Search")
    print("="*70 + "\n")

    sherlock = SherlockOSINT()
    username = "test_user"

    # Search specific platforms only
    print("Searching specific platforms only...")
    platforms = ["GitHub", "Twitter", "LinkedIn", "Instagram", "Reddit"]

    results = sherlock.search_username(username, platforms=platforms)

    print(f"\nChecked {len(platforms)} platforms:")
    for result in results.results:
        status = "FOUND" if result.exists else "Not found"
        print(f"  {result.platform:20s} [{status}]")

    # Search by category
    print("\n\nSearching by category (development)...")
    results_dev = sherlock.search_username(username, categories=["development"])

    print(f"\nDevelopment platforms checked: {results_dev.total_platforms}")
    print(f"Found: {results_dev.found_platforms}")

    sherlock.close()


def example_3_batch_search():
    """
    Example 3: Batch Search Multiple Usernames
    """
    print("\n" + "="*70)
    print("EXAMPLE 3: Batch Search")
    print("="*70 + "\n")

    sherlock = SherlockOSINT()

    # List of usernames to search
    usernames = [
        "john_doe",
        "jane_smith",
        "test_user"
    ]

    print(f"Searching {len(usernames)} usernames...\n")

    # Batch search
    batch_results = sherlock.batch_search(usernames)

    # Display summary
    print("\nBatch Search Results:")
    print("-" * 70)

    for result in batch_results:
        success_rate = result.found_platforms / result.total_platforms * 100
        print(f"{result.username:20s} - {result.found_platforms:3d} found ({success_rate:5.1f}%)")

    sherlock.close()


async def example_4_async_search():
    """
    Example 4: High-Performance Async Search
    """
    print("\n" + "="*70)
    print("EXAMPLE 4: Async Search (High Performance)")
    print("="*70 + "\n")

    # Initialize async Sherlock
    sherlock = SherlockAsync(max_concurrent=50)

    username = "test_user"
    print(f"Async search for: {username}\n")

    # Execute async search
    results = await sherlock.search_username_async(
        username,
        show_progress=True
    )

    print(f"\n\nAsync search completed in {results.search_duration:.2f} seconds")
    print(f"Speed: {results.total_platforms / results.search_duration:.2f} platforms/second")

    # Statistics
    stats = sherlock.get_statistics()
    print(f"\nStatistics:")
    print(f"  Requests sent: {stats['requests_sent']}")
    print(f"  Requests failed: {stats['requests_failed']}")
    print(f"  Success rate: {stats['success_rate']:.1%}")


def example_5_export_results():
    """
    Example 5: Exporting Results to Multiple Formats
    """
    print("\n" + "="*70)
    print("EXAMPLE 5: Export Results")
    print("="*70 + "\n")

    sherlock = SherlockOSINT()
    username = "test_user"

    # Search
    results = sherlock.search_username(username)

    # Create export directory
    export_dir = Path("exports")
    export_dir.mkdir(exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Export to JSON
    json_path = export_dir / f"{username}_{timestamp}.json"
    sherlock.export_results(results, format='json', output_path=str(json_path))
    print(f"Exported to JSON: {json_path}")

    # Export to CSV
    csv_path = export_dir / f"{username}_{timestamp}.csv"
    sherlock.export_results(results, format='csv', output_path=str(csv_path))
    print(f"Exported to CSV: {csv_path}")

    # Export to Markdown
    md_path = export_dir / f"{username}_{timestamp}.md"
    sherlock.export_results(results, format='markdown', output_path=str(md_path))
    print(f"Exported to Markdown: {md_path}")

    print("\nAll exports completed successfully!")

    sherlock.close()


def example_6_confidence_filtering():
    """
    Example 6: Filtering by Confidence Score
    """
    print("\n" + "="*70)
    print("EXAMPLE 6: Confidence-Based Filtering")
    print("="*70 + "\n")

    sherlock = SherlockOSINT()
    username = "test_user"

    # Search with minimum confidence threshold
    print("Searching with minimum 75% confidence...")

    results = sherlock.search_username(username, min_confidence=0.75)

    print(f"\nHigh-confidence results ({len([r for r in results.results if r.exists])} found):")

    for result in results.results:
        if result.exists:
            print(f"  {result.platform:20s} {result.url:50s} ({result.confidence:.0%})")

    sherlock.close()


def example_7_integration_elasticsearch():
    """
    Example 7: Elasticsearch Integration
    """
    print("\n" + "="*70)
    print("EXAMPLE 7: Elasticsearch Integration")
    print("="*70 + "\n")

    try:
        from elasticsearch import Elasticsearch

        # Connect to Elasticsearch
        es = Elasticsearch(['http://localhost:9200'])

        # Verify connection
        if not es.ping():
            print("ERROR: Cannot connect to Elasticsearch")
            return

        # Initialize Sherlock with Elasticsearch
        sherlock = SherlockOSINT(elasticsearch_client=es)

        # Search - results automatically stored
        username = "test_user"
        results = sherlock.search_username(username)

        print(f"Search completed and stored in Elasticsearch")
        print(f"Results indexed: sherlock-searches, sherlock-results")

        # Query stored results
        query = {
            "query": {
                "match": {
                    "username": username
                }
            }
        }

        es_results = es.search(index="sherlock-results", body=query)
        print(f"\nElasticsearch query returned {es_results['hits']['total']['value']} results")

        sherlock.close()

    except ImportError:
        print("ERROR: elasticsearch package not installed")
        print("Install with: pip install elasticsearch")
    except Exception as e:
        print(f"ERROR: {e}")


def example_8_integration_redis():
    """
    Example 8: Redis Caching Integration
    """
    print("\n" + "="*70)
    print("EXAMPLE 8: Redis Caching")
    print("="*70 + "\n")

    try:
        import redis

        # Connect to Redis
        redis_client = redis.Redis(host='localhost', port=6379, db=0)

        # Test connection
        redis_client.ping()

        # Initialize Sherlock with Redis
        sherlock = SherlockOSINT(
            redis_client=redis_client,
            enable_cache=True
        )

        username = "test_user"

        # First search - fetch from platforms
        print("First search (no cache)...")
        start = time.time()
        results1 = sherlock.search_username(username, platforms=["GitHub", "Twitter", "LinkedIn"])
        duration1 = time.time() - start

        # Second search - load from cache
        print("\nSecond search (with cache)...")
        start = time.time()
        results2 = sherlock.search_username(username, platforms=["GitHub", "Twitter", "LinkedIn"])
        duration2 = time.time() - start

        # Compare
        print(f"\nPerformance comparison:")
        print(f"  First search:  {duration1:.2f}s")
        print(f"  Second search: {duration2:.2f}s")
        print(f"  Speedup:       {duration1/duration2:.1f}x faster")

        # Statistics
        stats = sherlock.get_statistics()
        print(f"\nCache statistics:")
        print(f"  Cache hits: {stats['cache_hits']}")
        print(f"  Cache misses: {stats['cache_misses']}")
        print(f"  Hit rate: {stats['cache_hit_rate']:.1%}")

        sherlock.close()

    except ImportError:
        print("ERROR: redis package not installed")
        print("Install with: pip install redis")
    except Exception as e:
        print(f"ERROR: {e}")
        print("Make sure Redis server is running on localhost:6379")


async def example_9_async_batch():
    """
    Example 9: Async Batch Search
    """
    print("\n" + "="*70)
    print("EXAMPLE 9: Async Batch Search")
    print("="*70 + "\n")

    sherlock = SherlockAsync(max_concurrent=50)

    usernames = ["user1", "user2", "user3"]

    print(f"Batch searching {len(usernames)} usernames asynchronously...\n")

    # Async batch search
    batch_results = await sherlock.batch_search_async(
        usernames,
        delay_between_searches=0.5  # Small delay between users
    )

    # Display results
    print("\nBatch Results Summary:")
    print("-" * 70)

    for result in batch_results:
        print(f"{result.username:20s} - {result.found_platforms:3d} platforms found in {result.search_duration:.2f}s")


def example_10_category_analysis():
    """
    Example 10: Category-Based Analysis
    """
    print("\n" + "="*70)
    print("EXAMPLE 10: Category-Based Analysis")
    print("="*70 + "\n")

    sherlock = SherlockOSINT()
    username = "test_user"

    categories = {
        'social': 'Social Media',
        'development': 'Development',
        'gaming': 'Gaming',
        'professional': 'Professional',
        'blogging': 'Blogging'
    }

    print(f"Analyzing username '{username}' across categories:\n")

    for category, name in categories.items():
        results = sherlock.search_username(username, categories=[category])

        print(f"{name:20s} - {results.found_platforms:2d}/{results.total_platforms:2d} platforms")

        # Show found platforms
        found = [r for r in results.results if r.exists]
        if found:
            for result in found[:3]:  # Show first 3
                print(f"  - {result.platform}")

    sherlock.close()


def run_all_examples():
    """Run all examples sequentially"""
    examples = [
        ("Basic Search", example_1_basic_search),
        ("Filtered Search", example_2_filtered_search),
        ("Batch Search", example_3_batch_search),
        ("Async Search", lambda: asyncio.run(example_4_async_search())),
        ("Export Results", example_5_export_results),
        ("Confidence Filtering", example_6_confidence_filtering),
        ("Elasticsearch Integration", example_7_integration_elasticsearch),
        ("Redis Caching", example_8_integration_redis),
        ("Async Batch", lambda: asyncio.run(example_9_async_batch())),
        ("Category Analysis", example_10_category_analysis)
    ]

    print("\n" + "="*70)
    print("SHERLOCK OSINT - EXAMPLE SUITE")
    print("="*70)

    for i, (name, func) in enumerate(examples, 1):
        print(f"\n\nRunning Example {i}/{len(examples)}: {name}")
        print("-" * 70)

        try:
            func()
        except KeyboardInterrupt:
            print("\n\nExamples interrupted by user")
            break
        except Exception as e:
            print(f"\nERROR in {name}: {e}")
            import traceback
            traceback.print_exc()

        # Pause between examples
        if i < len(examples):
            time.sleep(2)

    print("\n\n" + "="*70)
    print("All examples completed!")
    print("="*70)


def main():
    """Main entry point"""
    import argparse

    parser = argparse.ArgumentParser(description="Sherlock OSINT Examples")
    parser.add_argument(
        'example',
        nargs='?',
        type=int,
        help='Example number to run (1-10), or omit to run all'
    )
    parser.add_argument(
        '--list',
        action='store_true',
        help='List all available examples'
    )

    args = parser.parse_args()

    if args.list:
        print("\nAvailable Examples:")
        print("  1. Basic Search")
        print("  2. Filtered Search")
        print("  3. Batch Search")
        print("  4. Async Search")
        print("  5. Export Results")
        print("  6. Confidence Filtering")
        print("  7. Elasticsearch Integration")
        print("  8. Redis Caching")
        print("  9. Async Batch")
        print(" 10. Category Analysis")
        print("\nUsage: python examples.py [1-10]")
        return

    if args.example:
        examples = {
            1: example_1_basic_search,
            2: example_2_filtered_search,
            3: example_3_batch_search,
            4: lambda: asyncio.run(example_4_async_search()),
            5: example_5_export_results,
            6: example_6_confidence_filtering,
            7: example_7_integration_elasticsearch,
            8: example_8_integration_redis,
            9: lambda: asyncio.run(example_9_async_batch()),
            10: example_10_category_analysis
        }

        if args.example in examples:
            examples[args.example]()
        else:
            print(f"ERROR: Invalid example number: {args.example}")
            print("Use --list to see available examples")
    else:
        run_all_examples()


if __name__ == "__main__":
    main()
