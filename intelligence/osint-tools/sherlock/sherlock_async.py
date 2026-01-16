"""
Sherlock Async - Asynchronous OSINT Username Search

High-performance async implementation for concurrent platform checking
across hundreds of platforms simultaneously.

Author: Apollo Intelligence Platform
License: MIT
"""

import asyncio
import aiohttp
import time
import logging
from typing import Dict, List, Optional, Set
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
import json
from tqdm.asyncio import tqdm

from sherlock_integration import (
    SherlockResult,
    BatchSearchResult,
    ConfidenceLevel
)


class SherlockAsync:
    """
    Asynchronous Sherlock OSINT engine for high-performance username searches
    """

    def __init__(self,
                 config_path: Optional[str] = None,
                 timeout: int = 10,
                 max_concurrent: int = 50,
                 rate_limit_delay: float = 0.1,
                 elasticsearch_client=None,
                 redis_client=None):
        """
        Initialize async Sherlock engine

        Args:
            config_path: Path to platforms configuration
            timeout: Request timeout in seconds
            max_concurrent: Maximum concurrent requests
            rate_limit_delay: Delay between batches (seconds)
            elasticsearch_client: Elasticsearch client for storage
            redis_client: Redis client for caching
        """
        self.logger = logging.getLogger(__name__)
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.rate_limit_delay = rate_limit_delay
        self.es_client = elasticsearch_client
        self.redis_client = redis_client

        # Load platforms
        if config_path is None:
            config_path = Path(__file__).parent / "platforms_config.json"

        self.platforms = self._load_platforms(config_path)

        # Semaphore for rate limiting
        self.semaphore = asyncio.Semaphore(max_concurrent)

        # Statistics
        self.stats = {
            'requests_sent': 0,
            'requests_failed': 0,
            'platforms_found': 0,
            'total_response_time': 0.0
        }

        self.logger.info(
            f"Sherlock Async initialized: {len(self.platforms)} platforms, "
            f"{max_concurrent} concurrent requests"
        )

    def _load_platforms(self, config_path: Path) -> Dict:
        """Load platform configurations"""
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            self.logger.error(f"Failed to load platforms: {e}")
            return {}

    async def _create_session(self) -> aiohttp.ClientSession:
        """Create aiohttp session with custom headers"""
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'keep-alive'
        }

        timeout_config = aiohttp.ClientTimeout(total=self.timeout)

        connector = aiohttp.TCPConnector(
            limit=100,
            limit_per_host=10,
            ttl_dns_cache=300
        )

        return aiohttp.ClientSession(
            headers=headers,
            timeout=timeout_config,
            connector=connector
        )

    async def _check_platform_async(self,
                                    session: aiohttp.ClientSession,
                                    username: str,
                                    platform_name: str,
                                    platform_config: Dict,
                                    progress_bar=None) -> SherlockResult:
        """
        Asynchronously check if username exists on platform

        Args:
            session: aiohttp session
            username: Username to check
            platform_name: Platform name
            platform_config: Platform configuration
            progress_bar: Optional progress bar to update

        Returns:
            SherlockResult object
        """
        async with self.semaphore:
            start_time = time.time()
            url = platform_config['url'].format(username)

            try:
                async with session.get(url, allow_redirects=True) as response:
                    response_time = time.time() - start_time
                    self.stats['requests_sent'] += 1
                    self.stats['total_response_time'] += response_time

                    # Read response text for content-based detection
                    response_text = await response.text()

                    # Determine existence
                    exists = self._determine_existence_async(
                        response,
                        response_text,
                        platform_config
                    )

                    # Calculate confidence
                    confidence = self._calculate_confidence_async(
                        response,
                        platform_config,
                        exists
                    )

                    if exists:
                        self.stats['platforms_found'] += 1

                    result = SherlockResult(
                        username=username,
                        platform=platform_name,
                        url=url,
                        exists=exists,
                        confidence=confidence,
                        response_time=response_time,
                        http_status=response.status,
                        additional_data={
                            'category': platform_config.get('category', 'unknown'),
                            'final_url': str(response.url)
                        }
                    )

            except asyncio.TimeoutError:
                self.stats['requests_failed'] += 1
                result = SherlockResult(
                    username=username,
                    platform=platform_name,
                    url=url,
                    exists=False,
                    confidence=ConfidenceLevel.UNKNOWN.value,
                    response_time=self.timeout,
                    http_status=0,
                    error_message="Request timeout"
                )

            except aiohttp.ClientError as e:
                self.stats['requests_failed'] += 1
                result = SherlockResult(
                    username=username,
                    platform=platform_name,
                    url=url,
                    exists=False,
                    confidence=ConfidenceLevel.UNKNOWN.value,
                    response_time=time.time() - start_time,
                    http_status=0,
                    error_message=f"Client error: {str(e)}"
                )

            except Exception as e:
                self.stats['requests_failed'] += 1
                self.logger.error(f"Error checking {platform_name}: {e}")
                result = SherlockResult(
                    username=username,
                    platform=platform_name,
                    url=url,
                    exists=False,
                    confidence=ConfidenceLevel.UNKNOWN.value,
                    response_time=time.time() - start_time,
                    http_status=0,
                    error_message=f"Unexpected error: {str(e)}"
                )

            finally:
                if progress_bar:
                    progress_bar.update(1)

                # Rate limiting delay
                await asyncio.sleep(self.rate_limit_delay)

            return result

    def _determine_existence_async(self,
                                   response: aiohttp.ClientResponse,
                                   response_text: str,
                                   config: Dict) -> bool:
        """Determine if username exists based on response"""
        error_type = config.get('errorType', 'status_code')

        if error_type == 'status_code':
            error_code = config.get('errorCode', 404)
            return response.status != error_code

        elif error_type == 'message':
            error_msg = config.get('errorMsg', '')
            return error_msg not in response_text

        elif error_type == 'response_url':
            error_url = config.get('errorUrl', '')
            return error_url not in str(response.url)

        # Default
        return response.status == 200

    def _calculate_confidence_async(self,
                                    response: aiohttp.ClientResponse,
                                    config: Dict,
                                    exists: bool) -> float:
        """Calculate confidence score"""
        if not exists:
            return ConfidenceLevel.UNKNOWN.value

        confidence = ConfidenceLevel.MEDIUM.value

        # Increase for 200 status
        if response.status == 200:
            confidence = ConfidenceLevel.HIGH.value

        # Increase for reliable platforms
        if config.get('reliable', False):
            confidence = min(confidence + 0.1, 1.0)

        # Decrease for redirects
        if len(response.history) > 0:
            confidence = max(confidence - 0.1, 0.5)

        return round(confidence, 2)

    async def search_username_async(self,
                                   username: str,
                                   platforms: Optional[List[str]] = None,
                                   categories: Optional[List[str]] = None,
                                   show_progress: bool = True) -> BatchSearchResult:
        """
        Asynchronously search username across platforms

        Args:
            username: Username to search
            platforms: Specific platforms to search
            categories: Platform categories to filter
            show_progress: Show progress bar

        Returns:
            BatchSearchResult object
        """
        start_time = time.time()

        # Filter platforms
        platforms_to_check = self._filter_platforms(platforms, categories)

        self.logger.info(
            f"Async search: '{username}' across {len(platforms_to_check)} platforms"
        )

        # Reset stats
        self.stats = {
            'requests_sent': 0,
            'requests_failed': 0,
            'platforms_found': 0,
            'total_response_time': 0.0
        }

        # Create session
        async with await self._create_session() as session:
            # Create progress bar
            progress_bar = None
            if show_progress:
                progress_bar = tqdm(
                    total=len(platforms_to_check),
                    desc=f"Searching {username}",
                    unit="platform"
                )

            # Create tasks for all platforms
            tasks = [
                self._check_platform_async(
                    session,
                    username,
                    platform_name,
                    platform_config,
                    progress_bar
                )
                for platform_name, platform_config in platforms_to_check.items()
            ]

            # Execute all tasks concurrently
            results = await asyncio.gather(*tasks, return_exceptions=True)

            if progress_bar:
                progress_bar.close()

        # Filter out exceptions
        valid_results = [
            r for r in results
            if isinstance(r, SherlockResult)
        ]

        # Sort by confidence
        valid_results.sort(key=lambda x: x.confidence, reverse=True)

        # Count found platforms
        found_platforms = sum(1 for r in valid_results if r.exists)

        search_duration = time.time() - start_time

        batch_result = BatchSearchResult(
            username=username,
            total_platforms=len(platforms_to_check),
            found_platforms=found_platforms,
            results=valid_results,
            search_duration=search_duration,
            timestamp=datetime.utcnow().isoformat()
        )

        # Log statistics
        avg_response_time = (
            self.stats['total_response_time'] / self.stats['requests_sent']
            if self.stats['requests_sent'] > 0
            else 0
        )

        self.logger.info(
            f"Async search complete: {found_platforms}/{len(platforms_to_check)} found "
            f"in {search_duration:.2f}s (avg: {avg_response_time:.2f}s/request, "
            f"failed: {self.stats['requests_failed']})"
        )

        return batch_result

    def _filter_platforms(self,
                         platforms: Optional[List[str]] = None,
                         categories: Optional[List[str]] = None) -> Dict:
        """Filter platforms by name or category"""
        if platforms:
            return {
                name: config
                for name, config in self.platforms.items()
                if name in platforms
            }

        if categories:
            return {
                name: config
                for name, config in self.platforms.items()
                if config.get('category', '') in categories
            }

        return self.platforms

    async def batch_search_async(self,
                                usernames: List[str],
                                platforms: Optional[List[str]] = None,
                                categories: Optional[List[str]] = None,
                                delay_between_searches: float = 1.0) -> List[BatchSearchResult]:
        """
        Asynchronously search multiple usernames

        Args:
            usernames: List of usernames
            platforms: Specific platforms to search
            categories: Platform categories
            delay_between_searches: Delay between username searches

        Returns:
            List of BatchSearchResult objects
        """
        results = []

        for i, username in enumerate(usernames, 1):
            self.logger.info(f"Processing username {i}/{len(usernames)}: {username}")

            result = await self.search_username_async(
                username,
                platforms,
                categories
            )

            results.append(result)

            # Delay between searches
            if i < len(usernames):
                await asyncio.sleep(delay_between_searches)

        return results

    def search_username(self, *args, **kwargs) -> BatchSearchResult:
        """
        Synchronous wrapper for async search

        Usage:
            sherlock = SherlockAsync()
            results = sherlock.search_username("username")
        """
        return asyncio.run(self.search_username_async(*args, **kwargs))

    def batch_search(self, *args, **kwargs) -> List[BatchSearchResult]:
        """
        Synchronous wrapper for async batch search

        Usage:
            sherlock = SherlockAsync()
            results = sherlock.batch_search(["user1", "user2"])
        """
        return asyncio.run(self.batch_search_async(*args, **kwargs))

    def get_statistics(self) -> Dict:
        """Get current search statistics"""
        return {
            **self.stats,
            'platforms_available': len(self.platforms),
            'max_concurrent': self.max_concurrent,
            'success_rate': (
                (self.stats['requests_sent'] - self.stats['requests_failed']) /
                self.stats['requests_sent']
                if self.stats['requests_sent'] > 0
                else 0
            )
        }


async def benchmark_async_vs_sync():
    """Benchmark async vs sync performance"""
    import sys
    sys.path.append(str(Path(__file__).parent))

    from sherlock_integration import SherlockOSINT

    test_username = "test_user_benchmark"

    # Test with limited platforms for fair comparison
    test_platforms = [
        "GitHub", "Twitter", "Instagram", "Reddit",
        "LinkedIn", "Medium", "YouTube", "TikTok"
    ]

    print("=" * 60)
    print("SHERLOCK ASYNC VS SYNC BENCHMARK")
    print("=" * 60)

    # Async test
    print("\n[1] Testing ASYNC implementation...")
    sherlock_async = SherlockAsync(max_concurrent=50)
    start_async = time.time()
    result_async = await sherlock_async.search_username_async(
        test_username,
        platforms=test_platforms,
        show_progress=True
    )
    duration_async = time.time() - start_async

    print(f"\nAsync Results:")
    print(f"  Duration: {duration_async:.2f}s")
    print(f"  Platforms checked: {result_async.total_platforms}")
    print(f"  Requests/second: {result_async.total_platforms / duration_async:.2f}")

    # Sync test
    print("\n[2] Testing SYNC implementation...")
    sherlock_sync = SherlockOSINT(max_workers=10)
    start_sync = time.time()
    result_sync = sherlock_sync.search_username(
        test_username,
        platforms=test_platforms
    )
    duration_sync = time.time() - start_sync

    print(f"\nSync Results:")
    print(f"  Duration: {duration_sync:.2f}s")
    print(f"  Platforms checked: {result_sync.total_platforms}")
    print(f"  Requests/second: {result_sync.total_platforms / duration_sync:.2f}")

    # Comparison
    print("\n" + "=" * 60)
    print("COMPARISON:")
    print("=" * 60)
    speedup = duration_sync / duration_async
    print(f"Async is {speedup:.2f}x faster than sync")
    print(f"Time saved: {duration_sync - duration_async:.2f}s")
    print("=" * 60)


async def main():
    """Example usage"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Initialize async Sherlock
    sherlock = SherlockAsync(max_concurrent=50)

    # Search single username
    print("\n" + "=" * 60)
    print("SHERLOCK ASYNC - USERNAME SEARCH")
    print("=" * 60 + "\n")

    results = await sherlock.search_username_async("ruja_ignatova")

    print(f"\nSearch Results for '{results.username}':")
    print(f"  Platforms checked: {results.total_platforms}")
    print(f"  Platforms found: {results.found_platforms}")
    print(f"  Search duration: {results.search_duration:.2f}s")
    print(f"  Speed: {results.total_platforms / results.search_duration:.2f} platforms/sec\n")

    # Show found platforms
    found_results = [r for r in results.results if r.exists]
    if found_results:
        print("Found on platforms:")
        for result in found_results[:10]:  # Show top 10
            print(f"  - {result.platform:20s} {result.url:50s} ({result.confidence:.0%})")

        if len(found_results) > 10:
            print(f"  ... and {len(found_results) - 10} more")

    # Statistics
    stats = sherlock.get_statistics()
    print(f"\nStatistics:")
    print(f"  Success rate: {stats['success_rate']:.1%}")
    print(f"  Failed requests: {stats['requests_failed']}")

    # Run benchmark
    print("\n" + "=" * 60)
    print("Running benchmark...")
    print("=" * 60)
    await benchmark_async_vs_sync()


if __name__ == "__main__":
    asyncio.run(main())
