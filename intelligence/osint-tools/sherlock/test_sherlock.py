"""
Sherlock OSINT - Test Suite

Comprehensive test coverage for username search functionality.

Author: Apollo Intelligence Platform
License: MIT
"""

import pytest
import asyncio
import json
from pathlib import Path
import time

from sherlock_integration import (
    SherlockOSINT,
    SherlockResult,
    BatchSearchResult,
    ConfidenceLevel
)
from sherlock_async import SherlockAsync


class TestSherlockIntegration:
    """Test suite for SherlockOSINT class"""

    @pytest.fixture
    def sherlock(self):
        """Create Sherlock instance for testing"""
        return SherlockOSINT(max_workers=10)

    @pytest.fixture
    def test_username(self):
        """Test username"""
        return "test_sherlock_user"

    def test_initialization(self, sherlock):
        """Test Sherlock initialization"""
        assert sherlock is not None
        assert len(sherlock.platforms) > 0
        assert sherlock.timeout == 10
        assert sherlock.max_workers == 10

    def test_platform_loading(self, sherlock):
        """Test platform configuration loading"""
        assert "GitHub" in sherlock.platforms
        assert "Twitter" in sherlock.platforms
        assert "Instagram" in sherlock.platforms

        github_config = sherlock.platforms["GitHub"]
        assert "url" in github_config
        assert "errorType" in github_config
        assert "{}" in github_config["url"]

    def test_search_username(self, sherlock, test_username):
        """Test basic username search"""
        results = sherlock.search_username(test_username)

        assert isinstance(results, BatchSearchResult)
        assert results.username == test_username
        assert results.total_platforms > 0
        assert len(results.results) > 0
        assert results.search_duration > 0

    def test_search_specific_platforms(self, sherlock, test_username):
        """Test search with specific platforms"""
        platforms = ["GitHub", "Twitter", "LinkedIn"]

        results = sherlock.search_username(
            test_username,
            platforms=platforms
        )

        assert results.total_platforms == len(platforms)
        assert all(r.platform in platforms for r in results.results)

    def test_search_by_category(self, sherlock, test_username):
        """Test search by category"""
        results = sherlock.search_username(
            test_username,
            categories=["development"]
        )

        assert results.total_platforms > 0

        # Verify all results are development category
        for result in results.results:
            if result.additional_data:
                category = result.additional_data.get('category', '')
                assert category == 'development'

    def test_confidence_filtering(self, sherlock, test_username):
        """Test minimum confidence threshold"""
        results = sherlock.search_username(
            test_username,
            min_confidence=0.8
        )

        # All found results should have confidence >= 0.8
        for result in results.results:
            if result.exists:
                assert result.confidence >= 0.8

    def test_batch_search(self, sherlock):
        """Test batch username search"""
        usernames = ["user1", "user2", "user3"]

        batch_results = sherlock.batch_search(usernames)

        assert len(batch_results) == len(usernames)
        assert all(isinstance(r, BatchSearchResult) for r in batch_results)

    def test_export_json(self, sherlock, test_username, tmp_path):
        """Test JSON export"""
        results = sherlock.search_username(
            test_username,
            platforms=["GitHub", "Twitter"]
        )

        output_file = tmp_path / "test_results.json"
        exported_path = sherlock.export_results(
            results,
            format='json',
            output_path=str(output_file)
        )

        assert Path(exported_path).exists()

        # Verify JSON content
        with open(exported_path, 'r') as f:
            data = json.load(f)
            assert data['username'] == test_username
            assert 'results' in data

    def test_export_csv(self, sherlock, test_username, tmp_path):
        """Test CSV export"""
        results = sherlock.search_username(
            test_username,
            platforms=["GitHub"]
        )

        output_file = tmp_path / "test_results.csv"
        exported_path = sherlock.export_results(
            results,
            format='csv',
            output_path=str(output_file)
        )

        assert Path(exported_path).exists()

        # Verify CSV has content
        with open(exported_path, 'r') as f:
            content = f.read()
            assert 'Username' in content
            assert 'Platform' in content

    def test_export_markdown(self, sherlock, test_username, tmp_path):
        """Test Markdown export"""
        results = sherlock.search_username(
            test_username,
            platforms=["GitHub"]
        )

        output_file = tmp_path / "test_results.md"
        exported_path = sherlock.export_results(
            results,
            format='markdown',
            output_path=str(output_file)
        )

        assert Path(exported_path).exists()

        # Verify Markdown has content
        with open(exported_path, 'r') as f:
            content = f.read()
            assert test_username in content
            assert 'Sherlock OSINT Report' in content

    def test_statistics(self, sherlock, test_username):
        """Test statistics tracking"""
        # Perform search
        sherlock.search_username(test_username, platforms=["GitHub"])

        stats = sherlock.get_statistics()

        assert stats['total_searches'] > 0
        assert stats['total_platforms_checked'] > 0
        assert 'cache_hits' in stats
        assert 'cache_misses' in stats

    def test_result_structure(self, sherlock, test_username):
        """Test SherlockResult structure"""
        results = sherlock.search_username(
            test_username,
            platforms=["GitHub"]
        )

        result = results.results[0]

        assert isinstance(result, SherlockResult)
        assert result.username == test_username
        assert result.platform == "GitHub"
        assert isinstance(result.url, str)
        assert isinstance(result.exists, bool)
        assert 0.0 <= result.confidence <= 1.0
        assert result.response_time >= 0
        assert isinstance(result.http_status, int)


class TestSherlockAsync:
    """Test suite for SherlockAsync class"""

    @pytest.fixture
    def sherlock_async(self):
        """Create async Sherlock instance"""
        return SherlockAsync(max_concurrent=10)

    @pytest.fixture
    def test_username(self):
        """Test username"""
        return "test_async_user"

    @pytest.mark.asyncio
    async def test_async_search(self, sherlock_async, test_username):
        """Test async username search"""
        results = await sherlock_async.search_username_async(
            test_username,
            show_progress=False
        )

        assert isinstance(results, BatchSearchResult)
        assert results.username == test_username
        assert results.total_platforms > 0

    @pytest.mark.asyncio
    async def test_async_specific_platforms(self, sherlock_async, test_username):
        """Test async search with specific platforms"""
        platforms = ["GitHub", "Twitter"]

        results = await sherlock_async.search_username_async(
            test_username,
            platforms=platforms,
            show_progress=False
        )

        assert results.total_platforms == len(platforms)

    @pytest.mark.asyncio
    async def test_async_batch_search(self, sherlock_async):
        """Test async batch search"""
        usernames = ["user1", "user2"]

        batch_results = await sherlock_async.batch_search_async(
            usernames,
            delay_between_searches=0.1
        )

        assert len(batch_results) == len(usernames)

    @pytest.mark.asyncio
    async def test_async_performance(self, sherlock_async, test_username):
        """Test async performance is faster than sync"""
        platforms = ["GitHub", "Twitter", "LinkedIn", "Reddit"]

        # Async search
        start_async = time.time()
        results_async = await sherlock_async.search_username_async(
            test_username,
            platforms=platforms,
            show_progress=False
        )
        duration_async = time.time() - start_async

        # Verify async completed
        assert results_async.total_platforms == len(platforms)
        assert duration_async > 0

        # Async should be reasonably fast
        # (Platform checks should be concurrent)
        # Expect less than 15 seconds for 4 platforms
        assert duration_async < 15

    def test_sync_wrapper(self, sherlock_async, test_username):
        """Test synchronous wrapper for async methods"""
        # Use sync wrapper
        results = sherlock_async.search_username(
            test_username,
            platforms=["GitHub"]
        )

        assert isinstance(results, BatchSearchResult)

    @pytest.mark.asyncio
    async def test_async_statistics(self, sherlock_async, test_username):
        """Test async statistics"""
        await sherlock_async.search_username_async(
            test_username,
            platforms=["GitHub"],
            show_progress=False
        )

        stats = sherlock_async.get_statistics()

        assert stats['requests_sent'] > 0
        assert 'success_rate' in stats
        assert 0 <= stats['success_rate'] <= 1


class TestConfidenceScoring:
    """Test confidence scoring logic"""

    @pytest.fixture
    def sherlock(self):
        return SherlockOSINT()

    def test_confidence_levels(self):
        """Test confidence level enum"""
        assert ConfidenceLevel.CONFIRMED.value == 0.95
        assert ConfidenceLevel.HIGH.value == 0.85
        assert ConfidenceLevel.MEDIUM.value == 0.70
        assert ConfidenceLevel.LOW.value == 0.50
        assert ConfidenceLevel.UNKNOWN.value == 0.0

    def test_confidence_calculation(self, sherlock):
        """Test confidence score calculation"""
        # Mock response object
        class MockResponse:
            def __init__(self, status_code):
                self.status_code = status_code
                self.history = []

        config = {"reliable": True}

        # Test high confidence (200 + reliable)
        response = MockResponse(200)
        confidence = sherlock._calculate_confidence(response, config, exists=True)
        assert confidence >= 0.85

        # Test unknown (doesn't exist)
        confidence = sherlock._calculate_confidence(response, config, exists=False)
        assert confidence == 0.0


class TestCaching:
    """Test caching functionality"""

    @pytest.fixture
    def sherlock_with_mock_redis(self):
        """Create Sherlock with mock Redis"""
        class MockRedis:
            def __init__(self):
                self.store = {}

            def get(self, key):
                return self.store.get(key)

            def setex(self, key, ttl, value):
                self.store[key] = value

        redis_mock = MockRedis()
        return SherlockOSINT(
            redis_client=redis_mock,
            enable_cache=True
        )

    def test_cache_key_generation(self, sherlock_with_mock_redis):
        """Test cache key generation"""
        key1 = sherlock_with_mock_redis._get_cache_key("user1", "GitHub")
        key2 = sherlock_with_mock_redis._get_cache_key("user1", "GitHub")
        key3 = sherlock_with_mock_redis._get_cache_key("user2", "GitHub")

        assert key1 == key2  # Same input = same key
        assert key1 != key3  # Different input = different key


class TestPlatformDetection:
    """Test platform detection methods"""

    @pytest.fixture
    def sherlock(self):
        return SherlockOSINT()

    def test_status_code_detection(self, sherlock):
        """Test status code detection method"""
        class MockResponse:
            def __init__(self, status_code):
                self.status_code = status_code
                self.text = ""
                self.url = ""

        config = {
            "errorType": "status_code",
            "errorCode": 404
        }

        # User exists (200)
        response = MockResponse(200)
        assert sherlock._determine_existence(response, config) is True

        # User doesn't exist (404)
        response = MockResponse(404)
        assert sherlock._determine_existence(response, config) is False

    def test_message_detection(self, sherlock):
        """Test error message detection"""
        class MockResponse:
            def __init__(self, text):
                self.status_code = 200
                self.text = text
                self.url = ""

        config = {
            "errorType": "message",
            "errorMsg": "User not found"
        }

        # User exists
        response = MockResponse("Welcome to the profile page")
        assert sherlock._determine_existence(response, config) is True

        # User doesn't exist
        response = MockResponse("Error: User not found")
        assert sherlock._determine_existence(response, config) is False


class TestErrorHandling:
    """Test error handling and edge cases"""

    @pytest.fixture
    def sherlock(self):
        return SherlockOSINT(timeout=5)

    def test_empty_username(self, sherlock):
        """Test handling of empty username"""
        # Should still execute but might not find anything
        results = sherlock.search_username(
            "",
            platforms=["GitHub"]
        )

        assert isinstance(results, BatchSearchResult)

    def test_invalid_platform_filter(self, sherlock):
        """Test filtering with non-existent platform"""
        results = sherlock.search_username(
            "test",
            platforms=["NonExistentPlatform123"]
        )

        assert results.total_platforms == 0

    def test_timeout_handling(self, sherlock):
        """Test timeout handling"""
        # Use very short timeout to trigger timeout
        sherlock.timeout = 0.001

        results = sherlock.search_username(
            "test",
            platforms=["GitHub"]
        )

        # Should complete without crashing
        assert isinstance(results, BatchSearchResult)


def test_module_imports():
    """Test that all modules can be imported"""
    try:
        from sherlock_integration import SherlockOSINT
        from sherlock_async import SherlockAsync

        assert SherlockOSINT is not None
        assert SherlockAsync is not None
    except ImportError as e:
        pytest.fail(f"Failed to import modules: {e}")


def test_configuration_file_exists():
    """Test that platforms configuration file exists"""
    config_path = Path(__file__).parent / "platforms_config.json"
    assert config_path.exists()

    # Verify JSON is valid
    with open(config_path, 'r') as f:
        data = json.load(f)
        assert len(data) > 0


# Performance benchmarks
@pytest.mark.benchmark
class TestPerformance:
    """Performance benchmarks"""

    @pytest.mark.asyncio
    async def test_async_faster_than_sync(self):
        """Benchmark: Async should be faster than sync"""
        platforms = ["GitHub", "Twitter", "LinkedIn", "Reddit", "Instagram"]
        username = "benchmark_user"

        # Async benchmark
        sherlock_async = SherlockAsync(max_concurrent=50)
        start_async = time.time()
        await sherlock_async.search_username_async(
            username,
            platforms=platforms,
            show_progress=False
        )
        duration_async = time.time() - start_async

        # Sync benchmark
        sherlock_sync = SherlockOSINT(max_workers=5)
        start_sync = time.time()
        sherlock_sync.search_username(username, platforms=platforms)
        duration_sync = time.time() - start_sync

        # Async should be significantly faster
        print(f"\nAsync: {duration_async:.2f}s, Sync: {duration_sync:.2f}s")
        print(f"Speedup: {duration_sync/duration_async:.2f}x")

        # Verify async is faster (with some tolerance)
        assert duration_async < duration_sync * 0.8  # At least 20% faster


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
