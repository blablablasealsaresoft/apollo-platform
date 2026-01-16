"""
Rate Limiter - Token Bucket Algorithm Implementation
Handles per-API and global rate limiting with Redis backend
"""

import time
import redis
import asyncio
from typing import Dict, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)


@dataclass
class RateLimitConfig:
    """Rate limit configuration"""
    requests_per_second: float
    burst_size: int
    time_window: int = 60  # seconds


class TokenBucket:
    """Token bucket algorithm for rate limiting"""

    def __init__(self, rate: float, capacity: int):
        """
        Initialize token bucket

        Args:
            rate: Tokens per second
            capacity: Maximum tokens (burst size)
        """
        self.rate = rate
        self.capacity = capacity
        self.tokens = capacity
        self.last_update = time.time()
        self._lock = asyncio.Lock()

    async def consume(self, tokens: int = 1) -> bool:
        """
        Try to consume tokens

        Args:
            tokens: Number of tokens to consume

        Returns:
            True if tokens available, False otherwise
        """
        async with self._lock:
            now = time.time()
            elapsed = now - self.last_update

            # Refill tokens based on time elapsed
            self.tokens = min(
                self.capacity,
                self.tokens + elapsed * self.rate
            )
            self.last_update = now

            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False

    async def wait_for_token(self, tokens: int = 1) -> float:
        """
        Calculate wait time for tokens

        Args:
            tokens: Number of tokens needed

        Returns:
            Wait time in seconds
        """
        async with self._lock:
            now = time.time()
            elapsed = now - self.last_update

            # Calculate current tokens
            current_tokens = min(
                self.capacity,
                self.tokens + elapsed * self.rate
            )

            if current_tokens >= tokens:
                return 0.0

            # Calculate time needed to accumulate tokens
            tokens_needed = tokens - current_tokens
            wait_time = tokens_needed / self.rate
            return wait_time


class RateLimiter:
    """Redis-backed rate limiter with token bucket algorithm"""

    def __init__(self, redis_client: Optional[redis.Redis] = None):
        """
        Initialize rate limiter

        Args:
            redis_client: Redis client for distributed rate limiting
        """
        self.redis = redis_client
        self.local_buckets: Dict[str, TokenBucket] = {}
        self.api_configs: Dict[str, RateLimitConfig] = {}
        self.global_bucket: Optional[TokenBucket] = None

        # Default global rate limit: 1000 req/sec, burst 5000
        self.set_global_limit(1000.0, 5000)

    def set_global_limit(self, rate: float, burst: int):
        """
        Set global rate limit

        Args:
            rate: Requests per second
            burst: Burst size
        """
        self.global_bucket = TokenBucket(rate, burst)
        logger.info(f"Global rate limit set: {rate} req/s, burst {burst}")

    def register_api(self, api_name: str, config: RateLimitConfig):
        """
        Register API with rate limit configuration

        Args:
            api_name: API identifier
            config: Rate limit configuration
        """
        self.api_configs[api_name] = config
        self.local_buckets[api_name] = TokenBucket(
            config.requests_per_second,
            config.burst_size
        )
        logger.info(f"Registered rate limit for {api_name}: "
                   f"{config.requests_per_second} req/s, "
                   f"burst {config.burst_size}")

    async def acquire(self, api_name: str, tokens: int = 1) -> Tuple[bool, float]:
        """
        Acquire tokens for API call

        Args:
            api_name: API identifier
            tokens: Number of tokens needed

        Returns:
            (success, wait_time) tuple
        """
        # Check global limit first
        if self.global_bucket:
            if not await self.global_bucket.consume(tokens):
                wait_time = await self.global_bucket.wait_for_token(tokens)
                return False, wait_time

        # Check API-specific limit
        if api_name in self.local_buckets:
            bucket = self.local_buckets[api_name]
            if await bucket.consume(tokens):
                return True, 0.0
            else:
                wait_time = await bucket.wait_for_token(tokens)
                return False, wait_time

        # No rate limit configured for this API
        return True, 0.0

    async def wait_and_acquire(self, api_name: str, tokens: int = 1,
                               max_wait: float = 60.0) -> bool:
        """
        Wait for tokens and acquire

        Args:
            api_name: API identifier
            tokens: Number of tokens needed
            max_wait: Maximum wait time in seconds

        Returns:
            True if acquired, False if timeout
        """
        start_time = time.time()

        while True:
            success, wait_time = await self.acquire(api_name, tokens)

            if success:
                return True

            # Check if we've waited too long
            elapsed = time.time() - start_time
            if elapsed + wait_time > max_wait:
                logger.warning(f"Rate limit timeout for {api_name}")
                return False

            # Wait for tokens
            await asyncio.sleep(min(wait_time, max_wait - elapsed))

    async def acquire_redis(self, key: str, limit: int, window: int) -> bool:
        """
        Redis-backed rate limiting using sliding window

        Args:
            key: Rate limit key
            limit: Maximum requests in window
            window: Time window in seconds

        Returns:
            True if within limit, False otherwise
        """
        if not self.redis:
            return True

        try:
            now = time.time()
            window_start = now - window

            # Use pipeline for atomic operations
            pipe = self.redis.pipeline()

            # Remove old entries
            pipe.zremrangebyscore(key, 0, window_start)

            # Count current entries
            pipe.zcard(key)

            # Add current request
            pipe.zadd(key, {str(now): now})

            # Set expiry
            pipe.expire(key, window)

            results = pipe.execute()
            current_count = results[1]

            return current_count < limit

        except Exception as e:
            logger.error(f"Redis rate limit error: {e}")
            return True  # Fail open

    def get_stats(self, api_name: str) -> Dict:
        """
        Get rate limit statistics for API

        Args:
            api_name: API identifier

        Returns:
            Statistics dictionary
        """
        if api_name not in self.local_buckets:
            return {}

        bucket = self.local_buckets[api_name]
        config = self.api_configs.get(api_name)

        return {
            'api_name': api_name,
            'current_tokens': bucket.tokens,
            'capacity': bucket.capacity,
            'rate': bucket.rate,
            'utilization': 1.0 - (bucket.tokens / bucket.capacity),
            'config': {
                'requests_per_second': config.requests_per_second if config else None,
                'burst_size': config.burst_size if config else None
            }
        }

    def get_all_stats(self) -> Dict[str, Dict]:
        """
        Get statistics for all registered APIs

        Returns:
            Dictionary of API statistics
        """
        return {
            api_name: self.get_stats(api_name)
            for api_name in self.local_buckets.keys()
        }

    def reset(self, api_name: Optional[str] = None):
        """
        Reset rate limiter

        Args:
            api_name: Specific API to reset, or None for all
        """
        if api_name:
            if api_name in self.local_buckets:
                config = self.api_configs[api_name]
                self.local_buckets[api_name] = TokenBucket(
                    config.requests_per_second,
                    config.burst_size
                )
                logger.info(f"Reset rate limiter for {api_name}")
        else:
            for api_name, config in self.api_configs.items():
                self.local_buckets[api_name] = TokenBucket(
                    config.requests_per_second,
                    config.burst_size
                )
            logger.info("Reset all rate limiters")


class AdaptiveRateLimiter(RateLimiter):
    """Adaptive rate limiter that adjusts based on API responses"""

    def __init__(self, redis_client: Optional[redis.Redis] = None):
        super().__init__(redis_client)
        self.error_counts: Dict[str, int] = {}
        self.success_counts: Dict[str, int] = {}
        self.adjustment_threshold = 10

    async def record_success(self, api_name: str):
        """Record successful API call"""
        self.success_counts[api_name] = self.success_counts.get(api_name, 0) + 1

        # Increase rate limit if doing well
        if self.success_counts[api_name] % self.adjustment_threshold == 0:
            await self._adjust_rate_up(api_name)

    async def record_error(self, api_name: str, is_rate_limit: bool = False):
        """Record failed API call"""
        self.error_counts[api_name] = self.error_counts.get(api_name, 0) + 1

        # Decrease rate limit if hitting errors
        if is_rate_limit or self.error_counts[api_name] % 3 == 0:
            await self._adjust_rate_down(api_name)

    async def _adjust_rate_up(self, api_name: str, factor: float = 1.1):
        """Increase rate limit"""
        if api_name in self.local_buckets:
            bucket = self.local_buckets[api_name]
            bucket.rate *= factor
            logger.info(f"Increased rate limit for {api_name} to {bucket.rate} req/s")

    async def _adjust_rate_down(self, api_name: str, factor: float = 0.5):
        """Decrease rate limit"""
        if api_name in self.local_buckets:
            bucket = self.local_buckets[api_name]
            bucket.rate *= factor
            bucket.rate = max(bucket.rate, 0.1)  # Minimum 0.1 req/s
            logger.info(f"Decreased rate limit for {api_name} to {bucket.rate} req/s")
