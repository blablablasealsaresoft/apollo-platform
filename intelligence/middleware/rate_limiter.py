"""
Rate Limiter Middleware
Token bucket algorithm with per-user and per-endpoint limits
"""

from fastapi import Request, HTTPException, status
from typing import Dict, Tuple
from datetime import datetime, timedelta
import time
import logging

logger = logging.getLogger(__name__)


class RateLimiter:
    """
    Rate limiter using token bucket algorithm.
    Implements per-user quotas and per-endpoint limits.
    """

    def __init__(
        self,
        requests_per_minute: int = 60,
        requests_per_hour: int = 1000,
        requests_per_day: int = 10000
    ):
        self.requests_per_minute = requests_per_minute
        self.requests_per_hour = requests_per_hour
        self.requests_per_day = requests_per_day

        # Storage for rate limit tracking
        self.minute_buckets: Dict[str, Tuple[int, float]] = {}
        self.hour_buckets: Dict[str, Tuple[int, float]] = {}
        self.day_buckets: Dict[str, Tuple[int, float]] = {}

    async def __call__(self, request: Request) -> bool:
        """
        Check rate limits for the request.

        Args:
            request: FastAPI request object

        Returns:
            True if request is allowed

        Raises:
            HTTPException if rate limit exceeded
        """
        # Get user identifier (IP address or user ID from token)
        user_id = self._get_user_identifier(request)
        endpoint = f"{request.method}:{request.url.path}"
        key = f"{user_id}:{endpoint}"

        # Check all rate limits
        current_time = time.time()

        # Check per-minute limit
        if not self._check_bucket(
            key,
            self.minute_buckets,
            self.requests_per_minute,
            60,
            current_time
        ):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded: too many requests per minute",
                headers={"Retry-After": "60"}
            )

        # Check per-hour limit
        if not self._check_bucket(
            key,
            self.hour_buckets,
            self.requests_per_hour,
            3600,
            current_time
        ):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded: too many requests per hour",
                headers={"Retry-After": "3600"}
            )

        # Check per-day limit
        if not self._check_bucket(
            key,
            self.day_buckets,
            self.requests_per_day,
            86400,
            current_time
        ):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded: daily quota exhausted",
                headers={"Retry-After": "86400"}
            )

        # Add rate limit headers to response
        remaining_minute = self._get_remaining(key, self.minute_buckets, self.requests_per_minute)
        remaining_hour = self._get_remaining(key, self.hour_buckets, self.requests_per_hour)

        # Store in request state for response headers
        request.state.rate_limit_remaining = remaining_minute
        request.state.rate_limit_limit = self.requests_per_minute

        logger.debug(f"Rate limit check passed for {key}: {remaining_minute}/{self.requests_per_minute}")

        return True

    def _get_user_identifier(self, request: Request) -> str:
        """
        Get unique identifier for user (IP or user ID from token).

        Args:
            request: FastAPI request object

        Returns:
            User identifier string
        """
        # Try to get user ID from token first
        auth_header = request.headers.get("authorization", "")
        if auth_header.startswith("Bearer "):
            # In production, decode token and get user ID
            # For now, use truncated token as identifier
            return f"user_{auth_header[7:20]}"

        # Fall back to IP address
        client_ip = request.client.host if request.client else "unknown"
        return f"ip_{client_ip}"

    def _check_bucket(
        self,
        key: str,
        bucket_dict: Dict[str, Tuple[int, float]],
        limit: int,
        window_seconds: int,
        current_time: float
    ) -> bool:
        """
        Check and update token bucket.

        Args:
            key: Unique key for this user/endpoint combination
            bucket_dict: Dictionary storing bucket state
            limit: Maximum requests in window
            window_seconds: Time window in seconds
            current_time: Current timestamp

        Returns:
            True if request is allowed, False if limit exceeded
        """
        if key not in bucket_dict:
            # First request, initialize bucket
            bucket_dict[key] = (1, current_time)
            return True

        count, last_reset = bucket_dict[key]

        # Check if window has expired
        if current_time - last_reset >= window_seconds:
            # Reset bucket
            bucket_dict[key] = (1, current_time)
            return True

        # Check if limit exceeded
        if count >= limit:
            return False

        # Increment counter
        bucket_dict[key] = (count + 1, last_reset)
        return True

    def _get_remaining(
        self,
        key: str,
        bucket_dict: Dict[str, Tuple[int, float]],
        limit: int
    ) -> int:
        """
        Get remaining requests in bucket.

        Args:
            key: Unique key for this user/endpoint combination
            bucket_dict: Dictionary storing bucket state
            limit: Maximum requests in window

        Returns:
            Number of remaining requests
        """
        if key not in bucket_dict:
            return limit

        count, _ = bucket_dict[key]
        return max(0, limit - count)

    def reset_user_limits(self, user_id: str):
        """
        Reset rate limits for a specific user.
        Useful for testing or admin overrides.

        Args:
            user_id: User identifier to reset
        """
        # Remove all entries for this user
        for bucket in [self.minute_buckets, self.hour_buckets, self.day_buckets]:
            keys_to_remove = [k for k in bucket.keys() if k.startswith(user_id)]
            for key in keys_to_remove:
                del bucket[key]

        logger.info(f"Rate limits reset for user: {user_id}")


# Pre-configured rate limiters for different tiers
class RateLimitTiers:
    """Pre-configured rate limiters for different subscription tiers."""

    FREE = RateLimiter(
        requests_per_minute=10,
        requests_per_hour=100,
        requests_per_day=1000
    )

    PRO = RateLimiter(
        requests_per_minute=60,
        requests_per_hour=1000,
        requests_per_day=10000
    )

    ENTERPRISE = RateLimiter(
        requests_per_minute=300,
        requests_per_hour=10000,
        requests_per_day=100000
    )
