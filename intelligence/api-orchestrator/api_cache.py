"""
API Response Caching System
Redis-based caching with TTL management and cache warming
"""

import json
import hashlib
import time
import asyncio
from typing import Optional, Any, Dict, List, Callable
from datetime import datetime, timedelta
from dataclasses import dataclass
import logging
import pickle

try:
    import redis.asyncio as redis
except ImportError:
    import redis

logger = logging.getLogger(__name__)


@dataclass
class CacheConfig:
    """Cache configuration"""
    default_ttl: int = 3600  # 1 hour
    max_ttl: int = 86400  # 24 hours
    enable_compression: bool = False
    namespace: str = "api_cache"


class CacheKey:
    """Cache key generator"""

    @staticmethod
    def generate(api_name: str, endpoint: str, params: Dict = None) -> str:
        """
        Generate cache key from API call parameters

        Args:
            api_name: API identifier
            endpoint: API endpoint
            params: Request parameters

        Returns:
            Cache key string
        """
        key_parts = [api_name, endpoint]

        if params:
            # Sort params for consistent key generation
            sorted_params = json.dumps(params, sort_keys=True)
            key_parts.append(sorted_params)

        key_string = ":".join(key_parts)
        key_hash = hashlib.sha256(key_string.encode()).hexdigest()

        return f"api_cache:{api_name}:{key_hash}"

    @staticmethod
    def pattern(api_name: Optional[str] = None) -> str:
        """
        Generate cache key pattern for scanning

        Args:
            api_name: API identifier or None for all

        Returns:
            Key pattern
        """
        if api_name:
            return f"api_cache:{api_name}:*"
        return "api_cache:*"


class APICache:
    """Redis-based API response cache"""

    def __init__(
        self,
        redis_client: Optional[redis.Redis] = None,
        config: Optional[CacheConfig] = None
    ):
        """
        Initialize API cache

        Args:
            redis_client: Redis client
            config: Cache configuration
        """
        self.redis = redis_client
        self.config = config or CacheConfig()
        self.local_cache: Dict[str, tuple] = {}  # Fallback to memory
        self.hit_count = 0
        self.miss_count = 0
        self.warming_tasks: Dict[str, asyncio.Task] = {}

    async def get(self, key: str) -> Optional[Any]:
        """
        Get value from cache

        Args:
            key: Cache key

        Returns:
            Cached value or None
        """
        # Try Redis first
        if self.redis:
            try:
                value = await self._get_redis(key)
                if value is not None:
                    self.hit_count += 1
                    return value
            except Exception as e:
                logger.error(f"Redis get error: {e}")

        # Fallback to local cache
        if key in self.local_cache:
            value, expiry = self.local_cache[key]
            if expiry > time.time():
                self.hit_count += 1
                return value
            else:
                del self.local_cache[key]

        self.miss_count += 1
        return None

    async def set(
        self,
        key: str,
        value: Any,
        ttl: Optional[int] = None
    ) -> bool:
        """
        Set value in cache

        Args:
            key: Cache key
            value: Value to cache
            ttl: Time to live in seconds

        Returns:
            True if successful
        """
        ttl = ttl or self.config.default_ttl
        ttl = min(ttl, self.config.max_ttl)

        # Try Redis first
        if self.redis:
            try:
                await self._set_redis(key, value, ttl)
                return True
            except Exception as e:
                logger.error(f"Redis set error: {e}")

        # Fallback to local cache
        expiry = time.time() + ttl
        self.local_cache[key] = (value, expiry)
        return True

    async def delete(self, key: str) -> bool:
        """
        Delete value from cache

        Args:
            key: Cache key

        Returns:
            True if deleted
        """
        deleted = False

        # Delete from Redis
        if self.redis:
            try:
                result = await self.redis.delete(key)
                deleted = result > 0
            except Exception as e:
                logger.error(f"Redis delete error: {e}")

        # Delete from local cache
        if key in self.local_cache:
            del self.local_cache[key]
            deleted = True

        return deleted

    async def clear(self, pattern: Optional[str] = None):
        """
        Clear cache entries matching pattern

        Args:
            pattern: Key pattern or None for all
        """
        pattern = pattern or "api_cache:*"

        # Clear from Redis
        if self.redis:
            try:
                cursor = 0
                while True:
                    cursor, keys = await self.redis.scan(
                        cursor,
                        match=pattern,
                        count=100
                    )

                    if keys:
                        await self.redis.delete(*keys)

                    if cursor == 0:
                        break
            except Exception as e:
                logger.error(f"Redis clear error: {e}")

        # Clear from local cache
        keys_to_delete = [
            key for key in self.local_cache.keys()
            if self._match_pattern(key, pattern)
        ]
        for key in keys_to_delete:
            del self.local_cache[key]

        logger.info(f"Cleared cache with pattern: {pattern}")

    async def get_or_fetch(
        self,
        key: str,
        fetch_func: Callable,
        ttl: Optional[int] = None,
        *args,
        **kwargs
    ) -> Any:
        """
        Get from cache or fetch and cache

        Args:
            key: Cache key
            fetch_func: Function to fetch data
            ttl: Time to live
            *args: Function arguments
            **kwargs: Function keyword arguments

        Returns:
            Cached or fetched value
        """
        # Try cache first
        value = await self.get(key)
        if value is not None:
            return value

        # Fetch data
        if asyncio.iscoroutinefunction(fetch_func):
            value = await fetch_func(*args, **kwargs)
        else:
            value = fetch_func(*args, **kwargs)

        # Cache the result
        if value is not None:
            await self.set(key, value, ttl)

        return value

    async def warm(
        self,
        key: str,
        fetch_func: Callable,
        ttl: Optional[int] = None,
        interval: Optional[int] = None,
        *args,
        **kwargs
    ):
        """
        Warm cache by periodically refreshing

        Args:
            key: Cache key
            fetch_func: Function to fetch data
            ttl: Time to live
            interval: Refresh interval in seconds
            *args: Function arguments
            **kwargs: Function keyword arguments
        """
        interval = interval or (ttl or self.config.default_ttl) // 2

        async def refresh_loop():
            while True:
                try:
                    if asyncio.iscoroutinefunction(fetch_func):
                        value = await fetch_func(*args, **kwargs)
                    else:
                        value = fetch_func(*args, **kwargs)

                    await self.set(key, value, ttl)
                    logger.debug(f"Warmed cache for key: {key}")

                except Exception as e:
                    logger.error(f"Cache warming error for {key}: {e}")

                await asyncio.sleep(interval)

        # Cancel existing warming task
        if key in self.warming_tasks:
            self.warming_tasks[key].cancel()

        # Start new warming task
        task = asyncio.create_task(refresh_loop())
        self.warming_tasks[key] = task
        logger.info(f"Started cache warming for: {key}")

    async def stop_warming(self, key: str):
        """Stop cache warming for key"""
        if key in self.warming_tasks:
            self.warming_tasks[key].cancel()
            del self.warming_tasks[key]
            logger.info(f"Stopped cache warming for: {key}")

    async def _get_redis(self, key: str) -> Optional[Any]:
        """Get from Redis"""
        value = await self.redis.get(key)
        if value is None:
            return None

        try:
            return pickle.loads(value)
        except Exception:
            return value.decode('utf-8')

    async def _set_redis(self, key: str, value: Any, ttl: int):
        """Set in Redis"""
        try:
            serialized = pickle.dumps(value)
        except Exception:
            serialized = str(value).encode('utf-8')

        await self.redis.setex(key, ttl, serialized)

    def _match_pattern(self, key: str, pattern: str) -> bool:
        """Simple pattern matching"""
        if pattern == "*":
            return True

        if pattern.endswith("*"):
            prefix = pattern[:-1]
            return key.startswith(prefix)

        return key == pattern

    def get_stats(self) -> Dict:
        """Get cache statistics"""
        total_requests = self.hit_count + self.miss_count
        hit_rate = (
            self.hit_count / total_requests
            if total_requests > 0 else 0
        )

        stats = {
            'hits': self.hit_count,
            'misses': self.miss_count,
            'total_requests': total_requests,
            'hit_rate': hit_rate,
            'local_cache_size': len(self.local_cache),
            'warming_tasks': len(self.warming_tasks)
        }

        return stats

    async def get_redis_stats(self) -> Dict:
        """Get Redis cache statistics"""
        if not self.redis:
            return {}

        try:
            info = await self.redis.info('stats')
            keyspace = await self.redis.info('keyspace')

            return {
                'redis_hits': info.get('keyspace_hits', 0),
                'redis_misses': info.get('keyspace_misses', 0),
                'total_keys': sum(
                    db_info.get('keys', 0)
                    for db_info in keyspace.values()
                ),
                'connected': True
            }
        except Exception as e:
            logger.error(f"Redis stats error: {e}")
            return {'connected': False}

    def reset_stats(self):
        """Reset cache statistics"""
        self.hit_count = 0
        self.miss_count = 0


class CacheInvalidator:
    """Cache invalidation strategies"""

    def __init__(self, cache: APICache):
        self.cache = cache
        self.invalidation_rules: Dict[str, Dict] = {}

    def register_rule(
        self,
        name: str,
        pattern: str,
        strategy: str = "ttl",
        **kwargs
    ):
        """
        Register invalidation rule

        Args:
            name: Rule name
            pattern: Cache key pattern
            strategy: Invalidation strategy (ttl, event, manual)
            **kwargs: Strategy-specific parameters
        """
        self.invalidation_rules[name] = {
            'pattern': pattern,
            'strategy': strategy,
            'params': kwargs
        }
        logger.info(f"Registered cache invalidation rule: {name}")

    async def invalidate(self, rule_name: str):
        """Execute invalidation rule"""
        if rule_name not in self.invalidation_rules:
            logger.warning(f"Unknown invalidation rule: {rule_name}")
            return

        rule = self.invalidation_rules[rule_name]
        pattern = rule['pattern']

        await self.cache.clear(pattern)
        logger.info(f"Invalidated cache using rule: {rule_name}")

    async def invalidate_all(self):
        """Execute all invalidation rules"""
        for rule_name in self.invalidation_rules.keys():
            await self.invalidate(rule_name)


class MultiLevelCache:
    """Multi-level cache (L1: memory, L2: Redis)"""

    def __init__(
        self,
        redis_client: Optional[redis.Redis] = None,
        l1_size: int = 1000
    ):
        """
        Initialize multi-level cache

        Args:
            redis_client: Redis client for L2
            l1_size: Maximum L1 cache entries
        """
        self.l1_cache: Dict[str, tuple] = {}
        self.l1_size = l1_size
        self.l2_cache = APICache(redis_client) if redis_client else None

    async def get(self, key: str) -> Optional[Any]:
        """Get from cache (L1 then L2)"""
        # Check L1
        if key in self.l1_cache:
            value, expiry = self.l1_cache[key]
            if expiry > time.time():
                return value
            del self.l1_cache[key]

        # Check L2
        if self.l2_cache:
            value = await self.l2_cache.get(key)
            if value is not None:
                # Promote to L1
                self._set_l1(key, value, 300)  # 5 min in L1
                return value

        return None

    async def set(self, key: str, value: Any, ttl: int = 3600):
        """Set in both cache levels"""
        # Set in L1
        self._set_l1(key, value, min(ttl, 300))

        # Set in L2
        if self.l2_cache:
            await self.l2_cache.set(key, value, ttl)

    def _set_l1(self, key: str, value: Any, ttl: int):
        """Set in L1 cache with LRU eviction"""
        if len(self.l1_cache) >= self.l1_size:
            # Evict oldest entry
            oldest_key = min(
                self.l1_cache.keys(),
                key=lambda k: self.l1_cache[k][1]
            )
            del self.l1_cache[oldest_key]

        expiry = time.time() + ttl
        self.l1_cache[key] = (value, expiry)
