"""
Dependency Injection
FastAPI dependencies for database, cache, and authentication
"""

from fastapi import Header, HTTPException, status
from typing import Optional, Generator, AsyncGenerator
import logging
import asyncio
from contextlib import asynccontextmanager

import asyncpg
import redis.asyncio as aioredis

from config import settings

logger = logging.getLogger(__name__)

# Connection pools (initialized at startup)
_db_pool: Optional[asyncpg.Pool] = None
_redis_pool: Optional[aioredis.Redis] = None


async def init_db_pool() -> asyncpg.Pool:
    """Initialize PostgreSQL connection pool"""
    global _db_pool
    if _db_pool is None:
        try:
            _db_pool = await asyncpg.create_pool(
                dsn=settings.postgres_url,
                min_size=5,
                max_size=20,
                command_timeout=60,
                max_inactive_connection_lifetime=300,
            )
            logger.info("PostgreSQL connection pool initialized")
        except Exception as e:
            logger.error(f"Failed to initialize PostgreSQL pool: {e}")
            raise
    return _db_pool


async def init_redis_pool() -> aioredis.Redis:
    """Initialize Redis connection pool"""
    global _redis_pool
    if _redis_pool is None:
        try:
            _redis_pool = aioredis.from_url(
                settings.redis_url,
                encoding="utf-8",
                decode_responses=True,
                max_connections=20,
            )
            # Test connection
            await _redis_pool.ping()
            logger.info("Redis connection pool initialized")
        except Exception as e:
            logger.error(f"Failed to initialize Redis pool: {e}")
            raise
    return _redis_pool


async def close_pools():
    """Close all connection pools"""
    global _db_pool, _redis_pool

    if _db_pool:
        await _db_pool.close()
        _db_pool = None
        logger.info("PostgreSQL pool closed")

    if _redis_pool:
        await _redis_pool.close()
        _redis_pool = None
        logger.info("Redis pool closed")


async def get_db() -> AsyncGenerator[asyncpg.Pool, None]:
    """
    Database dependency injection.
    Provides PostgreSQL connection pool to routes.
    """
    global _db_pool

    if _db_pool is None:
        await init_db_pool()

    try:
        yield _db_pool
    except asyncpg.PostgresError as e:
        logger.error(f"Database error: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database temporarily unavailable"
        )


async def get_db_connection():
    """
    Get a single database connection from the pool.
    Use this when you need a dedicated connection for transactions.
    """
    global _db_pool

    if _db_pool is None:
        await init_db_pool()

    async with _db_pool.acquire() as connection:
        yield connection


async def get_cache() -> AsyncGenerator[aioredis.Redis, None]:
    """
    Cache dependency injection.
    Provides Redis connection to routes.
    """
    global _redis_pool

    if _redis_pool is None:
        await init_redis_pool()

    try:
        yield _redis_pool
    except aioredis.RedisError as e:
        logger.error(f"Redis error: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Cache temporarily unavailable"
        )


async def verify_api_key(
    x_api_key: Optional[str] = Header(None),
    required_scopes: Optional[list] = None
) -> dict:
    """
    Verify API key from header with scope-based validation.

    Args:
        x_api_key: API key from X-API-Key header
        required_scopes: Optional list of required scopes

    Returns:
        API key information dict if valid

    Raises:
        HTTPException if API key is invalid
    """
    import hashlib
    import time

    if not x_api_key:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="API key required"
        )

    # Validate API key format
    if not x_api_key.startswith("apollo_") or len(x_api_key) < 40:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid API key format"
        )

    # Hash the API key for lookup
    key_hash = hashlib.sha256(x_api_key.encode()).hexdigest()

    # Check Redis cache first
    global _redis_pool
    if _redis_pool is None:
        await init_redis_pool()

    cached_key = await _redis_pool.get(f"apikey:{key_hash}")
    if cached_key:
        import json
        key_data = json.loads(cached_key)
    else:
        # Lookup in database
        global _db_pool
        if _db_pool is None:
            await init_db_pool()

        async with _db_pool.acquire() as conn:
            row = await conn.fetchrow(
                """SELECT id, user_id, scopes, status, rate_limit, rate_limit_window,
                          expires_at, ip_whitelist
                   FROM api_keys WHERE key_hash = $1""",
                key_hash
            )

            if not row:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Invalid API key"
                )

            key_data = dict(row)

            # Cache the key data (5 minute TTL)
            import json
            await _redis_pool.setex(
                f"apikey:{key_hash}",
                300,
                json.dumps(key_data, default=str)
            )

    # Check key status
    if key_data.get('status') != 'active':
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"API key is {key_data.get('status', 'invalid')}"
        )

    # Check expiration
    if key_data.get('expires_at'):
        from datetime import datetime
        expires_at = key_data['expires_at']
        if isinstance(expires_at, str):
            expires_at = datetime.fromisoformat(expires_at.replace('Z', '+00:00'))
        if expires_at < datetime.now(expires_at.tzinfo):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="API key has expired"
            )

    # Check rate limit
    rate_limit = key_data.get('rate_limit', 100)
    rate_window = key_data.get('rate_limit_window', 60)
    rate_key = f"ratelimit:apikey:{key_data['id']}"

    current_count = await _redis_pool.incr(rate_key)
    if current_count == 1:
        await _redis_pool.expire(rate_key, rate_window)

    if current_count > rate_limit:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded",
            headers={"Retry-After": str(rate_window)}
        )

    # Check required scopes
    if required_scopes:
        key_scopes = key_data.get('scopes', [])
        if isinstance(key_scopes, str):
            import json
            key_scopes = json.loads(key_scopes)

        # admin:full grants all permissions
        if 'admin:full' not in key_scopes:
            missing_scopes = [s for s in required_scopes if s not in key_scopes]
            if missing_scopes:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Missing required scopes: {', '.join(missing_scopes)}"
                )

    return {
        "key_id": key_data.get('id'),
        "user_id": key_data.get('user_id'),
        "scopes": key_data.get('scopes', []),
        "remaining_requests": max(0, rate_limit - current_count)
    }


async def get_current_user(token: str) -> dict:
    """
    Get current user from JWT token.

    Args:
        token: JWT token string

    Returns:
        User information dictionary
    """
    from middleware.auth import decode_token

    payload = decode_token(token)

    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials"
        )

    # In production, fetch user from database
    return {
        "user_id": payload.get("sub"),
        "role": payload.get("role", "user"),
        "email": payload.get("email")
    }


async def get_user_tier(token: str) -> str:
    """
    Get user subscription tier from token.

    Args:
        token: JWT token string

    Returns:
        User tier: free, pro, or enterprise
    """
    user = await get_current_user(token)

    # In production, fetch tier from database
    return user.get("tier", "free")
