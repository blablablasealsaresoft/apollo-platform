"""
API Orchestrator - Central Management for 1000+ APIs
Handles rate limiting, caching, retry logic, and circuit breaking
"""

import asyncio
import hashlib
import logging
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import aiohttp
from redis import Redis

logger = logging.getLogger(__name__)


@dataclass
class APIConfig:
    """Configuration for an API"""
    name: str
    base_url: str
    rate_limit: int  # requests per minute
    requires_auth: bool = False
    auth_type: str = 'api_key'  # api_key, bearer, oauth
    auth_header: str = 'Authorization'
    timeout: int = 30
    retry_count: int = 3
    retry_delay: float = 1.0
    circuit_breaker_threshold: int = 5
    circuit_breaker_timeout: int = 60
    cache_ttl: int = 300  # seconds
    headers: Dict[str, str] = field(default_factory=dict)


@dataclass
class APIResponse:
    """Response from API call"""
    success: bool
    status_code: Optional[int]
    data: Any
    error: Optional[str]
    cached: bool
    response_time_ms: float
    api_name: str
    timestamp: datetime


class RateLimiter:
    """Token bucket rate limiter"""

    def __init__(self, redis_client: Redis):
        self.redis = redis_client

    async def check_rate_limit(
        self,
        api_name: str,
        rate_limit: int
    ) -> bool:
        """
        Check if request is within rate limit

        Args:
            api_name: Name of the API
            rate_limit: Requests per minute

        Returns:
            True if request is allowed
        """
        key = f"rate_limit:{api_name}:minute"
        current_minute = datetime.now().strftime("%Y%m%d%H%M")
        full_key = f"{key}:{current_minute}"

        current = self.redis.get(full_key)
        if current is None:
            self.redis.setex(full_key, 60, 1)
            return True

        current_count = int(current)
        if current_count < rate_limit:
            self.redis.incr(full_key)
            return True

        return False

    async def wait_for_rate_limit(
        self,
        api_name: str,
        rate_limit: int
    ):
        """Wait until rate limit allows request"""
        while not await self.check_rate_limit(api_name, rate_limit):
            await asyncio.sleep(1)


class CircuitBreaker:
    """Circuit breaker pattern for API resilience"""

    def __init__(self, redis_client: Redis):
        self.redis = redis_client

    def is_open(self, api_name: str) -> bool:
        """Check if circuit breaker is open (blocking requests)"""
        key = f"circuit_breaker:{api_name}:open"
        return self.redis.get(key) is not None

    def record_failure(
        self,
        api_name: str,
        threshold: int,
        timeout: int
    ):
        """Record API failure"""
        failure_key = f"circuit_breaker:{api_name}:failures"
        failures = self.redis.incr(failure_key)
        self.redis.expire(failure_key, 60)

        if failures >= threshold:
            # Open circuit breaker
            open_key = f"circuit_breaker:{api_name}:open"
            self.redis.setex(open_key, timeout, 1)
            logger.warning(
                f"Circuit breaker opened for {api_name} "
                f"after {failures} failures"
            )

    def record_success(self, api_name: str):
        """Record API success"""
        failure_key = f"circuit_breaker:{api_name}:failures"
        self.redis.delete(failure_key)


class APIOrchestrator:
    """
    Orchestrates calls to 1000+ public APIs
    Features: rate limiting, caching, retry logic, circuit breaking
    """

    def __init__(
        self,
        redis_client: Optional[Redis] = None,
        redis_host: str = 'localhost',
        redis_port: int = 6379
    ):
        """
        Initialize API orchestrator

        Args:
            redis_client: Existing Redis client
            redis_host: Redis host
            redis_port: Redis port
        """
        if redis_client:
            self.redis = redis_client
        else:
            self.redis = Redis(host=redis_host, port=redis_port, decode_responses=True)

        self.rate_limiter = RateLimiter(self.redis)
        self.circuit_breaker = CircuitBreaker(self.redis)
        self.apis: Dict[str, APIConfig] = {}
        self._load_api_registry()

    def _load_api_registry(self):
        """Load registry of public APIs"""
        # Intelligence & OSINT APIs
        self.register_api(APIConfig(
            name='shodan',
            base_url='https://api.shodan.io',
            rate_limit=1,
            requires_auth=True
        ))

        self.register_api(APIConfig(
            name='censys',
            base_url='https://search.censys.io/api',
            rate_limit=5,
            requires_auth=True
        ))

        self.register_api(APIConfig(
            name='virustotal',
            base_url='https://www.virustotal.com/api/v3',
            rate_limit=4,
            requires_auth=True,
            auth_type='bearer'
        ))

        self.register_api(APIConfig(
            name='dehashed',
            base_url='https://api.dehashed.com',
            rate_limit=10,
            requires_auth=True
        ))

        self.register_api(APIConfig(
            name='haveibeenpwned',
            base_url='https://haveibeenpwned.com/api/v3',
            rate_limit=1,
            requires_auth=True
        ))

        # Blockchain APIs (already covered in blockchain_engine.py)
        self.register_api(APIConfig(
            name='blockchain_info',
            base_url='https://blockchain.info',
            rate_limit=10,
            requires_auth=False
        ))

        self.register_api(APIConfig(
            name='etherscan',
            base_url='https://api.etherscan.io/api',
            rate_limit=5,
            requires_auth=True
        ))

        # Geolocation APIs
        self.register_api(APIConfig(
            name='ipapi',
            base_url='http://ip-api.com/json',
            rate_limit=45,
            requires_auth=False
        ))

        self.register_api(APIConfig(
            name='ipinfo',
            base_url='https://ipinfo.io',
            rate_limit=50,
            requires_auth=False
        ))

        # Social Media APIs
        self.register_api(APIConfig(
            name='twitter',
            base_url='https://api.twitter.com/2',
            rate_limit=15,
            requires_auth=True,
            auth_type='bearer'
        ))

        # DNS/Domain APIs
        self.register_api(APIConfig(
            name='securitytrails',
            base_url='https://api.securitytrails.com/v1',
            rate_limit=50,
            requires_auth=True
        ))

        # Threat Intelligence APIs
        self.register_api(APIConfig(
            name='alienvault',
            base_url='https://otx.alienvault.com/api/v1',
            rate_limit=10,
            requires_auth=True
        ))

        self.register_api(APIConfig(
            name='threatcrowd',
            base_url='https://www.threatcrowd.org/searchApi/v2',
            rate_limit=10,
            requires_auth=False
        ))

        # ... Add 1000+ more APIs

    def register_api(self, config: APIConfig):
        """Register a new API"""
        self.apis[config.name] = config
        logger.info(f"Registered API: {config.name}")

    async def call_api(
        self,
        api_name: str,
        endpoint: str,
        method: str = 'GET',
        params: Optional[Dict] = None,
        data: Optional[Dict] = None,
        headers: Optional[Dict] = None,
        api_key: Optional[str] = None,
        use_cache: bool = True
    ) -> APIResponse:
        """
        Call an API with full orchestration

        Args:
            api_name: Name of registered API
            endpoint: API endpoint
            method: HTTP method
            params: Query parameters
            data: Request body
            headers: Additional headers
            api_key: API key for authentication
            use_cache: Whether to use caching

        Returns:
            APIResponse object
        """
        if api_name not in self.apis:
            return APIResponse(
                success=False,
                status_code=None,
                data=None,
                error=f"API '{api_name}' not registered",
                cached=False,
                response_time_ms=0,
                api_name=api_name,
                timestamp=datetime.now()
            )

        config = self.apis[api_name]

        # Check circuit breaker
        if self.circuit_breaker.is_open(api_name):
            return APIResponse(
                success=False,
                status_code=None,
                data=None,
                error="Circuit breaker is open",
                cached=False,
                response_time_ms=0,
                api_name=api_name,
                timestamp=datetime.now()
            )

        # Check cache
        if use_cache and method == 'GET':
            cached_response = await self._get_cached_response(
                api_name, endpoint, params
            )
            if cached_response:
                return cached_response

        # Wait for rate limit
        await self.rate_limiter.wait_for_rate_limit(
            api_name, config.rate_limit
        )

        # Build request
        url = f"{config.base_url}/{endpoint.lstrip('/')}"
        request_headers = config.headers.copy()
        if headers:
            request_headers.update(headers)

        # Add authentication
        if config.requires_auth and api_key:
            if config.auth_type == 'api_key':
                request_headers[config.auth_header] = api_key
            elif config.auth_type == 'bearer':
                request_headers[config.auth_header] = f"Bearer {api_key}"

        # Make request with retry logic
        start_time = datetime.now()
        for attempt in range(config.retry_count):
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.request(
                        method,
                        url,
                        params=params,
                        json=data,
                        headers=request_headers,
                        timeout=aiohttp.ClientTimeout(total=config.timeout)
                    ) as response:
                        response_time = (
                            datetime.now() - start_time
                        ).total_seconds() * 1000

                        if response.status == 200:
                            response_data = await response.json()

                            # Cache successful response
                            if use_cache and method == 'GET':
                                await self._cache_response(
                                    api_name, endpoint, params,
                                    response_data, config.cache_ttl
                                )

                            # Record success
                            self.circuit_breaker.record_success(api_name)

                            return APIResponse(
                                success=True,
                                status_code=response.status,
                                data=response_data,
                                error=None,
                                cached=False,
                                response_time_ms=response_time,
                                api_name=api_name,
                                timestamp=datetime.now()
                            )
                        elif response.status == 429:
                            # Rate limited - wait and retry
                            logger.warning(f"Rate limited by {api_name}")
                            await asyncio.sleep(config.retry_delay * (attempt + 1))
                            continue
                        else:
                            error_text = await response.text()
                            raise Exception(
                                f"HTTP {response.status}: {error_text}"
                            )

            except Exception as e:
                logger.error(
                    f"API call failed (attempt {attempt + 1}): {e}"
                )
                if attempt < config.retry_count - 1:
                    await asyncio.sleep(config.retry_delay * (attempt + 1))
                else:
                    # Record failure
                    self.circuit_breaker.record_failure(
                        api_name,
                        config.circuit_breaker_threshold,
                        config.circuit_breaker_timeout
                    )

                    return APIResponse(
                        success=False,
                        status_code=None,
                        data=None,
                        error=str(e),
                        cached=False,
                        response_time_ms=(
                            datetime.now() - start_time
                        ).total_seconds() * 1000,
                        api_name=api_name,
                        timestamp=datetime.now()
                    )

    async def _get_cached_response(
        self,
        api_name: str,
        endpoint: str,
        params: Optional[Dict]
    ) -> Optional[APIResponse]:
        """Get cached API response"""
        cache_key = self._generate_cache_key(api_name, endpoint, params)
        cached = self.redis.get(cache_key)

        if cached:
            import json
            data = json.loads(cached)
            logger.info(f"Cache hit for {api_name}/{endpoint}")
            return APIResponse(
                success=True,
                status_code=200,
                data=data,
                error=None,
                cached=True,
                response_time_ms=0,
                api_name=api_name,
                timestamp=datetime.now()
            )

        return None

    async def _cache_response(
        self,
        api_name: str,
        endpoint: str,
        params: Optional[Dict],
        data: Any,
        ttl: int
    ):
        """Cache API response"""
        import json
        cache_key = self._generate_cache_key(api_name, endpoint, params)
        self.redis.setex(cache_key, ttl, json.dumps(data))

    def _generate_cache_key(
        self,
        api_name: str,
        endpoint: str,
        params: Optional[Dict]
    ) -> str:
        """Generate cache key for request"""
        key_parts = [api_name, endpoint]
        if params:
            import json
            key_parts.append(json.dumps(params, sort_keys=True))

        key_string = ":".join(key_parts)
        hash_key = hashlib.md5(key_string.encode()).hexdigest()
        return f"api_cache:{hash_key}"

    async def batch_call(
        self,
        calls: List[Dict[str, Any]]
    ) -> List[APIResponse]:
        """
        Execute multiple API calls concurrently

        Args:
            calls: List of call specifications (api_name, endpoint, etc.)

        Returns:
            List of APIResponse objects
        """
        tasks = [
            self.call_api(**call)
            for call in calls
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        return [
            r if isinstance(r, APIResponse) else APIResponse(
                success=False,
                status_code=None,
                data=None,
                error=str(r),
                cached=False,
                response_time_ms=0,
                api_name='unknown',
                timestamp=datetime.now()
            )
            for r in results
        ]

    def get_api_stats(self, api_name: str) -> Dict[str, Any]:
        """Get statistics for an API"""
        failure_key = f"circuit_breaker:{api_name}:failures"
        failures = self.redis.get(failure_key) or 0
        is_open = self.circuit_breaker.is_open(api_name)

        return {
            'api_name': api_name,
            'failures': int(failures),
            'circuit_breaker_open': is_open,
            'registered': api_name in self.apis
        }

    def list_apis(self) -> List[str]:
        """List all registered APIs"""
        return list(self.apis.keys())

    def get_api_count(self) -> int:
        """Get total number of registered APIs"""
        return len(self.apis)
