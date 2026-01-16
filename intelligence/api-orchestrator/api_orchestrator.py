"""
API Orchestrator - Main Orchestration System
Manages 1,000+ public APIs with intelligent selection, rate limiting, and fault tolerance
"""

import asyncio
import json
import time
from typing import Dict, List, Optional, Any, Union
from pathlib import Path
import logging

from rate_limiter import RateLimiter, RateLimitConfig, AdaptiveRateLimiter
from circuit_breaker import CircuitBreakerManager, CircuitBreakerConfig, HealthChecker
from api_cache import APICache, CacheKey, CacheConfig
from api_client import APIClient, AuthConfig, RequestConfig, AuthType, BatchAPIClient
from api_analytics import APIAnalytics

logger = logging.getLogger(__name__)


class APIRegistry:
    """API Registry Management"""

    def __init__(self, registry_path: Optional[str] = None):
        """
        Initialize API registry

        Args:
            registry_path: Path to registry JSON file
        """
        self.registry_path = registry_path or str(
            Path(__file__).parent / "api_registry.json"
        )
        self.registry: Dict[str, Any] = {}
        self.apis_by_category: Dict[str, List[str]] = {}
        self.apis_by_name: Dict[str, Dict] = {}

        self.load_registry()

    def load_registry(self):
        """Load API registry from JSON file"""
        try:
            with open(self.registry_path, 'r') as f:
                self.registry = json.load(f)

            # Index APIs
            self._index_apis()

            logger.info(f"Loaded {self.get_total_apis()} APIs from registry")

        except FileNotFoundError:
            logger.error(f"Registry file not found: {self.registry_path}")
            self.registry = {"categories": {}}
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in registry: {e}")
            self.registry = {"categories": {}}

    def _index_apis(self):
        """Index APIs for fast lookup"""
        self.apis_by_category.clear()
        self.apis_by_name.clear()

        for cat_name, cat_data in self.registry.get("categories", {}).items():
            self.apis_by_category[cat_name] = []

            for api_id, api_config in cat_data.get("apis", {}).items():
                # Add to category index
                self.apis_by_category[cat_name].append(api_id)

                # Add to name index with metadata
                self.apis_by_name[api_id] = {
                    **api_config,
                    "id": api_id,
                    "category": cat_name
                }

    def get_api(self, api_id: str) -> Optional[Dict]:
        """Get API configuration by ID"""
        return self.apis_by_name.get(api_id)

    def get_apis_by_category(self, category: str) -> List[Dict]:
        """Get all APIs in category"""
        api_ids = self.apis_by_category.get(category, [])
        return [self.apis_by_name[api_id] for api_id in api_ids]

    def search_apis(self, query: str) -> List[Dict]:
        """Search APIs by name or category"""
        query = query.lower()
        results = []

        for api_id, api_config in self.apis_by_name.items():
            if (query in api_id.lower() or
                query in api_config.get("name", "").lower() or
                query in api_config.get("category", "").lower()):
                results.append(api_config)

        return results

    def get_categories(self) -> List[str]:
        """Get all category names"""
        return list(self.apis_by_category.keys())

    def get_total_apis(self) -> int:
        """Get total number of APIs"""
        return len(self.apis_by_name)

    def get_stats(self) -> Dict:
        """Get registry statistics"""
        return {
            "total_apis": self.get_total_apis(),
            "total_categories": len(self.apis_by_category),
            "categories": {
                cat: len(apis) for cat, apis in self.apis_by_category.items()
            }
        }


class APIOrchestrator:
    """Main API Orchestrator"""

    def __init__(
        self,
        registry_path: Optional[str] = None,
        redis_client: Optional[Any] = None,
        enable_caching: bool = True,
        enable_adaptive_rate_limiting: bool = True
    ):
        """
        Initialize API Orchestrator

        Args:
            registry_path: Path to API registry
            redis_client: Redis client for caching and rate limiting
            enable_caching: Enable response caching
            enable_adaptive_rate_limiting: Enable adaptive rate limiting
        """
        # Core components
        self.registry = APIRegistry(registry_path)

        # Rate limiting
        if enable_adaptive_rate_limiting:
            self.rate_limiter = AdaptiveRateLimiter(redis_client)
        else:
            self.rate_limiter = RateLimiter(redis_client)

        # Circuit breaker
        self.circuit_breaker = CircuitBreakerManager()

        # Caching
        self.cache = APICache(redis_client) if enable_caching else None

        # Analytics
        self.analytics = APIAnalytics()

        # Health checking
        self.health_checker = HealthChecker()

        # API clients
        self.clients: Dict[str, APIClient] = {}

        # Initialize rate limiters for all APIs
        self._initialize_rate_limiters()

        logger.info(f"Initialized API Orchestrator with {self.registry.get_total_apis()} APIs")

    def _initialize_rate_limiters(self):
        """Initialize rate limiters for all APIs"""
        for api_id, api_config in self.registry.apis_by_name.items():
            rate_limit = api_config.get("rate_limit", {})

            if rate_limit:
                config = RateLimitConfig(
                    requests_per_second=rate_limit.get("requests_per_second", 1.0),
                    burst_size=rate_limit.get("burst", 10)
                )
                self.rate_limiter.register_api(api_id, config)

    def _get_client(self, api_id: str) -> Optional[APIClient]:
        """Get or create API client"""
        if api_id in self.clients:
            return self.clients[api_id]

        api_config = self.registry.get_api(api_id)
        if not api_config:
            logger.error(f"API not found: {api_id}")
            return None

        # Create auth config
        auth_config = self._create_auth_config(api_config)

        # Create client
        client = APIClient(
            base_url=api_config.get("base_url"),
            auth_config=auth_config
        )

        self.clients[api_id] = client
        return client

    def _create_auth_config(self, api_config: Dict) -> Optional[AuthConfig]:
        """Create authentication configuration"""
        auth_type_str = api_config.get("auth_type", "none")

        if auth_type_str == "none":
            return None

        # Map string to AuthType enum
        auth_type_map = {
            "api_key": AuthType.API_KEY,
            "bearer_token": AuthType.BEARER_TOKEN,
            "basic_auth": AuthType.BASIC_AUTH,
            "oauth2": AuthType.OAUTH2,
            "jwt": AuthType.JWT,
            "hmac": AuthType.HMAC
        }

        auth_type = auth_type_map.get(auth_type_str, AuthType.NONE)

        return AuthConfig(auth_type=auth_type)

    async def call_api(
        self,
        api_id: str,
        endpoint: str,
        params: Optional[Dict] = None,
        method: str = "GET",
        use_cache: bool = True,
        max_retries: int = 3
    ) -> Dict[str, Any]:
        """
        Call single API with full orchestration

        Args:
            api_id: API identifier
            endpoint: API endpoint
            params: Request parameters
            method: HTTP method
            use_cache: Use response caching
            max_retries: Maximum retry attempts

        Returns:
            API response
        """
        start_time = time.time()
        api_config = self.registry.get_api(api_id)

        if not api_config:
            raise ValueError(f"API not found: {api_id}")

        # Check cache
        if use_cache and self.cache:
            cache_key = CacheKey.generate(api_id, endpoint, params)
            cached_response = await self.cache.get(cache_key)

            if cached_response is not None:
                duration = time.time() - start_time
                self.analytics.record_call(
                    api_id, endpoint, duration, 200, True,
                    cached=True
                )
                return cached_response

        # Wait for rate limit
        acquired = await self.rate_limiter.wait_and_acquire(api_id, tokens=1)

        if not acquired:
            raise Exception(f"Rate limit timeout for {api_id}")

        # Get client
        client = self._get_client(api_id)
        await client.start()

        try:
            # Call API with circuit breaker
            async def api_call():
                config = RequestConfig(
                    method=method,
                    params=params,
                    max_retries=max_retries
                )
                return await client.request(endpoint, config)

            breaker_config = CircuitBreakerConfig(
                failure_threshold=5,
                timeout=60.0
            )

            response = await self.circuit_breaker.call(
                api_id,
                api_call,
                config=breaker_config
            )

            # Cache response
            if use_cache and self.cache and response:
                cache_key = CacheKey.generate(api_id, endpoint, params)
                await self.cache.set(cache_key, response)

            # Record success
            duration = time.time() - start_time
            self.analytics.record_call(
                api_id, endpoint, duration,
                response.get("status", 200), True
            )

            # Record for adaptive rate limiting
            if isinstance(self.rate_limiter, AdaptiveRateLimiter):
                await self.rate_limiter.record_success(api_id)

            return response

        except Exception as e:
            # Record failure
            duration = time.time() - start_time
            self.analytics.record_call(
                api_id, endpoint, duration, 500, False,
                error=str(e)
            )

            # Record for adaptive rate limiting
            if isinstance(self.rate_limiter, AdaptiveRateLimiter):
                is_rate_limit = "rate limit" in str(e).lower()
                await self.rate_limiter.record_error(api_id, is_rate_limit)

            raise

    async def call_apis(
        self,
        category: Optional[str] = None,
        api_ids: Optional[List[str]] = None,
        target: Optional[str] = None,
        parallel: bool = True,
        max_concurrent: int = 10
    ) -> Dict[str, Any]:
        """
        Call multiple APIs

        Args:
            category: API category to call (all APIs in category)
            api_ids: Specific API IDs to call
            target: Target identifier (username, email, etc.)
            parallel: Execute in parallel
            max_concurrent: Maximum concurrent requests

        Returns:
            Results from all APIs
        """
        # Determine which APIs to call
        if api_ids:
            apis_to_call = api_ids
        elif category:
            api_configs = self.registry.get_apis_by_category(category)
            apis_to_call = [api["id"] for api in api_configs]
        else:
            raise ValueError("Must specify either category or api_ids")

        if not apis_to_call:
            return {}

        logger.info(f"Calling {len(apis_to_call)} APIs" +
                   (f" in parallel (max {max_concurrent})" if parallel else " sequentially"))

        # Execute calls
        if parallel:
            results = await self._call_apis_parallel(
                apis_to_call, target, max_concurrent
            )
        else:
            results = await self._call_apis_sequential(apis_to_call, target)

        return results

    async def _call_apis_parallel(
        self,
        api_ids: List[str],
        target: Optional[str],
        max_concurrent: int
    ) -> Dict[str, Any]:
        """Call APIs in parallel"""
        semaphore = asyncio.Semaphore(max_concurrent)

        async def limited_call(api_id: str):
            async with semaphore:
                try:
                    # Get default endpoint for API
                    api_config = self.registry.get_api(api_id)
                    endpoints = api_config.get("endpoints", {})

                    if endpoints:
                        endpoint = list(endpoints.values())[0]
                        if target:
                            endpoint = endpoint.replace("{username}", target)
                            endpoint = endpoint.replace("{target}", target)
                    else:
                        endpoint = "/"

                    result = await self.call_api(api_id, endpoint)
                    return {api_id: {"success": True, "data": result}}

                except Exception as e:
                    logger.error(f"API call failed for {api_id}: {e}")
                    return {api_id: {"success": False, "error": str(e)}}

        tasks = [limited_call(api_id) for api_id in api_ids]
        results_list = await asyncio.gather(*tasks, return_exceptions=True)

        # Merge results
        results = {}
        for result in results_list:
            if isinstance(result, dict):
                results.update(result)
            else:
                logger.error(f"Unexpected result type: {type(result)}")

        return results

    async def _call_apis_sequential(
        self,
        api_ids: List[str],
        target: Optional[str]
    ) -> Dict[str, Any]:
        """Call APIs sequentially"""
        results = {}

        for api_id in api_ids:
            try:
                api_config = self.registry.get_api(api_id)
                endpoints = api_config.get("endpoints", {})

                if endpoints:
                    endpoint = list(endpoints.values())[0]
                    if target:
                        endpoint = endpoint.replace("{username}", target)
                        endpoint = endpoint.replace("{target}", target)
                else:
                    endpoint = "/"

                result = await self.call_api(api_id, endpoint)
                results[api_id] = {"success": True, "data": result}

            except Exception as e:
                logger.error(f"API call failed for {api_id}: {e}")
                results[api_id] = {"success": False, "error": str(e)}

        return results

    def get_stats(self) -> Dict[str, Any]:
        """Get orchestrator statistics"""
        return {
            "registry": self.registry.get_stats(),
            "rate_limiter": self.rate_limiter.get_all_stats(),
            "circuit_breaker": self.circuit_breaker.get_all_stats(),
            "cache": self.cache.get_stats() if self.cache else None,
            "analytics": {
                "top_apis": self.analytics.get_top_apis(10),
                "slow_apis": self.analytics.get_slow_apis(5.0, 10),
                "errors": self.analytics.get_error_summary(),
                "costs": self.analytics.get_cost_summary()
            }
        }

    def get_health(self) -> Dict[str, Any]:
        """Get health status"""
        unhealthy_breakers = self.circuit_breaker.get_unhealthy_breakers()

        return {
            "healthy": len(unhealthy_breakers) == 0,
            "total_apis": self.registry.get_total_apis(),
            "unhealthy_apis": len(unhealthy_breakers),
            "circuit_breakers": unhealthy_breakers,
            "health_checks": self.health_checker.get_all_status()
        }

    async def close(self):
        """Close all resources"""
        # Close all clients
        for client in self.clients.values():
            await client.close()

        # Stop health checker
        await self.health_checker.stop()

        logger.info("API Orchestrator closed")


# Convenience function
async def create_orchestrator(
    registry_path: Optional[str] = None,
    **kwargs
) -> APIOrchestrator:
    """Create and initialize API orchestrator"""
    orchestrator = APIOrchestrator(registry_path, **kwargs)
    return orchestrator
