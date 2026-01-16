"""
API Orchestrator System
Comprehensive API management for 1,000+ public APIs
"""

from .api_orchestrator import APIOrchestrator, APIRegistry, create_orchestrator
from .api_client import APIClient, AuthConfig, AuthType, RequestConfig, BatchAPIClient
from .rate_limiter import RateLimiter, AdaptiveRateLimiter, RateLimitConfig
from .circuit_breaker import CircuitBreaker, CircuitBreakerManager, CircuitState
from .api_cache import APICache, CacheKey, CacheConfig
from .api_analytics import APIAnalytics, APIMetrics, APIQuota

__version__ = "1.0.0"

__all__ = [
    # Main orchestrator
    "APIOrchestrator",
    "APIRegistry",
    "create_orchestrator",

    # API client
    "APIClient",
    "BatchAPIClient",
    "AuthConfig",
    "AuthType",
    "RequestConfig",

    # Rate limiting
    "RateLimiter",
    "AdaptiveRateLimiter",
    "RateLimitConfig",

    # Circuit breaker
    "CircuitBreaker",
    "CircuitBreakerManager",
    "CircuitState",

    # Caching
    "APICache",
    "CacheKey",
    "CacheConfig",

    # Analytics
    "APIAnalytics",
    "APIMetrics",
    "APIQuota",
]
