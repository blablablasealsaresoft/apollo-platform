"""
Sherlock OSINT Tool Integration
================================

Advanced username search across 400+ social media platforms.

This package provides:
- SherlockEngine: Core async search engine with rate limiting and proxy support
- BatchUsernameProcessor: Batch processing for multiple usernames
- SherlockResultsStorage: Elasticsearch storage backend
- FastAPI endpoints for REST API access

Usage:
    from sherlock import SherlockEngine

    # Basic search
    engine = SherlockEngine()
    results = await engine.search_username("target_username")

    # With proxy support
    from sherlock import ProxyConfig
    proxy = ProxyConfig(protocol="socks5", host="127.0.0.1", port=9050)
    engine = SherlockEngine(proxies=[proxy])

    # With rate limiting
    from sherlock import RateLimitConfig
    rate_limit = RateLimitConfig(requests_per_second=5)
    engine = SherlockEngine(rate_limit=rate_limit)

Author: Apollo Intelligence Platform
License: MIT
"""

from .sherlock_engine import (
    SherlockEngine,
    UsernameResult,
    PlatformConfig,
    ProxyConfig,
    RateLimitConfig,
    # Convenience functions
    search_username,
    get_available_platforms,
    get_platform_categories
)

from .batch_processor import (
    BatchUsernameProcessor,
    BatchSearchResult
)

from .results_storage import (
    SherlockResultsStorage
)

# Version info
__version__ = "2.0.0"
__author__ = "Apollo Intelligence Platform"

__all__ = [
    # Core engine
    'SherlockEngine',
    'UsernameResult',
    'PlatformConfig',
    'ProxyConfig',
    'RateLimitConfig',

    # Batch processing
    'BatchUsernameProcessor',
    'BatchSearchResult',

    # Storage
    'SherlockResultsStorage',

    # Convenience functions
    'search_username',
    'get_available_platforms',
    'get_platform_categories',

    # Version
    '__version__',
    '__author__'
]
