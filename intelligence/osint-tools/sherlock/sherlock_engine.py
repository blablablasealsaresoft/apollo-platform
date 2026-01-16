"""
Sherlock Engine - Username Search Across 400+ Social Media Platforms

Production-ready OSINT engine for username enumeration with:
- Support for 400+ platforms from official Sherlock data
- Async/concurrent checking for maximum speed
- Rate limiting to avoid bans
- Proxy support for anonymity
- Screenshot capability for found profiles
- Database integration for result storage

Author: Apollo Intelligence Platform
License: MIT
"""

import asyncio
import json
import logging
import random
import hashlib
from typing import Dict, List, Optional, Set, Any, Callable
from dataclasses import dataclass, asdict, field
from datetime import datetime
from pathlib import Path
import aiohttp
from aiohttp_socks import ProxyConnector
from urllib.parse import quote, urlparse
import ssl
import certifi
import redis.asyncio as aioredis
from redis.asyncio import Redis

logger = logging.getLogger(__name__)

# Redis cache TTL defaults
DEFAULT_CACHE_TTL = 3600  # 1 hour
FOUND_RESULT_CACHE_TTL = 86400  # 24 hours for found results
NOT_FOUND_CACHE_TTL = 1800  # 30 minutes for not found


@dataclass
class UsernameResult:
    """Result from username search on a single platform"""
    username: str
    platform: str
    url: str
    status: str  # 'found', 'not_found', 'error', 'rate_limited', 'timeout'
    confidence_score: float
    response_time_ms: int
    http_status: Optional[int]
    timestamp: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)
    screenshot_path: Optional[str] = None
    profile_data: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        data = asdict(self)
        data['timestamp'] = self.timestamp.isoformat() if self.timestamp else None
        return data

    @property
    def cache_key(self) -> str:
        """Generate cache key for this result"""
        return hashlib.md5(f"{self.username}:{self.platform}".encode()).hexdigest()


@dataclass
class PlatformConfig:
    """Configuration for a social media platform"""
    name: str
    url_template: str
    error_type: str  # 'status_code', 'message', 'response_url'
    error_msg: Optional[str] = None
    error_code: Optional[int] = None
    request_method: str = 'GET'
    request_payload: Optional[Dict] = None
    headers: Optional[Dict] = None
    category: str = 'unknown'
    reliable: bool = True

    @classmethod
    def from_dict(cls, name: str, config: Dict[str, Any]) -> 'PlatformConfig':
        """Create PlatformConfig from dictionary"""
        return cls(
            name=name,
            url_template=config.get('url', ''),
            error_type=config.get('errorType', 'status_code'),
            error_msg=config.get('errorMsg'),
            error_code=config.get('errorCode', 404),
            request_method=config.get('requestMethod', 'GET'),
            request_payload=config.get('requestPayload'),
            headers=config.get('headers'),
            category=config.get('category', 'unknown'),
            reliable=config.get('reliable', True)
        )


@dataclass
class ProxyConfig:
    """Proxy configuration for anonymous requests"""
    protocol: str  # 'http', 'https', 'socks4', 'socks5'
    host: str
    port: int
    username: Optional[str] = None
    password: Optional[str] = None

    @property
    def url(self) -> str:
        """Get proxy URL"""
        if self.username and self.password:
            return f"{self.protocol}://{self.username}:{self.password}@{self.host}:{self.port}"
        return f"{self.protocol}://{self.host}:{self.port}"


@dataclass
class RateLimitConfig:
    """Rate limiting configuration"""
    requests_per_second: float = 10.0
    burst_limit: int = 20
    per_platform_delay: float = 0.1
    backoff_factor: float = 2.0
    max_retries: int = 3


class SherlockEngine:
    """
    Production Sherlock OSINT Engine

    Searches for usernames across 400+ social media platforms with:
    - High-performance async concurrent checking
    - Smart rate limiting per platform
    - Rotating proxy support
    - Screenshot capture for found profiles
    - Database integration

    Usage:
        engine = SherlockEngine()
        results = await engine.search_username("target_username")

        # With proxy
        engine = SherlockEngine(proxies=[ProxyConfig(...)])

        # With rate limiting
        engine = SherlockEngine(rate_limit=RateLimitConfig(requests_per_second=5))
    """

    # Default user agents for rotation
    DEFAULT_USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0",
    ]

    def __init__(
        self,
        config_path: Optional[str] = None,
        timeout: int = 10,
        max_concurrent: int = 50,
        user_agent: Optional[str] = None,
        rotate_user_agents: bool = True,
        proxies: Optional[List[ProxyConfig]] = None,
        rate_limit: Optional[RateLimitConfig] = None,
        enable_screenshots: bool = False,
        redis_client: Any = None,
        elasticsearch_client: Any = None,
        progress_callback: Optional[Callable[[str, int, int], None]] = None
    ):
        """
        Initialize Sherlock Engine

        Args:
            config_path: Path to platforms_config.json (None for default)
            timeout: Request timeout in seconds
            max_concurrent: Maximum concurrent requests
            user_agent: Custom user agent (or None for rotation)
            rotate_user_agents: Enable user agent rotation
            proxies: List of proxy configurations
            rate_limit: Rate limiting configuration
            enable_screenshots: Enable screenshot capture for found profiles
            redis_client: Redis client for caching
            elasticsearch_client: Elasticsearch client for storage
            progress_callback: Callback for progress updates (platform, current, total)
        """
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.user_agent = user_agent
        self.rotate_user_agents = rotate_user_agents
        self.proxies = proxies or []
        self.rate_limit = rate_limit or RateLimitConfig()
        self.enable_screenshots = enable_screenshots
        self.redis_client = redis_client
        self.es_client = elasticsearch_client
        self.progress_callback = progress_callback

        # Redis cache settings
        self._redis_cache_enabled = redis_client is not None
        self._cache_prefix = "sherlock:cache:"
        self._cache_ttl = DEFAULT_CACHE_TTL

        # Load platforms from JSON config
        if config_path is None:
            config_path = Path(__file__).parent / "platforms_config.json"
        self.platforms = self._load_platforms_from_json(config_path)

        # Statistics tracking
        self.stats = {
            'requests_sent': 0,
            'requests_succeeded': 0,
            'requests_failed': 0,
            'profiles_found': 0,
            'rate_limited': 0,
            'timeouts': 0,
            'total_response_time_ms': 0
        }

        # Rate limiting state
        self._request_times: List[float] = []
        self._platform_last_request: Dict[str, float] = {}

        logger.info(f"SherlockEngine initialized with {len(self.platforms)} platforms")

    def _load_platforms_from_json(self, config_path: Path) -> Dict[str, PlatformConfig]:
        """Load platform configurations from JSON file"""
        platforms = {}

        try:
            if isinstance(config_path, str):
                config_path = Path(config_path)

            if config_path.exists():
                with open(config_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)

                for name, config in data.items():
                    try:
                        platforms[name] = PlatformConfig.from_dict(name, config)
                    except Exception as e:
                        logger.warning(f"Failed to load platform {name}: {e}")

                logger.info(f"Loaded {len(platforms)} platforms from {config_path}")
            else:
                logger.warning(f"Config file not found: {config_path}, using fallback")
                platforms = self._get_fallback_platforms()

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse platforms config: {e}")
            platforms = self._get_fallback_platforms()
        except Exception as e:
            logger.error(f"Error loading platforms: {e}")
            platforms = self._get_fallback_platforms()

        return platforms

    def _get_fallback_platforms(self) -> Dict[str, PlatformConfig]:
        """Return fallback platform configurations if JSON fails to load"""
        return {
            "GitHub": PlatformConfig("GitHub", "https://github.com/{}", "status_code", error_code=404, category="development"),
            "Twitter": PlatformConfig("Twitter", "https://twitter.com/{}", "status_code", error_code=404, category="social"),
            "Instagram": PlatformConfig("Instagram", "https://www.instagram.com/{}", "status_code", error_code=404, category="social"),
            "LinkedIn": PlatformConfig("LinkedIn", "https://www.linkedin.com/in/{}", "status_code", error_code=404, category="professional"),
            "Reddit": PlatformConfig("Reddit", "https://www.reddit.com/user/{}", "status_code", error_code=404, category="forum"),
            "YouTube": PlatformConfig("YouTube", "https://www.youtube.com/@{}", "status_code", error_code=404, category="video"),
            "TikTok": PlatformConfig("TikTok", "https://www.tiktok.com/@{}", "message", error_msg="Couldn't find this account", category="social"),
            "Medium": PlatformConfig("Medium", "https://medium.com/@{}", "status_code", error_code=404, category="blogging"),
            "Twitch": PlatformConfig("Twitch", "https://www.twitch.tv/{}", "status_code", error_code=404, category="streaming"),
            "Steam": PlatformConfig("Steam", "https://steamcommunity.com/id/{}", "message", error_msg="The specified profile could not be found", category="gaming"),
        }

    def _get_user_agent(self) -> str:
        """Get user agent string (with optional rotation)"""
        if self.user_agent:
            return self.user_agent
        if self.rotate_user_agents:
            return random.choice(self.DEFAULT_USER_AGENTS)
        return self.DEFAULT_USER_AGENTS[0]

    def _get_proxy(self) -> Optional[ProxyConfig]:
        """Get a random proxy from the pool"""
        if not self.proxies:
            return None
        return random.choice(self.proxies)

    async def _wait_for_rate_limit(self, platform: str):
        """Wait to respect rate limiting"""
        current_time = asyncio.get_event_loop().time()

        # Clean old request times (keep last second only)
        self._request_times = [
            t for t in self._request_times
            if current_time - t < 1.0
        ]

        # Check global rate limit
        if len(self._request_times) >= self.rate_limit.requests_per_second:
            wait_time = 1.0 - (current_time - self._request_times[0])
            if wait_time > 0:
                await asyncio.sleep(wait_time)

        # Check per-platform delay
        last_request = self._platform_last_request.get(platform, 0)
        platform_delay = current_time - last_request
        if platform_delay < self.rate_limit.per_platform_delay:
            await asyncio.sleep(self.rate_limit.per_platform_delay - platform_delay)

        # Record this request
        self._request_times.append(asyncio.get_event_loop().time())
        self._platform_last_request[platform] = asyncio.get_event_loop().time()

    async def _create_session(self, proxy: Optional[ProxyConfig] = None) -> aiohttp.ClientSession:
        """Create aiohttp session with optional proxy"""
        headers = {
            'User-Agent': self._get_user_agent(),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Cache-Control': 'max-age=0'
        }

        timeout = aiohttp.ClientTimeout(total=self.timeout)

        # Configure SSL
        ssl_context = ssl.create_default_context(cafile=certifi.where())

        connector = None
        if proxy:
            if proxy.protocol in ('socks4', 'socks5'):
                connector = ProxyConnector.from_url(proxy.url, ssl=ssl_context)
            else:
                # HTTP/HTTPS proxy handled differently
                connector = aiohttp.TCPConnector(
                    limit=100,
                    limit_per_host=10,
                    ssl=ssl_context
                )
        else:
            connector = aiohttp.TCPConnector(
                limit=100,
                limit_per_host=10,
                ssl=ssl_context,
                ttl_dns_cache=300
            )

        return aiohttp.ClientSession(
            headers=headers,
            timeout=timeout,
            connector=connector,
            trust_env=True
        )

    async def search_username(
        self,
        username: str,
        platforms: Optional[List[str]] = None,
        categories: Optional[List[str]] = None,
        reliable_only: bool = False,
        use_cache: bool = True
    ) -> List[UsernameResult]:
        """
        Search for username across specified platforms

        Args:
            username: Username to search for
            platforms: List of platform names (None = all platforms)
            categories: List of categories to filter by
            reliable_only: Only search platforms marked as reliable
            use_cache: Whether to use Redis caching (default True)

        Returns:
            List of UsernameResult objects
        """
        # Filter platforms
        search_platforms = self._filter_platforms(platforms, categories, reliable_only)
        platform_names = list(search_platforms.keys())

        logger.info(
            f"Searching username '{username}' across "
            f"{len(search_platforms)} platforms"
        )

        valid_results = []
        platforms_to_check = {}

        # Check cache first if enabled
        if use_cache and self._redis_cache_enabled:
            cached_results = await self._batch_get_cached_results(username, platform_names)
            for platform_name, cached in cached_results.items():
                if cached is not None:
                    valid_results.append(cached)
                else:
                    # Need to check this platform
                    platforms_to_check[platform_name] = search_platforms[platform_name]
        else:
            platforms_to_check = search_platforms

        # Only make HTTP requests for uncached platforms
        if platforms_to_check:
            logger.info(f"Making requests for {len(platforms_to_check)} uncached platforms")

            # Create semaphore for concurrent requests
            semaphore = asyncio.Semaphore(self.max_concurrent)

            # Get proxy for this search
            proxy = self._get_proxy()

            async with await self._create_session(proxy) as session:
                tasks = []
                for idx, (platform_name, config) in enumerate(platforms_to_check.items()):
                    tasks.append(
                        self._check_platform(
                            session, username, platform_name, config, semaphore, idx, len(platforms_to_check)
                        )
                    )

                results = await asyncio.gather(*tasks, return_exceptions=True)

            # Process results
            new_results = []
            for r in results:
                if isinstance(r, UsernameResult):
                    valid_results.append(r)
                    new_results.append(r)
                elif isinstance(r, Exception):
                    logger.debug(f"Task exception: {r}")

            # Cache the new results
            if use_cache and new_results:
                await self._batch_set_cached_results(new_results)

        # Sort by confidence score descending
        valid_results.sort(key=lambda x: x.confidence_score, reverse=True)

        found_count = sum(1 for r in valid_results if r.status == 'found')
        self.stats['profiles_found'] += found_count

        cache_hits = len(search_platforms) - len(platforms_to_check) if use_cache else 0
        logger.info(
            f"Search completed: {len(valid_results)} results, "
            f"{found_count} found, {cache_hits} cache hits"
        )

        return valid_results

    def _filter_platforms(
        self,
        platforms: Optional[List[str]] = None,
        categories: Optional[List[str]] = None,
        reliable_only: bool = False
    ) -> Dict[str, PlatformConfig]:
        """Filter platforms by name, category, and reliability"""
        result = self.platforms.copy()

        if platforms:
            result = {k: v for k, v in result.items() if k in platforms}

        if categories:
            result = {k: v for k, v in result.items() if v.category in categories}

        if reliable_only:
            result = {k: v for k, v in result.items() if v.reliable}

        return result

    async def search_username_sync(
        self,
        username: str,
        platforms: Optional[List[str]] = None,
        categories: Optional[List[str]] = None
    ) -> List[UsernameResult]:
        """Synchronous wrapper for search_username"""
        return asyncio.run(self.search_username(username, platforms, categories))

    async def _check_platform(
        self,
        session: aiohttp.ClientSession,
        username: str,
        platform_name: str,
        config: PlatformConfig,
        semaphore: asyncio.Semaphore,
        current_index: int = 0,
        total_platforms: int = 0
    ) -> UsernameResult:
        """
        Check if username exists on a single platform

        Args:
            session: aiohttp ClientSession
            username: Username to check
            platform_name: Name of the platform
            config: Platform configuration
            semaphore: Concurrency limiter
            current_index: Current platform index for progress tracking
            total_platforms: Total platforms for progress tracking

        Returns:
            UsernameResult with search outcome
        """
        async with semaphore:
            # Rate limiting
            await self._wait_for_rate_limit(platform_name)

            start_time = datetime.now()
            url = config.url_template.format(quote(username))

            # Merge headers
            headers = {}
            if config.headers:
                headers.update(config.headers)

            self.stats['requests_sent'] += 1

            try:
                if config.request_method == 'GET':
                    async with session.get(
                        url,
                        headers=headers,
                        allow_redirects=True
                    ) as response:
                        response_time_ms = int((datetime.now() - start_time).total_seconds() * 1000)
                        self.stats['total_response_time_ms'] += response_time_ms

                        text = await response.text()
                        status = self._determine_status(response, text, config)
                        confidence = self._calculate_confidence(status, response, text, config)

                        if status == 'found':
                            self.stats['requests_succeeded'] += 1
                        elif status == 'rate_limited':
                            self.stats['rate_limited'] += 1

                        # Progress callback
                        if self.progress_callback:
                            self.progress_callback(platform_name, current_index + 1, total_platforms)

                        return UsernameResult(
                            username=username,
                            platform=platform_name,
                            url=url,
                            status=status,
                            confidence_score=confidence,
                            response_time_ms=response_time_ms,
                            http_status=response.status,
                            timestamp=datetime.now(),
                            metadata={
                                'final_url': str(response.url),
                                'content_length': len(text),
                                'category': config.category,
                                'reliable': config.reliable,
                                'redirected': str(response.url) != url
                            }
                        )
                else:
                    # POST request
                    async with session.post(
                        url,
                        headers=headers,
                        json=config.request_payload
                    ) as response:
                        response_time_ms = int((datetime.now() - start_time).total_seconds() * 1000)
                        self.stats['total_response_time_ms'] += response_time_ms

                        text = await response.text()
                        status = self._determine_status(response, text, config)
                        confidence = self._calculate_confidence(status, response, text, config)

                        if status == 'found':
                            self.stats['requests_succeeded'] += 1

                        if self.progress_callback:
                            self.progress_callback(platform_name, current_index + 1, total_platforms)

                        return UsernameResult(
                            username=username,
                            platform=platform_name,
                            url=url,
                            status=status,
                            confidence_score=confidence,
                            response_time_ms=response_time_ms,
                            http_status=response.status,
                            timestamp=datetime.now(),
                            metadata={
                                'content_length': len(text),
                                'category': config.category,
                                'reliable': config.reliable
                            }
                        )

            except asyncio.TimeoutError:
                response_time_ms = int((datetime.now() - start_time).total_seconds() * 1000)
                self.stats['timeouts'] += 1
                self.stats['requests_failed'] += 1

                return UsernameResult(
                    username=username,
                    platform=platform_name,
                    url=url,
                    status='timeout',
                    confidence_score=0.0,
                    response_time_ms=response_time_ms,
                    http_status=None,
                    timestamp=datetime.now(),
                    metadata={'error': 'timeout', 'category': config.category}
                )

            except aiohttp.ClientResponseError as e:
                response_time_ms = int((datetime.now() - start_time).total_seconds() * 1000)
                self.stats['requests_failed'] += 1

                # Check if rate limited
                status = 'rate_limited' if e.status == 429 else 'error'
                if status == 'rate_limited':
                    self.stats['rate_limited'] += 1

                return UsernameResult(
                    username=username,
                    platform=platform_name,
                    url=url,
                    status=status,
                    confidence_score=0.0,
                    response_time_ms=response_time_ms,
                    http_status=e.status,
                    timestamp=datetime.now(),
                    metadata={'error': str(e), 'category': config.category}
                )

            except Exception as e:
                response_time_ms = int((datetime.now() - start_time).total_seconds() * 1000)
                self.stats['requests_failed'] += 1

                logger.debug(f"Error checking {platform_name}: {str(e)}")

                return UsernameResult(
                    username=username,
                    platform=platform_name,
                    url=url,
                    status='error',
                    confidence_score=0.0,
                    response_time_ms=response_time_ms,
                    http_status=None,
                    timestamp=datetime.now(),
                    metadata={'error': str(e), 'category': config.category}
                )

    def _determine_status(
        self,
        response: aiohttp.ClientResponse,
        text: str,
        config: PlatformConfig
    ) -> str:
        """
        Determine if username was found based on response

        Args:
            response: HTTP response object
            text: Response body text
            config: Platform configuration

        Returns:
            Status string: 'found', 'not_found', 'error', 'rate_limited'
        """
        # Check for rate limiting first
        if response.status == 429:
            return 'rate_limited'

        # Check for server errors
        if response.status >= 500:
            return 'error'

        if config.error_type == 'status_code':
            if response.status == config.error_code:
                return 'not_found'
            elif response.status == 200:
                return 'found'
            elif response.status in (301, 302, 303, 307, 308):
                # Redirect might indicate not found or found
                return 'found'  # Usually redirects to the profile
            else:
                return 'error'

        elif config.error_type == 'message':
            if config.error_msg:
                # Case-insensitive search for error message
                if config.error_msg.lower() in text.lower():
                    return 'not_found'
            if response.status == 200:
                return 'found'
            return 'error'

        elif config.error_type == 'response_url':
            final_url = str(response.url).lower()
            # Check if redirected to error/not-found page
            error_indicators = ['404', 'notfound', 'not-found', 'error', 'deleted', 'suspended']
            if any(indicator in final_url for indicator in error_indicators):
                return 'not_found'
            if response.status == 200:
                return 'found'
            return 'error'

        # Default behavior
        if response.status == 200:
            return 'found'
        return 'error'

    def _calculate_confidence(
        self,
        status: str,
        response: aiohttp.ClientResponse,
        text: str,
        config: PlatformConfig
    ) -> float:
        """
        Calculate confidence score for result

        Factors:
        - HTTP status code
        - Content length
        - Platform reliability flag
        - Whether redirected
        - Username presence in content

        Args:
            status: Determined status
            response: HTTP response
            text: Response body
            config: Platform configuration

        Returns:
            Confidence score between 0.0 and 1.0
        """
        if status in ('not_found', 'error', 'rate_limited', 'timeout'):
            # For not_found, confidence is in the NOT_FOUND determination
            return 0.0 if status != 'not_found' else 0.95

        # Base confidence for found status
        confidence = 0.70

        # HTTP 200 boost
        if response.status == 200:
            confidence += 0.10

        # Content length boost (more content = more likely real profile)
        content_length = len(text)
        if content_length > 5000:
            confidence += 0.10
        elif content_length > 1000:
            confidence += 0.05
        elif content_length < 200:
            confidence -= 0.10  # Suspicious if too little content

        # Reliable platform boost
        if config.reliable:
            confidence += 0.05

        # Redirect penalty (sometimes indicates issues)
        if len(response.history) > 1:
            confidence -= 0.05

        # Clamp between 0 and 1
        return round(max(0.0, min(1.0, confidence)), 2)

    def get_platforms(self) -> List[str]:
        """Get list of all supported platforms"""
        return list(self.platforms.keys())

    def get_platform_count(self) -> int:
        """Get total number of supported platforms"""
        return len(self.platforms)

    def get_platforms_by_category(self) -> Dict[str, List[str]]:
        """Get platforms grouped by category"""
        categories: Dict[str, List[str]] = {}
        for name, config in self.platforms.items():
            cat = config.category
            if cat not in categories:
                categories[cat] = []
            categories[cat].append(name)
        return categories

    def get_categories(self) -> List[str]:
        """Get list of all platform categories"""
        return list(set(c.category for c in self.platforms.values()))

    def get_statistics(self) -> Dict[str, Any]:
        """Get search statistics"""
        avg_response_time = (
            self.stats['total_response_time_ms'] / self.stats['requests_sent']
            if self.stats['requests_sent'] > 0
            else 0
        )

        success_rate = (
            self.stats['requests_succeeded'] / self.stats['requests_sent']
            if self.stats['requests_sent'] > 0
            else 0
        )

        return {
            **self.stats,
            'platforms_available': len(self.platforms),
            'avg_response_time_ms': round(avg_response_time, 2),
            'success_rate': round(success_rate, 4)
        }

    def reset_statistics(self):
        """Reset search statistics"""
        self.stats = {
            'requests_sent': 0,
            'requests_succeeded': 0,
            'requests_failed': 0,
            'profiles_found': 0,
            'rate_limited': 0,
            'timeouts': 0,
            'total_response_time_ms': 0
        }

    # =========================================================================
    # Redis Caching Methods
    # =========================================================================

    async def _get_cached_result(self, username: str, platform: str) -> Optional[UsernameResult]:
        """
        Get cached result from Redis

        Args:
            username: Username that was searched
            platform: Platform name

        Returns:
            Cached UsernameResult or None if not cached
        """
        if not self._redis_cache_enabled or not self.redis_client:
            return None

        try:
            cache_key = f"{self._cache_prefix}{username}:{platform}"
            cached_data = await self.redis_client.get(cache_key)

            if cached_data:
                data = json.loads(cached_data)
                # Reconstruct UsernameResult from cached data
                data['timestamp'] = datetime.fromisoformat(data['timestamp'])
                result = UsernameResult(**data)
                logger.debug(f"Cache hit for {username}@{platform}")
                return result

        except Exception as e:
            logger.debug(f"Cache get failed for {username}@{platform}: {e}")

        return None

    async def _set_cached_result(self, result: UsernameResult):
        """
        Cache a result in Redis

        Args:
            result: UsernameResult to cache
        """
        if not self._redis_cache_enabled or not self.redis_client:
            return

        try:
            cache_key = f"{self._cache_prefix}{result.username}:{result.platform}"
            data = result.to_dict()

            # Set appropriate TTL based on result status
            if result.status == 'found':
                ttl = FOUND_RESULT_CACHE_TTL
            elif result.status == 'not_found':
                ttl = NOT_FOUND_CACHE_TTL
            else:
                ttl = DEFAULT_CACHE_TTL

            await self.redis_client.setex(
                cache_key,
                ttl,
                json.dumps(data)
            )
            logger.debug(f"Cached result for {result.username}@{result.platform} (TTL: {ttl}s)")

        except Exception as e:
            logger.debug(f"Cache set failed for {result.username}@{result.platform}: {e}")

    async def _batch_get_cached_results(
        self,
        username: str,
        platforms: List[str]
    ) -> Dict[str, Optional[UsernameResult]]:
        """
        Batch get cached results from Redis using pipeline

        Args:
            username: Username to search
            platforms: List of platform names

        Returns:
            Dict mapping platform name to cached result (or None)
        """
        if not self._redis_cache_enabled or not self.redis_client:
            return {p: None for p in platforms}

        try:
            pipe = self.redis_client.pipeline()
            for platform in platforms:
                cache_key = f"{self._cache_prefix}{username}:{platform}"
                pipe.get(cache_key)

            cached_values = await pipe.execute()

            results = {}
            for platform, cached_data in zip(platforms, cached_values):
                if cached_data:
                    try:
                        data = json.loads(cached_data)
                        data['timestamp'] = datetime.fromisoformat(data['timestamp'])
                        results[platform] = UsernameResult(**data)
                    except Exception:
                        results[platform] = None
                else:
                    results[platform] = None

            cache_hits = sum(1 for r in results.values() if r is not None)
            if cache_hits > 0:
                logger.info(f"Cache hits: {cache_hits}/{len(platforms)} platforms for {username}")

            return results

        except Exception as e:
            logger.debug(f"Batch cache get failed: {e}")
            return {p: None for p in platforms}

    async def _batch_set_cached_results(self, results: List[UsernameResult]):
        """
        Batch cache results in Redis using pipeline

        Args:
            results: List of UsernameResult to cache
        """
        if not self._redis_cache_enabled or not self.redis_client or not results:
            return

        try:
            pipe = self.redis_client.pipeline()

            for result in results:
                cache_key = f"{self._cache_prefix}{result.username}:{result.platform}"
                data = result.to_dict()

                # Set appropriate TTL
                if result.status == 'found':
                    ttl = FOUND_RESULT_CACHE_TTL
                elif result.status == 'not_found':
                    ttl = NOT_FOUND_CACHE_TTL
                else:
                    ttl = DEFAULT_CACHE_TTL

                pipe.setex(cache_key, ttl, json.dumps(data))

            await pipe.execute()
            logger.debug(f"Batch cached {len(results)} results")

        except Exception as e:
            logger.debug(f"Batch cache set failed: {e}")

    async def clear_cache(self, username: Optional[str] = None):
        """
        Clear cached results

        Args:
            username: Clear only for specific username (None = clear all)
        """
        if not self._redis_cache_enabled or not self.redis_client:
            return

        try:
            if username:
                pattern = f"{self._cache_prefix}{username}:*"
            else:
                pattern = f"{self._cache_prefix}*"

            # Use SCAN to find keys (safe for large datasets)
            cursor = 0
            deleted = 0
            while True:
                cursor, keys = await self.redis_client.scan(cursor, match=pattern, count=100)
                if keys:
                    await self.redis_client.delete(*keys)
                    deleted += len(keys)
                if cursor == 0:
                    break

            logger.info(f"Cleared {deleted} cached results")

        except Exception as e:
            logger.error(f"Cache clear failed: {e}")

    async def get_cache_stats(self) -> Dict[str, Any]:
        """
        Get cache statistics

        Returns:
            Dict with cache statistics
        """
        if not self._redis_cache_enabled or not self.redis_client:
            return {"enabled": False}

        try:
            # Count cached entries
            pattern = f"{self._cache_prefix}*"
            cursor = 0
            total_keys = 0
            sample_keys = []

            while True:
                cursor, keys = await self.redis_client.scan(cursor, match=pattern, count=100)
                total_keys += len(keys)
                if len(sample_keys) < 10:
                    sample_keys.extend(keys[:10 - len(sample_keys)])
                if cursor == 0:
                    break

            return {
                "enabled": True,
                "total_cached_entries": total_keys,
                "cache_prefix": self._cache_prefix,
                "default_ttl": self._cache_ttl,
                "found_result_ttl": FOUND_RESULT_CACHE_TTL,
                "not_found_ttl": NOT_FOUND_CACHE_TTL
            }

        except Exception as e:
            logger.error(f"Cache stats failed: {e}")
            return {"enabled": True, "error": str(e)}

    @classmethod
    async def create_with_redis(
        cls,
        redis_url: str = "redis://localhost:6379/0",
        **kwargs
    ) -> 'SherlockEngine':
        """
        Factory method to create SherlockEngine with Redis caching

        Args:
            redis_url: Redis connection URL
            **kwargs: Additional arguments for SherlockEngine

        Returns:
            SherlockEngine instance with Redis caching enabled
        """
        try:
            redis_client = await aioredis.from_url(
                redis_url,
                encoding="utf-8",
                decode_responses=True
            )
            # Test connection
            await redis_client.ping()
            logger.info(f"Connected to Redis at {redis_url}")

            return cls(redis_client=redis_client, **kwargs)

        except Exception as e:
            logger.warning(f"Failed to connect to Redis: {e}. Running without cache.")
            return cls(**kwargs)

    async def take_screenshot(
        self,
        url: str,
        output_path: str,
        width: int = 1920,
        height: int = 1080
    ) -> Optional[str]:
        """
        Take screenshot of a profile page using Playwright

        Args:
            url: URL to screenshot
            output_path: Path to save screenshot
            width: Browser width
            height: Browser height

        Returns:
            Path to screenshot or None if failed
        """
        if not self.enable_screenshots:
            return None

        try:
            from playwright.async_api import async_playwright

            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                context = await browser.new_context(
                    viewport={'width': width, 'height': height},
                    user_agent=self._get_user_agent()
                )
                page = await context.new_page()

                await page.goto(url, wait_until='networkidle', timeout=30000)
                await page.screenshot(path=output_path, full_page=True)

                await browser.close()

                logger.info(f"Screenshot saved: {output_path}")
                return output_path

        except ImportError:
            logger.warning("Playwright not installed. Screenshots disabled.")
            return None
        except Exception as e:
            logger.error(f"Screenshot failed for {url}: {e}")
            return None

    async def search_with_screenshots(
        self,
        username: str,
        platforms: Optional[List[str]] = None,
        screenshot_dir: str = "screenshots"
    ) -> List[UsernameResult]:
        """
        Search username and take screenshots of found profiles

        Args:
            username: Username to search
            platforms: Platforms to search
            screenshot_dir: Directory to save screenshots

        Returns:
            List of UsernameResult with screenshot paths
        """
        import os
        os.makedirs(screenshot_dir, exist_ok=True)

        results = await self.search_username(username, platforms)

        # Take screenshots of found profiles
        for result in results:
            if result.status == 'found' and self.enable_screenshots:
                screenshot_name = f"{username}_{result.platform}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
                screenshot_path = os.path.join(screenshot_dir, screenshot_name)

                path = await self.take_screenshot(result.url, screenshot_path)
                result.screenshot_path = path

        return results

    def add_proxy(self, proxy: ProxyConfig):
        """Add a proxy to the pool"""
        self.proxies.append(proxy)

    def remove_proxy(self, proxy: ProxyConfig):
        """Remove a proxy from the pool"""
        if proxy in self.proxies:
            self.proxies.remove(proxy)

    def clear_proxies(self):
        """Clear all proxies"""
        self.proxies.clear()

    async def validate_proxy(self, proxy: ProxyConfig) -> bool:
        """Test if a proxy is working"""
        try:
            async with await self._create_session(proxy) as session:
                async with session.get(
                    'https://httpbin.org/ip',
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        logger.info(f"Proxy working, IP: {data.get('origin')}")
                        return True
        except Exception as e:
            logger.warning(f"Proxy validation failed: {e}")
        return False


# Convenience functions for synchronous usage
def search_username(
    username: str,
    platforms: Optional[List[str]] = None,
    **kwargs
) -> List[UsernameResult]:
    """
    Synchronous convenience function to search for a username

    Args:
        username: Username to search
        platforms: List of platforms (None = all)
        **kwargs: Additional arguments for SherlockEngine

    Returns:
        List of UsernameResult objects
    """
    engine = SherlockEngine(**kwargs)
    return asyncio.run(engine.search_username(username, platforms))


def get_available_platforms() -> List[str]:
    """Get list of all available platforms"""
    engine = SherlockEngine()
    return engine.get_platforms()


def get_platform_categories() -> Dict[str, List[str]]:
    """Get platforms grouped by category"""
    engine = SherlockEngine()
    return engine.get_platforms_by_category()
