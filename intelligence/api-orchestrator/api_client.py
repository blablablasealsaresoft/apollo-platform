"""
API Client - HTTP Client with Authentication and Error Handling
Supports async requests, multiple auth methods, and retry logic
"""

import aiohttp
import asyncio
import time
import hmac
import hashlib
import base64
from typing import Dict, Optional, Any, Union
from urllib.parse import urlencode, urlparse
from dataclasses import dataclass
from enum import Enum
import logging
import json

logger = logging.getLogger(__name__)


class AuthType(Enum):
    """Authentication types"""
    NONE = "none"
    API_KEY = "api_key"
    BEARER_TOKEN = "bearer_token"
    BASIC_AUTH = "basic_auth"
    OAUTH2 = "oauth2"
    JWT = "jwt"
    HMAC = "hmac"
    CUSTOM = "custom"


@dataclass
class AuthConfig:
    """Authentication configuration"""
    auth_type: AuthType
    api_key: Optional[str] = None
    api_key_header: str = "X-API-Key"
    token: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    secret: Optional[str] = None
    custom_headers: Optional[Dict[str, str]] = None


@dataclass
class RequestConfig:
    """Request configuration"""
    method: str = "GET"
    timeout: float = 30.0
    max_retries: int = 3
    retry_delay: float = 1.0
    retry_backoff: float = 2.0
    verify_ssl: bool = True
    follow_redirects: bool = True
    headers: Optional[Dict[str, str]] = None
    params: Optional[Dict[str, Any]] = None
    json_data: Optional[Dict[str, Any]] = None
    form_data: Optional[Dict[str, Any]] = None


class APIClient:
    """Async HTTP client for API calls"""

    def __init__(
        self,
        base_url: Optional[str] = None,
        auth_config: Optional[AuthConfig] = None,
        default_headers: Optional[Dict[str, str]] = None
    ):
        """
        Initialize API client

        Args:
            base_url: Base URL for API
            auth_config: Authentication configuration
            default_headers: Default headers for all requests
        """
        self.base_url = base_url
        self.auth_config = auth_config
        self.default_headers = default_headers or {}
        self.session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self):
        """Async context manager entry"""
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.close()

    async def start(self):
        """Initialize HTTP session"""
        if self.session is None:
            timeout = aiohttp.ClientTimeout(total=30)
            self.session = aiohttp.ClientSession(timeout=timeout)
            logger.debug("Started HTTP session")

    async def close(self):
        """Close HTTP session"""
        if self.session:
            await self.session.close()
            self.session = None
            logger.debug("Closed HTTP session")

    async def request(
        self,
        endpoint: str,
        config: Optional[RequestConfig] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Execute HTTP request with retry logic

        Args:
            endpoint: API endpoint
            config: Request configuration
            **kwargs: Additional request parameters

        Returns:
            Response data
        """
        config = config or RequestConfig()
        url = self._build_url(endpoint)

        # Ensure session is started
        if self.session is None:
            await self.start()

        # Build request parameters
        headers = self._build_headers(config)
        params = config.params or {}

        retry_count = 0
        last_error = None

        while retry_count <= config.max_retries:
            try:
                # Execute request
                async with self.session.request(
                    method=config.method,
                    url=url,
                    headers=headers,
                    params=params,
                    json=config.json_data,
                    data=config.form_data,
                    timeout=aiohttp.ClientTimeout(total=config.timeout),
                    ssl=config.verify_ssl,
                    allow_redirects=config.follow_redirects,
                    **kwargs
                ) as response:
                    # Log request
                    logger.debug(
                        f"{config.method} {url} -> {response.status}"
                    )

                    # Handle response
                    return await self._handle_response(response)

            except aiohttp.ClientError as e:
                last_error = e
                retry_count += 1

                if retry_count <= config.max_retries:
                    # Calculate backoff delay
                    delay = config.retry_delay * (
                        config.retry_backoff ** (retry_count - 1)
                    )
                    logger.warning(
                        f"Request failed, retrying in {delay}s "
                        f"(attempt {retry_count}/{config.max_retries}): {e}"
                    )
                    await asyncio.sleep(delay)
                else:
                    logger.error(f"Request failed after {retry_count} attempts: {e}")

            except Exception as e:
                logger.error(f"Unexpected error: {e}")
                raise

        # All retries exhausted
        raise last_error

    async def get(self, endpoint: str, params: Optional[Dict] = None, **kwargs):
        """GET request"""
        config = RequestConfig(method="GET", params=params)
        return await self.request(endpoint, config, **kwargs)

    async def post(
        self,
        endpoint: str,
        json_data: Optional[Dict] = None,
        form_data: Optional[Dict] = None,
        **kwargs
    ):
        """POST request"""
        config = RequestConfig(
            method="POST",
            json_data=json_data,
            form_data=form_data
        )
        return await self.request(endpoint, config, **kwargs)

    async def put(
        self,
        endpoint: str,
        json_data: Optional[Dict] = None,
        **kwargs
    ):
        """PUT request"""
        config = RequestConfig(method="PUT", json_data=json_data)
        return await self.request(endpoint, config, **kwargs)

    async def delete(self, endpoint: str, **kwargs):
        """DELETE request"""
        config = RequestConfig(method="DELETE")
        return await self.request(endpoint, config, **kwargs)

    def _build_url(self, endpoint: str) -> str:
        """Build full URL from endpoint"""
        if endpoint.startswith(("http://", "https://")):
            return endpoint

        if self.base_url:
            return f"{self.base_url.rstrip('/')}/{endpoint.lstrip('/')}"

        return endpoint

    def _build_headers(self, config: RequestConfig) -> Dict[str, str]:
        """Build request headers with authentication"""
        headers = self.default_headers.copy()

        # Add config headers
        if config.headers:
            headers.update(config.headers)

        # Add authentication
        if self.auth_config:
            auth_headers = self._get_auth_headers()
            headers.update(auth_headers)

        return headers

    def _get_auth_headers(self) -> Dict[str, str]:
        """Generate authentication headers"""
        if not self.auth_config:
            return {}

        auth_type = self.auth_config.auth_type

        if auth_type == AuthType.API_KEY:
            return {
                self.auth_config.api_key_header: self.auth_config.api_key
            }

        elif auth_type == AuthType.BEARER_TOKEN:
            return {
                "Authorization": f"Bearer {self.auth_config.token}"
            }

        elif auth_type == AuthType.BASIC_AUTH:
            credentials = f"{self.auth_config.username}:{self.auth_config.password}"
            encoded = base64.b64encode(credentials.encode()).decode()
            return {
                "Authorization": f"Basic {encoded}"
            }

        elif auth_type == AuthType.JWT:
            return {
                "Authorization": f"Bearer {self.auth_config.token}"
            }

        elif auth_type == AuthType.CUSTOM:
            return self.auth_config.custom_headers or {}

        return {}

    async def _handle_response(self, response: aiohttp.ClientResponse) -> Dict:
        """Handle HTTP response"""
        # Check status code
        if response.status >= 400:
            error_text = await response.text()
            raise aiohttp.ClientResponseError(
                request_info=response.request_info,
                history=response.history,
                status=response.status,
                message=error_text
            )

        # Parse response
        content_type = response.headers.get("Content-Type", "")

        if "application/json" in content_type:
            data = await response.json()
        else:
            text = await response.text()
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                data = {"text": text}

        return {
            "status": response.status,
            "headers": dict(response.headers),
            "data": data
        }

    def sign_request_hmac(
        self,
        method: str,
        url: str,
        body: Optional[str] = None,
        timestamp: Optional[int] = None
    ) -> str:
        """
        Sign request using HMAC

        Args:
            method: HTTP method
            url: Request URL
            body: Request body
            timestamp: Unix timestamp

        Returns:
            HMAC signature
        """
        if not self.auth_config or not self.auth_config.secret:
            raise ValueError("HMAC secret not configured")

        timestamp = timestamp or int(time.time())
        parsed_url = urlparse(url)
        path = parsed_url.path

        # Build message to sign
        message_parts = [
            str(timestamp),
            method.upper(),
            path
        ]

        if body:
            message_parts.append(body)

        message = "\n".join(message_parts)

        # Generate signature
        signature = hmac.new(
            self.auth_config.secret.encode(),
            message.encode(),
            hashlib.sha256
        ).hexdigest()

        return signature


class BatchAPIClient:
    """Client for batch API requests"""

    def __init__(
        self,
        base_url: Optional[str] = None,
        auth_config: Optional[AuthConfig] = None,
        max_concurrent: int = 10
    ):
        """
        Initialize batch client

        Args:
            base_url: Base URL
            auth_config: Authentication configuration
            max_concurrent: Maximum concurrent requests
        """
        self.client = APIClient(base_url, auth_config)
        self.max_concurrent = max_concurrent
        self.semaphore = asyncio.Semaphore(max_concurrent)

    async def __aenter__(self):
        await self.client.start()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.client.close()

    async def batch_request(
        self,
        requests: list[Dict[str, Any]]
    ) -> list[Dict[str, Any]]:
        """
        Execute multiple requests concurrently

        Args:
            requests: List of request configurations
                Each dict should have 'endpoint' and optional 'config'

        Returns:
            List of responses
        """
        async def limited_request(req: Dict) -> Dict:
            async with self.semaphore:
                try:
                    endpoint = req['endpoint']
                    config = req.get('config')
                    result = await self.client.request(endpoint, config)
                    return {
                        'success': True,
                        'endpoint': endpoint,
                        'result': result
                    }
                except Exception as e:
                    logger.error(f"Batch request failed for {req['endpoint']}: {e}")
                    return {
                        'success': False,
                        'endpoint': req['endpoint'],
                        'error': str(e)
                    }

        tasks = [limited_request(req) for req in requests]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        return results


class RateLimitedClient(APIClient):
    """API client with built-in rate limiting"""

    def __init__(
        self,
        base_url: Optional[str] = None,
        auth_config: Optional[AuthConfig] = None,
        requests_per_second: float = 10.0
    ):
        """
        Initialize rate limited client

        Args:
            base_url: Base URL
            auth_config: Authentication configuration
            requests_per_second: Rate limit
        """
        super().__init__(base_url, auth_config)
        self.requests_per_second = requests_per_second
        self.last_request_time = 0.0

    async def request(
        self,
        endpoint: str,
        config: Optional[RequestConfig] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """Execute rate limited request"""
        # Calculate wait time
        min_interval = 1.0 / self.requests_per_second
        now = time.time()
        elapsed = now - self.last_request_time

        if elapsed < min_interval:
            wait_time = min_interval - elapsed
            await asyncio.sleep(wait_time)

        # Execute request
        self.last_request_time = time.time()
        return await super().request(endpoint, config, **kwargs)
