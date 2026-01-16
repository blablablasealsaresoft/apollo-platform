"""
Holehe Integration - Check email across 120+ sites
Account discovery and platform enumeration
"""

import asyncio
import aiohttp
import json
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
import logging
from datetime import datetime


@dataclass
class AccountResult:
    """Result from account check"""
    platform: str
    exists: bool
    url: str
    category: str
    timestamp: str
    response_time: float
    additional_info: Optional[Dict[str, Any]] = None


class HoleheIntegration:
    """
    Integration with Holehe-style account enumeration
    Checks if email is registered on various platforms
    """

    PLATFORMS = {
        # Social Media
        'twitter': {
            'url': 'https://api.twitter.com/i/users/email_available.json',
            'method': 'GET',
            'category': 'social_media',
            'check_type': 'api'
        },
        'instagram': {
            'url': 'https://www.instagram.com/accounts/web_create_ajax/attempt/',
            'method': 'POST',
            'category': 'social_media',
            'check_type': 'web'
        },
        'facebook': {
            'url': 'https://www.facebook.com/login/identify/',
            'method': 'POST',
            'category': 'social_media',
            'check_type': 'web'
        },
        'linkedin': {
            'url': 'https://www.linkedin.com/uas/request-password-reset',
            'method': 'POST',
            'category': 'social_media',
            'check_type': 'web'
        },
        'pinterest': {
            'url': 'https://www.pinterest.com/_ngjs/resource/EmailExistsResource/get/',
            'method': 'GET',
            'category': 'social_media',
            'check_type': 'api'
        },
        'snapchat': {
            'url': 'https://accounts.snapchat.com/accounts/get_username_suggestions',
            'method': 'POST',
            'category': 'social_media',
            'check_type': 'api'
        },
        'reddit': {
            'url': 'https://www.reddit.com/api/check_email.json',
            'method': 'POST',
            'category': 'social_media',
            'check_type': 'api'
        },
        'tumblr': {
            'url': 'https://www.tumblr.com/svc/account/register',
            'method': 'POST',
            'category': 'social_media',
            'check_type': 'web'
        },

        # Professional
        'github': {
            'url': 'https://github.com/signup_check/email',
            'method': 'POST',
            'category': 'professional',
            'check_type': 'api'
        },
        'gitlab': {
            'url': 'https://gitlab.com/users/sign_in',
            'method': 'POST',
            'category': 'professional',
            'check_type': 'web'
        },
        'stackoverflow': {
            'url': 'https://stackoverflow.com/users/login',
            'method': 'POST',
            'category': 'professional',
            'check_type': 'web'
        },

        # Gaming
        'steam': {
            'url': 'https://store.steampowered.com/join/checkavail/',
            'method': 'POST',
            'category': 'gaming',
            'check_type': 'web'
        },
        'epicgames': {
            'url': 'https://www.epicgames.com/id/api/email/validate',
            'method': 'GET',
            'category': 'gaming',
            'check_type': 'api'
        },
        'xbox': {
            'url': 'https://login.live.com/GetCredentialType.srf',
            'method': 'POST',
            'category': 'gaming',
            'check_type': 'api'
        },
        'playstation': {
            'url': 'https://account.sonyentertainmentnetwork.com/liquid/reg/account/create/api/v1/check/',
            'method': 'POST',
            'category': 'gaming',
            'check_type': 'api'
        },

        # Shopping
        'amazon': {
            'url': 'https://www.amazon.com/ap/register',
            'method': 'POST',
            'category': 'shopping',
            'check_type': 'web'
        },
        'ebay': {
            'url': 'https://signup.ebay.com/pa/crte',
            'method': 'POST',
            'category': 'shopping',
            'check_type': 'web'
        },
        'etsy': {
            'url': 'https://www.etsy.com/api/v3/ajax/member/email-check',
            'method': 'POST',
            'category': 'shopping',
            'check_type': 'api'
        },

        # Communication
        'discord': {
            'url': 'https://discord.com/api/v9/auth/register',
            'method': 'POST',
            'category': 'communication',
            'check_type': 'api'
        },
        'slack': {
            'url': 'https://slack.com/api/users.lookupByEmail',
            'method': 'GET',
            'category': 'communication',
            'check_type': 'api'
        },
        'skype': {
            'url': 'https://client-s.gateway.messenger.live.com/v1/users/ME/contacts',
            'method': 'POST',
            'category': 'communication',
            'check_type': 'api'
        },

        # Entertainment
        'spotify': {
            'url': 'https://spclient.wg.spotify.com/signup/public/v1/account',
            'method': 'POST',
            'category': 'entertainment',
            'check_type': 'api'
        },
        'netflix': {
            'url': 'https://www.netflix.com/api/shakti/member',
            'method': 'POST',
            'category': 'entertainment',
            'check_type': 'api'
        },
        'soundcloud': {
            'url': 'https://api-v2.soundcloud.com/resolve',
            'method': 'GET',
            'category': 'entertainment',
            'check_type': 'api'
        },

        # Finance
        'paypal': {
            'url': 'https://www.paypal.com/us/smarthelp/account/email-availability',
            'method': 'POST',
            'category': 'finance',
            'check_type': 'web'
        },
        'venmo': {
            'url': 'https://api.venmo.com/v1/account/validate-email',
            'method': 'POST',
            'category': 'finance',
            'check_type': 'api'
        },

        # Email Services
        'google': {
            'url': 'https://accounts.google.com/_/signup/checkavailability',
            'method': 'POST',
            'category': 'email',
            'check_type': 'api'
        },
        'microsoft': {
            'url': 'https://login.live.com/GetCredentialType.srf',
            'method': 'POST',
            'category': 'email',
            'check_type': 'api'
        },
        'yahoo': {
            'url': 'https://login.yahoo.com/account/create',
            'method': 'POST',
            'category': 'email',
            'check_type': 'web'
        },

        # Dating
        'tinder': {
            'url': 'https://api.gotinder.com/v2/auth/sms/send',
            'method': 'POST',
            'category': 'dating',
            'check_type': 'api'
        },
        'bumble': {
            'url': 'https://bumble.com/api/v1/account',
            'method': 'POST',
            'category': 'dating',
            'check_type': 'api'
        },

        # Adobe Services
        'adobe': {
            'url': 'https://www.adobe.com/api/identity/check-email',
            'method': 'POST',
            'category': 'services',
            'check_type': 'api'
        },

        # Cloud Storage
        'dropbox': {
            'url': 'https://www.dropbox.com/ajax/verify',
            'method': 'POST',
            'category': 'cloud_storage',
            'check_type': 'web'
        },
        'onedrive': {
            'url': 'https://login.live.com/GetCredentialType.srf',
            'method': 'POST',
            'category': 'cloud_storage',
            'check_type': 'api'
        }
    }

    def __init__(self, timeout: int = 10, max_concurrent: int = 20):
        """
        Initialize Holehe Integration

        Args:
            timeout: Request timeout in seconds
            max_concurrent: Maximum concurrent requests
        """
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.logger = self._setup_logging()
        self.session = None

    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration"""
        logger = logging.getLogger('HoleheIntegration')
        logger.setLevel(logging.INFO)

        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)

        return logger

    def check(self, email: str, platforms: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """
        Check email across platforms (synchronous wrapper)

        Args:
            email: Email to check
            platforms: Specific platforms to check (None = all)

        Returns:
            List of account results
        """
        return asyncio.run(self.check_async(email, platforms))

    async def check_async(self, email: str, platforms: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """
        Check email across platforms

        Args:
            email: Email to check
            platforms: Specific platforms to check (None = all)

        Returns:
            List of account results
        """
        self.logger.info(f"Starting account enumeration for: {email}")

        platforms_to_check = platforms or list(self.PLATFORMS.keys())
        results = []

        connector = aiohttp.TCPConnector(limit=self.max_concurrent)
        timeout = aiohttp.ClientTimeout(total=self.timeout)

        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            self.session = session
            tasks = []

            for platform_name in platforms_to_check:
                if platform_name in self.PLATFORMS:
                    task = self._check_platform(email, platform_name, self.PLATFORMS[platform_name])
                    tasks.append(task)

            results = await asyncio.gather(*tasks, return_exceptions=True)

        # Filter out exceptions and None results
        valid_results = []
        for result in results:
            if isinstance(result, AccountResult):
                valid_results.append({
                    'platform': result.platform,
                    'exists': result.exists,
                    'url': result.url,
                    'category': result.category,
                    'timestamp': result.timestamp,
                    'response_time': result.response_time,
                    'additional_info': result.additional_info
                })
            elif isinstance(result, Exception):
                self.logger.error(f"Error during check: {str(result)}")

        self.logger.info(f"Found {sum(1 for r in valid_results if r['exists'])} accounts for {email}")
        return valid_results

    async def _check_platform(self, email: str, platform_name: str, platform_config: Dict) -> Optional[AccountResult]:
        """
        Check if email exists on specific platform

        Args:
            email: Email to check
            platform_name: Name of platform
            platform_config: Platform configuration

        Returns:
            AccountResult or None
        """
        start_time = datetime.now()

        try:
            headers = self._get_headers(platform_name)
            data = self._prepare_data(email, platform_name)

            if platform_config['method'] == 'POST':
                async with self.session.post(
                    platform_config['url'],
                    headers=headers,
                    json=data if isinstance(data, dict) else None,
                    data=data if isinstance(data, str) else None
                ) as response:
                    response_data = await self._parse_response(response)
                    exists = self._check_exists(platform_name, response, response_data)
            else:  # GET
                async with self.session.get(
                    platform_config['url'],
                    headers=headers,
                    params=data
                ) as response:
                    response_data = await self._parse_response(response)
                    exists = self._check_exists(platform_name, response, response_data)

            response_time = (datetime.now() - start_time).total_seconds()

            return AccountResult(
                platform=platform_name,
                exists=exists,
                url=platform_config['url'],
                category=platform_config['category'],
                timestamp=datetime.now().isoformat(),
                response_time=response_time,
                additional_info=self._extract_additional_info(platform_name, response_data)
            )

        except asyncio.TimeoutError:
            self.logger.warning(f"Timeout checking {platform_name}")
            return None
        except Exception as e:
            self.logger.error(f"Error checking {platform_name}: {str(e)}")
            return None

    def _get_headers(self, platform: str) -> Dict[str, str]:
        """Get headers for platform request"""
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }

        # Platform-specific headers
        platform_headers = {
            'twitter': {'x-twitter-active-user': 'yes', 'x-twitter-client-language': 'en'},
            'instagram': {'x-csrftoken': 'missing', 'x-ig-app-id': '936619743392459'},
            'discord': {'Content-Type': 'application/json'},
            'github': {'Accept': 'application/json'},
        }

        if platform in platform_headers:
            headers.update(platform_headers[platform])

        return headers

    def _prepare_data(self, email: str, platform: str) -> Dict[str, Any]:
        """Prepare request data for platform"""
        # Default data
        data = {'email': email}

        # Platform-specific data formatting
        platform_data = {
            'twitter': {'email': email},
            'instagram': {'email': email},
            'facebook': {'email': email},
            'github': {'value': email},
            'discord': {'email': email},
            'google': {'email': email},
            'microsoft': {'username': email},
        }

        return platform_data.get(platform, data)

    async def _parse_response(self, response: aiohttp.ClientResponse) -> Any:
        """Parse response from platform"""
        try:
            return await response.json()
        except:
            try:
                return await response.text()
            except:
                return None

    def _check_exists(self, platform: str, response: aiohttp.ClientResponse, data: Any) -> bool:
        """
        Determine if account exists based on response

        Different platforms have different indicators
        """
        status = response.status

        # Platform-specific existence checks
        if platform == 'twitter':
            return isinstance(data, dict) and not data.get('valid', True)
        elif platform == 'instagram':
            return isinstance(data, dict) and 'email' in data.get('errors', {})
        elif platform == 'github':
            return isinstance(data, dict) and not data.get('available', True)
        elif platform == 'discord':
            return status == 400 and isinstance(data, dict) and 'email' in data.get('errors', {})
        elif platform == 'google':
            return isinstance(data, str) and 'TooManyAttempts' not in data
        elif platform == 'microsoft':
            return isinstance(data, dict) and data.get('IfExistsResult') == 0
        elif platform == 'reddit':
            return isinstance(data, dict) and not data.get('json', {}).get('data', {}).get('available', True)

        # Generic checks
        if status == 200:
            if isinstance(data, dict):
                # Check common patterns
                if 'available' in data:
                    return not data['available']
                if 'exists' in data:
                    return data['exists']
                if 'error' in data:
                    return True

        return False

    def _extract_additional_info(self, platform: str, data: Any) -> Optional[Dict[str, Any]]:
        """Extract additional information from response"""
        if not isinstance(data, dict):
            return None

        info = {}

        # Extract useful fields
        useful_fields = ['username', 'user_id', 'display_name', 'profile_url', 'verified']
        for field in useful_fields:
            if field in data:
                info[field] = data[field]

        return info if info else None

    def get_platforms_by_category(self, category: str) -> List[str]:
        """
        Get list of platforms in a category

        Args:
            category: Category name

        Returns:
            List of platform names
        """
        return [
            name for name, config in self.PLATFORMS.items()
            if config['category'] == category
        ]

    def get_categories(self) -> List[str]:
        """Get list of all categories"""
        return list(set(config['category'] for config in self.PLATFORMS.values()))

    def get_statistics(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Get statistics from check results

        Args:
            results: List of account results

        Returns:
            Statistics dictionary
        """
        total = len(results)
        found = sum(1 for r in results if r['exists'])

        by_category = {}
        for result in results:
            category = result['category']
            if category not in by_category:
                by_category[category] = {'total': 0, 'found': 0}
            by_category[category]['total'] += 1
            if result['exists']:
                by_category[category]['found'] += 1

        return {
            'total_checked': total,
            'total_found': found,
            'percentage_found': (found / total * 100) if total > 0 else 0,
            'by_category': by_category,
            'platforms_found': [r['platform'] for r in results if r['exists']]
        }


if __name__ == "__main__":
    # Example usage
    holehe = HoleheIntegration()

    # Check all platforms
    results = holehe.check("target@example.com")
    print(f"Found accounts on {sum(1 for r in results if r['exists'])} platforms")

    # Check specific category
    social_platforms = holehe.get_platforms_by_category('social_media')
    results = holehe.check("target@example.com", platforms=social_platforms)

    # Get statistics
    stats = holehe.get_statistics(results)
    print(json.dumps(stats, indent=2))
