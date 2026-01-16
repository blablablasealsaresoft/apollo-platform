"""
HaveIBeenPwned (HIBP) API Integration
Check for breached accounts and compromised passwords
"""

import asyncio
import aiohttp
import logging
import hashlib
from typing import Dict, List, Optional, Any
from datetime import datetime


class HaveIBeenPwnedIntegration:
    """
    HaveIBeenPwned API integration
    Check emails, domains, and passwords against breach database
    """

    BASE_URL = "https://haveibeenpwned.com/api/v3"
    PWNED_PASSWORDS_URL = "https://api.pwnedpasswords.com"

    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize HIBP integration

        Args:
            api_key: HIBP API key (required for email/domain searches)
        """
        self.api_key = api_key
        self.logger = logging.getLogger(__name__)

        if not api_key:
            self.logger.warning("HIBP API key not provided - email/domain searches will fail")

        # Rate limiting
        self.rate_limit_delay = 1.5  # HIBP requires 1.5s between requests
        self.last_request_time = 0

    async def _make_request(
        self,
        endpoint: str,
        params: Optional[Dict] = None,
        use_api_key: bool = True
    ) -> Any:
        """
        Make request to HIBP API

        Args:
            endpoint: API endpoint
            params: Query parameters
            use_api_key: Whether to include API key

        Returns:
            API response
        """
        # Rate limiting
        current_time = asyncio.get_event_loop().time()
        time_since_last_request = current_time - self.last_request_time
        if time_since_last_request < self.rate_limit_delay:
            await asyncio.sleep(self.rate_limit_delay - time_since_last_request)

        headers = {
            'User-Agent': 'Apollo-Breach-Correlation',
            'Accept': 'application/json'
        }

        if use_api_key:
            if not self.api_key:
                raise ValueError("HIBP API key required for this request")
            headers['hibp-api-key'] = self.api_key

        url = f"{self.BASE_URL}/{endpoint}"

        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(
                    url,
                    headers=headers,
                    params=params,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    self.last_request_time = asyncio.get_event_loop().time()

                    if response.status == 200:
                        return await response.json()
                    elif response.status == 404:
                        # No breaches found
                        return []
                    elif response.status == 401:
                        raise Exception("Invalid HIBP API key")
                    elif response.status == 429:
                        raise Exception("Rate limit exceeded")
                    else:
                        error_text = await response.text()
                        raise Exception(f"API request failed: {response.status} - {error_text}")

            except asyncio.TimeoutError:
                raise Exception("Request timeout")
            except Exception as e:
                self.logger.error(f"Request failed: {e}")
                raise

    async def check_email_breaches(
        self,
        email: str,
        truncate_response: bool = False,
        include_unverified: bool = True
    ) -> List[Dict[str, Any]]:
        """
        Check if email has been in any breaches

        Args:
            email: Email address to check
            truncate_response: Return only breach names
            include_unverified: Include unverified breaches

        Returns:
            List of breaches
        """
        self.logger.info(f"Checking HIBP for email breaches: {email}")

        params = {
            'truncateResponse': str(truncate_response).lower(),
            'includeUnverified': str(include_unverified).lower()
        }

        endpoint = f"breachedaccount/{email}"
        breaches = await self._make_request(endpoint, params=params)

        return self._parse_breaches(breaches)

    async def check_email_pastes(self, email: str) -> List[Dict[str, Any]]:
        """
        Check if email has been in any pastes

        Args:
            email: Email address to check

        Returns:
            List of pastes
        """
        self.logger.info(f"Checking HIBP for email pastes: {email}")

        endpoint = f"pasteaccount/{email}"
        pastes = await self._make_request(endpoint)

        return self._parse_pastes(pastes)

    async def check_domain_breaches(
        self,
        domain: str,
        include_unverified: bool = True
    ) -> List[Dict[str, Any]]:
        """
        Check breaches for a domain

        Args:
            domain: Domain to check
            include_unverified: Include unverified breaches

        Returns:
            List of breaches affecting the domain
        """
        self.logger.info(f"Checking HIBP for domain breaches: {domain}")

        # First get all breaches
        all_breaches = await self.get_all_breaches()

        # Filter by domain
        domain_breaches = []
        for breach in all_breaches:
            if domain.lower() in breach.get('Domain', '').lower():
                domain_breaches.append(breach)

        return domain_breaches

    async def check_password(self, password: str) -> int:
        """
        Check if password has been pwned using k-anonymity

        Args:
            password: Password to check

        Returns:
            Number of times password has been seen in breaches
        """
        self.logger.info("Checking password against Pwned Passwords")

        # Hash the password
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()

        # Use k-anonymity - only send first 5 chars
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]

        # Query the range API
        url = f"{self.PWNED_PASSWORDS_URL}/range/{prefix}"

        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                if response.status != 200:
                    raise Exception(f"Pwned Passwords API failed: {response.status}")

                text = await response.text()

                # Parse response
                for line in text.split('\n'):
                    if ':' not in line:
                        continue

                    hash_suffix, count = line.strip().split(':')
                    if hash_suffix == suffix:
                        return int(count)

        return 0  # Password not found in breaches

    async def check_password_hash(self, sha1_hash: str) -> int:
        """
        Check if password hash has been pwned

        Args:
            sha1_hash: SHA1 hash of password

        Returns:
            Number of times hash has been seen in breaches
        """
        self.logger.info(f"Checking password hash: {sha1_hash[:10]}...")

        sha1_hash = sha1_hash.upper()
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]

        url = f"{self.PWNED_PASSWORDS_URL}/range/{prefix}"

        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                if response.status != 200:
                    raise Exception(f"Pwned Passwords API failed: {response.status}")

                text = await response.text()

                for line in text.split('\n'):
                    if ':' not in line:
                        continue

                    hash_suffix, count = line.strip().split(':')
                    if hash_suffix == suffix:
                        return int(count)

        return 0

    async def get_all_breaches(self, domain: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get all breaches in the system

        Args:
            domain: Optional domain filter

        Returns:
            List of all breaches
        """
        self.logger.info("Fetching all breaches from HIBP")

        params = {}
        if domain:
            params['domain'] = domain

        breaches = await self._make_request("breaches", params=params, use_api_key=False)

        return self._parse_breaches(breaches)

    async def get_breach(self, breach_name: str) -> Dict[str, Any]:
        """
        Get details for a specific breach

        Args:
            breach_name: Name of the breach

        Returns:
            Breach details
        """
        self.logger.info(f"Fetching breach details: {breach_name}")

        endpoint = f"breach/{breach_name}"
        breach = await self._make_request(endpoint, use_api_key=False)

        return self._parse_breach(breach)

    async def get_data_classes(self) -> List[str]:
        """
        Get all data classes in the system

        Returns:
            List of data class names
        """
        self.logger.info("Fetching data classes from HIBP")

        data_classes = await self._make_request("dataclasses", use_api_key=False)

        return data_classes

    async def bulk_check_passwords(self, passwords: List[str]) -> Dict[str, int]:
        """
        Check multiple passwords

        Args:
            passwords: List of passwords to check

        Returns:
            Dictionary of password to pwn count
        """
        results = {}

        for password in passwords:
            try:
                count = await self.check_password(password)
                # Use hash prefix as key for privacy
                sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest()
                results[sha1_hash[:10]] = count
            except Exception as e:
                self.logger.error(f"Failed to check password: {e}")

        return results

    def _parse_breaches(self, breaches: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Parse and standardize breach data"""
        if not breaches:
            return []

        parsed = []
        for breach in breaches:
            parsed.append(self._parse_breach(breach))

        return parsed

    def _parse_breach(self, breach: Dict[str, Any]) -> Dict[str, Any]:
        """Parse individual breach"""
        return {
            'Name': breach.get('Name'),
            'Title': breach.get('Title'),
            'Domain': breach.get('Domain'),
            'BreachDate': self._parse_date(breach.get('BreachDate')),
            'AddedDate': self._parse_date(breach.get('AddedDate')),
            'ModifiedDate': self._parse_date(breach.get('ModifiedDate')),
            'PwnCount': breach.get('PwnCount'),
            'Description': breach.get('Description'),
            'DataClasses': breach.get('DataClasses', []),
            'IsVerified': breach.get('IsVerified', False),
            'IsFabricated': breach.get('IsFabricated', False),
            'IsSensitive': breach.get('IsSensitive', False),
            'IsRetired': breach.get('IsRetired', False),
            'IsSpamList': breach.get('IsSpamList', False),
            'LogoPath': breach.get('LogoPath')
        }

    def _parse_pastes(self, pastes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Parse and standardize paste data"""
        if not pastes:
            return []

        parsed = []
        for paste in pastes:
            parsed.append({
                'Source': paste.get('Source'),
                'Id': paste.get('Id'),
                'Title': paste.get('Title'),
                'Date': self._parse_date(paste.get('Date')),
                'EmailCount': paste.get('EmailCount'),
                'Link': f"https://pastebin.com/{paste.get('Id')}" if paste.get('Source') == 'Pastebin' else None
            })

        return parsed

    def _parse_date(self, date_string: Optional[str]) -> Optional[datetime]:
        """Parse date string to datetime"""
        if not date_string:
            return None

        try:
            # HIBP uses ISO 8601 format
            return datetime.fromisoformat(date_string.replace('Z', '+00:00'))
        except Exception:
            return None

    async def get_breach_summary(self, email: str) -> Dict[str, Any]:
        """
        Get comprehensive breach summary for email

        Args:
            email: Email address

        Returns:
            Breach summary with statistics
        """
        breaches = await self.check_email_breaches(email)
        pastes = await self.check_email_pastes(email)

        # Calculate statistics
        total_pwns = sum(b.get('PwnCount', 0) for b in breaches)
        data_classes = set()
        for breach in breaches:
            data_classes.update(breach.get('DataClasses', []))

        # Get most severe breaches
        verified_breaches = [b for b in breaches if b.get('IsVerified')]
        sensitive_breaches = [b for b in breaches if b.get('IsSensitive')]

        return {
            'email': email,
            'total_breaches': len(breaches),
            'verified_breaches': len(verified_breaches),
            'sensitive_breaches': len(sensitive_breaches),
            'total_pastes': len(pastes),
            'total_pwns': total_pwns,
            'data_classes_exposed': list(data_classes),
            'breaches': breaches,
            'pastes': pastes,
            'risk_score': self._calculate_risk_score(breaches, pastes)
        }

    def _calculate_risk_score(self, breaches: List[Dict], pastes: List[Dict]) -> float:
        """
        Calculate risk score based on breaches and pastes

        Args:
            breaches: List of breaches
            pastes: List of pastes

        Returns:
            Risk score (0-100)
        """
        score = 0

        # Base score from number of breaches
        score += min(len(breaches) * 5, 40)

        # Add score for verified breaches
        verified = sum(1 for b in breaches if b.get('IsVerified'))
        score += min(verified * 3, 15)

        # Add score for sensitive breaches
        sensitive = sum(1 for b in breaches if b.get('IsSensitive'))
        score += min(sensitive * 5, 20)

        # Add score for pastes
        score += min(len(pastes) * 2, 10)

        # Add score for data classes
        data_classes = set()
        for breach in breaches:
            data_classes.update(breach.get('DataClasses', []))

        # Critical data classes
        critical_classes = {'Passwords', 'Credit cards', 'Social security numbers', 'Bank account numbers'}
        critical_exposed = data_classes.intersection(critical_classes)
        score += len(critical_exposed) * 5

        return min(score, 100)

    async def monitor_email(self, email: str, callback=None) -> Dict[str, Any]:
        """
        Monitor email for new breaches

        Args:
            email: Email to monitor
            callback: Optional callback function for notifications

        Returns:
            Current breach status
        """
        summary = await self.get_breach_summary(email)

        if callback:
            await callback(summary)

        return summary


if __name__ == "__main__":
    # Example usage
    logging.basicConfig(level=logging.INFO)

    async def main():
        # Initialize with API key
        hibp = HaveIBeenPwnedIntegration(api_key="your-api-key")

        # Check email breaches
        breaches = await hibp.check_email_breaches("test@example.com")
        print(f"Found {len(breaches)} breaches")

        for breach in breaches:
            print(f"\nBreach: {breach['Name']}")
            print(f"Date: {breach['BreachDate']}")
            print(f"Pwned: {breach['PwnCount']:,}")
            print(f"Data: {', '.join(breach['DataClasses'])}")

        # Check password
        password = "password123"
        count = await hibp.check_password(password)
        print(f"\nPassword '{password}' seen {count:,} times in breaches")

        # Get comprehensive summary
        summary = await hibp.get_breach_summary("test@example.com")
        print(f"\nRisk Score: {summary['risk_score']}/100")

    asyncio.run(main())
