#!/usr/bin/env python3
"""
Have I Been Pwned (HIBP) API Client
Integration with HIBP breach database and Pwned Passwords API

HIBP provides:
- Breach database checking for emails
- Paste appearances for emails
- Domain search for breached accounts
- Pwned Passwords API (k-anonymity)

API Documentation: https://haveibeenpwned.com/API/v3
"""

import asyncio
import aiohttp
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
import logging
import hashlib
import json


logger = logging.getLogger(__name__)


@dataclass
class HIBPBreach:
    """Breach information from HIBP"""
    name: str
    title: str
    domain: str
    breach_date: Optional[datetime]
    added_date: datetime
    modified_date: Optional[datetime]
    pwn_count: int
    description: str
    data_classes: List[str]
    logo_path: Optional[str]
    is_verified: bool
    is_fabricated: bool
    is_sensitive: bool
    is_retired: bool
    is_spam_list: bool

    def to_dict(self) -> Dict[str, Any]:
        return {
            'name': self.name,
            'title': self.title,
            'domain': self.domain,
            'breach_date': self.breach_date.isoformat() if self.breach_date else None,
            'added_date': self.added_date.isoformat(),
            'modified_date': self.modified_date.isoformat() if self.modified_date else None,
            'pwn_count': self.pwn_count,
            'description': self.description,
            'data_classes': self.data_classes,
            'logo_path': self.logo_path,
            'is_verified': self.is_verified,
            'is_fabricated': self.is_fabricated,
            'is_sensitive': self.is_sensitive,
            'is_retired': self.is_retired,
            'is_spam_list': self.is_spam_list
        }

    @property
    def severity(self) -> str:
        """Calculate breach severity"""
        critical_data = ['passwords', 'credit cards', 'bank accounts']
        high_risk_data = ['email addresses', 'phone numbers', 'physical addresses']

        data_lower = [d.lower() for d in self.data_classes]

        for cd in critical_data:
            if any(cd in d for d in data_lower):
                return 'critical'

        for hrd in high_risk_data:
            if any(hrd in d for d in data_lower):
                return 'high'

        if self.pwn_count > 1000000:
            return 'high'
        elif self.pwn_count > 100000:
            return 'medium'

        return 'low'


@dataclass
class HIBPPaste:
    """Paste appearance from HIBP"""
    source: str
    paste_id: str
    title: Optional[str]
    date: Optional[datetime]
    email_count: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            'source': self.source,
            'paste_id': self.paste_id,
            'title': self.title,
            'date': self.date.isoformat() if self.date else None,
            'email_count': self.email_count
        }


@dataclass
class HIBPCheckResult:
    """Result of HIBP check"""
    query: str
    query_type: str
    breaches: List[HIBPBreach] = field(default_factory=list)
    pastes: List[HIBPPaste] = field(default_factory=list)
    checked_at: datetime = field(default_factory=datetime.utcnow)

    @property
    def breaches_found(self) -> int:
        return len(self.breaches)

    @property
    def pastes_found(self) -> int:
        return len(self.pastes)

    @property
    def severity(self) -> str:
        """Overall severity"""
        if not self.breaches:
            return 'none'

        severities = [b.severity for b in self.breaches]
        if 'critical' in severities:
            return 'critical'
        if 'high' in severities:
            return 'high'
        if 'medium' in severities:
            return 'medium'
        return 'low'

    def to_dict(self) -> Dict[str, Any]:
        return {
            'query': self.query,
            'query_type': self.query_type,
            'breaches_found': self.breaches_found,
            'pastes_found': self.pastes_found,
            'severity': self.severity,
            'breaches': [b.to_dict() for b in self.breaches],
            'pastes': [p.to_dict() for p in self.pastes],
            'checked_at': self.checked_at.isoformat()
        }


@dataclass
class PasswordCheckResult:
    """Result of password check"""
    sha1_hash: str
    compromised: bool
    exposure_count: int
    checked_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'sha1_prefix': self.sha1_hash[:5],
            'compromised': self.compromised,
            'exposure_count': self.exposure_count,
            'checked_at': self.checked_at.isoformat()
        }


class HIBPClient:
    """
    Have I Been Pwned API client

    Features:
    - Breach checking for emails
    - Paste checking for emails
    - Domain search
    - Pwned Passwords API (no API key required)
    """

    # API endpoints
    BASE_URL = "https://haveibeenpwned.com/api/v3"
    PASSWORDS_URL = "https://api.pwnedpasswords.com"

    # Rate limits
    RATE_LIMIT_DELAY = 1.5  # seconds between requests (free tier: 1.5s)

    def __init__(
        self,
        api_key: Optional[str] = None,
        user_agent: str = "Apollo-Intelligence-Platform"
    ):
        """
        Initialize HIBP client

        Args:
            api_key: HIBP API key (required for breach/paste lookups)
            user_agent: User agent string
        """
        self.api_key = api_key
        self.user_agent = user_agent

        self._session: Optional[aiohttp.ClientSession] = None
        self._last_request: Optional[datetime] = None

        # Statistics
        self.stats = {
            'total_checks': 0,
            'breaches_found': 0,
            'pastes_found': 0,
            'password_checks': 0,
            'last_check': None
        }

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp session"""
        if self._session is None or self._session.closed:
            headers = {
                'User-Agent': self.user_agent,
                'Accept': 'application/json'
            }
            if self.api_key:
                headers['hibp-api-key'] = self.api_key

            self._session = aiohttp.ClientSession(headers=headers)
        return self._session

    async def close(self):
        """Close the session"""
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None

    async def _rate_limit_wait(self):
        """Apply rate limiting"""
        if self._last_request:
            elapsed = (datetime.utcnow() - self._last_request).total_seconds()
            if elapsed < self.RATE_LIMIT_DELAY:
                await asyncio.sleep(self.RATE_LIMIT_DELAY - elapsed)
        self._last_request = datetime.utcnow()

    async def check_email(
        self,
        email: str,
        include_unverified: bool = False,
        truncate_response: bool = False
    ) -> HIBPCheckResult:
        """
        Check email for breaches

        Args:
            email: Email address to check
            include_unverified: Include unverified breaches
            truncate_response: Return truncated response

        Returns:
            HIBPCheckResult with breaches
        """
        if not self.api_key:
            raise ValueError("API key required for email breach checks")

        await self._rate_limit_wait()

        session = await self._get_session()
        breaches = []

        try:
            url = f"{self.BASE_URL}/breachedaccount/{email}"
            params = {'truncateResponse': 'true' if truncate_response else 'false'}
            if include_unverified:
                params['includeUnverified'] = 'true'

            logger.info(f"HIBP: Checking email {email[:20]}...")

            async with session.get(
                url,
                params=params,
                timeout=aiohttp.ClientTimeout(total=30)
            ) as response:
                if response.status == 200:
                    data = await response.json()

                    for breach_data in data:
                        breach = self._parse_breach(breach_data)
                        breaches.append(breach)

                    logger.info(f"HIBP: Found {len(breaches)} breaches for {email[:20]}...")

                elif response.status == 404:
                    logger.info(f"HIBP: No breaches found for {email[:20]}...")

                elif response.status == 401:
                    logger.error("HIBP: Invalid API key")
                    raise ValueError("Invalid API key")

                elif response.status == 429:
                    logger.warning("HIBP: Rate limit exceeded")
                    raise RuntimeError("Rate limit exceeded")

                else:
                    text = await response.text()
                    logger.error(f"HIBP error: {response.status} - {text}")

        except aiohttp.ClientError as e:
            logger.error(f"HIBP request failed: {e}")
            raise

        # Update statistics
        self.stats['total_checks'] += 1
        self.stats['breaches_found'] += len(breaches)
        self.stats['last_check'] = datetime.utcnow()

        return HIBPCheckResult(
            query=email,
            query_type='email',
            breaches=breaches
        )

    async def check_pastes(self, email: str) -> List[HIBPPaste]:
        """
        Check email for paste appearances

        Args:
            email: Email address to check

        Returns:
            List of paste appearances
        """
        if not self.api_key:
            raise ValueError("API key required for paste checks")

        await self._rate_limit_wait()

        session = await self._get_session()
        pastes = []

        try:
            url = f"{self.BASE_URL}/pasteaccount/{email}"

            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=30)
            ) as response:
                if response.status == 200:
                    data = await response.json()

                    for paste_data in data:
                        paste = HIBPPaste(
                            source=paste_data.get('Source', ''),
                            paste_id=paste_data.get('Id', ''),
                            title=paste_data.get('Title'),
                            date=datetime.fromisoformat(
                                paste_data['Date'].replace('Z', '+00:00')
                            ) if paste_data.get('Date') else None,
                            email_count=paste_data.get('EmailCount', 0)
                        )
                        pastes.append(paste)

                    logger.info(f"HIBP: Found {len(pastes)} pastes for {email[:20]}...")
                    self.stats['pastes_found'] += len(pastes)

                elif response.status == 404:
                    logger.info(f"HIBP: No pastes found for {email[:20]}...")

        except aiohttp.ClientError as e:
            logger.error(f"HIBP paste check failed: {e}")

        return pastes

    async def check_email_full(
        self,
        email: str,
        include_pastes: bool = True
    ) -> HIBPCheckResult:
        """
        Full email check including breaches and pastes

        Args:
            email: Email address to check
            include_pastes: Also check for paste appearances

        Returns:
            Complete HIBPCheckResult
        """
        result = await self.check_email(email)

        if include_pastes:
            pastes = await self.check_pastes(email)
            result.pastes = pastes

        return result

    async def check_password(
        self,
        password: str
    ) -> PasswordCheckResult:
        """
        Check if password has been exposed using Pwned Passwords API

        Uses k-anonymity model - only sends first 5 characters of SHA-1 hash.
        This means your full password is NEVER sent to the API.

        No API key required for this endpoint.

        Args:
            password: Password to check

        Returns:
            PasswordCheckResult
        """
        # Hash the password
        sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]

        # Create a separate session without API key header
        async with aiohttp.ClientSession(
            headers={'User-Agent': self.user_agent}
        ) as session:
            try:
                url = f"{self.PASSWORDS_URL}/range/{prefix}"

                logger.debug(f"HIBP Passwords: Checking hash prefix {prefix}...")

                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=15)
                ) as response:
                    if response.status == 200:
                        text = await response.text()

                        # Search for our suffix
                        for line in text.splitlines():
                            parts = line.split(':')
                            if len(parts) == 2:
                                hash_suffix, count = parts
                                if hash_suffix == suffix:
                                    self.stats['password_checks'] += 1
                                    return PasswordCheckResult(
                                        sha1_hash=sha1_hash,
                                        compromised=True,
                                        exposure_count=int(count)
                                    )

                        # Not found = not compromised
                        self.stats['password_checks'] += 1
                        return PasswordCheckResult(
                            sha1_hash=sha1_hash,
                            compromised=False,
                            exposure_count=0
                        )

                    else:
                        logger.error(f"HIBP Passwords error: {response.status}")

            except aiohttp.ClientError as e:
                logger.error(f"HIBP password check failed: {e}")
                raise

        return PasswordCheckResult(
            sha1_hash=sha1_hash,
            compromised=False,
            exposure_count=0
        )

    async def get_all_breaches(
        self,
        domain: Optional[str] = None
    ) -> List[HIBPBreach]:
        """
        Get all breaches in the HIBP database

        Args:
            domain: Filter by domain (optional)

        Returns:
            List of all breaches
        """
        session = await self._get_session()
        breaches = []

        try:
            url = f"{self.BASE_URL}/breaches"
            params = {}
            if domain:
                params['domain'] = domain

            async with session.get(
                url,
                params=params,
                timeout=aiohttp.ClientTimeout(total=60)
            ) as response:
                if response.status == 200:
                    data = await response.json()

                    for breach_data in data:
                        breach = self._parse_breach(breach_data)
                        breaches.append(breach)

                    logger.info(f"HIBP: Retrieved {len(breaches)} breaches")

        except aiohttp.ClientError as e:
            logger.error(f"HIBP get all breaches failed: {e}")

        return breaches

    async def get_breach_info(self, breach_name: str) -> Optional[HIBPBreach]:
        """
        Get information about a specific breach

        Args:
            breach_name: Name of the breach

        Returns:
            HIBPBreach or None
        """
        session = await self._get_session()

        try:
            url = f"{self.BASE_URL}/breach/{breach_name}"

            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=30)
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    return self._parse_breach(data)
                elif response.status == 404:
                    logger.info(f"HIBP: Breach '{breach_name}' not found")

        except aiohttp.ClientError as e:
            logger.error(f"HIBP get breach info failed: {e}")

        return None

    async def get_data_classes(self) -> List[str]:
        """
        Get all data classes in HIBP

        Returns:
            List of data class names
        """
        session = await self._get_session()

        try:
            url = f"{self.BASE_URL}/dataclasses"

            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=30)
            ) as response:
                if response.status == 200:
                    return await response.json()

        except aiohttp.ClientError as e:
            logger.error(f"HIBP get data classes failed: {e}")

        return []

    def _parse_breach(self, data: Dict[str, Any]) -> HIBPBreach:
        """Parse breach data from API response"""
        return HIBPBreach(
            name=data.get('Name', ''),
            title=data.get('Title', ''),
            domain=data.get('Domain', ''),
            breach_date=datetime.fromisoformat(
                data['BreachDate'] + 'T00:00:00'
            ) if data.get('BreachDate') else None,
            added_date=datetime.fromisoformat(
                data['AddedDate'].replace('Z', '+00:00')
            ) if data.get('AddedDate') else datetime.utcnow(),
            modified_date=datetime.fromisoformat(
                data['ModifiedDate'].replace('Z', '+00:00')
            ) if data.get('ModifiedDate') else None,
            pwn_count=data.get('PwnCount', 0),
            description=data.get('Description', ''),
            data_classes=data.get('DataClasses', []),
            logo_path=data.get('LogoPath'),
            is_verified=data.get('IsVerified', False),
            is_fabricated=data.get('IsFabricated', False),
            is_sensitive=data.get('IsSensitive', False),
            is_retired=data.get('IsRetired', False),
            is_spam_list=data.get('IsSpamList', False)
        )

    async def bulk_check_emails(
        self,
        emails: List[str],
        include_pastes: bool = False
    ) -> Dict[str, HIBPCheckResult]:
        """
        Check multiple emails for breaches

        Args:
            emails: List of email addresses
            include_pastes: Also check for paste appearances

        Returns:
            Dictionary mapping email to result
        """
        results = {}

        for email in emails:
            try:
                if include_pastes:
                    result = await self.check_email_full(email)
                else:
                    result = await self.check_email(email)
                results[email] = result
            except Exception as e:
                logger.error(f"Error checking {email}: {e}")
                results[email] = HIBPCheckResult(
                    query=email,
                    query_type='email',
                    breaches=[],
                    pastes=[]
                )

        return results

    def get_statistics(self) -> Dict[str, Any]:
        """Get client statistics"""
        return {
            **self.stats,
            'api_key_configured': bool(self.api_key),
            'last_check': self.stats['last_check'].isoformat() if self.stats['last_check'] else None
        }

    def export_results(
        self,
        results: List[HIBPCheckResult],
        output_file: str
    ):
        """Export results to JSON"""
        data = {
            'export_time': datetime.utcnow().isoformat(),
            'total_results': len(results),
            'statistics': self.get_statistics(),
            'results': [r.to_dict() for r in results]
        }

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        logger.info(f"Results exported to {output_file}")


async def main():
    """Example usage"""
    # Initialize client
    client = HIBPClient(
        api_key=None  # Get from https://haveibeenpwned.com/API/Key
    )

    try:
        print("[*] Have I Been Pwned API Client")
        print("=" * 50)

        # Password check (no API key required)
        print("\n[*] Checking password 'password123'...")
        pwd_result = await client.check_password("password123")
        print(f"    Compromised: {pwd_result.compromised}")
        print(f"    Exposure count: {pwd_result.exposure_count}")

        # Get all breaches (no API key required)
        print("\n[*] Getting recent breaches...")
        breaches = await client.get_all_breaches()
        print(f"    Total breaches in database: {len(breaches)}")

        if breaches:
            recent = sorted(breaches, key=lambda b: b.added_date, reverse=True)[:5]
            print("\n[*] Recent breaches:")
            for breach in recent:
                print(f"    - {breach.name}: {breach.pwn_count:,} accounts ({breach.breach_date})")

        # Email check requires API key
        print("\n[*] To check emails, get an API key at:")
        print("    https://haveibeenpwned.com/API/Key")

        # Get statistics
        stats = client.get_statistics()
        print(f"\n[*] Statistics: {stats}")

    finally:
        await client.close()


if __name__ == "__main__":
    asyncio.run(main())
