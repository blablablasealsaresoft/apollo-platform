#!/usr/bin/env python3
"""
Enhanced Breach Database Checker
Integration with HaveIBeenPwned, DeHashed, and hash lookup services

This module provides:
- HIBP API integration for breach checking
- DeHashed API integration for credential leaks
- Hash lookup services (hashes.org, crackstation, etc.)
- Credential leak monitoring
- Domain exposure tracking
"""

import asyncio
import aiohttp
from typing import List, Dict, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
import json
import hashlib
import logging
import re
from enum import Enum


class BreachSeverity(Enum):
    """Breach severity levels"""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class BreachInfo:
    """Information about a data breach"""
    breach_id: str
    name: str
    title: str
    domain: str
    breach_date: Optional[datetime]
    added_date: datetime
    modified_date: Optional[datetime]
    pwn_count: int
    description: str
    data_classes: List[str]
    is_verified: bool
    is_fabricated: bool
    is_sensitive: bool
    is_retired: bool
    is_spam_list: bool
    logo_path: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            'breach_id': self.breach_id,
            'name': self.name,
            'title': self.title,
            'domain': self.domain,
            'breach_date': self.breach_date.isoformat() if self.breach_date else None,
            'added_date': self.added_date.isoformat(),
            'modified_date': self.modified_date.isoformat() if self.modified_date else None,
            'pwn_count': self.pwn_count,
            'description': self.description,
            'data_classes': self.data_classes,
            'is_verified': self.is_verified,
            'is_fabricated': self.is_fabricated,
            'is_sensitive': self.is_sensitive,
            'severity': self._calculate_severity()
        }

    def _calculate_severity(self) -> str:
        """Calculate breach severity"""
        # Check for critical data types
        critical_data = ['passwords', 'credit cards', 'bank accounts', 'social security numbers']
        high_risk_data = ['email addresses', 'phone numbers', 'physical addresses', 'dates of birth']

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
class CredentialLeak:
    """Credential leak from breach database"""
    source: str
    email: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None  # Will be masked/hashed
    password_hash: Optional[str] = None
    hash_type: Optional[str] = None
    ip_address: Optional[str] = None
    phone: Optional[str] = None
    name: Optional[str] = None
    database_name: str = ''
    breach_date: Optional[datetime] = None
    found_date: datetime = field(default_factory=datetime.utcnow)
    additional_data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self, mask_sensitive: bool = True) -> Dict[str, Any]:
        data = {
            'source': self.source,
            'email': self.email,
            'username': self.username,
            'database_name': self.database_name,
            'breach_date': self.breach_date.isoformat() if self.breach_date else None,
            'found_date': self.found_date.isoformat(),
            'hash_type': self.hash_type
        }

        if mask_sensitive:
            data['password'] = '***REDACTED***' if self.password else None
            data['password_hash'] = self.password_hash[:10] + '...' if self.password_hash else None
        else:
            data['password'] = self.password
            data['password_hash'] = self.password_hash

        return data


@dataclass
class HashLookupResult:
    """Result from hash lookup service"""
    hash_value: str
    hash_type: str
    plaintext: Optional[str]
    source: str
    found: bool
    lookup_time: datetime = field(default_factory=datetime.utcnow)


@dataclass
class BreachCheckResult:
    """Result of breach checking"""
    query: str
    query_type: str  # email, domain, username, phone
    breaches_found: int
    pastes_found: int
    breaches: List[BreachInfo]
    credentials: List[CredentialLeak]
    severity: str
    checked_at: datetime
    sources_checked: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            'query': self.query,
            'query_type': self.query_type,
            'breaches_found': self.breaches_found,
            'pastes_found': self.pastes_found,
            'breaches': [b.to_dict() for b in self.breaches],
            'credentials_count': len(self.credentials),
            'severity': self.severity,
            'checked_at': self.checked_at.isoformat(),
            'sources_checked': self.sources_checked
        }


class BreachChecker:
    """
    Enhanced breach database checker with multiple source integration

    Supports:
    - HaveIBeenPwned (HIBP) API v3
    - DeHashed API
    - LeakCheck API
    - Hash lookup services
    """

    # API endpoints
    HIBP_BASE_URL = "https://haveibeenpwned.com/api/v3"
    HIBP_PASSWORDS_URL = "https://api.pwnedpasswords.com"
    DEHASHED_URL = "https://api.dehashed.com/search"
    LEAKCHECK_URL = "https://leakcheck.io/api/public"

    # Rate limits (requests per period)
    RATE_LIMITS = {
        'hibp': {'requests': 10, 'period': 60},  # 10 per minute
        'dehashed': {'requests': 3, 'period': 1},  # 3 per second
        'leakcheck': {'requests': 10, 'period': 60}
    }

    def __init__(
        self,
        hibp_api_key: Optional[str] = None,
        dehashed_api_key: Optional[str] = None,
        dehashed_email: Optional[str] = None,
        leakcheck_api_key: Optional[str] = None
    ):
        """
        Initialize breach checker

        Args:
            hibp_api_key: HaveIBeenPwned API key (required for account lookups)
            dehashed_api_key: DeHashed API key
            dehashed_email: DeHashed account email
            leakcheck_api_key: LeakCheck API key
        """
        self.hibp_api_key = hibp_api_key
        self.dehashed_api_key = dehashed_api_key
        self.dehashed_email = dehashed_email
        self.leakcheck_api_key = leakcheck_api_key

        self.logger = self._setup_logging()

        # Rate limiting
        self._last_requests: Dict[str, List[datetime]] = {
            'hibp': [],
            'dehashed': [],
            'leakcheck': []
        }

        # Cache
        self._cache: Dict[str, BreachCheckResult] = {}
        self._cache_duration = 3600  # 1 hour

        # Statistics
        self.stats = {
            'total_checks': 0,
            'breaches_found': 0,
            'credentials_found': 0,
            'hibp_queries': 0,
            'dehashed_queries': 0
        }

    def _setup_logging(self) -> logging.Logger:
        """Setup logging"""
        logger = logging.getLogger("BreachChecker")
        logger.setLevel(logging.INFO)

        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)

        return logger

    async def _rate_limit(self, service: str):
        """Apply rate limiting for a service"""
        if service not in self.RATE_LIMITS:
            return

        limits = self.RATE_LIMITS[service]
        now = datetime.utcnow()

        # Clean old entries
        cutoff = now - timedelta(seconds=limits['period'])
        self._last_requests[service] = [
            t for t in self._last_requests[service] if t > cutoff
        ]

        # Check if we need to wait
        if len(self._last_requests[service]) >= limits['requests']:
            oldest = self._last_requests[service][0]
            wait_time = (oldest + timedelta(seconds=limits['period']) - now).total_seconds()
            if wait_time > 0:
                self.logger.debug(f"Rate limiting {service}, waiting {wait_time:.1f}s")
                await asyncio.sleep(wait_time)

        self._last_requests[service].append(now)

    async def check_email(
        self,
        email: str,
        include_unverified: bool = False,
        check_pastes: bool = True
    ) -> BreachCheckResult:
        """
        Check email address for breaches

        Args:
            email: Email address to check
            include_unverified: Include unverified breaches
            check_pastes: Check for paste occurrences

        Returns:
            BreachCheckResult with findings
        """
        self.logger.info(f"Checking email: {email}")

        # Check cache
        cache_key = f"email_{hashlib.md5(email.lower().encode()).hexdigest()}"
        if cache_key in self._cache:
            cache_entry = self._cache[cache_key]
            age = (datetime.utcnow() - cache_entry.checked_at).total_seconds()
            if age < self._cache_duration:
                self.logger.debug("Returning cached result")
                return cache_entry

        breaches = []
        credentials = []
        sources_checked = []
        pastes_count = 0

        # Check HIBP
        if self.hibp_api_key:
            try:
                hibp_breaches = await self._check_hibp_email(email, include_unverified)
                breaches.extend(hibp_breaches)
                sources_checked.append('hibp')
                self.stats['hibp_queries'] += 1

                if check_pastes:
                    pastes_count = await self._check_hibp_pastes(email)

            except Exception as e:
                self.logger.error(f"HIBP check failed: {e}")

        # Check DeHashed
        if self.dehashed_api_key:
            try:
                dehashed_creds = await self._check_dehashed(f"email:{email}")
                credentials.extend(dehashed_creds)
                sources_checked.append('dehashed')
                self.stats['dehashed_queries'] += 1
            except Exception as e:
                self.logger.error(f"DeHashed check failed: {e}")

        # Determine severity
        severity = self._calculate_overall_severity(breaches, credentials)

        result = BreachCheckResult(
            query=email,
            query_type='email',
            breaches_found=len(breaches),
            pastes_found=pastes_count,
            breaches=breaches,
            credentials=credentials,
            severity=severity,
            checked_at=datetime.utcnow(),
            sources_checked=sources_checked
        )

        # Update cache and stats
        self._cache[cache_key] = result
        self.stats['total_checks'] += 1
        self.stats['breaches_found'] += len(breaches)
        self.stats['credentials_found'] += len(credentials)

        self.logger.info(
            f"Email check complete: {len(breaches)} breaches, "
            f"{len(credentials)} credentials, severity: {severity}"
        )

        return result

    async def check_domain(
        self,
        domain: str,
        include_breached_accounts: bool = False
    ) -> BreachCheckResult:
        """
        Check domain for breaches

        Args:
            domain: Domain to check
            include_breached_accounts: Include list of breached accounts (requires paid HIBP)

        Returns:
            BreachCheckResult with findings
        """
        self.logger.info(f"Checking domain: {domain}")

        breaches = []
        credentials = []
        sources_checked = []

        # Check HIBP domain search
        if self.hibp_api_key:
            try:
                domain_breaches = await self._check_hibp_domain(domain)
                breaches.extend(domain_breaches)
                sources_checked.append('hibp_domain')
            except Exception as e:
                self.logger.error(f"HIBP domain check failed: {e}")

        # Check DeHashed for domain
        if self.dehashed_api_key:
            try:
                dehashed_creds = await self._check_dehashed(f"domain:{domain}")
                credentials.extend(dehashed_creds)
                sources_checked.append('dehashed')
            except Exception as e:
                self.logger.error(f"DeHashed domain check failed: {e}")

        severity = self._calculate_overall_severity(breaches, credentials)

        result = BreachCheckResult(
            query=domain,
            query_type='domain',
            breaches_found=len(breaches),
            pastes_found=0,
            breaches=breaches,
            credentials=credentials,
            severity=severity,
            checked_at=datetime.utcnow(),
            sources_checked=sources_checked
        )

        self.stats['total_checks'] += 1

        return result

    async def check_username(self, username: str) -> BreachCheckResult:
        """
        Check username for breaches

        Args:
            username: Username to check

        Returns:
            BreachCheckResult with findings
        """
        self.logger.info(f"Checking username: {username}")

        credentials = []
        sources_checked = []

        # Check DeHashed for username
        if self.dehashed_api_key:
            try:
                dehashed_creds = await self._check_dehashed(f"username:{username}")
                credentials.extend(dehashed_creds)
                sources_checked.append('dehashed')
            except Exception as e:
                self.logger.error(f"DeHashed check failed: {e}")

        severity = self._calculate_overall_severity([], credentials)

        return BreachCheckResult(
            query=username,
            query_type='username',
            breaches_found=0,
            pastes_found=0,
            breaches=[],
            credentials=credentials,
            severity=severity,
            checked_at=datetime.utcnow(),
            sources_checked=sources_checked
        )

    async def check_password(
        self,
        password: str,
        use_k_anonymity: bool = True
    ) -> Dict[str, Any]:
        """
        Check if password has been exposed in breaches using HIBP Pwned Passwords API

        Uses k-anonymity model - only sends first 5 chars of SHA1 hash

        Args:
            password: Password to check
            use_k_anonymity: Use k-anonymity (recommended, True by default)

        Returns:
            Dictionary with check results
        """
        self.logger.info("Checking password against breach database")

        # Hash the password with SHA1
        sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()

        if use_k_anonymity:
            # Send only first 5 characters (k-anonymity)
            prefix = sha1_hash[:5]
            suffix = sha1_hash[5:]

            try:
                await self._rate_limit('hibp')

                async with aiohttp.ClientSession() as session:
                    url = f"{self.HIBP_PASSWORDS_URL}/range/{prefix}"

                    async with session.get(url, timeout=15) as response:
                        if response.status == 200:
                            text = await response.text()

                            # Search for our suffix in the results
                            for line in text.splitlines():
                                parts = line.split(':')
                                if len(parts) == 2:
                                    hash_suffix, count = parts
                                    if hash_suffix == suffix:
                                        return {
                                            'compromised': True,
                                            'exposure_count': int(count),
                                            'sha1_hash': sha1_hash,
                                            'message': f"Password found in {count} breaches"
                                        }

                            return {
                                'compromised': False,
                                'exposure_count': 0,
                                'sha1_hash': sha1_hash,
                                'message': "Password not found in breach database"
                            }
                        else:
                            self.logger.error(f"HIBP Passwords API error: {response.status}")

            except Exception as e:
                self.logger.error(f"Password check error: {e}")

        return {
            'compromised': None,
            'exposure_count': None,
            'sha1_hash': sha1_hash,
            'error': 'Check failed'
        }

    async def _check_hibp_email(
        self,
        email: str,
        include_unverified: bool
    ) -> List[BreachInfo]:
        """Check HIBP for email breaches"""
        breaches = []

        await self._rate_limit('hibp')

        try:
            async with aiohttp.ClientSession() as session:
                url = f"{self.HIBP_BASE_URL}/breachedaccount/{email}"
                params = {'truncateResponse': 'false'}
                if include_unverified:
                    params['includeUnverified'] = 'true'

                headers = {
                    'hibp-api-key': self.hibp_api_key,
                    'User-Agent': 'Apollo-Intelligence-Platform'
                }

                async with session.get(
                    url,
                    headers=headers,
                    params=params,
                    timeout=30
                ) as response:
                    if response.status == 200:
                        data = await response.json()

                        for breach in data:
                            breaches.append(BreachInfo(
                                breach_id=breach.get('Name', ''),
                                name=breach.get('Name', ''),
                                title=breach.get('Title', ''),
                                domain=breach.get('Domain', ''),
                                breach_date=datetime.fromisoformat(
                                    breach['BreachDate'] + 'T00:00:00'
                                ) if breach.get('BreachDate') else None,
                                added_date=datetime.fromisoformat(
                                    breach['AddedDate'].replace('Z', '+00:00')
                                ) if breach.get('AddedDate') else datetime.utcnow(),
                                modified_date=datetime.fromisoformat(
                                    breach['ModifiedDate'].replace('Z', '+00:00')
                                ) if breach.get('ModifiedDate') else None,
                                pwn_count=breach.get('PwnCount', 0),
                                description=breach.get('Description', ''),
                                data_classes=breach.get('DataClasses', []),
                                is_verified=breach.get('IsVerified', False),
                                is_fabricated=breach.get('IsFabricated', False),
                                is_sensitive=breach.get('IsSensitive', False),
                                is_retired=breach.get('IsRetired', False),
                                is_spam_list=breach.get('IsSpamList', False),
                                logo_path=breach.get('LogoPath')
                            ))

                    elif response.status == 404:
                        self.logger.info("No breaches found in HIBP")
                    elif response.status == 401:
                        self.logger.error("HIBP API key invalid or missing")
                    elif response.status == 429:
                        self.logger.warning("HIBP rate limit exceeded")
                    else:
                        self.logger.warning(f"HIBP returned status {response.status}")

        except Exception as e:
            self.logger.error(f"HIBP email check error: {e}")

        return breaches

    async def _check_hibp_pastes(self, email: str) -> int:
        """Check HIBP for paste occurrences"""
        await self._rate_limit('hibp')

        try:
            async with aiohttp.ClientSession() as session:
                url = f"{self.HIBP_BASE_URL}/pasteaccount/{email}"

                headers = {
                    'hibp-api-key': self.hibp_api_key,
                    'User-Agent': 'Apollo-Intelligence-Platform'
                }

                async with session.get(
                    url,
                    headers=headers,
                    timeout=30
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        return len(data)
                    elif response.status == 404:
                        return 0

        except Exception as e:
            self.logger.error(f"HIBP paste check error: {e}")

        return 0

    async def _check_hibp_domain(self, domain: str) -> List[BreachInfo]:
        """Check HIBP for domain breaches"""
        breaches = []

        await self._rate_limit('hibp')

        try:
            async with aiohttp.ClientSession() as session:
                # Get all breaches and filter by domain
                url = f"{self.HIBP_BASE_URL}/breaches"

                headers = {
                    'hibp-api-key': self.hibp_api_key,
                    'User-Agent': 'Apollo-Intelligence-Platform'
                }

                async with session.get(
                    url,
                    headers=headers,
                    timeout=30
                ) as response:
                    if response.status == 200:
                        data = await response.json()

                        for breach in data:
                            if breach.get('Domain', '').lower() == domain.lower():
                                breaches.append(BreachInfo(
                                    breach_id=breach.get('Name', ''),
                                    name=breach.get('Name', ''),
                                    title=breach.get('Title', ''),
                                    domain=breach.get('Domain', ''),
                                    breach_date=datetime.fromisoformat(
                                        breach['BreachDate'] + 'T00:00:00'
                                    ) if breach.get('BreachDate') else None,
                                    added_date=datetime.fromisoformat(
                                        breach['AddedDate'].replace('Z', '+00:00')
                                    ) if breach.get('AddedDate') else datetime.utcnow(),
                                    modified_date=None,
                                    pwn_count=breach.get('PwnCount', 0),
                                    description=breach.get('Description', ''),
                                    data_classes=breach.get('DataClasses', []),
                                    is_verified=breach.get('IsVerified', False),
                                    is_fabricated=breach.get('IsFabricated', False),
                                    is_sensitive=breach.get('IsSensitive', False),
                                    is_retired=breach.get('IsRetired', False),
                                    is_spam_list=breach.get('IsSpamList', False)
                                ))

        except Exception as e:
            self.logger.error(f"HIBP domain check error: {e}")

        return breaches

    async def _check_dehashed(self, query: str) -> List[CredentialLeak]:
        """Check DeHashed for credential leaks"""
        credentials = []

        if not self.dehashed_api_key or not self.dehashed_email:
            self.logger.warning("DeHashed credentials not configured")
            return credentials

        await self._rate_limit('dehashed')

        try:
            async with aiohttp.ClientSession() as session:
                auth = aiohttp.BasicAuth(
                    self.dehashed_email,
                    self.dehashed_api_key
                )

                params = {'query': query}

                async with session.get(
                    self.DEHASHED_URL,
                    auth=auth,
                    params=params,
                    timeout=30
                ) as response:
                    if response.status == 200:
                        data = await response.json()

                        for entry in data.get('entries', []):
                            cred = CredentialLeak(
                                source='dehashed',
                                email=entry.get('email'),
                                username=entry.get('username'),
                                password=entry.get('password'),
                                password_hash=entry.get('hashed_password'),
                                hash_type=entry.get('hash_type'),
                                ip_address=entry.get('ip_address'),
                                phone=entry.get('phone'),
                                name=entry.get('name'),
                                database_name=entry.get('database_name', ''),
                                additional_data={
                                    'vin': entry.get('vin'),
                                    'address': entry.get('address')
                                }
                            )
                            credentials.append(cred)

                        self.logger.info(f"DeHashed: Found {len(credentials)} credentials")
                    else:
                        self.logger.warning(f"DeHashed returned status {response.status}")

        except Exception as e:
            self.logger.error(f"DeHashed check error: {e}")

        return credentials

    async def lookup_hash(
        self,
        hash_value: str,
        hash_type: Optional[str] = None
    ) -> HashLookupResult:
        """
        Look up a password hash in online databases

        Args:
            hash_value: The hash to look up
            hash_type: Hash type (md5, sha1, sha256, etc.)

        Returns:
            HashLookupResult with plaintext if found
        """
        # Detect hash type if not provided
        if not hash_type:
            hash_type = self._detect_hash_type(hash_value)

        self.logger.info(f"Looking up hash: {hash_value[:16]}... (type: {hash_type})")

        # Note: Many hash lookup services have been shut down or require payment
        # This is a placeholder for integration with available services

        # Check against common services (implement as available)
        sources_to_try = [
            ('crackstation', self._lookup_crackstation),
            ('md5decrypt', self._lookup_md5decrypt),
        ]

        for source_name, lookup_func in sources_to_try:
            try:
                plaintext = await lookup_func(hash_value, hash_type)
                if plaintext:
                    return HashLookupResult(
                        hash_value=hash_value,
                        hash_type=hash_type,
                        plaintext=plaintext,
                        source=source_name,
                        found=True
                    )
            except Exception as e:
                self.logger.debug(f"Hash lookup failed for {source_name}: {e}")

        return HashLookupResult(
            hash_value=hash_value,
            hash_type=hash_type,
            plaintext=None,
            source='none',
            found=False
        )

    def _detect_hash_type(self, hash_value: str) -> str:
        """Detect hash type based on length and format"""
        hash_value = hash_value.lower()
        length = len(hash_value)

        if length == 32:
            return 'md5'
        elif length == 40:
            return 'sha1'
        elif length == 64:
            return 'sha256'
        elif length == 128:
            return 'sha512'
        elif hash_value.startswith('$2a$') or hash_value.startswith('$2b$'):
            return 'bcrypt'
        elif hash_value.startswith('$argon2'):
            return 'argon2'
        else:
            return 'unknown'

    async def _lookup_crackstation(
        self,
        hash_value: str,
        hash_type: str
    ) -> Optional[str]:
        """Look up hash on CrackStation (placeholder)"""
        # CrackStation requires solving a CAPTCHA, so this is just a placeholder
        # In a real implementation, you might use their API if available
        self.logger.debug("CrackStation lookup not implemented (requires CAPTCHA)")
        return None

    async def _lookup_md5decrypt(
        self,
        hash_value: str,
        hash_type: str
    ) -> Optional[str]:
        """Look up hash on md5decrypt.net (placeholder)"""
        # Similar to above - many services require payment or CAPTCHA
        self.logger.debug("md5decrypt lookup not implemented")
        return None

    def _calculate_overall_severity(
        self,
        breaches: List[BreachInfo],
        credentials: List[CredentialLeak]
    ) -> str:
        """Calculate overall severity from breaches and credentials"""
        if not breaches and not credentials:
            return 'none'

        # Check for critical indicators
        for breach in breaches:
            if breach._calculate_severity() == 'critical':
                return 'critical'

        # Passwords found = critical
        for cred in credentials:
            if cred.password or cred.password_hash:
                return 'critical'

        # Many breaches = high
        if len(breaches) > 5 or len(credentials) > 10:
            return 'high'

        # Some breaches = medium
        if len(breaches) > 0 or len(credentials) > 0:
            return 'medium'

        return 'low'

    async def check_multiple(
        self,
        queries: List[str],
        query_type: str = 'email'
    ) -> Dict[str, BreachCheckResult]:
        """
        Check multiple queries

        Args:
            queries: List of emails/usernames/domains to check
            query_type: Type of query (email, domain, username)

        Returns:
            Dictionary mapping query to result
        """
        results = {}

        for query in queries:
            if query_type == 'email':
                result = await self.check_email(query)
            elif query_type == 'domain':
                result = await self.check_domain(query)
            elif query_type == 'username':
                result = await self.check_username(query)
            else:
                continue

            results[query] = result

            # Small delay between checks
            await asyncio.sleep(0.5)

        return results

    def get_statistics(self) -> Dict[str, Any]:
        """Get checker statistics"""
        return {
            **self.stats,
            'cache_size': len(self._cache),
            'hibp_configured': bool(self.hibp_api_key),
            'dehashed_configured': bool(self.dehashed_api_key)
        }

    def export_results(
        self,
        results: List[BreachCheckResult],
        output_file: str,
        include_credentials: bool = False
    ):
        """Export results to JSON"""
        data = {
            'export_time': datetime.utcnow().isoformat(),
            'total_results': len(results),
            'statistics': self.get_statistics(),
            'results': []
        }

        for result in results:
            result_data = result.to_dict()
            if include_credentials:
                result_data['credentials'] = [
                    c.to_dict(mask_sensitive=True) for c in result.credentials
                ]
            data['results'].append(result_data)

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        self.logger.info(f"Results exported to {output_file}")


# Import timedelta for rate limiting
from datetime import timedelta


async def main():
    """Example usage"""
    # Initialize checker (would use real API keys in production)
    checker = BreachChecker(
        hibp_api_key="your_hibp_api_key_here",  # Get from haveibeenpwned.com/API/Key
        dehashed_api_key="your_dehashed_key",
        dehashed_email="your_dehashed_email"
    )

    print("[*] Apollo Breach Checker")
    print("=" * 50)

    # Check password (doesn't require API key)
    print("\n[*] Checking password strength...")
    password_result = await checker.check_password("password123")
    print(f"    Compromised: {password_result['compromised']}")
    print(f"    Exposure count: {password_result.get('exposure_count', 'N/A')}")

    # Check email (requires HIBP API key)
    print("\n[*] To check emails, you need a HIBP API key")
    print("    Get one at: https://haveibeenpwned.com/API/Key")

    # Get statistics
    stats = checker.get_statistics()
    print(f"\n[*] Statistics:")
    for key, value in stats.items():
        print(f"    {key}: {value}")


if __name__ == "__main__":
    asyncio.run(main())
