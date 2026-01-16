"""
Breach Database Engine
Unified interface for breach data from multiple sources
"""

import asyncio
import logging
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from datetime import datetime
import aiohttp

logger = logging.getLogger(__name__)


@dataclass
class BreachRecord:
    """Record from breach database"""
    source: str
    email: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    hashed_password: Optional[str] = None
    hash_type: Optional[str] = None
    name: Optional[str] = None
    ip_address: Optional[str] = None
    phone: Optional[str] = None
    address: Optional[str] = None
    database_name: str = ''
    breach_date: Optional[datetime] = None
    additional_fields: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BreachSummary:
    """Summary of breach results"""
    total_records: int
    unique_emails: int
    unique_usernames: int
    databases_found: Set[str]
    earliest_breach: Optional[datetime]
    latest_breach: Optional[datetime]
    records: List[BreachRecord]


class BreachDatabaseEngine:
    """
    Unified breach database search engine
    Searches DeHashed, HIBP, and other sources
    """

    def __init__(
        self,
        dehashed_key: Optional[str] = None,
        dehashed_email: Optional[str] = None,
        hibp_key: Optional[str] = None
    ):
        """
        Initialize breach database engine

        Args:
            dehashed_key: DeHashed API key
            dehashed_email: DeHashed account email
            hibp_key: Have I Been Pwned API key
        """
        self.dehashed_key = dehashed_key
        self.dehashed_email = dehashed_email
        self.hibp_key = hibp_key

        self.dehashed_url = 'https://api.dehashed.com/search'
        self.hibp_url = 'https://haveibeenpwned.com/api/v3'

    async def search_email(
        self,
        email: str,
        sources: Optional[List[str]] = None
    ) -> BreachSummary:
        """
        Search for email in breach databases

        Args:
            email: Email address to search
            sources: List of sources (None = all)

        Returns:
            BreachSummary with results
        """
        logger.info(f"Searching breach databases for: {email}")

        all_sources = sources or ['dehashed', 'hibp']
        tasks = []

        if 'dehashed' in all_sources and self.dehashed_key:
            tasks.append(self._search_dehashed_email(email))

        if 'hibp' in all_sources and self.hibp_key:
            tasks.append(self._search_hibp_email(email))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Combine results
        all_records = []
        for result in results:
            if isinstance(result, list):
                all_records.extend(result)

        # Calculate summary
        summary = self._calculate_summary(all_records)

        logger.info(
            f"Breach search complete: {summary.total_records} records "
            f"from {len(summary.databases_found)} databases"
        )

        return summary

    async def search_username(
        self,
        username: str,
        sources: Optional[List[str]] = None
    ) -> BreachSummary:
        """Search for username in breach databases"""
        logger.info(f"Searching breach databases for username: {username}")

        all_sources = sources or ['dehashed']
        tasks = []

        if 'dehashed' in all_sources and self.dehashed_key:
            tasks.append(self._search_dehashed_username(username))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        all_records = []
        for result in results:
            if isinstance(result, list):
                all_records.extend(result)

        summary = self._calculate_summary(all_records)

        return summary

    async def _search_dehashed_email(self, email: str) -> List[BreachRecord]:
        """Search DeHashed for email"""
        if not self.dehashed_key or not self.dehashed_email:
            logger.warning("DeHashed credentials not configured")
            return []

        try:
            async with aiohttp.ClientSession() as session:
                auth = aiohttp.BasicAuth(
                    self.dehashed_email,
                    self.dehashed_key
                )

                params = {'query': f'email:{email}'}

                async with session.get(
                    self.dehashed_url,
                    auth=auth,
                    params=params,
                    timeout=30
                ) as response:
                    if response.status == 200:
                        data = await response.json()

                        records = []
                        for entry in data.get('entries', []):
                            records.append(BreachRecord(
                                source='dehashed',
                                email=entry.get('email'),
                                username=entry.get('username'),
                                password=entry.get('password'),
                                hashed_password=entry.get('hashed_password'),
                                hash_type=entry.get('hash_type'),
                                name=entry.get('name'),
                                ip_address=entry.get('ip_address'),
                                phone=entry.get('phone'),
                                address=entry.get('address'),
                                database_name=entry.get('database_name', ''),
                                additional_fields=entry
                            ))

                        logger.info(
                            f"DeHashed: Found {len(records)} records"
                        )
                        return records
                    else:
                        logger.warning(
                            f"DeHashed API error: {response.status}"
                        )
                        return []

        except Exception as e:
            logger.error(f"DeHashed search error: {e}")
            return []

    async def _search_dehashed_username(
        self,
        username: str
    ) -> List[BreachRecord]:
        """Search DeHashed for username"""
        if not self.dehashed_key or not self.dehashed_email:
            return []

        try:
            async with aiohttp.ClientSession() as session:
                auth = aiohttp.BasicAuth(
                    self.dehashed_email,
                    self.dehashed_key
                )

                params = {'query': f'username:{username}'}

                async with session.get(
                    self.dehashed_url,
                    auth=auth,
                    params=params,
                    timeout=30
                ) as response:
                    if response.status == 200:
                        data = await response.json()

                        records = []
                        for entry in data.get('entries', []):
                            records.append(BreachRecord(
                                source='dehashed',
                                email=entry.get('email'),
                                username=entry.get('username'),
                                password=entry.get('password'),
                                hashed_password=entry.get('hashed_password'),
                                hash_type=entry.get('hash_type'),
                                database_name=entry.get('database_name', ''),
                                additional_fields=entry
                            ))

                        return records
                    else:
                        return []

        except Exception as e:
            logger.error(f"DeHashed username search error: {e}")
            return []

    async def _search_hibp_email(self, email: str) -> List[BreachRecord]:
        """Search Have I Been Pwned for email"""
        if not self.hibp_key:
            logger.warning("HIBP API key not configured")
            return []

        try:
            async with aiohttp.ClientSession() as session:
                headers = {
                    'hibp-api-key': self.hibp_key,
                    'User-Agent': 'Apollo-Intelligence-Platform'
                }

                url = f"{self.hibp_url}/breachedaccount/{email}"

                async with session.get(
                    url,
                    headers=headers,
                    timeout=30
                ) as response:
                    if response.status == 200:
                        breaches = await response.json()

                        records = []
                        for breach in breaches:
                            records.append(BreachRecord(
                                source='hibp',
                                email=email,
                                database_name=breach.get('Name', ''),
                                breach_date=datetime.fromisoformat(
                                    breach.get('BreachDate', '') + 'T00:00:00'
                                ) if breach.get('BreachDate') else None,
                                additional_fields={
                                    'title': breach.get('Title'),
                                    'domain': breach.get('Domain'),
                                    'description': breach.get('Description'),
                                    'data_classes': breach.get('DataClasses', []),
                                    'is_verified': breach.get('IsVerified'),
                                    'pwn_count': breach.get('PwnCount')
                                }
                            ))

                        logger.info(
                            f"HIBP: Found {len(records)} breaches"
                        )
                        return records
                    elif response.status == 404:
                        # No breaches found
                        logger.info("HIBP: No breaches found")
                        return []
                    else:
                        logger.warning(
                            f"HIBP API error: {response.status}"
                        )
                        return []

        except Exception as e:
            logger.error(f"HIBP search error: {e}")
            return []

    def _calculate_summary(
        self,
        records: List[BreachRecord]
    ) -> BreachSummary:
        """Calculate summary statistics"""
        unique_emails = set()
        unique_usernames = set()
        databases = set()
        breach_dates = []

        for record in records:
            if record.email:
                unique_emails.add(record.email)
            if record.username:
                unique_usernames.add(record.username)
            if record.database_name:
                databases.add(record.database_name)
            if record.breach_date:
                breach_dates.append(record.breach_date)

        return BreachSummary(
            total_records=len(records),
            unique_emails=len(unique_emails),
            unique_usernames=len(unique_usernames),
            databases_found=databases,
            earliest_breach=min(breach_dates) if breach_dates else None,
            latest_breach=max(breach_dates) if breach_dates else None,
            records=records
        )

    async def search_multiple(
        self,
        identifiers: List[str],
        search_type: str = 'email'
    ) -> Dict[str, BreachSummary]:
        """
        Search multiple identifiers

        Args:
            identifiers: List of emails or usernames
            search_type: 'email' or 'username'

        Returns:
            Dictionary mapping identifier to results
        """
        tasks = []

        for identifier in identifiers:
            if search_type == 'email':
                tasks.append(self.search_email(identifier))
            elif search_type == 'username':
                tasks.append(self.search_username(identifier))

        results = await asyncio.gather(*tasks)

        return {
            identifier: result
            for identifier, result in zip(identifiers, results)
        }

    def export_results(
        self,
        summary: BreachSummary,
        format: str = 'json'
    ) -> str:
        """Export breach results"""
        if format == 'json':
            import json
            from dataclasses import asdict

            data = {
                'summary': {
                    'total_records': summary.total_records,
                    'unique_emails': summary.unique_emails,
                    'unique_usernames': summary.unique_usernames,
                    'databases': list(summary.databases_found),
                    'earliest_breach': summary.earliest_breach.isoformat()
                    if summary.earliest_breach else None,
                    'latest_breach': summary.latest_breach.isoformat()
                    if summary.latest_breach else None
                },
                'records': [asdict(r) for r in summary.records]
            }

            return json.dumps(data, indent=2, default=str)

        elif format == 'csv':
            import csv
            from io import StringIO

            output = StringIO()
            writer = csv.writer(output)

            writer.writerow([
                'Source', 'Email', 'Username', 'Password',
                'Database', 'Breach Date'
            ])

            for record in summary.records:
                writer.writerow([
                    record.source,
                    record.email or '',
                    record.username or '',
                    record.password or 'REDACTED',
                    record.database_name,
                    record.breach_date.isoformat()
                    if record.breach_date else ''
                ])

            return output.getvalue()

        else:
            raise ValueError(f"Unsupported format: {format}")

    async def monitor_credentials(
        self,
        identifiers: List[str],
        check_interval: int = 3600,
        callback: Optional[callable] = None
    ):
        """
        Continuously monitor credentials for new breaches

        Args:
            identifiers: List of emails/usernames to monitor
            check_interval: Check interval in seconds
            callback: Optional callback for new findings
        """
        logger.info(f"Starting credential monitoring for {len(identifiers)} identifiers")

        # Track previous results
        previous_results: Dict[str, BreachSummary] = {}

        while True:
            for identifier in identifiers:
                try:
                    # Check for breaches
                    current = await self.search_email(identifier)

                    # Compare with previous results
                    if identifier in previous_results:
                        prev = previous_results[identifier]

                        # Find new breaches
                        prev_dbs = prev.databases_found
                        new_dbs = current.databases_found - prev_dbs

                        if new_dbs:
                            logger.warning(
                                f"New breach detected for {identifier}: {new_dbs}"
                            )

                            if callback:
                                await callback(identifier, new_dbs, current)

                    previous_results[identifier] = current

                except Exception as e:
                    logger.error(f"Error monitoring {identifier}: {e}")

            # Wait for next check
            await asyncio.sleep(check_interval)

    async def check_password_exposure(
        self,
        password: str,
        use_k_anonymity: bool = True
    ) -> Dict[str, Any]:
        """
        Check if password has been exposed using HIBP Pwned Passwords

        Uses k-anonymity model - only sends first 5 chars of SHA1 hash

        Args:
            password: Password to check
            use_k_anonymity: Use k-anonymity (recommended)

        Returns:
            Exposure information
        """
        import hashlib

        sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()

        if use_k_anonymity:
            prefix = sha1_hash[:5]
            suffix = sha1_hash[5:]

            try:
                async with aiohttp.ClientSession() as session:
                    url = f"https://api.pwnedpasswords.com/range/{prefix}"

                    async with session.get(url, timeout=15) as response:
                        if response.status == 200:
                            text = await response.text()

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

            except Exception as e:
                logger.error(f"Password check error: {e}")

        return {
            'compromised': None,
            'error': 'Check failed'
        }
