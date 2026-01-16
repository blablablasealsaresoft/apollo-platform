#!/usr/bin/env python3
"""
DeHashed API Client
Integration with DeHashed breach database search API

DeHashed provides access to:
- Leaked emails and passwords
- Username exposure
- IP address leaks
- Phone numbers
- Names and addresses
- VIN numbers and more

API Documentation: https://dehashed.com/docs
"""

import asyncio
import aiohttp
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
import logging
import json


logger = logging.getLogger(__name__)


@dataclass
class DeHashedEntry:
    """Entry from DeHashed database"""
    id: str
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
    obtained_from: Optional[str] = None
    vin: Optional[str] = None

    def to_dict(self, mask_password: bool = True) -> Dict[str, Any]:
        """Convert to dictionary"""
        data = {
            'id': self.id,
            'email': self.email,
            'username': self.username,
            'hash_type': self.hash_type,
            'name': self.name,
            'ip_address': self.ip_address,
            'phone': self.phone,
            'address': self.address,
            'database_name': self.database_name,
            'obtained_from': self.obtained_from,
            'vin': self.vin
        }

        if mask_password:
            data['password'] = '***REDACTED***' if self.password else None
            data['hashed_password'] = self.hashed_password[:10] + '...' if self.hashed_password else None
        else:
            data['password'] = self.password
            data['hashed_password'] = self.hashed_password

        return data


@dataclass
class DeHashedSearchResult:
    """DeHashed search result"""
    query: str
    query_type: str
    total_entries: int
    balance: int  # Remaining API credits
    entries: List[DeHashedEntry] = field(default_factory=list)
    took: float = 0.0  # Query time in seconds
    searched_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'query': self.query,
            'query_type': self.query_type,
            'total_entries': self.total_entries,
            'balance': self.balance,
            'entries': [e.to_dict() for e in self.entries],
            'took': self.took,
            'searched_at': self.searched_at.isoformat()
        }


class DeHashedClient:
    """
    DeHashed API client for breach database searches

    Supports searching by:
    - email
    - username
    - ip_address
    - phone
    - name
    - address
    - vin
    - hashed_password
    - password (exact match only)
    """

    BASE_URL = "https://api.dehashed.com/search"

    # Search field types
    SEARCH_FIELDS = [
        'email', 'username', 'ip_address', 'phone',
        'name', 'address', 'vin', 'hashed_password', 'password'
    ]

    def __init__(
        self,
        api_key: str,
        email: str,
        rate_limit: float = 0.5  # seconds between requests
    ):
        """
        Initialize DeHashed client

        Args:
            api_key: DeHashed API key
            email: DeHashed account email
            rate_limit: Minimum seconds between requests
        """
        self.api_key = api_key
        self.email = email
        self.rate_limit = rate_limit

        self._last_request_time: Optional[datetime] = None
        self._session: Optional[aiohttp.ClientSession] = None

        # Statistics
        self.stats = {
            'total_searches': 0,
            'total_entries': 0,
            'api_balance': None,
            'last_search': None
        }

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp session"""
        if self._session is None or self._session.closed:
            auth = aiohttp.BasicAuth(self.email, self.api_key)
            self._session = aiohttp.ClientSession(
                auth=auth,
                headers={
                    'Accept': 'application/json',
                    'User-Agent': 'Apollo-Intelligence-Platform/1.0'
                }
            )
        return self._session

    async def close(self):
        """Close the session"""
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None

    async def _rate_limit_wait(self):
        """Apply rate limiting"""
        if self._last_request_time:
            elapsed = (datetime.utcnow() - self._last_request_time).total_seconds()
            if elapsed < self.rate_limit:
                await asyncio.sleep(self.rate_limit - elapsed)
        self._last_request_time = datetime.utcnow()

    async def search(
        self,
        query: str,
        field: str = 'email',
        page: int = 1,
        size: int = 100
    ) -> DeHashedSearchResult:
        """
        Search DeHashed database

        Args:
            query: Search query
            field: Field to search (email, username, etc.)
            page: Page number (starting from 1)
            size: Results per page (max 10000)

        Returns:
            DeHashedSearchResult with entries
        """
        if field not in self.SEARCH_FIELDS:
            raise ValueError(f"Invalid field: {field}. Must be one of: {self.SEARCH_FIELDS}")

        await self._rate_limit_wait()

        session = await self._get_session()
        entries = []

        try:
            # Build search query
            search_query = f'{field}:{query}'

            params = {
                'query': search_query,
                'page': page,
                'size': min(size, 10000)
            }

            logger.info(f"DeHashed search: {field}:{query[:30]}...")

            async with session.get(
                self.BASE_URL,
                params=params,
                timeout=aiohttp.ClientTimeout(total=60)
            ) as response:
                if response.status == 200:
                    data = await response.json()

                    # Parse entries
                    for entry_data in data.get('entries', []) or []:
                        entry = DeHashedEntry(
                            id=str(entry_data.get('id', '')),
                            email=entry_data.get('email'),
                            username=entry_data.get('username'),
                            password=entry_data.get('password'),
                            hashed_password=entry_data.get('hashed_password'),
                            hash_type=entry_data.get('hash_type'),
                            name=entry_data.get('name'),
                            ip_address=entry_data.get('ip_address'),
                            phone=entry_data.get('phone'),
                            address=entry_data.get('address'),
                            database_name=entry_data.get('database_name', ''),
                            obtained_from=entry_data.get('obtained_from'),
                            vin=entry_data.get('vin')
                        )
                        entries.append(entry)

                    # Update statistics
                    balance = data.get('balance', 0)
                    total = data.get('total', len(entries))
                    took = data.get('took', 0)

                    self.stats['total_searches'] += 1
                    self.stats['total_entries'] += len(entries)
                    self.stats['api_balance'] = balance
                    self.stats['last_search'] = datetime.utcnow()

                    logger.info(
                        f"DeHashed: Found {total} entries, "
                        f"returned {len(entries)}, balance: {balance}"
                    )

                    return DeHashedSearchResult(
                        query=query,
                        query_type=field,
                        total_entries=total,
                        balance=balance,
                        entries=entries,
                        took=took
                    )

                elif response.status == 401:
                    logger.error("DeHashed: Authentication failed")
                    raise ValueError("Invalid API credentials")

                elif response.status == 429:
                    logger.warning("DeHashed: Rate limit exceeded")
                    raise RuntimeError("Rate limit exceeded")

                elif response.status == 402:
                    logger.error("DeHashed: Insufficient credits")
                    raise RuntimeError("Insufficient API credits")

                else:
                    text = await response.text()
                    logger.error(f"DeHashed error: {response.status} - {text}")
                    raise RuntimeError(f"API error: {response.status}")

        except aiohttp.ClientError as e:
            logger.error(f"DeHashed request failed: {e}")
            raise

        return DeHashedSearchResult(
            query=query,
            query_type=field,
            total_entries=0,
            balance=self.stats.get('api_balance', 0) or 0,
            entries=[]
        )

    async def search_email(self, email: str, **kwargs) -> DeHashedSearchResult:
        """Search by email address"""
        return await self.search(email, field='email', **kwargs)

    async def search_username(self, username: str, **kwargs) -> DeHashedSearchResult:
        """Search by username"""
        return await self.search(username, field='username', **kwargs)

    async def search_ip(self, ip_address: str, **kwargs) -> DeHashedSearchResult:
        """Search by IP address"""
        return await self.search(ip_address, field='ip_address', **kwargs)

    async def search_phone(self, phone: str, **kwargs) -> DeHashedSearchResult:
        """Search by phone number"""
        return await self.search(phone, field='phone', **kwargs)

    async def search_name(self, name: str, **kwargs) -> DeHashedSearchResult:
        """Search by name"""
        return await self.search(name, field='name', **kwargs)

    async def search_domain(self, domain: str, **kwargs) -> DeHashedSearchResult:
        """
        Search for all emails from a domain

        Args:
            domain: Domain to search (e.g., example.com)

        Returns:
            DeHashedSearchResult with domain emails
        """
        # DeHashed supports wildcard search for domains
        return await self.search(f'*@{domain}', field='email', **kwargs)

    async def search_hash(self, password_hash: str, **kwargs) -> DeHashedSearchResult:
        """Search by password hash"""
        return await self.search(password_hash, field='hashed_password', **kwargs)

    async def bulk_search(
        self,
        queries: List[str],
        field: str = 'email'
    ) -> Dict[str, DeHashedSearchResult]:
        """
        Search multiple queries

        Args:
            queries: List of queries
            field: Field to search

        Returns:
            Dictionary mapping query to result
        """
        results = {}

        for query in queries:
            try:
                result = await self.search(query, field=field)
                results[query] = result
            except Exception as e:
                logger.error(f"Bulk search error for {query}: {e}")
                results[query] = DeHashedSearchResult(
                    query=query,
                    query_type=field,
                    total_entries=0,
                    balance=0,
                    entries=[]
                )

        return results

    def get_statistics(self) -> Dict[str, Any]:
        """Get client statistics"""
        return {
            **self.stats,
            'last_search': self.stats['last_search'].isoformat() if self.stats['last_search'] else None
        }

    def export_results(
        self,
        results: List[DeHashedSearchResult],
        output_file: str,
        include_passwords: bool = False
    ):
        """Export search results to JSON"""
        data = {
            'export_time': datetime.utcnow().isoformat(),
            'total_results': len(results),
            'statistics': self.get_statistics(),
            'results': []
        }

        for result in results:
            result_data = result.to_dict()
            if not include_passwords:
                for entry in result_data.get('entries', []):
                    if 'password' in entry:
                        entry['password'] = '***REDACTED***'
            data['results'].append(result_data)

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        logger.info(f"Results exported to {output_file}")


async def main():
    """Example usage"""
    # Initialize client (use real credentials)
    client = DeHashedClient(
        api_key="your_api_key",
        email="your_email@example.com"
    )

    try:
        print("[*] DeHashed Breach Database Client")
        print("=" * 50)

        # Note: These examples won't work without valid credentials
        print("\n[*] To use DeHashed:")
        print("    1. Sign up at https://dehashed.com")
        print("    2. Get API credentials")
        print("    3. Replace api_key and email above")

        # Example searches (commented out)
        # result = await client.search_email("test@example.com")
        # print(f"Found {result.total_entries} entries")

        # Get statistics
        stats = client.get_statistics()
        print(f"\n[*] Statistics: {stats}")

    finally:
        await client.close()


if __name__ == "__main__":
    asyncio.run(main())
