"""
DeHashed API Integration
Access to 11B+ breach records from DeHashed database
"""

import asyncio
import aiohttp
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
from urllib.parse import quote
import base64


class DeHashedIntegration:
    """
    DeHashed API integration
    Provides access to comprehensive breach database
    """

    BASE_URL = "https://api.dehashed.com/search"

    def __init__(self, email: Optional[str] = None, api_key: Optional[str] = None):
        """
        Initialize DeHashed integration

        Args:
            email: DeHashed account email
            api_key: DeHashed API key
        """
        self.email = email
        self.api_key = api_key
        self.logger = logging.getLogger(__name__)

        # Create authentication header
        if email and api_key:
            credentials = f"{email}:{api_key}"
            self.auth_header = base64.b64encode(credentials.encode()).decode()
        else:
            self.auth_header = None
            self.logger.warning("DeHashed credentials not provided - API calls will fail")

        # Rate limiting
        self.rate_limit_delay = 1.0  # seconds between requests
        self.last_request_time = 0

    async def _make_request(self, query: str, page: int = 1, size: int = 10000) -> Dict[str, Any]:
        """
        Make request to DeHashed API

        Args:
            query: Search query
            page: Page number
            size: Results per page

        Returns:
            API response data
        """
        if not self.auth_header:
            raise ValueError("DeHashed credentials not configured")

        # Rate limiting
        current_time = asyncio.get_event_loop().time()
        time_since_last_request = current_time - self.last_request_time
        if time_since_last_request < self.rate_limit_delay:
            await asyncio.sleep(self.rate_limit_delay - time_since_last_request)

        headers = {
            'Authorization': f'Basic {self.auth_header}',
            'Accept': 'application/json'
        }

        params = {
            'query': query,
            'page': page,
            'size': size
        }

        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(
                    self.BASE_URL,
                    headers=headers,
                    params=params,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    self.last_request_time = asyncio.get_event_loop().time()

                    if response.status == 200:
                        data = await response.json()
                        return data
                    elif response.status == 401:
                        raise Exception("Invalid DeHashed credentials")
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

    async def search_email(self, email: str) -> List[Dict[str, Any]]:
        """
        Search for email address

        Args:
            email: Email address to search

        Returns:
            List of breach records
        """
        self.logger.info(f"Searching DeHashed for email: {email}")

        query = f'email:"{email}"'
        results = await self._make_request(query)

        return self._parse_results(results)

    async def search_username(self, username: str) -> List[Dict[str, Any]]:
        """
        Search for username

        Args:
            username: Username to search

        Returns:
            List of breach records
        """
        self.logger.info(f"Searching DeHashed for username: {username}")

        query = f'username:"{username}"'
        results = await self._make_request(query)

        return self._parse_results(results)

    async def search_password(self, password: str) -> List[Dict[str, Any]]:
        """
        Search for password

        Args:
            password: Password to search

        Returns:
            List of breach records
        """
        self.logger.info("Searching DeHashed for password")

        query = f'password:"{password}"'
        results = await self._make_request(query)

        return self._parse_results(results)

    async def search_phone(self, phone: str) -> List[Dict[str, Any]]:
        """
        Search for phone number

        Args:
            phone: Phone number to search

        Returns:
            List of breach records
        """
        self.logger.info(f"Searching DeHashed for phone: {phone}")

        query = f'phone:"{phone}"'
        results = await self._make_request(query)

        return self._parse_results(results)

    async def search_ip(self, ip_address: str) -> List[Dict[str, Any]]:
        """
        Search for IP address

        Args:
            ip_address: IP address to search

        Returns:
            List of breach records
        """
        self.logger.info(f"Searching DeHashed for IP: {ip_address}")

        query = f'ip_address:"{ip_address}"'
        results = await self._make_request(query)

        return self._parse_results(results)

    async def search_name(self, name: str) -> List[Dict[str, Any]]:
        """
        Search for name

        Args:
            name: Name to search

        Returns:
            List of breach records
        """
        self.logger.info(f"Searching DeHashed for name: {name}")

        query = f'name:"{name}"'
        results = await self._make_request(query)

        return self._parse_results(results)

    async def search_vin(self, vin: str) -> List[Dict[str, Any]]:
        """
        Search for VIN (Vehicle Identification Number)

        Args:
            vin: VIN to search

        Returns:
            List of breach records
        """
        self.logger.info(f"Searching DeHashed for VIN: {vin}")

        query = f'vin:"{vin}"'
        results = await self._make_request(query)

        return self._parse_results(results)

    async def search_address(self, address: str) -> List[Dict[str, Any]]:
        """
        Search for address

        Args:
            address: Address to search

        Returns:
            List of breach records
        """
        self.logger.info(f"Searching DeHashed for address: {address}")

        query = f'address:"{address}"'
        results = await self._make_request(query)

        return self._parse_results(results)

    async def search_domain(self, domain: str) -> List[Dict[str, Any]]:
        """
        Search for domain

        Args:
            domain: Domain to search

        Returns:
            List of breach records
        """
        self.logger.info(f"Searching DeHashed for domain: {domain}")

        query = f'email:*@{domain}'
        results = await self._make_request(query)

        return self._parse_results(results)

    async def advanced_search(
        self,
        email: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        phone: Optional[str] = None,
        ip_address: Optional[str] = None,
        name: Optional[str] = None,
        database: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Perform advanced multi-field search

        Args:
            email: Email address
            username: Username
            password: Password
            phone: Phone number
            ip_address: IP address
            name: Name
            database: Specific database name

        Returns:
            List of breach records
        """
        query_parts = []

        if email:
            query_parts.append(f'email:"{email}"')
        if username:
            query_parts.append(f'username:"{username}"')
        if password:
            query_parts.append(f'password:"{password}"')
        if phone:
            query_parts.append(f'phone:"{phone}"')
        if ip_address:
            query_parts.append(f'ip_address:"{ip_address}"')
        if name:
            query_parts.append(f'name:"{name}"')
        if database:
            query_parts.append(f'database_name:"{database}"')

        if not query_parts:
            raise ValueError("At least one search parameter required")

        query = ' AND '.join(query_parts)
        self.logger.info(f"Advanced search query: {query}")

        results = await self._make_request(query)
        return self._parse_results(results)

    async def search_hash(self, hash_value: str, hash_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Search for password hash

        Args:
            hash_value: Hash value to search
            hash_type: Hash type (md5, sha1, bcrypt, etc.)

        Returns:
            List of breach records
        """
        self.logger.info(f"Searching DeHashed for hash: {hash_value[:10]}...")

        query = f'hashed_password:"{hash_value}"'
        results = await self._make_request(query)

        return self._parse_results(results)

    async def get_database_info(self) -> Dict[str, Any]:
        """
        Get information about available databases

        Returns:
            Database information
        """
        # DeHashed doesn't have a dedicated endpoint for this
        # This would require scraping their web interface or documentation
        self.logger.warning("Database info not available via API")
        return {}

    def _parse_results(self, api_response: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Parse API response into standardized format

        Args:
            api_response: Raw API response

        Returns:
            List of parsed breach records
        """
        if not api_response or 'entries' not in api_response:
            return []

        records = []

        for entry in api_response.get('entries', []):
            record = {
                'database_name': entry.get('database_name'),
                'obtained_date': self._parse_date(entry.get('obtained_from')),
                'email': entry.get('email'),
                'username': entry.get('username'),
                'password': entry.get('password'),
                'hashed_password': entry.get('hashed_password'),
                'hash_type': self._identify_hash_type(entry.get('hashed_password')),
                'phone': entry.get('phone'),
                'ip_address': entry.get('ip_address'),
                'name': entry.get('name'),
                'address': entry.get('address'),
                'vin': entry.get('vin'),
                'additional_data': {
                    'id': entry.get('id'),
                    'obtained_from': entry.get('obtained_from')
                }
            }

            # Add any additional fields
            for key, value in entry.items():
                if key not in record and value:
                    record['additional_data'][key] = value

            records.append(record)

        self.logger.info(f"Parsed {len(records)} records")
        return records

    def _parse_date(self, date_string: Optional[str]) -> Optional[datetime]:
        """Parse date string to datetime"""
        if not date_string:
            return None

        try:
            # Try various date formats
            formats = [
                '%Y-%m-%d',
                '%Y-%m-%d %H:%M:%S',
                '%Y/%m/%d',
                '%d/%m/%Y'
            ]

            for fmt in formats:
                try:
                    return datetime.strptime(date_string, fmt)
                except ValueError:
                    continue

            return None
        except Exception:
            return None

    def _identify_hash_type(self, hash_value: Optional[str]) -> Optional[str]:
        """
        Identify hash type based on format

        Args:
            hash_value: Hash value

        Returns:
            Hash type or None
        """
        if not hash_value:
            return None

        hash_length = len(hash_value)

        # Common hash types by length
        hash_types = {
            32: 'MD5',
            40: 'SHA1',
            64: 'SHA256',
            96: 'SHA384',
            128: 'SHA512'
        }

        # Check for bcrypt
        if hash_value.startswith('$2a$') or hash_value.startswith('$2b$') or hash_value.startswith('$2y$'):
            return 'bcrypt'

        # Check for other special formats
        if hash_value.startswith('$6$'):
            return 'SHA512crypt'
        if hash_value.startswith('$5$'):
            return 'SHA256crypt'
        if hash_value.startswith('$1$'):
            return 'MD5crypt'

        return hash_types.get(hash_length, 'Unknown')

    async def bulk_search(self, queries: List[Dict[str, str]]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Perform bulk searches

        Args:
            queries: List of search queries as dicts

        Returns:
            Dictionary of results by query
        """
        results = {}

        for query_dict in queries:
            query_type = query_dict.get('type')
            query_value = query_dict.get('value')

            if not query_type or not query_value:
                continue

            try:
                if query_type == 'email':
                    result = await self.search_email(query_value)
                elif query_type == 'username':
                    result = await self.search_username(query_value)
                elif query_type == 'phone':
                    result = await self.search_phone(query_value)
                elif query_type == 'ip':
                    result = await self.search_ip(query_value)
                elif query_type == 'name':
                    result = await self.search_name(query_value)
                else:
                    continue

                results[f"{query_type}:{query_value}"] = result

            except Exception as e:
                self.logger.error(f"Bulk search failed for {query_type}:{query_value} - {e}")
                results[f"{query_type}:{query_value}"] = []

        return results

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get DeHashed statistics

        Returns:
            Statistics about the database
        """
        # These are approximate numbers - update periodically
        return {
            'total_records': '11,000,000,000+',
            'databases': '1000+',
            'searchable_fields': [
                'email',
                'username',
                'password',
                'hashed_password',
                'phone',
                'ip_address',
                'name',
                'address',
                'vin'
            ],
            'supported_hash_types': [
                'MD5',
                'SHA1',
                'SHA256',
                'SHA512',
                'bcrypt',
                'NTLM'
            ]
        }


if __name__ == "__main__":
    # Example usage
    logging.basicConfig(level=logging.INFO)

    async def main():
        # Initialize with credentials
        dehashed = DeHashedIntegration(
            email="your-email@example.com",
            api_key="your-api-key"
        )

        # Search for email
        results = await dehashed.search_email("target@example.com")
        print(f"Found {len(results)} records")

        for record in results[:5]:  # Show first 5
            print(f"\nDatabase: {record['database_name']}")
            print(f"Email: {record['email']}")
            print(f"Username: {record['username']}")
            print(f"Password: {record['password']}")

        # Advanced search
        results = await dehashed.advanced_search(
            email="target@example.com",
            username="target_user"
        )
        print(f"\nAdvanced search found {len(results)} records")

    asyncio.run(main())
