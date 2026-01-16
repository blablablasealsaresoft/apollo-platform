"""
Snusbase API Integration
Access to comprehensive breach database with hash lookup
"""

import asyncio
import aiohttp
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime


class SnusbaseIntegration:
    """
    Snusbase API integration
    Search breach databases and lookup password hashes
    """

    BASE_URL = "https://api.snusbase.com"

    def __init__(self, api_key: Optional[str] = None, auth_token: Optional[str] = None):
        """
        Initialize Snusbase integration

        Args:
            api_key: Snusbase API key
            auth_token: Snusbase auth token
        """
        self.api_key = api_key
        self.auth_token = auth_token
        self.logger = logging.getLogger(__name__)

        if not (api_key or auth_token):
            self.logger.warning("Snusbase credentials not provided - API calls will fail")

        # Rate limiting
        self.rate_limit_delay = 1.0
        self.last_request_time = 0

    async def _make_request(
        self,
        endpoint: str,
        data: Optional[Dict] = None,
        method: str = 'POST'
    ) -> Dict[str, Any]:
        """
        Make request to Snusbase API

        Args:
            endpoint: API endpoint
            data: Request data
            method: HTTP method

        Returns:
            API response
        """
        if not (self.api_key or self.auth_token):
            raise ValueError("Snusbase credentials not configured")

        # Rate limiting
        current_time = asyncio.get_event_loop().time()
        time_since_last_request = current_time - self.last_request_time
        if time_since_last_request < self.rate_limit_delay:
            await asyncio.sleep(self.rate_limit_delay - time_since_last_request)

        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }

        if self.auth_token:
            headers['Authorization'] = f'Bearer {self.auth_token}'
        elif self.api_key:
            headers['Auth'] = self.api_key

        url = f"{self.BASE_URL}/{endpoint}"

        async with aiohttp.ClientSession() as session:
            try:
                if method == 'POST':
                    request_method = session.post
                else:
                    request_method = session.get

                async with request_method(
                    url,
                    headers=headers,
                    json=data if method == 'POST' else None,
                    params=data if method == 'GET' else None,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    self.last_request_time = asyncio.get_event_loop().time()

                    if response.status == 200:
                        return await response.json()
                    elif response.status == 401:
                        raise Exception("Invalid Snusbase credentials")
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

    async def search(
        self,
        terms: List[str],
        types: List[str],
        wildcard: bool = False
    ) -> List[Dict[str, Any]]:
        """
        Universal search method

        Args:
            terms: Search terms
            types: Search types (email, username, lastip, password, hash, name)
            wildcard: Enable wildcard search

        Returns:
            List of results
        """
        self.logger.info(f"Searching Snusbase: {terms} in {types}")

        data = {
            'terms': terms,
            'types': types,
            'wildcard': wildcard
        }

        response = await self._make_request('data/search', data=data)

        return self._parse_results(response)

    async def search_email(self, email: str) -> List[Dict[str, Any]]:
        """
        Search for email address

        Args:
            email: Email to search

        Returns:
            List of breach records
        """
        self.logger.info(f"Searching Snusbase for email: {email}")

        results = await self.search(terms=[email], types=['email'])

        return results

    async def search_username(self, username: str) -> List[Dict[str, Any]]:
        """
        Search for username

        Args:
            username: Username to search

        Returns:
            List of breach records
        """
        self.logger.info(f"Searching Snusbase for username: {username}")

        results = await self.search(terms=[username], types=['username'])

        return results

    async def search_password(self, password: str) -> List[Dict[str, Any]]:
        """
        Search for password

        Args:
            password: Password to search

        Returns:
            List of breach records
        """
        self.logger.info("Searching Snusbase for password")

        results = await self.search(terms=[password], types=['password'])

        return results

    async def search_hash(self, hash_value: str) -> List[Dict[str, Any]]:
        """
        Search for password hash

        Args:
            hash_value: Hash to search

        Returns:
            List of breach records with cracked passwords
        """
        self.logger.info(f"Searching Snusbase for hash: {hash_value[:10]}...")

        results = await self.search(terms=[hash_value], types=['hash'])

        return results

    async def search_ip(self, ip_address: str) -> List[Dict[str, Any]]:
        """
        Search for IP address

        Args:
            ip_address: IP address to search

        Returns:
            List of breach records
        """
        self.logger.info(f"Searching Snusbase for IP: {ip_address}")

        results = await self.search(terms=[ip_address], types=['lastip'])

        return results

    async def search_name(self, name: str) -> List[Dict[str, Any]]:
        """
        Search for name

        Args:
            name: Name to search

        Returns:
            List of breach records
        """
        self.logger.info(f"Searching Snusbase for name: {name}")

        results = await self.search(terms=[name], types=['name'])

        return results

    async def wildcard_search(
        self,
        pattern: str,
        search_type: str = 'email'
    ) -> List[Dict[str, Any]]:
        """
        Perform wildcard search

        Args:
            pattern: Search pattern with * as wildcard
            search_type: Type to search (email, username, etc.)

        Returns:
            List of matching records
        """
        self.logger.info(f"Wildcard search: {pattern} in {search_type}")

        results = await self.search(
            terms=[pattern],
            types=[search_type],
            wildcard=True
        )

        return results

    async def multi_search(
        self,
        terms: List[str],
        search_types: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """
        Search multiple terms at once

        Args:
            terms: List of search terms
            search_types: List of search types to use

        Returns:
            Combined results
        """
        if not search_types:
            search_types = ['email', 'username', 'password', 'hash', 'lastip', 'name']

        self.logger.info(f"Multi-search for {len(terms)} terms")

        results = await self.search(terms=terms, types=search_types)

        return results

    async def get_statistics(self) -> Dict[str, Any]:
        """
        Get Snusbase database statistics

        Returns:
            Database statistics
        """
        self.logger.info("Fetching Snusbase statistics")

        try:
            response = await self._make_request('data/stats', method='GET')
            return response
        except Exception as e:
            self.logger.error(f"Failed to get statistics: {e}")
            return {}

    async def hash_lookup(self, hashes: List[str]) -> Dict[str, str]:
        """
        Lookup multiple password hashes

        Args:
            hashes: List of hash values

        Returns:
            Dictionary of hash to cracked password
        """
        self.logger.info(f"Looking up {len(hashes)} hashes")

        results = {}

        # Search each hash
        for hash_value in hashes:
            try:
                search_results = await self.search_hash(hash_value)

                if search_results:
                    # Extract password from results
                    for result in search_results:
                        if result.get('password'):
                            results[hash_value] = result['password']
                            break

            except Exception as e:
                self.logger.error(f"Hash lookup failed for {hash_value[:10]}: {e}")

        return results

    async def enumerate_username(self, username: str) -> Dict[str, List[str]]:
        """
        Enumerate all data associated with username

        Args:
            username: Username to enumerate

        Returns:
            Dictionary of associated data
        """
        self.logger.info(f"Enumerating username: {username}")

        results = await self.search_username(username)

        # Aggregate all associated data
        emails = set()
        passwords = set()
        ips = set()
        names = set()
        databases = set()

        for result in results:
            if result.get('email'):
                emails.add(result['email'])
            if result.get('password'):
                passwords.add(result['password'])
            if result.get('lastip'):
                ips.add(result['lastip'])
            if result.get('name'):
                names.add(result['name'])
            if result.get('database'):
                databases.add(result['database'])

        return {
            'username': username,
            'emails': list(emails),
            'passwords': list(passwords),
            'ip_addresses': list(ips),
            'names': list(names),
            'databases': list(databases),
            'total_records': len(results)
        }

    async def enumerate_email(self, email: str) -> Dict[str, List[str]]:
        """
        Enumerate all data associated with email

        Args:
            email: Email to enumerate

        Returns:
            Dictionary of associated data
        """
        self.logger.info(f"Enumerating email: {email}")

        results = await self.search_email(email)

        # Aggregate all associated data
        usernames = set()
        passwords = set()
        ips = set()
        names = set()
        databases = set()

        for result in results:
            if result.get('username'):
                usernames.add(result['username'])
            if result.get('password'):
                passwords.add(result['password'])
            if result.get('lastip'):
                ips.add(result['lastip'])
            if result.get('name'):
                names.add(result['name'])
            if result.get('database'):
                databases.add(result['database'])

        return {
            'email': email,
            'usernames': list(usernames),
            'passwords': list(passwords),
            'ip_addresses': list(ips),
            'names': list(names),
            'databases': list(databases),
            'total_records': len(results)
        }

    def _parse_results(self, api_response: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Parse API response into standardized format

        Args:
            api_response: Raw API response

        Returns:
            List of parsed records
        """
        if not api_response:
            return []

        records = []

        # Snusbase returns results grouped by database
        results = api_response.get('results', {})

        for database, entries in results.items():
            if not entries:
                continue

            for entry in entries:
                record = {
                    'database': database,
                    'breach_date': self._parse_date(entry.get('breach_date')),
                    'email': entry.get('email'),
                    'username': entry.get('username'),
                    'password': entry.get('password'),
                    'hash': entry.get('hash'),
                    'hash_type': self._identify_hash_type(entry.get('hash')),
                    'lastip': entry.get('lastip'),
                    'name': entry.get('name'),
                    'additional_data': {}
                }

                # Add any additional fields
                for key, value in entry.items():
                    if key not in record and value:
                        record['additional_data'][key] = value

                records.append(record)

        self.logger.info(f"Parsed {len(records)} records from {len(results)} databases")

        return records

    def _parse_date(self, date_string: Optional[str]) -> Optional[datetime]:
        """Parse date string to datetime"""
        if not date_string:
            return None

        try:
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
        """Identify hash type based on format"""
        if not hash_value:
            return None

        hash_length = len(hash_value)

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

        # Check for other formats
        if hash_value.startswith('$6$'):
            return 'SHA512crypt'
        if hash_value.startswith('$5$'):
            return 'SHA256crypt'
        if hash_value.startswith('$1$'):
            return 'MD5crypt'
        if hash_value.startswith('$'):
            return 'Unknown crypt'

        return hash_types.get(hash_length, 'Unknown')

    async def bulk_email_search(self, emails: List[str]) -> Dict[str, List[Dict]]:
        """
        Search multiple emails at once

        Args:
            emails: List of email addresses

        Returns:
            Dictionary of email to results
        """
        self.logger.info(f"Bulk email search for {len(emails)} addresses")

        results = {}

        # Snusbase allows multiple terms in one request
        search_results = await self.search(terms=emails, types=['email'])

        # Group results by email
        for result in search_results:
            email = result.get('email')
            if email:
                if email not in results:
                    results[email] = []
                results[email].append(result)

        return results

    async def combo_list_check(self, combo_list: List[tuple]) -> List[Dict[str, Any]]:
        """
        Check combo list (email:password pairs)

        Args:
            combo_list: List of (email, password) tuples

        Returns:
            List of valid combinations
        """
        self.logger.info(f"Checking {len(combo_list)} combos")

        valid_combos = []

        for email, password in combo_list:
            try:
                # Search for the email
                results = await self.search_email(email)

                # Check if any results match the password
                for result in results:
                    if result.get('password') == password:
                        valid_combos.append({
                            'email': email,
                            'password': password,
                            'database': result.get('database'),
                            'match': True
                        })
                        break

            except Exception as e:
                self.logger.error(f"Combo check failed for {email}: {e}")

        return valid_combos


if __name__ == "__main__":
    # Example usage
    logging.basicConfig(level=logging.INFO)

    async def main():
        # Initialize with API key
        snusbase = SnusbaseIntegration(api_key="your-api-key")

        # Search for email
        results = await snusbase.search_email("test@example.com")
        print(f"Found {len(results)} records")

        for record in results[:5]:
            print(f"\nDatabase: {record['database']}")
            print(f"Email: {record['email']}")
            print(f"Username: {record['username']}")
            print(f"Password: {record['password']}")

        # Hash lookup
        hashes = [
            '5f4dcc3b5aa765d61d8327deb882cf99',  # password
            '482c811da5d5b4bc6d497ffa98491e38'   # password123
        ]
        cracked = await snusbase.hash_lookup(hashes)
        print(f"\nCracked {len(cracked)} hashes")

        # Enumerate username
        enum_results = await snusbase.enumerate_username("target_user")
        print(f"\nUsername enumeration:")
        print(f"Emails: {enum_results['emails']}")
        print(f"Passwords: {enum_results['passwords']}")

    asyncio.run(main())
