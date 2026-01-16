"""
Main Breach Search Engine
Multi-source breach database search and correlation system
"""

import asyncio
import logging
from typing import Dict, List, Optional, Set, Any
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import json
import hashlib

from dehashed_integration import DeHashedIntegration
from hibp_integration import HaveIBeenPwnedIntegration
from snusbase_integration import SnusbaseIntegration
from breach_correlator import BreachCorrelator
from credential_analyzer import CredentialAnalyzer


class SearchType(Enum):
    """Search type enumeration"""
    EMAIL = "email"
    USERNAME = "username"
    PASSWORD = "password"
    PHONE = "phone"
    IP_ADDRESS = "ip_address"
    NAME = "name"
    DOMAIN = "domain"
    HASH = "hash"


@dataclass
class BreachRecord:
    """Individual breach record"""
    source: str
    database: str
    breach_date: Optional[datetime]
    email: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    password_hash: Optional[str] = None
    hash_type: Optional[str] = None
    phone: Optional[str] = None
    ip_address: Optional[str] = None
    name: Optional[str] = None
    address: Optional[str] = None
    additional_data: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 1.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'source': self.source,
            'database': self.database,
            'breach_date': self.breach_date.isoformat() if self.breach_date else None,
            'email': self.email,
            'username': self.username,
            'password': self.password,
            'password_hash': self.password_hash,
            'hash_type': self.hash_type,
            'phone': self.phone,
            'ip_address': self.ip_address,
            'name': self.name,
            'address': self.address,
            'additional_data': self.additional_data,
            'confidence': self.confidence
        }


@dataclass
class SearchResults:
    """Aggregated search results"""
    query: str
    search_type: SearchType
    timestamp: datetime
    total_records: int
    sources: List[str]
    records: List[BreachRecord]
    correlations: Dict[str, Any] = field(default_factory=dict)
    credential_analysis: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'query': self.query,
            'search_type': self.search_type.value,
            'timestamp': self.timestamp.isoformat(),
            'total_records': self.total_records,
            'sources': self.sources,
            'records': [r.to_dict() for r in self.records],
            'correlations': self.correlations,
            'credential_analysis': self.credential_analysis
        }


class BreachSearch:
    """
    Main breach search engine
    Integrates multiple breach databases and correlation
    """

    def __init__(
        self,
        dehashed_email: Optional[str] = None,
        dehashed_api_key: Optional[str] = None,
        hibp_api_key: Optional[str] = None,
        snusbase_api_key: Optional[str] = None,
        intelx_api_key: Optional[str] = None,
        leakcheck_api_key: Optional[str] = None,
        config_file: Optional[str] = None
    ):
        """Initialize breach search engine"""
        self.logger = logging.getLogger(__name__)

        # Load configuration
        if config_file:
            self._load_config(config_file)
        else:
            self.config = {
                'dehashed_email': dehashed_email,
                'dehashed_api_key': dehashed_api_key,
                'hibp_api_key': hibp_api_key,
                'snusbase_api_key': snusbase_api_key,
                'intelx_api_key': intelx_api_key,
                'leakcheck_api_key': leakcheck_api_key
            }

        # Initialize integrations
        self.dehashed = DeHashedIntegration(
            email=self.config.get('dehashed_email'),
            api_key=self.config.get('dehashed_api_key')
        )

        self.hibp = HaveIBeenPwnedIntegration(
            api_key=self.config.get('hibp_api_key')
        )

        self.snusbase = SnusbaseIntegration(
            api_key=self.config.get('snusbase_api_key')
        )

        # Initialize analyzers
        self.correlator = BreachCorrelator()
        self.analyzer = CredentialAnalyzer()

        # Cache for results
        self.cache = {}

    def _load_config(self, config_file: str):
        """Load configuration from file"""
        try:
            with open(config_file, 'r') as f:
                self.config = json.load(f)
        except Exception as e:
            self.logger.error(f"Failed to load config: {e}")
            self.config = {}

    async def search_email(self, email: str, correlate: bool = True) -> SearchResults:
        """
        Search all breach databases for email

        Args:
            email: Email address to search
            correlate: Perform correlation analysis

        Returns:
            Aggregated search results
        """
        self.logger.info(f"Searching for email: {email}")

        # Check cache
        cache_key = f"email:{email}"
        if cache_key in self.cache:
            return self.cache[cache_key]

        # Search all sources concurrently
        tasks = [
            self._search_dehashed_email(email),
            self._search_hibp_email(email),
            self._search_snusbase_email(email)
        ]

        results_list = await asyncio.gather(*tasks, return_exceptions=True)

        # Aggregate results
        all_records = []
        sources = []

        for result in results_list:
            if isinstance(result, Exception):
                self.logger.error(f"Search error: {result}")
                continue
            if result:
                all_records.extend(result['records'])
                sources.append(result['source'])

        # Create search results
        search_results = SearchResults(
            query=email,
            search_type=SearchType.EMAIL,
            timestamp=datetime.now(),
            total_records=len(all_records),
            sources=sources,
            records=all_records
        )

        # Perform correlation and analysis
        if correlate and all_records:
            search_results.correlations = self.correlator.correlate_records(all_records)
            search_results.credential_analysis = self.analyzer.analyze_credentials(all_records)

        # Cache results
        self.cache[cache_key] = search_results

        return search_results

    async def search_username(self, username: str, correlate: bool = True) -> SearchResults:
        """
        Search all breach databases for username

        Args:
            username: Username to search
            correlate: Perform correlation analysis

        Returns:
            Aggregated search results
        """
        self.logger.info(f"Searching for username: {username}")

        # Check cache
        cache_key = f"username:{username}"
        if cache_key in self.cache:
            return self.cache[cache_key]

        # Search all sources concurrently
        tasks = [
            self._search_dehashed_username(username),
            self._search_snusbase_username(username)
        ]

        results_list = await asyncio.gather(*tasks, return_exceptions=True)

        # Aggregate results
        all_records = []
        sources = []

        for result in results_list:
            if isinstance(result, Exception):
                self.logger.error(f"Search error: {result}")
                continue
            if result:
                all_records.extend(result['records'])
                sources.append(result['source'])

        # Create search results
        search_results = SearchResults(
            query=username,
            search_type=SearchType.USERNAME,
            timestamp=datetime.now(),
            total_records=len(all_records),
            sources=sources,
            records=all_records
        )

        # Perform correlation and analysis
        if correlate and all_records:
            search_results.correlations = self.correlator.correlate_records(all_records)
            search_results.credential_analysis = self.analyzer.analyze_credentials(all_records)

        # Cache results
        self.cache[cache_key] = search_results

        return search_results

    async def search_password(self, password: str) -> SearchResults:
        """
        Search for password in breaches

        Args:
            password: Password to search

        Returns:
            Search results
        """
        self.logger.info("Searching for password")

        # Hash the password for privacy
        password_hash = hashlib.sha1(password.encode()).hexdigest().upper()

        # Search all sources concurrently
        tasks = [
            self._search_hibp_password(password),
            self._search_dehashed_password(password)
        ]

        results_list = await asyncio.gather(*tasks, return_exceptions=True)

        # Aggregate results
        all_records = []
        sources = []

        for result in results_list:
            if isinstance(result, Exception):
                self.logger.error(f"Search error: {result}")
                continue
            if result:
                all_records.extend(result['records'])
                sources.append(result['source'])

        # Create search results
        search_results = SearchResults(
            query=password_hash[:10] + "...",  # Don't store full password
            search_type=SearchType.PASSWORD,
            timestamp=datetime.now(),
            total_records=len(all_records),
            sources=sources,
            records=all_records
        )

        return search_results

    async def search_phone(self, phone: str, correlate: bool = True) -> SearchResults:
        """Search for phone number in breaches"""
        self.logger.info(f"Searching for phone: {phone}")

        # Search DeHashed
        result = await self._search_dehashed_phone(phone)

        all_records = result['records'] if result else []
        sources = [result['source']] if result else []

        search_results = SearchResults(
            query=phone,
            search_type=SearchType.PHONE,
            timestamp=datetime.now(),
            total_records=len(all_records),
            sources=sources,
            records=all_records
        )

        if correlate and all_records:
            search_results.correlations = self.correlator.correlate_records(all_records)

        return search_results

    async def search_ip(self, ip_address: str, correlate: bool = True) -> SearchResults:
        """Search for IP address in breaches"""
        self.logger.info(f"Searching for IP: {ip_address}")

        # Search DeHashed
        result = await self._search_dehashed_ip(ip_address)

        all_records = result['records'] if result else []
        sources = [result['source']] if result else []

        search_results = SearchResults(
            query=ip_address,
            search_type=SearchType.IP_ADDRESS,
            timestamp=datetime.now(),
            total_records=len(all_records),
            sources=sources,
            records=all_records
        )

        if correlate and all_records:
            search_results.correlations = self.correlator.correlate_records(all_records)

        return search_results

    async def search_domain(self, domain: str) -> SearchResults:
        """Search for domain breaches"""
        self.logger.info(f"Searching for domain: {domain}")

        # Search HIBP for domain breaches
        result = await self._search_hibp_domain(domain)

        all_records = result['records'] if result else []
        sources = [result['source']] if result else []

        search_results = SearchResults(
            query=domain,
            search_type=SearchType.DOMAIN,
            timestamp=datetime.now(),
            total_records=len(all_records),
            sources=sources,
            records=all_records
        )

        return search_results

    async def search_hash(self, hash_value: str) -> SearchResults:
        """Search for password hash"""
        self.logger.info(f"Searching for hash: {hash_value[:10]}...")

        # Search Snusbase
        result = await self._search_snusbase_hash(hash_value)

        all_records = result['records'] if result else []
        sources = [result['source']] if result else []

        search_results = SearchResults(
            query=hash_value[:10] + "...",
            search_type=SearchType.HASH,
            timestamp=datetime.now(),
            total_records=len(all_records),
            sources=sources,
            records=all_records
        )

        return search_results

    async def multi_search(
        self,
        email: Optional[str] = None,
        username: Optional[str] = None,
        phone: Optional[str] = None,
        name: Optional[str] = None
    ) -> Dict[str, SearchResults]:
        """
        Perform multiple searches concurrently

        Returns:
            Dictionary of search results by type
        """
        tasks = {}

        if email:
            tasks['email'] = self.search_email(email)
        if username:
            tasks['username'] = self.search_username(username)
        if phone:
            tasks['phone'] = self.search_phone(phone)
        if name:
            tasks['name'] = self._search_dehashed_name(name)

        results = await asyncio.gather(*tasks.values(), return_exceptions=True)

        return {
            key: result for key, result in zip(tasks.keys(), results)
            if not isinstance(result, Exception)
        }

    # Internal search methods for each source

    async def _search_dehashed_email(self, email: str) -> Optional[Dict]:
        """Search DeHashed for email"""
        try:
            results = await self.dehashed.search_email(email)
            records = [
                BreachRecord(
                    source='DeHashed',
                    database=r.get('database_name', 'Unknown'),
                    breach_date=r.get('obtained_date'),
                    email=r.get('email'),
                    username=r.get('username'),
                    password=r.get('password'),
                    password_hash=r.get('hashed_password'),
                    hash_type=r.get('hash_type'),
                    phone=r.get('phone'),
                    ip_address=r.get('ip_address'),
                    name=r.get('name'),
                    address=r.get('address'),
                    additional_data=r.get('additional_data', {})
                )
                for r in results
            ]
            return {'source': 'DeHashed', 'records': records}
        except Exception as e:
            self.logger.error(f"DeHashed email search failed: {e}")
            return None

    async def _search_dehashed_username(self, username: str) -> Optional[Dict]:
        """Search DeHashed for username"""
        try:
            results = await self.dehashed.search_username(username)
            records = [
                BreachRecord(
                    source='DeHashed',
                    database=r.get('database_name', 'Unknown'),
                    breach_date=r.get('obtained_date'),
                    email=r.get('email'),
                    username=r.get('username'),
                    password=r.get('password'),
                    password_hash=r.get('hashed_password'),
                    hash_type=r.get('hash_type'),
                    phone=r.get('phone'),
                    ip_address=r.get('ip_address'),
                    name=r.get('name'),
                    additional_data=r.get('additional_data', {})
                )
                for r in results
            ]
            return {'source': 'DeHashed', 'records': records}
        except Exception as e:
            self.logger.error(f"DeHashed username search failed: {e}")
            return None

    async def _search_dehashed_password(self, password: str) -> Optional[Dict]:
        """Search DeHashed for password"""
        try:
            results = await self.dehashed.search_password(password)
            records = [
                BreachRecord(
                    source='DeHashed',
                    database=r.get('database_name', 'Unknown'),
                    breach_date=r.get('obtained_date'),
                    email=r.get('email'),
                    username=r.get('username'),
                    password=r.get('password'),
                    additional_data=r.get('additional_data', {})
                )
                for r in results
            ]
            return {'source': 'DeHashed', 'records': records}
        except Exception as e:
            self.logger.error(f"DeHashed password search failed: {e}")
            return None

    async def _search_dehashed_phone(self, phone: str) -> Optional[Dict]:
        """Search DeHashed for phone"""
        try:
            results = await self.dehashed.search_phone(phone)
            records = [
                BreachRecord(
                    source='DeHashed',
                    database=r.get('database_name', 'Unknown'),
                    breach_date=r.get('obtained_date'),
                    email=r.get('email'),
                    username=r.get('username'),
                    phone=r.get('phone'),
                    name=r.get('name'),
                    additional_data=r.get('additional_data', {})
                )
                for r in results
            ]
            return {'source': 'DeHashed', 'records': records}
        except Exception as e:
            self.logger.error(f"DeHashed phone search failed: {e}")
            return None

    async def _search_dehashed_ip(self, ip_address: str) -> Optional[Dict]:
        """Search DeHashed for IP"""
        try:
            results = await self.dehashed.search_ip(ip_address)
            records = [
                BreachRecord(
                    source='DeHashed',
                    database=r.get('database_name', 'Unknown'),
                    breach_date=r.get('obtained_date'),
                    email=r.get('email'),
                    username=r.get('username'),
                    ip_address=r.get('ip_address'),
                    additional_data=r.get('additional_data', {})
                )
                for r in results
            ]
            return {'source': 'DeHashed', 'records': records}
        except Exception as e:
            self.logger.error(f"DeHashed IP search failed: {e}")
            return None

    async def _search_dehashed_name(self, name: str) -> Optional[Dict]:
        """Search DeHashed for name"""
        try:
            results = await self.dehashed.search_name(name)
            records = [
                BreachRecord(
                    source='DeHashed',
                    database=r.get('database_name', 'Unknown'),
                    breach_date=r.get('obtained_date'),
                    email=r.get('email'),
                    username=r.get('username'),
                    name=r.get('name'),
                    additional_data=r.get('additional_data', {})
                )
                for r in results
            ]
            return {'source': 'DeHashed', 'records': records}
        except Exception as e:
            self.logger.error(f"DeHashed name search failed: {e}")
            return None

    async def _search_hibp_email(self, email: str) -> Optional[Dict]:
        """Search HIBP for email breaches"""
        try:
            breaches = await self.hibp.check_email_breaches(email)
            pastes = await self.hibp.check_email_pastes(email)

            records = []

            # Process breaches
            for breach in breaches:
                records.append(BreachRecord(
                    source='HaveIBeenPwned',
                    database=breach.get('Name', 'Unknown'),
                    breach_date=breach.get('BreachDate'),
                    email=email,
                    additional_data={
                        'description': breach.get('Description'),
                        'data_classes': breach.get('DataClasses', []),
                        'verified': breach.get('IsVerified', False),
                        'pwn_count': breach.get('PwnCount', 0)
                    }
                ))

            # Process pastes
            for paste in pastes:
                records.append(BreachRecord(
                    source='HaveIBeenPwned',
                    database=f"Paste-{paste.get('Source', 'Unknown')}",
                    breach_date=paste.get('Date'),
                    email=email,
                    additional_data={
                        'paste_id': paste.get('Id'),
                        'title': paste.get('Title'),
                        'email_count': paste.get('EmailCount', 0)
                    }
                ))

            return {'source': 'HaveIBeenPwned', 'records': records}
        except Exception as e:
            self.logger.error(f"HIBP email search failed: {e}")
            return None

    async def _search_hibp_password(self, password: str) -> Optional[Dict]:
        """Search HIBP for password"""
        try:
            count = await self.hibp.check_password(password)

            if count > 0:
                records = [BreachRecord(
                    source='HaveIBeenPwned',
                    database='Pwned Passwords',
                    breach_date=None,
                    password=password,
                    additional_data={
                        'pwn_count': count,
                        'severity': 'critical' if count > 1000 else 'high' if count > 100 else 'medium'
                    }
                )]
                return {'source': 'HaveIBeenPwned', 'records': records}

            return {'source': 'HaveIBeenPwned', 'records': []}
        except Exception as e:
            self.logger.error(f"HIBP password search failed: {e}")
            return None

    async def _search_hibp_domain(self, domain: str) -> Optional[Dict]:
        """Search HIBP for domain breaches"""
        try:
            breaches = await self.hibp.check_domain_breaches(domain)

            records = [
                BreachRecord(
                    source='HaveIBeenPwned',
                    database=breach.get('Name', 'Unknown'),
                    breach_date=breach.get('BreachDate'),
                    additional_data={
                        'description': breach.get('Description'),
                        'data_classes': breach.get('DataClasses', []),
                        'verified': breach.get('IsVerified', False),
                        'pwn_count': breach.get('PwnCount', 0),
                        'domain': domain
                    }
                )
                for breach in breaches
            ]

            return {'source': 'HaveIBeenPwned', 'records': records}
        except Exception as e:
            self.logger.error(f"HIBP domain search failed: {e}")
            return None

    async def _search_snusbase_email(self, email: str) -> Optional[Dict]:
        """Search Snusbase for email"""
        try:
            results = await self.snusbase.search_email(email)

            records = [
                BreachRecord(
                    source='Snusbase',
                    database=r.get('database', 'Unknown'),
                    breach_date=r.get('breach_date'),
                    email=r.get('email'),
                    username=r.get('username'),
                    password=r.get('password'),
                    password_hash=r.get('hash'),
                    hash_type=r.get('hash_type'),
                    additional_data=r.get('additional_data', {})
                )
                for r in results
            ]

            return {'source': 'Snusbase', 'records': records}
        except Exception as e:
            self.logger.error(f"Snusbase email search failed: {e}")
            return None

    async def _search_snusbase_username(self, username: str) -> Optional[Dict]:
        """Search Snusbase for username"""
        try:
            results = await self.snusbase.search_username(username)

            records = [
                BreachRecord(
                    source='Snusbase',
                    database=r.get('database', 'Unknown'),
                    breach_date=r.get('breach_date'),
                    email=r.get('email'),
                    username=r.get('username'),
                    password=r.get('password'),
                    password_hash=r.get('hash'),
                    hash_type=r.get('hash_type'),
                    additional_data=r.get('additional_data', {})
                )
                for r in results
            ]

            return {'source': 'Snusbase', 'records': records}
        except Exception as e:
            self.logger.error(f"Snusbase username search failed: {e}")
            return None

    async def _search_snusbase_hash(self, hash_value: str) -> Optional[Dict]:
        """Search Snusbase for hash"""
        try:
            results = await self.snusbase.search_hash(hash_value)

            records = [
                BreachRecord(
                    source='Snusbase',
                    database=r.get('database', 'Unknown'),
                    breach_date=r.get('breach_date'),
                    password=r.get('password'),
                    password_hash=hash_value,
                    hash_type=r.get('hash_type'),
                    additional_data=r.get('additional_data', {})
                )
                for r in results
            ]

            return {'source': 'Snusbase', 'records': records}
        except Exception as e:
            self.logger.error(f"Snusbase hash search failed: {e}")
            return None

    def export_results(self, results: SearchResults, output_file: str, format: str = 'json'):
        """
        Export search results to file

        Args:
            results: Search results to export
            output_file: Output file path
            format: Export format (json, csv, html)
        """
        if format == 'json':
            with open(output_file, 'w') as f:
                json.dump(results.to_dict(), f, indent=2)

        elif format == 'csv':
            import csv
            with open(output_file, 'w', newline='') as f:
                if results.records:
                    fieldnames = results.records[0].to_dict().keys()
                    writer = csv.DictWriter(f, fieldnames=fieldnames)
                    writer.writeheader()
                    for record in results.records:
                        writer.writerow(record.to_dict())

        elif format == 'html':
            html = self._generate_html_report(results)
            with open(output_file, 'w') as f:
                f.write(html)

    def _generate_html_report(self, results: SearchResults) -> str:
        """Generate HTML report"""
        html = f"""
        <html>
        <head>
            <title>Breach Search Results - {results.query}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #4CAF50; color: white; }}
                .summary {{ background-color: #f0f0f0; padding: 15px; margin-bottom: 20px; }}
            </style>
        </head>
        <body>
            <h1>Breach Search Results</h1>
            <div class="summary">
                <p><strong>Query:</strong> {results.query}</p>
                <p><strong>Search Type:</strong> {results.search_type.value}</p>
                <p><strong>Total Records:</strong> {results.total_records}</p>
                <p><strong>Sources:</strong> {', '.join(results.sources)}</p>
                <p><strong>Timestamp:</strong> {results.timestamp}</p>
            </div>
            <table>
                <tr>
                    <th>Source</th>
                    <th>Database</th>
                    <th>Breach Date</th>
                    <th>Email</th>
                    <th>Username</th>
                    <th>Password</th>
                </tr>
        """

        for record in results.records:
            html += f"""
                <tr>
                    <td>{record.source}</td>
                    <td>{record.database}</td>
                    <td>{record.breach_date or 'Unknown'}</td>
                    <td>{record.email or ''}</td>
                    <td>{record.username or ''}</td>
                    <td>{record.password or ''}</td>
                </tr>
            """

        html += """
            </table>
        </body>
        </html>
        """

        return html


if __name__ == "__main__":
    # Example usage
    logging.basicConfig(level=logging.INFO)

    async def main():
        # Initialize search engine
        searcher = BreachSearch(config_file='breach_config.json')

        # Search for email
        results = await searcher.search_email("target@example.com")

        print(f"Found {results.total_records} records from {len(results.sources)} sources")
        print(f"Correlations: {results.correlations}")

        # Export results
        searcher.export_results(results, 'breach_results.json', format='json')
        searcher.export_results(results, 'breach_results.html', format='html')

    asyncio.run(main())
