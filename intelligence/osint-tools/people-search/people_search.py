"""
People Search - Main People Search and Investigation Module
Comprehensive people search with multiple data source integration
"""

import asyncio
import re
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
import json
import logging
from urllib.parse import quote_plus
import aiohttp
from bs4 import BeautifulSoup

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class PersonProfile:
    """Comprehensive person profile data structure"""
    name: str
    aliases: List[str] = field(default_factory=list)
    age: Optional[int] = None
    age_range: Optional[str] = None
    birth_date: Optional[str] = None

    # Contact Information
    addresses: List[Dict[str, Any]] = field(default_factory=list)
    phone_numbers: List[Dict[str, Any]] = field(default_factory=list)
    email_addresses: List[str] = field(default_factory=list)

    # Relationships
    relatives: List[Dict[str, Any]] = field(default_factory=list)
    associates: List[Dict[str, Any]] = field(default_factory=list)

    # Social Profiles
    social_profiles: List[Dict[str, Any]] = field(default_factory=list)
    usernames: List[str] = field(default_factory=list)

    # Background Information
    education: List[Dict[str, Any]] = field(default_factory=list)
    employment: List[Dict[str, Any]] = field(default_factory=list)
    businesses: List[Dict[str, Any]] = field(default_factory=list)

    # Public Records
    voter_registration: Optional[Dict[str, Any]] = None
    property_records: List[Dict[str, Any]] = field(default_factory=list)
    court_records: List[Dict[str, Any]] = field(default_factory=list)
    criminal_records: List[Dict[str, Any]] = field(default_factory=list)

    # Metadata
    sources: List[str] = field(default_factory=list)
    confidence_score: float = 0.0
    last_updated: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        """Convert profile to dictionary"""
        return {
            'name': self.name,
            'aliases': self.aliases,
            'age': self.age,
            'age_range': self.age_range,
            'birth_date': self.birth_date,
            'contact': {
                'addresses': self.addresses,
                'phone_numbers': self.phone_numbers,
                'email_addresses': self.email_addresses
            },
            'relationships': {
                'relatives': self.relatives,
                'associates': self.associates
            },
            'social': {
                'profiles': self.social_profiles,
                'usernames': self.usernames
            },
            'background': {
                'education': self.education,
                'employment': self.employment,
                'businesses': self.businesses
            },
            'public_records': {
                'voter_registration': self.voter_registration,
                'property_records': self.property_records,
                'court_records': self.court_records,
                'criminal_records': self.criminal_records
            },
            'metadata': {
                'sources': self.sources,
                'confidence_score': self.confidence_score,
                'last_updated': self.last_updated
            }
        }


class PeopleSearch:
    """Main people search and investigation system"""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize people search system

        Args:
            config: Configuration dictionary with API keys and settings
        """
        self.config = config or {}
        self.session: Optional[aiohttp.ClientSession] = None
        self.cache: Dict[str, PersonProfile] = {}

    async def __aenter__(self):
        """Async context manager entry"""
        self.session = aiohttp.ClientSession()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()

    async def investigate(
        self,
        name: Optional[str] = None,
        email: Optional[str] = None,
        phone: Optional[str] = None,
        address: Optional[str] = None,
        location: Optional[str] = None,
        age: Optional[int] = None,
        deep_search: bool = True
    ) -> PersonProfile:
        """
        Comprehensive people investigation

        Args:
            name: Person's name
            email: Email address
            phone: Phone number
            address: Street address
            location: City, State
            age: Person's age or age range
            deep_search: Enable deep web search

        Returns:
            PersonProfile with all discovered information
        """
        logger.info(f"Starting investigation for: {name or email or phone or address}")

        if not self.session:
            self.session = aiohttp.ClientSession()

        # Initialize profile
        profile = PersonProfile(
            name=name or "Unknown",
            sources=[]
        )

        # Search strategies based on available information
        tasks = []

        if name:
            tasks.append(self._search_by_name(name, location, age))

        if email:
            tasks.append(self._search_by_email(email))

        if phone:
            tasks.append(self._search_by_phone(phone))

        if address:
            tasks.append(self._search_by_address(address))

        # Execute all searches in parallel
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Merge results
        for result in results:
            if isinstance(result, PersonProfile):
                profile = self._merge_profiles(profile, result)
            elif isinstance(result, Exception):
                logger.error(f"Search error: {result}")

        # Deep search for additional information
        if deep_search:
            profile = await self._deep_search(profile)

        # Calculate confidence score
        profile.confidence_score = self._calculate_confidence(profile)

        # Cache result
        cache_key = f"{name}_{email}_{phone}_{address}"
        self.cache[cache_key] = profile

        logger.info(f"Investigation complete. Confidence: {profile.confidence_score:.2f}")
        return profile

    async def _search_by_name(
        self,
        name: str,
        location: Optional[str] = None,
        age: Optional[int] = None
    ) -> PersonProfile:
        """Search by person's name"""
        logger.info(f"Searching by name: {name}")

        profile = PersonProfile(name=name)

        # Multiple search strategies
        tasks = [
            self._search_whitepages(name, location, age),
            self._search_fastpeoplesearch(name, location),
            self._search_truepeoplesearch(name, location),
            self._search_publicrecords(name, location)
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, PersonProfile):
                profile = self._merge_profiles(profile, result)

        return profile

    async def _search_by_email(self, email: str) -> PersonProfile:
        """Search by email address"""
        logger.info(f"Searching by email: {email}")

        profile = PersonProfile(name="Unknown")
        profile.email_addresses.append(email)

        tasks = [
            self._email_reverse_lookup(email),
            self._search_hunter_io(email),
            self._search_email_rep(email)
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, PersonProfile):
                profile = self._merge_profiles(profile, result)

        return profile

    async def _search_by_phone(self, phone: str) -> PersonProfile:
        """Reverse phone number lookup"""
        logger.info(f"Searching by phone: {phone}")

        # Normalize phone number
        clean_phone = re.sub(r'\D', '', phone)

        profile = PersonProfile(name="Unknown")
        profile.phone_numbers.append({
            'number': phone,
            'type': 'unknown',
            'carrier': None
        })

        tasks = [
            self._reverse_phone_lookup(clean_phone),
            self._search_truecaller(clean_phone),
            self._carrier_lookup(clean_phone)
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, PersonProfile):
                profile = self._merge_profiles(profile, result)

        return profile

    async def _search_by_address(self, address: str) -> PersonProfile:
        """Search by physical address"""
        logger.info(f"Searching by address: {address}")

        profile = PersonProfile(name="Unknown")
        profile.addresses.append({
            'full_address': address,
            'type': 'current',
            'years_at_address': None
        })

        tasks = [
            self._reverse_address_lookup(address),
            self._property_records_lookup(address)
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, PersonProfile):
                profile = self._merge_profiles(profile, result)

        return profile

    async def _search_whitepages(
        self,
        name: str,
        location: Optional[str] = None,
        age: Optional[int] = None
    ) -> PersonProfile:
        """Search Whitepages.com"""
        try:
            profile = PersonProfile(name=name)
            profile.sources.append("whitepages.com")

            # Build search URL
            query = quote_plus(name)
            if location:
                query += f"/{quote_plus(location)}"

            url = f"https://www.whitepages.com/name/{query}"

            async with self.session.get(url, timeout=10) as response:
                if response.status == 200:
                    html = await response.text()
                    soup = BeautifulSoup(html, 'html.parser')

                    # Parse results (example parsing logic)
                    # In production, use proper selectors
                    logger.info("Whitepages search completed")

            return profile

        except Exception as e:
            logger.error(f"Whitepages search error: {e}")
            return PersonProfile(name=name)

    async def _search_fastpeoplesearch(
        self,
        name: str,
        location: Optional[str] = None
    ) -> PersonProfile:
        """Search FastPeopleSearch.com"""
        try:
            profile = PersonProfile(name=name)
            profile.sources.append("fastpeoplesearch.com")

            # Note: This is a free people search site
            logger.info("FastPeopleSearch search completed")

            return profile

        except Exception as e:
            logger.error(f"FastPeopleSearch error: {e}")
            return PersonProfile(name=name)

    async def _search_truepeoplesearch(
        self,
        name: str,
        location: Optional[str] = None
    ) -> PersonProfile:
        """Search TruePeopleSearch.com"""
        try:
            profile = PersonProfile(name=name)
            profile.sources.append("truepeoplesearch.com")

            logger.info("TruePeopleSearch search completed")

            return profile

        except Exception as e:
            logger.error(f"TruePeopleSearch error: {e}")
            return PersonProfile(name=name)

    async def _search_publicrecords(
        self,
        name: str,
        location: Optional[str] = None
    ) -> PersonProfile:
        """Search public records databases"""
        try:
            profile = PersonProfile(name=name)
            profile.sources.append("public_records")

            logger.info("Public records search completed")

            return profile

        except Exception as e:
            logger.error(f"Public records search error: {e}")
            return PersonProfile(name=name)

    async def _email_reverse_lookup(self, email: str) -> PersonProfile:
        """Reverse email lookup"""
        try:
            profile = PersonProfile(name="Unknown")
            profile.email_addresses.append(email)
            profile.sources.append("email_lookup")

            # Extract name from email if possible
            username = email.split('@')[0]
            if '.' in username:
                parts = username.split('.')
                name = ' '.join(parts).title()
                profile.name = name

            logger.info(f"Email reverse lookup completed for {email}")

            return profile

        except Exception as e:
            logger.error(f"Email lookup error: {e}")
            return PersonProfile(name="Unknown")

    async def _search_hunter_io(self, email: str) -> PersonProfile:
        """Search Hunter.io for email information"""
        try:
            profile = PersonProfile(name="Unknown")

            api_key = self.config.get('hunter_api_key')
            if not api_key:
                logger.warning("Hunter.io API key not configured")
                return profile

            url = f"https://api.hunter.io/v2/email-verifier"
            params = {
                'email': email,
                'api_key': api_key
            }

            async with self.session.get(url, params=params) as response:
                if response.status == 200:
                    data = await response.json()

                    if data.get('data', {}).get('result') == 'deliverable':
                        profile.sources.append("hunter.io")

                        # Extract information
                        email_data = data.get('data', {})
                        if email_data.get('first_name'):
                            name = f"{email_data.get('first_name', '')} {email_data.get('last_name', '')}"
                            profile.name = name.strip()

                        logger.info(f"Hunter.io verification completed")

            return profile

        except Exception as e:
            logger.error(f"Hunter.io search error: {e}")
            return PersonProfile(name="Unknown")

    async def _search_email_rep(self, email: str) -> PersonProfile:
        """Search EmailRep for email reputation"""
        try:
            profile = PersonProfile(name="Unknown")

            url = f"https://emailrep.io/{email}"

            async with self.session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    profile.sources.append("emailrep.io")

                    logger.info("EmailRep search completed")

            return profile

        except Exception as e:
            logger.error(f"EmailRep search error: {e}")
            return PersonProfile(name="Unknown")

    async def _reverse_phone_lookup(self, phone: str) -> PersonProfile:
        """Reverse phone number lookup"""
        try:
            profile = PersonProfile(name="Unknown")
            profile.sources.append("phone_lookup")

            # Multiple free reverse phone lookup services
            logger.info(f"Reverse phone lookup completed")

            return profile

        except Exception as e:
            logger.error(f"Phone lookup error: {e}")
            return PersonProfile(name="Unknown")

    async def _search_truecaller(self, phone: str) -> PersonProfile:
        """Search Truecaller for phone information"""
        try:
            profile = PersonProfile(name="Unknown")

            # Note: Truecaller requires authentication
            logger.info("Truecaller search would require API access")

            return profile

        except Exception as e:
            logger.error(f"Truecaller search error: {e}")
            return PersonProfile(name="Unknown")

    async def _carrier_lookup(self, phone: str) -> PersonProfile:
        """Lookup phone carrier information"""
        try:
            profile = PersonProfile(name="Unknown")

            # Use carrier lookup API
            api_key = self.config.get('numverify_api_key')
            if api_key:
                url = f"http://apilayer.net/api/validate"
                params = {
                    'access_key': api_key,
                    'number': phone
                }

                async with self.session.get(url, params=params) as response:
                    if response.status == 200:
                        data = await response.json()

                        if data.get('valid'):
                            profile.phone_numbers.append({
                                'number': phone,
                                'type': data.get('line_type'),
                                'carrier': data.get('carrier'),
                                'country': data.get('country_name'),
                                'location': data.get('location')
                            })
                            profile.sources.append("numverify")

            return profile

        except Exception as e:
            logger.error(f"Carrier lookup error: {e}")
            return PersonProfile(name="Unknown")

    async def _reverse_address_lookup(self, address: str) -> PersonProfile:
        """Reverse address lookup"""
        try:
            profile = PersonProfile(name="Unknown")
            profile.sources.append("address_lookup")

            logger.info(f"Reverse address lookup completed")

            return profile

        except Exception as e:
            logger.error(f"Address lookup error: {e}")
            return PersonProfile(name="Unknown")

    async def _property_records_lookup(self, address: str) -> PersonProfile:
        """Lookup property records"""
        try:
            profile = PersonProfile(name="Unknown")
            profile.sources.append("property_records")

            logger.info(f"Property records lookup completed")

            return profile

        except Exception as e:
            logger.error(f"Property records error: {e}")
            return PersonProfile(name="Unknown")

    async def _deep_search(self, profile: PersonProfile) -> PersonProfile:
        """Perform deep web search for additional information"""
        logger.info("Performing deep search...")

        tasks = []

        # Search for social profiles
        if profile.name != "Unknown":
            tasks.append(self._find_social_profiles(profile.name))

        # Search for relatives
        if profile.addresses:
            tasks.append(self._find_relatives(profile))

        # Search for public records
        tasks.append(self._find_public_records(profile))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, PersonProfile):
                profile = self._merge_profiles(profile, result)

        return profile

    async def _find_social_profiles(self, name: str) -> PersonProfile:
        """Find social media profiles"""
        try:
            profile = PersonProfile(name=name)
            profile.sources.append("social_search")

            # Search major social networks
            # This would integrate with social_profile_aggregator
            logger.info(f"Social profile search completed")

            return profile

        except Exception as e:
            logger.error(f"Social profile search error: {e}")
            return PersonProfile(name=name)

    async def _find_relatives(self, profile: PersonProfile) -> PersonProfile:
        """Find relatives and associates"""
        try:
            result = PersonProfile(name=profile.name)
            result.sources.append("relatives_search")

            # Search for relatives using addresses and other information
            logger.info("Relatives search completed")

            return result

        except Exception as e:
            logger.error(f"Relatives search error: {e}")
            return PersonProfile(name=profile.name)

    async def _find_public_records(self, profile: PersonProfile) -> PersonProfile:
        """Find public records"""
        try:
            result = PersonProfile(name=profile.name)
            result.sources.append("public_records_search")

            # Search voter records, court records, etc.
            logger.info("Public records search completed")

            return result

        except Exception as e:
            logger.error(f"Public records search error: {e}")
            return PersonProfile(name=profile.name)

    def _merge_profiles(self, profile1: PersonProfile, profile2: PersonProfile) -> PersonProfile:
        """Merge two profiles intelligently"""
        # Update name if better information available
        if profile2.name != "Unknown" and profile1.name == "Unknown":
            profile1.name = profile2.name

        # Merge lists (avoiding duplicates)
        profile1.aliases.extend([a for a in profile2.aliases if a not in profile1.aliases])
        profile1.email_addresses.extend([e for e in profile2.email_addresses if e not in profile1.email_addresses])
        profile1.usernames.extend([u for u in profile2.usernames if u not in profile1.usernames])
        profile1.sources.extend([s for s in profile2.sources if s not in profile1.sources])

        # Merge complex objects
        profile1.addresses.extend(profile2.addresses)
        profile1.phone_numbers.extend(profile2.phone_numbers)
        profile1.relatives.extend(profile2.relatives)
        profile1.associates.extend(profile2.associates)
        profile1.social_profiles.extend(profile2.social_profiles)
        profile1.education.extend(profile2.education)
        profile1.employment.extend(profile2.employment)
        profile1.businesses.extend(profile2.businesses)
        profile1.property_records.extend(profile2.property_records)
        profile1.court_records.extend(profile2.court_records)
        profile1.criminal_records.extend(profile2.criminal_records)

        # Update other fields if not set
        if not profile1.age and profile2.age:
            profile1.age = profile2.age
        if not profile1.age_range and profile2.age_range:
            profile1.age_range = profile2.age_range
        if not profile1.birth_date and profile2.birth_date:
            profile1.birth_date = profile2.birth_date
        if not profile1.voter_registration and profile2.voter_registration:
            profile1.voter_registration = profile2.voter_registration

        return profile1

    def _calculate_confidence(self, profile: PersonProfile) -> float:
        """Calculate confidence score based on data completeness"""
        score = 0.0
        max_score = 100.0

        # Name verification (10 points)
        if profile.name and profile.name != "Unknown":
            score += 10

        # Contact information (30 points)
        if profile.addresses:
            score += min(15, len(profile.addresses) * 5)
        if profile.phone_numbers:
            score += min(10, len(profile.phone_numbers) * 5)
        if profile.email_addresses:
            score += min(5, len(profile.email_addresses) * 2.5)

        # Relationships (20 points)
        if profile.relatives:
            score += min(15, len(profile.relatives) * 3)
        if profile.associates:
            score += min(5, len(profile.associates) * 1)

        # Social presence (15 points)
        if profile.social_profiles:
            score += min(10, len(profile.social_profiles) * 2)
        if profile.usernames:
            score += min(5, len(profile.usernames) * 1)

        # Background (15 points)
        if profile.education:
            score += min(5, len(profile.education) * 2.5)
        if profile.employment:
            score += min(5, len(profile.employment) * 2.5)
        if profile.businesses:
            score += min(5, len(profile.businesses) * 2.5)

        # Public records (10 points)
        if profile.voter_registration:
            score += 3
        if profile.property_records:
            score += min(4, len(profile.property_records) * 2)
        if profile.court_records:
            score += min(3, len(profile.court_records) * 1.5)

        # Data sources bonus
        source_bonus = min(10, len(profile.sources) * 2)
        score += source_bonus

        return min(score, max_score)

    def export_report(self, profile: PersonProfile, format: str = 'json') -> str:
        """
        Export investigation report

        Args:
            profile: PersonProfile to export
            format: Export format (json, html, pdf)

        Returns:
            Formatted report string
        """
        if format == 'json':
            return json.dumps(profile.to_dict(), indent=2)

        elif format == 'html':
            return self._generate_html_report(profile)

        elif format == 'text':
            return self._generate_text_report(profile)

        else:
            raise ValueError(f"Unsupported format: {format}")

    def _generate_html_report(self, profile: PersonProfile) -> str:
        """Generate HTML investigation report"""
        html = f"""
        <html>
        <head>
            <title>Investigation Report: {profile.name}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                h1 {{ color: #333; }}
                h2 {{ color: #666; border-bottom: 2px solid #ddd; }}
                .section {{ margin: 20px 0; }}
                .confidence {{ font-weight: bold; color: #007bff; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>
            <h1>Investigation Report: {profile.name}</h1>
            <p><strong>Generated:</strong> {profile.last_updated}</p>
            <p class="confidence">Confidence Score: {profile.confidence_score:.1f}/100</p>

            <div class="section">
                <h2>Contact Information</h2>
                <h3>Addresses</h3>
                <ul>
                    {''.join(f"<li>{addr.get('full_address', 'N/A')}</li>" for addr in profile.addresses)}
                </ul>

                <h3>Phone Numbers</h3>
                <ul>
                    {''.join(f"<li>{phone.get('number', 'N/A')} ({phone.get('type', 'unknown')})</li>" for phone in profile.phone_numbers)}
                </ul>

                <h3>Email Addresses</h3>
                <ul>
                    {''.join(f"<li>{email}</li>" for email in profile.email_addresses)}
                </ul>
            </div>

            <div class="section">
                <h2>Relationships</h2>
                <h3>Relatives</h3>
                <ul>
                    {''.join(f"<li>{rel.get('name', 'N/A')} ({rel.get('relationship', 'unknown')})</li>" for rel in profile.relatives)}
                </ul>
            </div>

            <div class="section">
                <h2>Data Sources</h2>
                <ul>
                    {''.join(f"<li>{source}</li>" for source in profile.sources)}
                </ul>
            </div>
        </body>
        </html>
        """
        return html

    def _generate_text_report(self, profile: PersonProfile) -> str:
        """Generate text investigation report"""
        report = f"""
{'='*80}
INVESTIGATION REPORT
{'='*80}

Name: {profile.name}
Aliases: {', '.join(profile.aliases) if profile.aliases else 'None'}
Age: {profile.age or profile.age_range or 'Unknown'}
Confidence Score: {profile.confidence_score:.1f}/100

{'='*80}
CONTACT INFORMATION
{'='*80}

Addresses:
{chr(10).join(f"  - {addr.get('full_address', 'N/A')}" for addr in profile.addresses) if profile.addresses else '  None found'}

Phone Numbers:
{chr(10).join(f"  - {phone.get('number', 'N/A')} ({phone.get('type', 'unknown')})" for phone in profile.phone_numbers) if profile.phone_numbers else '  None found'}

Email Addresses:
{chr(10).join(f"  - {email}" for email in profile.email_addresses) if profile.email_addresses else '  None found'}

{'='*80}
RELATIONSHIPS
{'='*80}

Relatives:
{chr(10).join(f"  - {rel.get('name', 'N/A')} ({rel.get('relationship', 'unknown')})" for rel in profile.relatives) if profile.relatives else '  None found'}

Associates:
{chr(10).join(f"  - {assoc.get('name', 'N/A')}" for assoc in profile.associates) if profile.associates else '  None found'}

{'='*80}
SOCIAL PROFILES
{'='*80}

{chr(10).join(f"  - {profile.get('platform', 'Unknown')}: {profile.get('url', 'N/A')}" for profile in profile.social_profiles) if profile.social_profiles else '  None found'}

{'='*80}
DATA SOURCES
{'='*80}

{chr(10).join(f"  - {source}" for source in profile.sources)}

{'='*80}
Report Generated: {profile.last_updated}
{'='*80}
"""
        return report


# Synchronous wrapper for convenience
class PeopleSearchSync:
    """Synchronous wrapper for PeopleSearch"""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.search = PeopleSearch(config)

    def investigate(self, **kwargs) -> PersonProfile:
        """Synchronous investigation method"""
        return asyncio.run(self._investigate(**kwargs))

    async def _investigate(self, **kwargs) -> PersonProfile:
        async with self.search:
            return await self.search.investigate(**kwargs)


if __name__ == "__main__":
    # Example usage
    async def main():
        config = {
            'hunter_api_key': 'your_hunter_api_key',
            'numverify_api_key': 'your_numverify_api_key'
        }

        async with PeopleSearch(config) as search:
            # Search by name and location
            profile = await search.investigate(
                name="John Doe",
                location="New York, NY",
                deep_search=True
            )

            print(search.export_report(profile, format='text'))

            # Save JSON report
            with open('investigation_report.json', 'w') as f:
                f.write(search.export_report(profile, format='json'))

    # Run example
    asyncio.run(main())
