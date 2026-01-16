"""
Pipl Integration - Deep Web People Search
Identity resolution and contact aggregation using Pipl API
"""

import asyncio
import aiohttp
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
import logging
import json
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class PiplPerson:
    """Pipl person data structure"""
    # Basic Information
    names: List[Dict[str, Any]] = field(default_factory=list)
    age: Optional[int] = None
    gender: Optional[str] = None
    dob: Optional[str] = None

    # Contact Information
    emails: List[Dict[str, Any]] = field(default_factory=list)
    phones: List[Dict[str, Any]] = field(default_factory=list)
    addresses: List[Dict[str, Any]] = field(default_factory=list)

    # Online Presence
    usernames: List[Dict[str, Any]] = field(default_factory=list)
    user_ids: List[Dict[str, Any]] = field(default_factory=list)
    urls: List[Dict[str, Any]] = field(default_factory=list)
    images: List[Dict[str, Any]] = field(default_factory=list)

    # Professional Information
    jobs: List[Dict[str, Any]] = field(default_factory=list)
    educations: List[Dict[str, Any]] = field(default_factory=list)

    # Relationships
    relationships: List[Dict[str, Any]] = field(default_factory=list)

    # Metadata
    match_score: float = 0.0
    sources: List[Dict[str, Any]] = field(default_factory=list)
    search_id: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


class PiplIntegration:
    """
    Pipl API integration for deep web people search

    Features:
    - Identity resolution across multiple data sources
    - Deep web people search
    - Contact information aggregation
    - Social media profile discovery
    - Professional background research
    """

    BASE_URL = "https://api.pipl.com/search/v5/"

    def __init__(self, api_key: str):
        """
        Initialize Pipl integration

        Args:
            api_key: Pipl API key
        """
        self.api_key = api_key
        self.session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self):
        """Async context manager entry"""
        self.session = aiohttp.ClientSession()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()

    async def search_by_name(
        self,
        first_name: Optional[str] = None,
        middle_name: Optional[str] = None,
        last_name: Optional[str] = None,
        raw_name: Optional[str] = None,
        country: Optional[str] = None,
        state: Optional[str] = None,
        city: Optional[str] = None,
        minimum_probability: float = 0.5
    ) -> Optional[PiplPerson]:
        """
        Search for person by name

        Args:
            first_name: First name
            middle_name: Middle name
            last_name: Last name
            raw_name: Full name as single string
            country: Country code (e.g., 'US')
            state: State code (e.g., 'NY')
            city: City name
            minimum_probability: Minimum match probability (0.0-1.0)

        Returns:
            PiplPerson with aggregated information
        """
        if not self.session:
            self.session = aiohttp.ClientSession()

        params = {
            'key': self.api_key,
            'minimum_probability': minimum_probability
        }

        # Name parameters
        if raw_name:
            params['raw_name'] = raw_name
        else:
            if first_name:
                params['first_name'] = first_name
            if middle_name:
                params['middle_name'] = middle_name
            if last_name:
                params['last_name'] = last_name

        # Location parameters
        if country:
            params['country'] = country
        if state:
            params['state'] = state
        if city:
            params['city'] = city

        try:
            logger.info(f"Pipl search by name: {raw_name or f'{first_name} {last_name}'}")

            async with self.session.get(self.BASE_URL, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    return self._parse_response(data)
                elif response.status == 401:
                    logger.error("Pipl API authentication failed")
                    return None
                elif response.status == 403:
                    logger.error("Pipl API quota exceeded")
                    return None
                elif response.status == 404:
                    logger.info("No results found")
                    return None
                else:
                    logger.error(f"Pipl API error: {response.status}")
                    return None

        except Exception as e:
            logger.error(f"Pipl search error: {e}")
            return None

    async def search_by_email(
        self,
        email: str,
        minimum_probability: float = 0.5
    ) -> Optional[PiplPerson]:
        """
        Search for person by email address

        Args:
            email: Email address
            minimum_probability: Minimum match probability

        Returns:
            PiplPerson with aggregated information
        """
        if not self.session:
            self.session = aiohttp.ClientSession()

        params = {
            'key': self.api_key,
            'email': email,
            'minimum_probability': minimum_probability
        }

        try:
            logger.info(f"Pipl search by email: {email}")

            async with self.session.get(self.BASE_URL, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    return self._parse_response(data)
                else:
                    logger.error(f"Pipl email search error: {response.status}")
                    return None

        except Exception as e:
            logger.error(f"Pipl email search error: {e}")
            return None

    async def search_by_phone(
        self,
        phone: str,
        country_code: Optional[str] = None,
        minimum_probability: float = 0.5
    ) -> Optional[PiplPerson]:
        """
        Search for person by phone number

        Args:
            phone: Phone number
            country_code: Country code (e.g., 'US')
            minimum_probability: Minimum match probability

        Returns:
            PiplPerson with aggregated information
        """
        if not self.session:
            self.session = aiohttp.ClientSession()

        params = {
            'key': self.api_key,
            'phone': phone,
            'minimum_probability': minimum_probability
        }

        if country_code:
            params['country'] = country_code

        try:
            logger.info(f"Pipl search by phone: {phone}")

            async with self.session.get(self.BASE_URL, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    return self._parse_response(data)
                else:
                    logger.error(f"Pipl phone search error: {response.status}")
                    return None

        except Exception as e:
            logger.error(f"Pipl phone search error: {e}")
            return None

    async def search_by_username(
        self,
        username: str,
        minimum_probability: float = 0.5
    ) -> Optional[PiplPerson]:
        """
        Search for person by username

        Args:
            username: Username/handle
            minimum_probability: Minimum match probability

        Returns:
            PiplPerson with aggregated information
        """
        if not self.session:
            self.session = aiohttp.ClientSession()

        params = {
            'key': self.api_key,
            'username': username,
            'minimum_probability': minimum_probability
        }

        try:
            logger.info(f"Pipl search by username: {username}")

            async with self.session.get(self.BASE_URL, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    return self._parse_response(data)
                else:
                    logger.error(f"Pipl username search error: {response.status}")
                    return None

        except Exception as e:
            logger.error(f"Pipl username search error: {e}")
            return None

    async def search_by_user_id(
        self,
        user_id: str,
        platform: str,
        minimum_probability: float = 0.5
    ) -> Optional[PiplPerson]:
        """
        Search for person by social media user ID

        Args:
            user_id: User ID on platform
            platform: Platform name (e.g., 'facebook', 'linkedin')
            minimum_probability: Minimum match probability

        Returns:
            PiplPerson with aggregated information
        """
        if not self.session:
            self.session = aiohttp.ClientSession()

        params = {
            'key': self.api_key,
            'user_id': f"{user_id}@{platform}",
            'minimum_probability': minimum_probability
        }

        try:
            logger.info(f"Pipl search by user ID: {user_id} on {platform}")

            async with self.session.get(self.BASE_URL, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    return self._parse_response(data)
                else:
                    logger.error(f"Pipl user ID search error: {response.status}")
                    return None

        except Exception as e:
            logger.error(f"Pipl user ID search error: {e}")
            return None

    async def search_by_url(
        self,
        url: str,
        minimum_probability: float = 0.5
    ) -> Optional[PiplPerson]:
        """
        Search for person by profile URL

        Args:
            url: Profile URL
            minimum_probability: Minimum match probability

        Returns:
            PiplPerson with aggregated information
        """
        if not self.session:
            self.session = aiohttp.ClientSession()

        params = {
            'key': self.api_key,
            'url': url,
            'minimum_probability': minimum_probability
        }

        try:
            logger.info(f"Pipl search by URL: {url}")

            async with self.session.get(self.BASE_URL, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    return self._parse_response(data)
                else:
                    logger.error(f"Pipl URL search error: {response.status}")
                    return None

        except Exception as e:
            logger.error(f"Pipl URL search error: {e}")
            return None

    async def comprehensive_search(
        self,
        name: Optional[str] = None,
        email: Optional[str] = None,
        phone: Optional[str] = None,
        username: Optional[str] = None,
        location: Optional[Dict[str, str]] = None,
        minimum_probability: float = 0.5
    ) -> Optional[PiplPerson]:
        """
        Comprehensive search using all available information

        Args:
            name: Full name
            email: Email address
            phone: Phone number
            username: Username
            location: Location dict with 'city', 'state', 'country'
            minimum_probability: Minimum match probability

        Returns:
            PiplPerson with aggregated information
        """
        if not self.session:
            self.session = aiohttp.ClientSession()

        params = {
            'key': self.api_key,
            'minimum_probability': minimum_probability
        }

        if name:
            params['raw_name'] = name
        if email:
            params['email'] = email
        if phone:
            params['phone'] = phone
        if username:
            params['username'] = username

        if location:
            if 'city' in location:
                params['city'] = location['city']
            if 'state' in location:
                params['state'] = location['state']
            if 'country' in location:
                params['country'] = location['country']

        try:
            logger.info(f"Pipl comprehensive search")

            async with self.session.get(self.BASE_URL, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    return self._parse_response(data)
                else:
                    logger.error(f"Pipl comprehensive search error: {response.status}")
                    return None

        except Exception as e:
            logger.error(f"Pipl comprehensive search error: {e}")
            return None

    def _parse_response(self, data: Dict[str, Any]) -> Optional[PiplPerson]:
        """Parse Pipl API response"""
        try:
            person_data = data.get('person', {})

            if not person_data:
                logger.info("No person data in response")
                return None

            person = PiplPerson(
                match_score=data.get('match_score', 0.0),
                search_id=data.get('@search_id')
            )

            # Parse names
            person.names = person_data.get('names', [])

            # Parse age and gender
            if 'dob' in person_data:
                dob_data = person_data['dob']
                person.dob = dob_data.get('display')
                if 'date_range' in dob_data:
                    # Calculate age from date range
                    pass

            if 'gender' in person_data:
                person.gender = person_data['gender'].get('content')

            # Parse contact information
            person.emails = person_data.get('emails', [])
            person.phones = person_data.get('phones', [])
            person.addresses = person_data.get('addresses', [])

            # Parse online presence
            person.usernames = person_data.get('usernames', [])
            person.user_ids = person_data.get('user_ids', [])
            person.urls = person_data.get('urls', [])
            person.images = person_data.get('images', [])

            # Parse professional information
            person.jobs = person_data.get('jobs', [])
            person.educations = person_data.get('educations', [])

            # Parse relationships
            person.relationships = person_data.get('relationships', [])

            # Parse sources
            person.sources = data.get('sources', [])

            logger.info(f"Parsed Pipl person with match score: {person.match_score:.2f}")
            return person

        except Exception as e:
            logger.error(f"Error parsing Pipl response: {e}")
            return None

    def export_person(self, person: PiplPerson, format: str = 'json') -> str:
        """
        Export person data in specified format

        Args:
            person: PiplPerson to export
            format: Export format (json, text)

        Returns:
            Formatted person data
        """
        if format == 'json':
            return json.dumps({
                'names': person.names,
                'age': person.age,
                'gender': person.gender,
                'dob': person.dob,
                'emails': person.emails,
                'phones': person.phones,
                'addresses': person.addresses,
                'usernames': person.usernames,
                'user_ids': person.user_ids,
                'urls': person.urls,
                'images': person.images,
                'jobs': person.jobs,
                'educations': person.educations,
                'relationships': person.relationships,
                'match_score': person.match_score,
                'sources': person.sources,
                'search_id': person.search_id,
                'timestamp': person.timestamp
            }, indent=2)

        elif format == 'text':
            # Get primary name
            primary_name = "Unknown"
            if person.names:
                name_obj = person.names[0]
                primary_name = name_obj.get('display', 'Unknown')

            return f"""
PIPL DEEP WEB PERSON REPORT
{'='*80}

Name: {primary_name}
Age: {person.age or 'Unknown'}
Gender: {person.gender or 'Unknown'}
Date of Birth: {person.dob or 'Unknown'}
Match Score: {person.match_score:.2f}

CONTACT INFORMATION
{'='*80}

Email Addresses:
{chr(10).join(f"  - {email.get('address', 'N/A')} ({email.get('@type', 'unknown')})" for email in person.emails) if person.emails else '  None'}

Phone Numbers:
{chr(10).join(f"  - {phone.get('display', 'N/A')} ({phone.get('@type', 'unknown')})" for phone in person.phones) if person.phones else '  None'}

Addresses:
{chr(10).join(f"  - {addr.get('display', 'N/A')}" for addr in person.addresses) if person.addresses else '  None'}

ONLINE PRESENCE
{'='*80}

Usernames:
{chr(10).join(f"  - {username.get('content', 'N/A')}" for username in person.usernames) if person.usernames else '  None'}

Profile URLs:
{chr(10).join(f"  - {url.get('url', 'N/A')}" for url in person.urls) if person.urls else '  None'}

PROFESSIONAL BACKGROUND
{'='*80}

Jobs:
{chr(10).join(f"  - {job.get('title', 'N/A')} at {job.get('organization', 'N/A')}" for job in person.jobs) if person.jobs else '  None'}

Education:
{chr(10).join(f"  - {edu.get('degree', 'N/A')} from {edu.get('school', 'N/A')}" for edu in person.educations) if person.educations else '  None'}

RELATIONSHIPS
{'='*80}

{chr(10).join(f"  - {rel.get('type', 'Unknown')}: {rel.get('names', [{}])[0].get('display', 'N/A')}" for rel in person.relationships) if person.relationships else '  None'}

DATA SOURCES
{'='*80}

Total Sources: {len(person.sources)}
{chr(10).join(f"  - {source.get('@name', 'Unknown')} (Category: {source.get('@category', 'Unknown')})" for source in person.sources[:10]) if person.sources else '  None'}

{'='*80}
Search ID: {person.search_id}
Timestamp: {person.timestamp}
{'='*80}
"""

        return ""

    def get_best_name(self, person: PiplPerson) -> str:
        """Get the best available name for a person"""
        if not person.names:
            return "Unknown"

        # Prefer names marked as 'display'
        for name in person.names:
            if name.get('@valid_since') or name.get('@current'):
                return name.get('display', 'Unknown')

        # Return first name
        return person.names[0].get('display', 'Unknown')

    def get_primary_email(self, person: PiplPerson) -> Optional[str]:
        """Get primary email address"""
        if not person.emails:
            return None

        # Prefer current/personal emails
        for email in person.emails:
            if email.get('@type') == 'personal' or email.get('@current'):
                return email.get('address')

        # Return first email
        return person.emails[0].get('address')

    def get_primary_phone(self, person: PiplPerson) -> Optional[str]:
        """Get primary phone number"""
        if not person.phones:
            return None

        # Prefer mobile/current phones
        for phone in person.phones:
            if phone.get('@type') == 'mobile' or phone.get('@current'):
                return phone.get('display')

        # Return first phone
        return person.phones[0].get('display')


if __name__ == "__main__":
    # Example usage
    async def main():
        api_key = "your_pipl_api_key"

        async with PiplIntegration(api_key) as pipl:
            # Search by email
            person = await pipl.search_by_email("john.doe@example.com")

            if person:
                print(pipl.export_person(person, format='text'))

                # Save JSON report
                with open('pipl_report.json', 'w') as f:
                    f.write(pipl.export_person(person, format='json'))

            # Comprehensive search
            person2 = await pipl.comprehensive_search(
                name="John Doe",
                email="john@example.com",
                phone="+1-555-123-4567",
                location={'city': 'New York', 'state': 'NY', 'country': 'US'}
            )

            if person2:
                print(f"Match Score: {person2.match_score:.2f}")
                print(f"Primary Email: {pipl.get_primary_email(person2)}")
                print(f"Primary Phone: {pipl.get_primary_phone(person2)}")

    asyncio.run(main())
