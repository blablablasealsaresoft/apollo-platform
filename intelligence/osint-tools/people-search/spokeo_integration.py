"""
Spokeo Integration - People Search via Spokeo API
Comprehensive people search, background reports, and contact information
"""

import asyncio
import aiohttp
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
import logging
from urllib.parse import quote_plus
import json

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class SpokeoProfile:
    """Spokeo search result profile"""
    name: str
    age: Optional[int] = None
    addresses: List[Dict[str, Any]] = None
    phones: List[str] = None
    emails: List[str] = None
    relatives: List[str] = None
    social_profiles: List[Dict[str, Any]] = None
    jobs: List[Dict[str, Any]] = None
    education: List[Dict[str, Any]] = None
    photos: List[str] = None
    wealth_level: Optional[str] = None
    home_value: Optional[float] = None
    confidence_score: float = 0.0

    def __post_init__(self):
        self.addresses = self.addresses or []
        self.phones = self.phones or []
        self.emails = self.emails or []
        self.relatives = self.relatives or []
        self.social_profiles = self.social_profiles or []
        self.jobs = self.jobs or []
        self.education = self.education or []
        self.photos = self.photos or []


class SpokeoIntegration:
    """
    Spokeo API integration for people search

    Features:
    - Name search with location filtering
    - Reverse phone lookup
    - Email search
    - Address search
    - Background reports
    - Social media profiles
    """

    BASE_URL = "https://api.spokeo.com"

    def __init__(self, api_key: str):
        """
        Initialize Spokeo integration

        Args:
            api_key: Spokeo API key
        """
        self.api_key = api_key
        self.session: Optional[aiohttp.ClientSession] = None
        self._rate_limit_delay = 1.0  # Seconds between requests

    async def __aenter__(self):
        """Async context manager entry"""
        self.session = aiohttp.ClientSession()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()

    async def search_person(
        self,
        first_name: Optional[str] = None,
        last_name: Optional[str] = None,
        city: Optional[str] = None,
        state: Optional[str] = None,
        age_min: Optional[int] = None,
        age_max: Optional[int] = None
    ) -> List[SpokeoProfile]:
        """
        Search for person by name and location

        Args:
            first_name: First name
            last_name: Last name
            city: City name
            state: State code (e.g., 'NY')
            age_min: Minimum age
            age_max: Maximum age

        Returns:
            List of matching profiles
        """
        if not self.session:
            self.session = aiohttp.ClientSession()

        endpoint = f"{self.BASE_URL}/v1/person"

        params = {
            'api_key': self.api_key
        }

        if first_name:
            params['first_name'] = first_name
        if last_name:
            params['last_name'] = last_name
        if city:
            params['city'] = city
        if state:
            params['state'] = state
        if age_min:
            params['age_min'] = age_min
        if age_max:
            params['age_max'] = age_max

        try:
            logger.info(f"Searching Spokeo for: {first_name} {last_name}")

            async with self.session.get(endpoint, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    return self._parse_search_results(data)
                elif response.status == 401:
                    logger.error("Spokeo API authentication failed")
                    return []
                elif response.status == 429:
                    logger.warning("Spokeo rate limit exceeded")
                    await asyncio.sleep(self._rate_limit_delay * 2)
                    return []
                else:
                    logger.error(f"Spokeo API error: {response.status}")
                    return []

        except Exception as e:
            logger.error(f"Spokeo search error: {e}")
            return []

    async def reverse_phone_lookup(self, phone: str) -> Optional[SpokeoProfile]:
        """
        Reverse phone number lookup

        Args:
            phone: Phone number (digits only)

        Returns:
            SpokeoProfile if found
        """
        if not self.session:
            self.session = aiohttp.ClientSession()

        endpoint = f"{self.BASE_URL}/v1/phone"

        params = {
            'api_key': self.api_key,
            'phone': phone
        }

        try:
            logger.info(f"Spokeo reverse phone lookup: {phone}")

            async with self.session.get(endpoint, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    return self._parse_phone_result(data)
                else:
                    logger.error(f"Spokeo phone lookup error: {response.status}")
                    return None

        except Exception as e:
            logger.error(f"Spokeo phone lookup error: {e}")
            return None

    async def email_search(self, email: str) -> Optional[SpokeoProfile]:
        """
        Search by email address

        Args:
            email: Email address

        Returns:
            SpokeoProfile if found
        """
        if not self.session:
            self.session = aiohttp.ClientSession()

        endpoint = f"{self.BASE_URL}/v1/email"

        params = {
            'api_key': self.api_key,
            'email': email
        }

        try:
            logger.info(f"Spokeo email search: {email}")

            async with self.session.get(endpoint, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    return self._parse_email_result(data)
                else:
                    logger.error(f"Spokeo email search error: {response.status}")
                    return None

        except Exception as e:
            logger.error(f"Spokeo email search error: {e}")
            return None

    async def address_search(self, address: str, city: str, state: str) -> Optional[SpokeoProfile]:
        """
        Search by address

        Args:
            address: Street address
            city: City name
            state: State code

        Returns:
            SpokeoProfile if found
        """
        if not self.session:
            self.session = aiohttp.ClientSession()

        endpoint = f"{self.BASE_URL}/v1/address"

        params = {
            'api_key': self.api_key,
            'street_address': address,
            'city': city,
            'state': state
        }

        try:
            logger.info(f"Spokeo address search: {address}, {city}, {state}")

            async with self.session.get(endpoint, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    return self._parse_address_result(data)
                else:
                    logger.error(f"Spokeo address search error: {response.status}")
                    return None

        except Exception as e:
            logger.error(f"Spokeo address search error: {e}")
            return None

    async def get_full_report(self, spokeo_id: str) -> Optional[SpokeoProfile]:
        """
        Get full background report for a person

        Args:
            spokeo_id: Spokeo person ID from search results

        Returns:
            Complete SpokeoProfile with all available data
        """
        if not self.session:
            self.session = aiohttp.ClientSession()

        endpoint = f"{self.BASE_URL}/v1/person/{spokeo_id}"

        params = {
            'api_key': self.api_key
        }

        try:
            logger.info(f"Fetching full Spokeo report: {spokeo_id}")

            async with self.session.get(endpoint, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    return self._parse_full_report(data)
                else:
                    logger.error(f"Spokeo full report error: {response.status}")
                    return None

        except Exception as e:
            logger.error(f"Spokeo full report error: {e}")
            return None

    async def batch_search(
        self,
        searches: List[Dict[str, Any]]
    ) -> List[Optional[SpokeoProfile]]:
        """
        Perform multiple searches in parallel

        Args:
            searches: List of search parameters

        Returns:
            List of results
        """
        tasks = []

        for search in searches:
            search_type = search.get('type', 'name')

            if search_type == 'name':
                task = self.search_person(
                    first_name=search.get('first_name'),
                    last_name=search.get('last_name'),
                    city=search.get('city'),
                    state=search.get('state')
                )
            elif search_type == 'phone':
                task = self.reverse_phone_lookup(search.get('phone'))
            elif search_type == 'email':
                task = self.email_search(search.get('email'))
            elif search_type == 'address':
                task = self.address_search(
                    search.get('address'),
                    search.get('city'),
                    search.get('state')
                )
            else:
                continue

            tasks.append(task)

            # Rate limiting
            await asyncio.sleep(self._rate_limit_delay)

        results = await asyncio.gather(*tasks, return_exceptions=True)

        return [r if not isinstance(r, Exception) else None for r in results]

    def _parse_search_results(self, data: Dict[str, Any]) -> List[SpokeoProfile]:
        """Parse search results from Spokeo API"""
        profiles = []

        results = data.get('results', [])

        for result in results:
            profile = SpokeoProfile(
                name=result.get('full_name', 'Unknown'),
                age=result.get('age'),
                addresses=[{
                    'street': result.get('address_street'),
                    'city': result.get('address_city'),
                    'state': result.get('address_state'),
                    'zip': result.get('address_zip')
                }] if result.get('address_street') else [],
                phones=result.get('phone_numbers', []),
                emails=result.get('email_addresses', []),
                relatives=result.get('relatives', []),
                confidence_score=result.get('confidence', 0.0)
            )

            profiles.append(profile)

        logger.info(f"Found {len(profiles)} matching profiles")
        return profiles

    def _parse_phone_result(self, data: Dict[str, Any]) -> Optional[SpokeoProfile]:
        """Parse phone lookup result"""
        if not data.get('success'):
            return None

        result = data.get('data', {})

        profile = SpokeoProfile(
            name=result.get('full_name', 'Unknown'),
            age=result.get('age'),
            addresses=[{
                'street': addr.get('street'),
                'city': addr.get('city'),
                'state': addr.get('state'),
                'zip': addr.get('zip')
            } for addr in result.get('addresses', [])],
            phones=[result.get('phone')],
            emails=result.get('email_addresses', []),
            relatives=result.get('relatives', []),
            social_profiles=result.get('social_profiles', [])
        )

        return profile

    def _parse_email_result(self, data: Dict[str, Any]) -> Optional[SpokeoProfile]:
        """Parse email search result"""
        if not data.get('success'):
            return None

        result = data.get('data', {})

        profile = SpokeoProfile(
            name=result.get('full_name', 'Unknown'),
            age=result.get('age'),
            addresses=[{
                'street': addr.get('street'),
                'city': addr.get('city'),
                'state': addr.get('state'),
                'zip': addr.get('zip')
            } for addr in result.get('addresses', [])],
            phones=result.get('phone_numbers', []),
            emails=[result.get('email')],
            relatives=result.get('relatives', []),
            social_profiles=result.get('social_profiles', []),
            jobs=result.get('jobs', [])
        )

        return profile

    def _parse_address_result(self, data: Dict[str, Any]) -> Optional[SpokeoProfile]:
        """Parse address search result"""
        if not data.get('success'):
            return None

        result = data.get('data', {})

        profile = SpokeoProfile(
            name=result.get('full_name', 'Unknown'),
            age=result.get('age'),
            addresses=[{
                'street': result.get('street_address'),
                'city': result.get('city'),
                'state': result.get('state'),
                'zip': result.get('zip')
            }],
            phones=result.get('phone_numbers', []),
            emails=result.get('email_addresses', []),
            relatives=result.get('relatives', []),
            home_value=result.get('home_value')
        )

        return profile

    def _parse_full_report(self, data: Dict[str, Any]) -> Optional[SpokeoProfile]:
        """Parse full background report"""
        if not data.get('success'):
            return None

        result = data.get('data', {})

        profile = SpokeoProfile(
            name=result.get('full_name', 'Unknown'),
            age=result.get('age'),
            addresses=[{
                'street': addr.get('street'),
                'city': addr.get('city'),
                'state': addr.get('state'),
                'zip': addr.get('zip'),
                'type': addr.get('type')
            } for addr in result.get('addresses', [])],
            phones=result.get('phone_numbers', []),
            emails=result.get('email_addresses', []),
            relatives=result.get('relatives', []),
            social_profiles=result.get('social_profiles', []),
            jobs=result.get('jobs', []),
            education=result.get('education', []),
            photos=result.get('photos', []),
            wealth_level=result.get('wealth_level'),
            home_value=result.get('home_value'),
            confidence_score=result.get('confidence', 0.0)
        )

        return profile

    def export_profile(self, profile: SpokeoProfile, format: str = 'json') -> str:
        """
        Export profile in specified format

        Args:
            profile: SpokeoProfile to export
            format: Export format (json, text)

        Returns:
            Formatted profile data
        """
        if format == 'json':
            return json.dumps({
                'name': profile.name,
                'age': profile.age,
                'addresses': profile.addresses,
                'phones': profile.phones,
                'emails': profile.emails,
                'relatives': profile.relatives,
                'social_profiles': profile.social_profiles,
                'jobs': profile.jobs,
                'education': profile.education,
                'wealth_level': profile.wealth_level,
                'home_value': profile.home_value,
                'confidence_score': profile.confidence_score
            }, indent=2)

        elif format == 'text':
            return f"""
SPOKEO PROFILE REPORT
{'='*80}

Name: {profile.name}
Age: {profile.age or 'Unknown'}
Confidence Score: {profile.confidence_score:.2f}

CONTACT INFORMATION
{'='*80}

Addresses:
{chr(10).join(f"  - {addr.get('street')}, {addr.get('city')}, {addr.get('state')} {addr.get('zip')}" for addr in profile.addresses) if profile.addresses else '  None'}

Phone Numbers:
{chr(10).join(f"  - {phone}" for phone in profile.phones) if profile.phones else '  None'}

Email Addresses:
{chr(10).join(f"  - {email}" for email in profile.emails) if profile.emails else '  None'}

RELATIONSHIPS
{'='*80}

Relatives:
{chr(10).join(f"  - {rel}" for rel in profile.relatives) if profile.relatives else '  None'}

SOCIAL PROFILES
{'='*80}

{chr(10).join(f"  - {sp.get('platform')}: {sp.get('url')}" for sp in profile.social_profiles) if profile.social_profiles else '  None'}

BACKGROUND
{'='*80}

Jobs:
{chr(10).join(f"  - {job.get('title')} at {job.get('company')}" for job in profile.jobs) if profile.jobs else '  None'}

Education:
{chr(10).join(f"  - {edu.get('school')} ({edu.get('degree')})" for edu in profile.education) if profile.education else '  None'}

Wealth Level: {profile.wealth_level or 'Unknown'}
Home Value: ${profile.home_value:,.2f} if profile.home_value else 'Unknown'
{'='*80}
"""

        return ""


if __name__ == "__main__":
    # Example usage
    async def main():
        api_key = "your_spokeo_api_key"

        async with SpokeoIntegration(api_key) as spokeo:
            # Search by name
            profiles = await spokeo.search_person(
                first_name="John",
                last_name="Doe",
                city="New York",
                state="NY"
            )

            for profile in profiles:
                print(spokeo.export_profile(profile, format='text'))

            # Reverse phone lookup
            phone_result = await spokeo.reverse_phone_lookup("5551234567")
            if phone_result:
                print(spokeo.export_profile(phone_result, format='text'))

            # Email search
            email_result = await spokeo.email_search("john.doe@example.com")
            if email_result:
                print(spokeo.export_profile(email_result, format='json'))

    asyncio.run(main())
