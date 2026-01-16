"""
TruePeopleSearch - Free People Search Scraper
Name lookup, address history, phone numbers, and relatives
"""

import asyncio
import aiohttp
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from bs4 import BeautifulSoup
import re
import logging
from urllib.parse import quote_plus, urljoin
import json

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class TruePeopleProfile:
    """TruePeopleSearch profile data"""
    name: str
    age: Optional[int] = None
    age_range: Optional[str] = None

    # Current information
    current_address: Optional[Dict[str, Any]] = None
    current_phone: Optional[str] = None

    # Historical data
    previous_addresses: List[Dict[str, Any]] = field(default_factory=list)
    phone_numbers: List[str] = field(default_factory=list)

    # Relationships
    relatives: List[str] = field(default_factory=list)
    associates: List[str] = field(default_factory=list)

    # Additional info
    email_addresses: List[str] = field(default_factory=list)
    possible_emails: List[str] = field(default_factory=list)

    # Metadata
    profile_url: Optional[str] = None
    last_updated: Optional[str] = None


class TruePeopleSearch:
    """
    TruePeopleSearch scraper for free people search

    Features:
    - Name search with location filtering
    - Address history
    - Phone number lookup
    - Relatives and associates discovery
    - No API key required (web scraping)

    Note: This is a scraper. Always respect robots.txt and rate limits.
    """

    BASE_URL = "https://www.truepeoplesearch.com"

    def __init__(self, rate_limit: float = 2.0):
        """
        Initialize TruePeopleSearch scraper

        Args:
            rate_limit: Delay between requests in seconds
        """
        self.session: Optional[aiohttp.ClientSession] = None
        self.rate_limit = rate_limit
        self._last_request_time = 0

    async def __aenter__(self):
        """Async context manager entry"""
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        self.session = aiohttp.ClientSession(headers=headers)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()

    async def _rate_limit_wait(self):
        """Enforce rate limiting"""
        import time
        current_time = time.time()
        time_since_last = current_time - self._last_request_time

        if time_since_last < self.rate_limit:
            await asyncio.sleep(self.rate_limit - time_since_last)

        self._last_request_time = time.time()

    async def search_by_name(
        self,
        first_name: str,
        last_name: str,
        city: Optional[str] = None,
        state: Optional[str] = None
    ) -> List[TruePeopleProfile]:
        """
        Search for person by name

        Args:
            first_name: First name
            last_name: Last name
            city: City name (optional)
            state: State code (optional)

        Returns:
            List of matching profiles
        """
        if not self.session:
            await self.__aenter__()

        # Build search URL
        search_query = f"{first_name} {last_name}"
        if city and state:
            search_query += f" {city} {state}"

        url = f"{self.BASE_URL}/results?name={quote_plus(search_query)}"

        try:
            logger.info(f"Searching TruePeopleSearch for: {search_query}")

            await self._rate_limit_wait()

            async with self.session.get(url) as response:
                if response.status == 200:
                    html = await response.text()
                    return await self._parse_search_results(html)
                else:
                    logger.error(f"TruePeopleSearch error: {response.status}")
                    return []

        except Exception as e:
            logger.error(f"TruePeopleSearch search error: {e}")
            return []

    async def search_by_phone(self, phone: str) -> Optional[TruePeopleProfile]:
        """
        Reverse phone lookup

        Args:
            phone: Phone number

        Returns:
            TruePeopleProfile if found
        """
        if not self.session:
            await self.__aenter__()

        # Clean phone number
        clean_phone = re.sub(r'\D', '', phone)

        url = f"{self.BASE_URL}/results?phoneno={clean_phone}"

        try:
            logger.info(f"TruePeopleSearch phone lookup: {phone}")

            await self._rate_limit_wait()

            async with self.session.get(url) as response:
                if response.status == 200:
                    html = await response.text()
                    results = await self._parse_search_results(html)
                    return results[0] if results else None
                else:
                    logger.error(f"TruePeopleSearch phone lookup error: {response.status}")
                    return None

        except Exception as e:
            logger.error(f"TruePeopleSearch phone lookup error: {e}")
            return None

    async def search_by_address(
        self,
        street: str,
        city: str,
        state: str
    ) -> List[TruePeopleProfile]:
        """
        Search by address

        Args:
            street: Street address
            city: City name
            state: State code

        Returns:
            List of profiles at address
        """
        if not self.session:
            await self.__aenter__()

        search_query = f"{street} {city} {state}"
        url = f"{self.BASE_URL}/results?streetaddress={quote_plus(search_query)}"

        try:
            logger.info(f"TruePeopleSearch address lookup: {search_query}")

            await self._rate_limit_wait()

            async with self.session.get(url) as response:
                if response.status == 200:
                    html = await response.text()
                    return await self._parse_search_results(html)
                else:
                    logger.error(f"TruePeopleSearch address lookup error: {response.status}")
                    return []

        except Exception as e:
            logger.error(f"TruePeopleSearch address lookup error: {e}")
            return []

    async def get_full_profile(self, profile_url: str) -> Optional[TruePeopleProfile]:
        """
        Get full profile details

        Args:
            profile_url: Profile URL from search results

        Returns:
            Complete TruePeopleProfile
        """
        if not self.session:
            await self.__aenter__()

        try:
            logger.info(f"Fetching full profile: {profile_url}")

            await self._rate_limit_wait()

            async with self.session.get(profile_url) as response:
                if response.status == 200:
                    html = await response.text()
                    return await self._parse_full_profile(html, profile_url)
                else:
                    logger.error(f"Profile fetch error: {response.status}")
                    return None

        except Exception as e:
            logger.error(f"Profile fetch error: {e}")
            return None

    async def _parse_search_results(self, html: str) -> List[TruePeopleProfile]:
        """Parse search results page"""
        profiles = []

        try:
            soup = BeautifulSoup(html, 'html.parser')

            # Find all result cards
            result_cards = soup.find_all('div', class_='card')

            for card in result_cards:
                try:
                    profile = TruePeopleProfile(name="Unknown")

                    # Extract name
                    name_elem = card.find('a', class_='link-to-detail')
                    if name_elem:
                        profile.name = name_elem.text.strip()
                        profile.profile_url = urljoin(self.BASE_URL, name_elem.get('href', ''))

                    # Extract age
                    age_elem = card.find('span', class_='content-value', string=re.compile(r'Age \d+'))
                    if age_elem:
                        age_match = re.search(r'Age (\d+)', age_elem.text)
                        if age_match:
                            profile.age = int(age_match.group(1))

                    # Extract current address
                    address_elem = card.find('span', class_='content-value', attrs={'data-link-to-more': 'address'})
                    if address_elem:
                        address_text = address_elem.text.strip()
                        profile.current_address = {
                            'full_address': address_text,
                            'type': 'current'
                        }

                    # Extract phone
                    phone_elem = card.find('span', class_='content-value', attrs={'data-link-to-more': 'phone'})
                    if phone_elem:
                        profile.current_phone = phone_elem.text.strip()

                    profiles.append(profile)

                except Exception as e:
                    logger.error(f"Error parsing result card: {e}")
                    continue

            logger.info(f"Parsed {len(profiles)} profiles from search results")

        except Exception as e:
            logger.error(f"Error parsing search results: {e}")

        return profiles

    async def _parse_full_profile(self, html: str, url: str) -> Optional[TruePeopleProfile]:
        """Parse full profile page"""
        try:
            soup = BeautifulSoup(html, 'html.parser')

            profile = TruePeopleProfile(name="Unknown", profile_url=url)

            # Extract name
            name_elem = soup.find('h1')
            if name_elem:
                profile.name = name_elem.text.strip()

            # Extract age
            age_section = soup.find('div', class_='age')
            if age_section:
                age_text = age_section.text
                age_match = re.search(r'(\d+)', age_text)
                if age_match:
                    profile.age = int(age_match.group(1))
                else:
                    # Try to get age range
                    range_match = re.search(r'(\d+-\d+)', age_text)
                    if range_match:
                        profile.age_range = range_match.group(1)

            # Extract addresses
            address_section = soup.find('div', id='address')
            if address_section:
                addresses = address_section.find_all('div', class_='content-value')
                for idx, addr in enumerate(addresses):
                    address_data = {
                        'full_address': addr.text.strip(),
                        'type': 'current' if idx == 0 else 'previous'
                    }

                    if idx == 0:
                        profile.current_address = address_data
                    else:
                        profile.previous_addresses.append(address_data)

            # Extract phone numbers
            phone_section = soup.find('div', id='phone')
            if phone_section:
                phones = phone_section.find_all('div', class_='content-value')
                for phone in phones:
                    phone_text = phone.text.strip()
                    profile.phone_numbers.append(phone_text)
                    if not profile.current_phone and phone_text:
                        profile.current_phone = phone_text

            # Extract email addresses
            email_section = soup.find('div', id='email')
            if email_section:
                emails = email_section.find_all('div', class_='content-value')
                for email in emails:
                    email_text = email.text.strip()
                    if '@' in email_text:
                        profile.email_addresses.append(email_text)

            # Extract relatives
            relatives_section = soup.find('div', id='relatives')
            if relatives_section:
                relative_links = relatives_section.find_all('a')
                for rel in relative_links:
                    profile.relatives.append(rel.text.strip())

            # Extract associates
            associates_section = soup.find('div', id='associates')
            if associates_section:
                associate_links = associates_section.find_all('a')
                for assoc in associate_links:
                    profile.associates.append(assoc.text.strip())

            logger.info(f"Parsed full profile for: {profile.name}")
            return profile

        except Exception as e:
            logger.error(f"Error parsing full profile: {e}")
            return None

    async def batch_search(
        self,
        searches: List[Dict[str, Any]]
    ) -> List[List[TruePeopleProfile]]:
        """
        Perform multiple searches sequentially with rate limiting

        Args:
            searches: List of search parameters

        Returns:
            List of search results
        """
        results = []

        for search in searches:
            search_type = search.get('type', 'name')

            if search_type == 'name':
                result = await self.search_by_name(
                    first_name=search.get('first_name', ''),
                    last_name=search.get('last_name', ''),
                    city=search.get('city'),
                    state=search.get('state')
                )
            elif search_type == 'phone':
                result = await self.search_by_phone(search.get('phone', ''))
                result = [result] if result else []
            elif search_type == 'address':
                result = await self.search_by_address(
                    street=search.get('street', ''),
                    city=search.get('city', ''),
                    state=search.get('state', '')
                )
            else:
                result = []

            results.append(result)

        return results

    def export_profile(self, profile: TruePeopleProfile, format: str = 'json') -> str:
        """
        Export profile in specified format

        Args:
            profile: TruePeopleProfile to export
            format: Export format (json, text)

        Returns:
            Formatted profile data
        """
        if format == 'json':
            return json.dumps({
                'name': profile.name,
                'age': profile.age,
                'age_range': profile.age_range,
                'current_address': profile.current_address,
                'current_phone': profile.current_phone,
                'previous_addresses': profile.previous_addresses,
                'phone_numbers': profile.phone_numbers,
                'relatives': profile.relatives,
                'associates': profile.associates,
                'email_addresses': profile.email_addresses,
                'profile_url': profile.profile_url
            }, indent=2)

        elif format == 'text':
            return f"""
TRUEPEOPLESEARCH PROFILE
{'='*80}

Name: {profile.name}
Age: {profile.age or profile.age_range or 'Unknown'}

CURRENT INFORMATION
{'='*80}

Current Address:
  {profile.current_address.get('full_address') if profile.current_address else 'None'}

Current Phone:
  {profile.current_phone or 'None'}

CONTACT HISTORY
{'='*80}

Previous Addresses:
{chr(10).join(f"  - {addr.get('full_address')}" for addr in profile.previous_addresses) if profile.previous_addresses else '  None'}

Phone Numbers:
{chr(10).join(f"  - {phone}" for phone in profile.phone_numbers) if profile.phone_numbers else '  None'}

Email Addresses:
{chr(10).join(f"  - {email}" for email in profile.email_addresses) if profile.email_addresses else '  None'}

RELATIONSHIPS
{'='*80}

Relatives:
{chr(10).join(f"  - {rel}" for rel in profile.relatives) if profile.relatives else '  None'}

Associates:
{chr(10).join(f"  - {assoc}" for assoc in profile.associates) if profile.associates else '  None'}

{'='*80}
Profile URL: {profile.profile_url or 'N/A'}
{'='*80}
"""

        return ""

    async def comprehensive_search(
        self,
        name: str,
        location: Optional[str] = None
    ) -> List[TruePeopleProfile]:
        """
        Comprehensive search with automatic full profile fetching

        Args:
            name: Full name or "FirstName LastName"
            location: Optional "City, State" string

        Returns:
            List of complete profiles
        """
        # Parse name
        name_parts = name.strip().split()
        if len(name_parts) < 2:
            logger.error("Name must include first and last name")
            return []

        first_name = name_parts[0]
        last_name = ' '.join(name_parts[1:])

        # Parse location
        city = None
        state = None
        if location:
            location_parts = location.split(',')
            if len(location_parts) >= 2:
                city = location_parts[0].strip()
                state = location_parts[1].strip()

        # Search
        results = await self.search_by_name(first_name, last_name, city, state)

        # Fetch full profiles
        full_profiles = []
        for result in results[:5]:  # Limit to top 5 results
            if result.profile_url:
                full_profile = await self.get_full_profile(result.profile_url)
                if full_profile:
                    full_profiles.append(full_profile)

        return full_profiles


if __name__ == "__main__":
    # Example usage
    async def main():
        async with TruePeopleSearch(rate_limit=2.0) as tps:
            # Search by name
            results = await tps.search_by_name(
                first_name="John",
                last_name="Doe",
                city="New York",
                state="NY"
            )

            print(f"Found {len(results)} results")

            for result in results[:3]:
                print(tps.export_profile(result, format='text'))

                # Get full profile
                if result.profile_url:
                    full_profile = await tps.get_full_profile(result.profile_url)
                    if full_profile:
                        print(tps.export_profile(full_profile, format='json'))

            # Reverse phone lookup
            phone_result = await tps.search_by_phone("555-123-4567")
            if phone_result:
                print(tps.export_profile(phone_result, format='text'))

            # Comprehensive search
            comprehensive = await tps.comprehensive_search(
                name="John Doe",
                location="New York, NY"
            )

            for profile in comprehensive:
                print(tps.export_profile(profile, format='text'))

    asyncio.run(main())
