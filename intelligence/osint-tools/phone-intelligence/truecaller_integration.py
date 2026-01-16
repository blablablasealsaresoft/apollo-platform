"""
TrueCaller Integration
Caller ID lookup, spam detection, and name identification
"""

import requests
import json
import logging
import time
from typing import Dict, List, Optional, Any
from urllib.parse import quote


class TrueCallerClient:
    """
    TrueCaller API integration for caller ID and spam detection
    """

    # TrueCaller API endpoints
    SEARCH_API = "https://search5-noneu.truecaller.com/v2/search"
    BULK_API = "https://search5-noneu.truecaller.com/v2/bulk"

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize TrueCaller client

        Args:
            config: Configuration dictionary with API key
        """
        self.config = config or {}
        self.logger = self._setup_logging()

        # API credentials
        self.api_key = self.config.get('api_key')
        self.installation_id = self.config.get('installation_id', '')

        # Rate limiting
        self.rate_limit = self.config.get('rate_limit', 60)  # requests per minute
        self.last_request_time = 0

        # Session
        self.session = requests.Session()
        self._setup_session()

        self.logger.info("TrueCaller client initialized")

    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration"""
        logger = logging.getLogger('TrueCaller')
        logger.setLevel(logging.INFO)

        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)

        return logger

    def _setup_session(self):
        """Setup session with headers"""
        self.session.headers.update({
            'User-Agent': 'Truecaller/11.75.5 (Android;10)',
            'Accept': 'application/json',
            'Accept-Encoding': 'gzip',
            'Content-Type': 'application/json; charset=UTF-8'
        })

        if self.api_key:
            self.session.headers.update({
                'Authorization': f'Bearer {self.api_key}'
            })

    def _rate_limit_check(self):
        """Enforce rate limiting"""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        min_interval = 60.0 / self.rate_limit

        if time_since_last < min_interval:
            sleep_time = min_interval - time_since_last
            self.logger.debug(f"Rate limiting: sleeping {sleep_time:.2f}s")
            time.sleep(sleep_time)

        self.last_request_time = time.time()

    def lookup(self, phone: str) -> Dict[str, Any]:
        """
        Lookup phone number in TrueCaller

        Args:
            phone: Phone number in E.164 format

        Returns:
            Dictionary with caller information
        """
        try:
            self._rate_limit_check()
            self.logger.info(f"Looking up {phone} in TrueCaller")

            # Build request parameters
            params = {
                'q': phone,
                'countryCode': self._extract_country_code(phone),
                'type': 4,
                'locAddr': '',
                'placement': 'SEARCHRESULTS,HISTORY,DETAILS',
                'encoding': 'json'
            }

            if self.installation_id:
                params['installationId'] = self.installation_id

            # Make request
            response = self.session.get(
                self.SEARCH_API,
                params=params,
                timeout=30
            )

            if response.status_code == 200:
                data = response.json()
                return self._parse_response(data, phone)
            elif response.status_code == 429:
                self.logger.error("Rate limit exceeded")
                return {'error': 'Rate limit exceeded'}
            elif response.status_code == 403:
                self.logger.error("Authentication failed")
                return {'error': 'Authentication failed - check API key'}
            else:
                self.logger.error(f"API error: {response.status_code}")
                return {'error': f"API returned status {response.status_code}"}

        except Exception as e:
            self.logger.error(f"Error in lookup: {e}")
            return {'error': str(e)}

    def _extract_country_code(self, phone: str) -> str:
        """Extract country code from E.164 phone number"""
        if phone.startswith('+'):
            phone = phone[1:]

        # Common country codes
        if phone.startswith('1'):
            return 'US'
        elif phone.startswith('44'):
            return 'GB'
        elif phone.startswith('91'):
            return 'IN'
        elif phone.startswith('86'):
            return 'CN'
        # Add more as needed

        return 'US'  # Default

    def _parse_response(self, data: Dict[str, Any], phone: str) -> Dict[str, Any]:
        """Parse TrueCaller API response"""
        result = {
            'phone': phone,
            'name': None,
            'spam_score': 0,
            'spam_type': None,
            'is_spam': False,
            'carrier': None,
            'location': None,
            'social_profiles': [],
            'email': None,
            'tags': [],
            'verified': False,
            'businesses': [],
            'raw': data
        }

        try:
            # Check if data found
            if not data.get('data'):
                return result

            main_data = data['data'][0] if isinstance(data['data'], list) else data['data']

            # Name
            if 'name' in main_data:
                result['name'] = main_data['name']

            # Spam information
            if 'spamInfo' in main_data:
                spam_info = main_data['spamInfo']
                result['spam_score'] = spam_info.get('spamScore', 0)
                result['spam_type'] = spam_info.get('spamType')
                result['is_spam'] = result['spam_score'] > 50

            # Carrier
            if 'carrier' in main_data:
                result['carrier'] = main_data['carrier']

            # Location
            if 'address' in main_data:
                address = main_data['address']
                result['location'] = {
                    'city': address.get('city'),
                    'country': address.get('countryCode'),
                    'timezone': address.get('timeZone'),
                    'type': address.get('type')
                }

            # Social profiles
            if 'internetAddresses' in main_data:
                for addr in main_data['internetAddresses']:
                    profile = {
                        'type': addr.get('type'),
                        'id': addr.get('id'),
                        'service': addr.get('service'),
                        'url': self._build_social_url(addr)
                    }
                    result['social_profiles'].append(profile)

            # Email
            if 'email' in main_data:
                result['email'] = main_data['email']
            elif 'emails' in main_data and main_data['emails']:
                result['email'] = main_data['emails'][0]

            # Tags
            if 'tags' in main_data:
                result['tags'] = main_data['tags']

            # Verified
            if 'verified' in main_data:
                result['verified'] = main_data['verified']

            # Businesses
            if 'businesses' in main_data:
                result['businesses'] = main_data['businesses']

        except Exception as e:
            self.logger.error(f"Error parsing response: {e}")

        return result

    def _build_social_url(self, addr: Dict[str, Any]) -> str:
        """Build social media profile URL"""
        service = addr.get('service', '').lower()
        id_val = addr.get('id', '')

        url_map = {
            'facebook': f'https://facebook.com/{id_val}',
            'twitter': f'https://twitter.com/{id_val}',
            'linkedin': f'https://linkedin.com/in/{id_val}',
            'instagram': f'https://instagram.com/{id_val}',
        }

        return url_map.get(service, '')

    def bulk_lookup(self, phones: List[str]) -> Dict[str, Dict[str, Any]]:
        """
        Bulk lookup multiple phone numbers

        Args:
            phones: List of phone numbers

        Returns:
            Dictionary mapping phone numbers to results
        """
        self.logger.info(f"Bulk lookup for {len(phones)} numbers")

        results = {}

        # TrueCaller API may support bulk, otherwise do individual lookups
        for phone in phones:
            results[phone] = self.lookup(phone)

        return results

    def check_spam(self, phone: str) -> Dict[str, Any]:
        """
        Check if number is spam

        Args:
            phone: Phone number

        Returns:
            Spam information
        """
        result = self.lookup(phone)

        return {
            'phone': phone,
            'is_spam': result.get('is_spam', False),
            'spam_score': result.get('spam_score', 0),
            'spam_type': result.get('spam_type'),
            'tags': result.get('tags', [])
        }

    def get_name(self, phone: str) -> Optional[str]:
        """
        Get name associated with phone number

        Args:
            phone: Phone number

        Returns:
            Name or None
        """
        result = self.lookup(phone)
        return result.get('name')

    def get_social_profiles(self, phone: str) -> List[Dict[str, str]]:
        """
        Get social media profiles linked to phone

        Args:
            phone: Phone number

        Returns:
            List of social profiles
        """
        result = self.lookup(phone)
        return result.get('social_profiles', [])

    def search_by_name(self, name: str, country_code: str = 'US') -> List[Dict[str, Any]]:
        """
        Search for phone numbers by name

        Args:
            name: Person or business name
            country_code: Country code for search

        Returns:
            List of matching results
        """
        try:
            self._rate_limit_check()
            self.logger.info(f"Searching by name: {name}")

            params = {
                'q': name,
                'countryCode': country_code,
                'type': 2,  # Name search
                'encoding': 'json'
            }

            response = self.session.get(
                self.SEARCH_API,
                params=params,
                timeout=30
            )

            if response.status_code == 200:
                data = response.json()

                results = []
                if data.get('data'):
                    for item in data['data']:
                        results.append({
                            'name': item.get('name'),
                            'phone': item.get('phones', [{}])[0].get('e164Format'),
                            'location': item.get('address'),
                            'carrier': item.get('carrier'),
                            'verified': item.get('verified', False)
                        })

                return results
            else:
                self.logger.error(f"Search error: {response.status_code}")
                return []

        except Exception as e:
            self.logger.error(f"Error in name search: {e}")
            return []


def main():
    """Example usage"""
    # Initialize client
    client = TrueCallerClient({
        'api_key': 'YOUR_API_KEY',
        'installation_id': 'YOUR_INSTALLATION_ID'
    })

    # Lookup phone number
    phone = "+14155552671"
    result = client.lookup(phone)

    print(f"Lookup result for {phone}:")
    print(json.dumps(result, indent=2))

    # Check spam
    spam_info = client.check_spam(phone)
    if spam_info['is_spam']:
        print(f"\nWARNING: {phone} is reported as spam!")
        print(f"Spam score: {spam_info['spam_score']}")

    # Get name
    name = client.get_name(phone)
    if name:
        print(f"\nRegistered to: {name}")

    # Get social profiles
    profiles = client.get_social_profiles(phone)
    if profiles:
        print(f"\nSocial profiles found:")
        for profile in profiles:
            print(f"  - {profile['service']}: {profile['url']}")

    # Search by name
    search_results = client.search_by_name("John Smith", "US")
    print(f"\nFound {len(search_results)} results for 'John Smith'")


if __name__ == "__main__":
    main()
