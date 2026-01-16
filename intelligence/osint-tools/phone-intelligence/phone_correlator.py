"""
Phone Correlator
Link phone numbers to emails, social media, breaches, and person attribution
"""

import requests
import json
import logging
import hashlib
from typing import Dict, List, Optional, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
import re


class PhoneCorrelator:
    """
    Phone number correlation engine
    Links phone numbers to other identifiers and data sources
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize phone correlator

        Args:
            config: Configuration dictionary with API keys
        """
        self.config = config or {}
        self.logger = self._setup_logging()

        # API configurations
        self.haveibeenpwned_api_key = self.config.get('hibp_api_key')
        self.dehashed_api_key = self.config.get('dehashed_api_key')
        self.snusbase_api_key = self.config.get('snusbase_api_key')

        # Social media APIs (if available)
        self.social_apis = self.config.get('social_apis', {})

        # Cache for correlation results
        self.cache = {}

        self.logger.info("Phone correlator initialized")

    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration"""
        logger = logging.getLogger('PhoneCorrelator')
        logger.setLevel(logging.INFO)

        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)

        return logger

    def correlate(self, phone: str) -> Dict[str, Any]:
        """
        Perform comprehensive correlation for phone number

        Args:
            phone: Phone number in E.164 format

        Returns:
            Correlation results dictionary
        """
        self.logger.info(f"Starting correlation for {phone}")

        results = {
            'phone': phone,
            'social_media': {},
            'breaches': {},
            'correlations': {},
            'person_info': {},
            'related_emails': [],
            'related_usernames': [],
            'related_names': [],
            'confidence_score': 0
        }

        # Run correlation tasks in parallel
        tasks = {
            'social': lambda: self._find_social_media(phone),
            'breaches': lambda: self._search_breaches(phone),
            'person': lambda: self._find_person_info(phone),
            'email': lambda: self._find_email_correlations(phone)
        }

        with ThreadPoolExecutor(max_workers=4) as executor:
            future_to_task = {
                executor.submit(task): name
                for name, task in tasks.items()
            }

            for future in as_completed(future_to_task):
                task_name = future_to_task[future]
                try:
                    result = future.result(timeout=30)

                    if task_name == 'social':
                        results['social_media'] = result
                    elif task_name == 'breaches':
                        results['breaches'] = result
                    elif task_name == 'person':
                        results['person_info'] = result
                    elif task_name == 'email':
                        results['related_emails'] = result.get('emails', [])
                        results['correlations'] = result.get('correlations', {})

                except Exception as e:
                    self.logger.error(f"Error in {task_name}: {e}")

        # Extract related information
        results['related_usernames'] = self._extract_usernames(results)
        results['related_names'] = self._extract_names(results)

        # Calculate confidence score
        results['confidence_score'] = self._calculate_confidence(results)

        return results

    def _find_social_media(self, phone: str) -> Dict[str, Any]:
        """
        Find social media accounts linked to phone number

        Args:
            phone: Phone number

        Returns:
            Social media accounts dictionary
        """
        social_results = {
            'facebook': None,
            'twitter': None,
            'linkedin': None,
            'instagram': None,
            'snapchat': None,
            'telegram': None,
            'whatsapp': None,
            'signal': None,
            'total_found': 0
        }

        # Method 1: Direct API lookups (if available)
        if self.social_apis:
            social_results.update(self._api_social_lookup(phone))

        # Method 2: Search engines (indirect)
        search_results = self._search_engine_social_lookup(phone)
        for platform, data in search_results.items():
            if data and not social_results.get(platform):
                social_results[platform] = data

        # Count found platforms
        social_results['total_found'] = sum(
            1 for k, v in social_results.items()
            if k != 'total_found' and v is not None
        )

        return social_results

    def _api_social_lookup(self, phone: str) -> Dict[str, Any]:
        """Lookup using social media APIs"""
        results = {}

        # Facebook (requires API access)
        if 'facebook' in self.social_apis:
            try:
                fb_result = self._facebook_lookup(phone)
                if fb_result:
                    results['facebook'] = fb_result
            except Exception as e:
                self.logger.error(f"Facebook lookup error: {e}")

        # Twitter/X (requires API access)
        if 'twitter' in self.social_apis:
            try:
                twitter_result = self._twitter_lookup(phone)
                if twitter_result:
                    results['twitter'] = twitter_result
            except Exception as e:
                self.logger.error(f"Twitter lookup error: {e}")

        return results

    def _facebook_lookup(self, phone: str) -> Optional[Dict[str, str]]:
        """Facebook phone lookup"""
        # Requires Facebook API access
        # This is a placeholder structure
        return None

    def _twitter_lookup(self, phone: str) -> Optional[Dict[str, str]]:
        """Twitter phone lookup"""
        # Requires Twitter API access
        # This is a placeholder structure
        return None

    def _search_engine_social_lookup(self, phone: str) -> Dict[str, Any]:
        """Use search engines to find social media links"""
        results = {}

        # Common social media URL patterns
        patterns = {
            'facebook': r'facebook\.com/[\w\.-]+',
            'twitter': r'twitter\.com/[\w\.-]+',
            'linkedin': r'linkedin\.com/in/[\w\.-]+',
            'instagram': r'instagram\.com/[\w\.-]+',
        }

        # This would involve:
        # 1. Google dorking with phone number
        # 2. Parsing results for social media URLs
        # 3. Validating the links

        # Placeholder - actual implementation would use search APIs
        return results

    def _search_breaches(self, phone: str) -> Dict[str, Any]:
        """
        Search data breach databases for phone number

        Args:
            phone: Phone number

        Returns:
            Breach search results
        """
        results = {
            'found_in': [],
            'total_breaches': 0,
            'exposed_data': [],
            'breach_details': []
        }

        # Search multiple breach databases
        breach_sources = []

        # HaveIBeenPwned (phones not directly supported, but related emails might be)
        if self.haveibeenpwned_api_key:
            hibp_results = self._search_hibp(phone)
            if hibp_results:
                breach_sources.append(hibp_results)

        # Dehashed
        if self.dehashed_api_key:
            dehashed_results = self._search_dehashed(phone)
            if dehashed_results:
                breach_sources.append(dehashed_results)

        # SnusBase
        if self.snusbase_api_key:
            snusbase_results = self._search_snusbase(phone)
            if snusbase_results:
                breach_sources.append(snusbase_results)

        # Aggregate results
        for source in breach_sources:
            results['found_in'].extend(source.get('breaches', []))
            results['breach_details'].extend(source.get('details', []))

        results['total_breaches'] = len(results['found_in'])

        # Extract exposed data types
        data_types = set()
        for detail in results['breach_details']:
            if 'data_classes' in detail:
                data_types.update(detail['data_classes'])

        results['exposed_data'] = list(data_types)

        return results

    def _search_hibp(self, phone: str) -> Optional[Dict[str, Any]]:
        """Search HaveIBeenPwned"""
        # HIBP doesn't directly support phone searches
        # Would need to find associated email first
        return None

    def _search_dehashed(self, phone: str) -> Optional[Dict[str, Any]]:
        """Search Dehashed.com"""
        try:
            headers = {
                'Accept': 'application/json',
                'Authorization': f'Basic {self.dehashed_api_key}'
            }

            params = {
                'query': f'phone:{phone}'
            }

            response = requests.get(
                'https://api.dehashed.com/search',
                headers=headers,
                params=params,
                timeout=30
            )

            if response.status_code == 200:
                data = response.json()
                return self._parse_dehashed_response(data)

        except Exception as e:
            self.logger.error(f"Dehashed search error: {e}")

        return None

    def _parse_dehashed_response(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse Dehashed API response"""
        results = {
            'breaches': [],
            'details': []
        }

        if data.get('entries'):
            for entry in data['entries']:
                breach_name = entry.get('database_name', 'Unknown')
                if breach_name not in results['breaches']:
                    results['breaches'].append(breach_name)

                results['details'].append({
                    'breach': breach_name,
                    'email': entry.get('email'),
                    'username': entry.get('username'),
                    'name': entry.get('name'),
                    'phone': entry.get('phone'),
                    'data_classes': list(entry.keys())
                })

        return results

    def _search_snusbase(self, phone: str) -> Optional[Dict[str, Any]]:
        """Search SnusBase"""
        try:
            headers = {
                'Auth': self.snusbase_api_key,
                'Content-Type': 'application/json'
            }

            data = {
                'terms': [phone],
                'types': ['phone'],
                'wildcard': False
            }

            response = requests.post(
                'https://api.snusbase.com/data/search',
                headers=headers,
                json=data,
                timeout=30
            )

            if response.status_code == 200:
                return self._parse_snusbase_response(response.json())

        except Exception as e:
            self.logger.error(f"SnusBase search error: {e}")

        return None

    def _parse_snusbase_response(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse SnusBase API response"""
        results = {
            'breaches': [],
            'details': []
        }

        if data.get('results'):
            for db_name, entries in data['results'].items():
                results['breaches'].append(db_name)

                for entry in entries:
                    results['details'].append({
                        'breach': db_name,
                        'email': entry.get('email'),
                        'username': entry.get('username'),
                        'name': entry.get('name'),
                        'phone': entry.get('phone'),
                        'data_classes': list(entry.keys())
                    })

        return results

    def _find_person_info(self, phone: str) -> Dict[str, Any]:
        """
        Find person information associated with phone

        Args:
            phone: Phone number

        Returns:
            Person information dictionary
        """
        person_info = {
            'names': [],
            'addresses': [],
            'emails': [],
            'employers': [],
            'relatives': [],
            'age_range': None,
            'confidence': 0.0
        }

        # This would integrate with people search APIs like:
        # - TrueCaller (already integrated in main module)
        # - Whitepages
        # - Pipl
        # - BeenVerified
        # - Spokeo

        # Placeholder for structure
        return person_info

    def _find_email_correlations(self, phone: str) -> Dict[str, Any]:
        """
        Find emails correlated with phone number

        Args:
            phone: Phone number

        Returns:
            Email correlations
        """
        results = {
            'emails': [],
            'correlations': {}
        }

        # Search breach databases for associated emails
        breach_results = self._search_breaches(phone)

        # Extract emails from breach data
        emails = set()
        for detail in breach_results.get('breach_details', []):
            if detail.get('email'):
                emails.add(detail['email'])

        results['emails'] = list(emails)

        # Build correlation map
        for email in emails:
            results['correlations'][email] = {
                'found_in_breaches': [],
                'confidence': 0.7
            }

            for detail in breach_results.get('breach_details', []):
                if detail.get('email') == email:
                    results['correlations'][email]['found_in_breaches'].append(
                        detail.get('breach')
                    )

        return results

    def _extract_usernames(self, results: Dict[str, Any]) -> List[str]:
        """Extract unique usernames from correlation results"""
        usernames = set()

        # From breaches
        for detail in results.get('breaches', {}).get('breach_details', []):
            if detail.get('username'):
                usernames.add(detail['username'])

        # From social media
        social = results.get('social_media', {})
        for platform, data in social.items():
            if isinstance(data, dict) and data.get('username'):
                usernames.add(data['username'])

        return list(usernames)

    def _extract_names(self, results: Dict[str, Any]) -> List[str]:
        """Extract unique names from correlation results"""
        names = set()

        # From breaches
        for detail in results.get('breaches', {}).get('breach_details', []):
            if detail.get('name'):
                names.add(detail['name'])

        # From person info
        person_names = results.get('person_info', {}).get('names', [])
        names.update(person_names)

        return list(names)

    def _calculate_confidence(self, results: Dict[str, Any]) -> float:
        """Calculate confidence score for correlations"""
        score = 0.0
        factors = 0

        # Social media accounts found
        social_count = results.get('social_media', {}).get('total_found', 0)
        if social_count > 0:
            score += min(social_count * 0.15, 0.4)
            factors += 1

        # Breach database hits
        breach_count = results.get('breaches', {}).get('total_breaches', 0)
        if breach_count > 0:
            score += min(breach_count * 0.1, 0.3)
            factors += 1

        # Email correlations
        email_count = len(results.get('related_emails', []))
        if email_count > 0:
            score += min(email_count * 0.1, 0.2)
            factors += 1

        # Person info available
        if results.get('person_info', {}).get('names'):
            score += 0.1
            factors += 1

        # Normalize score
        if factors > 0:
            return min(score, 1.0)

        return 0.0

    def link_to_email(self, phone: str, email: str) -> Dict[str, Any]:
        """
        Check linkage between phone and email

        Args:
            phone: Phone number
            email: Email address

        Returns:
            Linkage analysis
        """
        result = {
            'phone': phone,
            'email': email,
            'linked': False,
            'confidence': 0.0,
            'evidence': []
        }

        # Search for both in breach databases
        phone_breaches = self._search_breaches(phone)
        email_breaches = self._search_email_breaches(email)

        # Find common breaches
        phone_breach_names = set(phone_breaches.get('found_in', []))
        email_breach_names = set(email_breaches.get('found_in', []))

        common_breaches = phone_breach_names.intersection(email_breach_names)

        if common_breaches:
            result['linked'] = True
            result['confidence'] = min(0.3 + (len(common_breaches) * 0.2), 0.9)
            result['evidence'].append(
                f"Found together in {len(common_breaches)} breach(es): {', '.join(list(common_breaches)[:3])}"
            )

        return result

    def _search_email_breaches(self, email: str) -> Dict[str, Any]:
        """Search breaches for email address"""
        # Similar to _search_breaches but for email
        # Implementation would mirror phone breach search
        return {
            'found_in': [],
            'total_breaches': 0
        }


def main():
    """Example usage"""
    # Initialize correlator with API keys
    correlator = PhoneCorrelator({
        'dehashed_api_key': 'YOUR_DEHASHED_KEY',
        'snusbase_api_key': 'YOUR_SNUSBASE_KEY',
        'hibp_api_key': 'YOUR_HIBP_KEY'
    })

    # Correlate phone number
    phone = "+14155552671"
    results = correlator.correlate(phone)

    print(f"Correlation results for {phone}:")
    print(json.dumps(results, indent=2))

    # Check phone-email linkage
    linkage = correlator.link_to_email(phone, "user@example.com")
    print(f"\nLinkage analysis:")
    print(f"Linked: {linkage['linked']}")
    print(f"Confidence: {linkage['confidence']}")
    print(f"Evidence: {linkage['evidence']}")


if __name__ == "__main__":
    main()
