"""
Email Hunter - Email discovery and verification
Hunter.io integration for company email finding
"""

import requests
import json
from typing import Dict, List, Optional, Any
from datetime import datetime
import logging
from dataclasses import dataclass
import time


@dataclass
class EmailPattern:
    """Email pattern for a domain"""
    pattern: str
    confidence: float
    example: str


@dataclass class EmailCandidate:
    """Email candidate with verification status"""
    email: str
    first_name: str
    last_name: str
    position: Optional[str]
    department: Optional[str]
    linkedin: Optional[str]
    twitter: Optional[str]
    confidence: float
    verified: bool


class EmailHunter:
    """
    Email discovery and verification system
    Integrates with Hunter.io and other sources
    """

    HUNTER_API = "https://api.hunter.io/v2"

    # Common email patterns
    COMMON_PATTERNS = [
        "{first}.{last}",
        "{first}{last}",
        "{f}{last}",
        "{first}.{l}",
        "{first}",
        "{last}",
        "{first}_{last}",
        "{f}.{last}",
        "{last}.{first}"
    ]

    def __init__(self, api_key: Optional[str] = None, rate_limit: int = 50):
        """
        Initialize Email Hunter

        Args:
            api_key: Hunter.io API key
            rate_limit: API calls per month (free tier = 50)
        """
        self.api_key = api_key
        self.rate_limit = rate_limit
        self.calls_made = 0
        self.logger = self._setup_logging()

    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration"""
        logger = logging.getLogger('EmailHunter')
        logger.setLevel(logging.INFO)

        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)

        return logger

    def find_emails(self, domain: str, limit: int = 10) -> List[str]:
        """
        Find emails for a domain

        Args:
            domain: Company domain
            limit: Maximum number of emails to return

        Returns:
            List of email addresses
        """
        if not self.api_key:
            self.logger.warning("No API key provided, using pattern-based search only")
            return []

        try:
            url = f"{self.HUNTER_API}/domain-search"
            params = {
                'domain': domain,
                'api_key': self.api_key,
                'limit': limit
            }

            response = requests.get(url, params=params, timeout=10)
            self.calls_made += 1

            if response.status_code == 200:
                data = response.json()
                emails = []

                for email_data in data.get('data', {}).get('emails', []):
                    emails.append(email_data.get('value'))

                self.logger.info(f"Found {len(emails)} emails for {domain}")
                return emails
            else:
                self.logger.error(f"Hunter.io API error: {response.status_code}")
                return []

        except Exception as e:
            self.logger.error(f"Email search error: {str(e)}")
            return []

    def verify_email(self, email: str) -> Dict[str, Any]:
        """
        Verify if email exists

        Args:
            email: Email to verify

        Returns:
            Verification result
        """
        if not self.api_key:
            self.logger.warning("No API key provided")
            return {'email': email, 'verified': False, 'error': 'No API key'}

        try:
            url = f"{self.HUNTER_API}/email-verifier"
            params = {
                'email': email,
                'api_key': self.api_key
            }

            response = requests.get(url, params=params, timeout=10)
            self.calls_made += 1

            if response.status_code == 200:
                data = response.json().get('data', {})

                return {
                    'email': email,
                    'verified': data.get('status') == 'valid',
                    'status': data.get('status'),
                    'score': data.get('score', 0),
                    'regexp': data.get('regexp', False),
                    'gibberish': data.get('gibberish', False),
                    'disposable': data.get('disposable', False),
                    'webmail': data.get('webmail', False),
                    'mx_records': data.get('mx_records', False),
                    'smtp_server': data.get('smtp_server', False),
                    'smtp_check': data.get('smtp_check', False),
                    'accept_all': data.get('accept_all', False),
                    'block': data.get('block', False)
                }
            else:
                self.logger.error(f"Hunter.io API error: {response.status_code}")
                return {'email': email, 'verified': False, 'error': f'API error: {response.status_code}'}

        except Exception as e:
            self.logger.error(f"Email verification error: {str(e)}")
            return {'email': email, 'verified': False, 'error': str(e)}

    def get_email_pattern(self, domain: str) -> Optional[EmailPattern]:
        """
        Get email pattern for domain

        Args:
            domain: Company domain

        Returns:
            EmailPattern or None
        """
        if not self.api_key:
            return self._guess_pattern(domain)

        try:
            url = f"{self.HUNTER_API}/domain-search"
            params = {
                'domain': domain,
                'api_key': self.api_key,
                'limit': 1
            }

            response = requests.get(url, params=params, timeout=10)
            self.calls_made += 1

            if response.status_code == 200:
                data = response.json().get('data', {})
                pattern = data.get('pattern')

                if pattern:
                    return EmailPattern(
                        pattern=pattern,
                        confidence=data.get('confidence', 0) / 100,
                        example=self._format_pattern_example(pattern, domain)
                    )
                else:
                    return self._guess_pattern(domain)
            else:
                return self._guess_pattern(domain)

        except Exception as e:
            self.logger.error(f"Pattern detection error: {str(e)}")
            return self._guess_pattern(domain)

    def _guess_pattern(self, domain: str) -> EmailPattern:
        """Guess email pattern based on common patterns"""
        # Default to most common pattern
        return EmailPattern(
            pattern="{first}.{last}",
            confidence=0.5,
            example=f"john.doe@{domain}"
        )

    def _format_pattern_example(self, pattern: str, domain: str) -> str:
        """Format pattern into example email"""
        example = pattern.replace('{first}', 'john')
        example = example.replace('{last}', 'doe')
        example = example.replace('{f}', 'j')
        example = example.replace('{l}', 'd')
        return f"{example}@{domain}"

    def generate_email(self,
                       first_name: str,
                       last_name: str,
                       domain: str,
                       pattern: Optional[str] = None) -> str:
        """
        Generate email based on pattern

        Args:
            first_name: First name
            last_name: Last name
            domain: Email domain
            pattern: Email pattern (auto-detect if None)

        Returns:
            Generated email address
        """
        if not pattern:
            pattern_obj = self.get_email_pattern(domain)
            pattern = pattern_obj.pattern if pattern_obj else "{first}.{last}"

        email = pattern.lower()
        email = email.replace('{first}', first_name.lower())
        email = email.replace('{last}', last_name.lower())
        email = email.replace('{f}', first_name[0].lower() if first_name else '')
        email = email.replace('{l}', last_name[0].lower() if last_name else '')

        return f"{email}@{domain}"

    def generate_email_variations(self,
                                  first_name: str,
                                  last_name: str,
                                  domain: str) -> List[str]:
        """
        Generate all possible email variations

        Args:
            first_name: First name
            last_name: Last name
            domain: Email domain

        Returns:
            List of email variations
        """
        variations = []

        for pattern in self.COMMON_PATTERNS:
            try:
                email = self.generate_email(first_name, last_name, domain, pattern)
                if email not in variations:
                    variations.append(email)
            except Exception as e:
                self.logger.debug(f"Error generating variation for pattern {pattern}: {str(e)}")

        return variations

    def get_domain_info(self, domain: str) -> Dict[str, Any]:
        """
        Get information about a domain

        Args:
            domain: Domain to lookup

        Returns:
            Domain information
        """
        if not self.api_key:
            return {'domain': domain, 'error': 'No API key'}

        try:
            url = f"{self.HUNTER_API}/domain-search"
            params = {
                'domain': domain,
                'api_key': self.api_key,
                'limit': 1
            }

            response = requests.get(url, params=params, timeout=10)
            self.calls_made += 1

            if response.status_code == 200:
                data = response.json().get('data', {})

                return {
                    'domain': domain,
                    'disposable': data.get('disposable', False),
                    'webmail': data.get('webmail', False),
                    'accept_all': data.get('accept_all', False),
                    'pattern': data.get('pattern'),
                    'organization': data.get('organization'),
                    'country': data.get('country'),
                    'state': data.get('state'),
                    'emails_count': data.get('emails', 0),
                    'confidence': data.get('confidence', 0)
                }
            else:
                return {'domain': domain, 'error': f'API error: {response.status_code}'}

        except Exception as e:
            self.logger.error(f"Domain info error: {str(e)}")
            return {'domain': domain, 'error': str(e)}

    def find_employee_emails(self,
                            domain: str,
                            department: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Find employee emails for a domain

        Args:
            domain: Company domain
            department: Filter by department

        Returns:
            List of employee email data
        """
        if not self.api_key:
            return []

        try:
            url = f"{self.HUNTER_API}/domain-search"
            params = {
                'domain': domain,
                'api_key': self.api_key,
                'limit': 100
            }

            if department:
                params['department'] = department

            response = requests.get(url, params=params, timeout=10)
            self.calls_made += 1

            if response.status_code == 200:
                data = response.json().get('data', {})
                emails = []

                for email_data in data.get('emails', []):
                    emails.append({
                        'email': email_data.get('value'),
                        'first_name': email_data.get('first_name'),
                        'last_name': email_data.get('last_name'),
                        'position': email_data.get('position'),
                        'department': email_data.get('department'),
                        'linkedin': email_data.get('linkedin'),
                        'twitter': email_data.get('twitter'),
                        'phone': email_data.get('phone_number'),
                        'confidence': email_data.get('confidence', 0),
                        'verified': email_data.get('verification', {}).get('status') == 'valid'
                    })

                return emails
            else:
                self.logger.error(f"Hunter.io API error: {response.status_code}")
                return []

        except Exception as e:
            self.logger.error(f"Employee email search error: {str(e)}")
            return []

    def get_api_usage(self) -> Dict[str, Any]:
        """
        Get API usage statistics

        Returns:
            Usage statistics
        """
        if not self.api_key:
            return {'error': 'No API key'}

        try:
            url = f"{self.HUNTER_API}/account"
            params = {'api_key': self.api_key}

            response = requests.get(url, params=params, timeout=10)

            if response.status_code == 200:
                data = response.json().get('data', {})

                return {
                    'requests_used': data.get('requests', {}).get('used', 0),
                    'requests_available': data.get('requests', {}).get('available', 0),
                    'plan_name': data.get('plan_name'),
                    'plan_level': data.get('plan_level'),
                    'reset_date': data.get('reset_date'),
                    'calls_this_session': self.calls_made
                }
            else:
                return {'error': f'API error: {response.status_code}'}

        except Exception as e:
            self.logger.error(f"API usage check error: {str(e)}")
            return {'error': str(e)}


if __name__ == "__main__":
    # Example usage
    hunter = EmailHunter(api_key='YOUR_API_KEY')

    # Find emails for domain
    emails = hunter.find_emails("example.com")
    print(f"Found emails: {emails}")

    # Verify email
    result = hunter.verify_email("john.doe@example.com")
    print(json.dumps(result, indent=2))

    # Generate email variations
    variations = hunter.generate_email_variations("John", "Doe", "example.com")
    print(f"Variations: {variations}")

    # Get domain info
    info = hunter.get_domain_info("example.com")
    print(json.dumps(info, indent=2))
