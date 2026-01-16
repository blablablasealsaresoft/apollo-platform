"""
Email Correlator - Cross-source correlation
Link emails to usernames, find associated accounts, breach correlation
"""

import re
import json
from typing import Dict, List, Optional, Any, Set
from datetime import datetime
import logging
from dataclasses import dataclass
from collections import defaultdict
import hashlib


@dataclass
class CorrelationResult:
    """Correlation result"""
    email: str
    related_emails: List[str]
    related_usernames: List[str]
    social_media_accounts: List[Dict[str, Any]]
    breaches: List[Dict[str, Any]]
    shared_attributes: Dict[str, List[str]]
    confidence_score: float


class EmailCorrelator:
    """
    Cross-source email correlation system
    Links emails to usernames, accounts, and breaches
    """

    # Common username patterns
    USERNAME_PATTERNS = [
        r'([a-zA-Z0-9_.-]+)@',  # Email prefix
        r'([a-zA-Z0-9_.-]+)',    # Any alphanumeric with separators
    ]

    # Social media platforms
    SOCIAL_PLATFORMS = {
        'twitter': 'https://twitter.com/{}',
        'instagram': 'https://instagram.com/{}',
        'facebook': 'https://facebook.com/{}',
        'linkedin': 'https://linkedin.com/in/{}',
        'github': 'https://github.com/{}',
        'reddit': 'https://reddit.com/user/{}',
        'tiktok': 'https://tiktok.com/@{}',
        'youtube': 'https://youtube.com/@{}',
        'twitch': 'https://twitch.tv/{}',
        'pinterest': 'https://pinterest.com/{}',
    }

    def __init__(self):
        """Initialize Email Correlator"""
        self.logger = self._setup_logging()
        self.correlation_cache = {}

    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration"""
        logger = logging.getLogger('EmailCorrelator')
        logger.setLevel(logging.INFO)

        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)

        return logger

    def correlate(self, email: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Correlate email with all available data

        Args:
            email: Email address
            data: Dictionary of collected data from various sources

        Returns:
            Correlation results
        """
        self.logger.info(f"Correlating data for: {email}")

        # Extract username from email
        username = self._extract_username(email)
        domain = email.split('@')[1] if '@' in email else ''

        # Find related emails
        related_emails = self._find_related_emails(email, username, domain, data)

        # Extract usernames
        related_usernames = self._extract_usernames(email, data)

        # Find social media accounts
        social_media = self._correlate_social_media(username, related_usernames, data)

        # Find shared attributes
        shared_attributes = self._find_shared_attributes(email, data)

        # Calculate confidence
        confidence = self._calculate_correlation_confidence(
            related_emails, related_usernames, social_media
        )

        return {
            'email': email,
            'username': username,
            'related_emails': related_emails,
            'related_usernames': related_usernames,
            'social_media_accounts': social_media,
            'shared_attributes': shared_attributes,
            'confidence_score': confidence,
            'correlation_timestamp': datetime.now().isoformat()
        }

    def _extract_username(self, email: str) -> str:
        """Extract username from email"""
        if '@' in email:
            return email.split('@')[0]
        return email

    def _find_related_emails(self,
                            email: str,
                            username: str,
                            domain: str,
                            data: Dict[str, Any]) -> List[str]:
        """
        Find related email addresses

        Args:
            email: Primary email
            username: Username from email
            domain: Email domain
            data: Available data

        Returns:
            List of related emails
        """
        related = set()

        # Look for email variations
        variations = self._generate_email_variations(username, domain)
        related.update(variations)

        # Extract from accounts data
        accounts = data.get('accounts', [])
        for account in accounts:
            if isinstance(account, dict):
                account_email = account.get('email')
                if account_email and account_email != email:
                    related.add(account_email)

        # Extract from breach data
        breaches = data.get('breaches', [])
        for breach in breaches:
            if isinstance(breach, dict):
                breach_email = breach.get('email')
                if breach_email and breach_email != email:
                    related.add(breach_email)

        # Remove the original email
        related.discard(email)

        return list(related)

    def _generate_email_variations(self, username: str, domain: str) -> List[str]:
        """Generate email variations"""
        variations = []

        # Common variations
        base_variations = [
            username,
            username.replace('.', ''),
            username.replace('_', ''),
            username.replace('-', ''),
        ]

        # Add numbers
        for base in base_variations:
            variations.append(f"{base}@{domain}")
            for i in range(1, 10):
                variations.append(f"{base}{i}@{domain}")

        return variations

    def _extract_usernames(self, email: str, data: Dict[str, Any]) -> List[str]:
        """
        Extract potential usernames

        Args:
            email: Email address
            data: Available data

        Returns:
            List of potential usernames
        """
        usernames = set()

        # Add email prefix
        if '@' in email:
            usernames.add(email.split('@')[0])

        # Extract from accounts
        accounts = data.get('accounts', [])
        for account in accounts:
            if isinstance(account, dict):
                # Look for username fields
                for field in ['username', 'user', 'handle', 'name']:
                    value = account.get(field)
                    if value:
                        usernames.add(str(value).lower())

                # Extract from platform
                platform = account.get('platform', '')
                if platform:
                    # Try to extract username from URL or identifier
                    username = self._extract_username_from_platform(platform, account)
                    if username:
                        usernames.add(username)

        # Generate variations
        email_prefix = email.split('@')[0] if '@' in email else email
        username_variations = [
            email_prefix,
            email_prefix.replace('.', ''),
            email_prefix.replace('_', ''),
            email_prefix.replace('-', ''),
        ]
        usernames.update(username_variations)

        return list(usernames)

    def _extract_username_from_platform(self, platform: str, account: Dict[str, Any]) -> Optional[str]:
        """Extract username from platform account data"""
        # Look for URL field
        url = account.get('url', '')
        if url:
            # Extract username from URL
            match = re.search(r'/([^/]+)/?$', url)
            if match:
                return match.group(1)

        return None

    def _correlate_social_media(self,
                                username: str,
                                related_usernames: List[str],
                                data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Correlate social media accounts

        Args:
            username: Primary username
            related_usernames: Related usernames
            data: Available data

        Returns:
            List of social media accounts
        """
        social_accounts = []

        # Get accounts from data
        accounts = data.get('accounts', [])

        for account in accounts:
            if not isinstance(account, dict):
                continue

            platform = account.get('platform', '').lower()

            # Check if it's a known social platform
            if platform in self.SOCIAL_PLATFORMS:
                social_accounts.append({
                    'platform': platform,
                    'username': account.get('username', username),
                    'url': account.get('url', self.SOCIAL_PLATFORMS[platform].format(username)),
                    'exists': account.get('exists', False),
                    'verified': account.get('verified', False),
                    'additional_info': account.get('additional_info', {})
                })

        return social_accounts

    def _find_shared_attributes(self, email: str, data: Dict[str, Any]) -> Dict[str, List[str]]:
        """
        Find shared attributes across sources

        Args:
            email: Email address
            data: Available data

        Returns:
            Dictionary of shared attributes
        """
        attributes = defaultdict(set)

        # Extract attributes from various sources
        accounts = data.get('accounts', [])
        for account in accounts:
            if not isinstance(account, dict):
                continue

            # Collect names
            for name_field in ['name', 'full_name', 'display_name']:
                name = account.get(name_field)
                if name:
                    attributes['names'].add(str(name))

            # Collect usernames
            username = account.get('username')
            if username:
                attributes['usernames'].add(str(username))

            # Collect locations
            location = account.get('location')
            if location:
                attributes['locations'].add(str(location))

            # Collect phone numbers
            phone = account.get('phone')
            if phone:
                attributes['phones'].add(str(phone))

        # Convert sets to lists
        return {key: list(values) for key, values in attributes.items()}

    def _calculate_correlation_confidence(self,
                                         related_emails: List[str],
                                         related_usernames: List[str],
                                         social_media: List[Dict[str, Any]]) -> float:
        """
        Calculate correlation confidence score

        Args:
            related_emails: Related emails found
            related_usernames: Related usernames found
            social_media: Social media accounts found

        Returns:
            Confidence score (0-1)
        """
        score = 0.0

        # More related emails = higher confidence
        if len(related_emails) > 0:
            score += min(len(related_emails) * 0.1, 0.3)

        # More usernames = higher confidence
        if len(related_usernames) > 1:
            score += min(len(related_usernames) * 0.05, 0.2)

        # Verified social media accounts = higher confidence
        verified_count = sum(1 for acc in social_media if acc.get('verified'))
        score += min(verified_count * 0.15, 0.3)

        # Social media presence = higher confidence
        active_accounts = sum(1 for acc in social_media if acc.get('exists'))
        score += min(active_accounts * 0.05, 0.2)

        return min(score, 1.0)

    def check_breaches(self, email: str) -> List[Dict[str, Any]]:
        """
        Check for data breaches
        (Placeholder for HIBP or similar integration)

        Args:
            email: Email to check

        Returns:
            List of breaches
        """
        # This is a placeholder
        # In production, integrate with Have I Been Pwned API
        self.logger.info(f"Breach check for {email}")
        return []

    def find_email_variations(self, username: str, domain: str) -> List[str]:
        """
        Find email variations

        Args:
            username: Username
            domain: Domain

        Returns:
            List of email variations
        """
        return self._generate_email_variations(username, domain)

    def find_social_media(self, email: str) -> List[Dict[str, Any]]:
        """
        Find social media accounts

        Args:
            email: Email address

        Returns:
            List of social media accounts
        """
        username = self._extract_username(email)
        accounts = []

        for platform, url_template in self.SOCIAL_PLATFORMS.items():
            accounts.append({
                'platform': platform,
                'username': username,
                'url': url_template.format(username),
                'exists': False,  # Would need to check
                'confidence': 0.5
            })

        return accounts

    def link_accounts(self, emails: List[str]) -> Dict[str, Any]:
        """
        Link multiple email accounts together

        Args:
            emails: List of email addresses

        Returns:
            Linked account information
        """
        # Extract all usernames
        all_usernames = set()
        all_domains = set()

        for email in emails:
            username = self._extract_username(email)
            domain = email.split('@')[1] if '@' in email else ''

            all_usernames.add(username)
            if domain:
                all_domains.add(domain)

        # Find common patterns
        common_prefixes = self._find_common_substrings(list(all_usernames))

        return {
            'emails': emails,
            'usernames': list(all_usernames),
            'domains': list(all_domains),
            'common_patterns': common_prefixes,
            'likely_same_person': self._calculate_same_person_probability(emails),
            'link_timestamp': datetime.now().isoformat()
        }

    def _find_common_substrings(self, strings: List[str]) -> List[str]:
        """Find common substrings in list of strings"""
        if not strings or len(strings) < 2:
            return []

        common = []
        first = strings[0].lower()

        # Check for common prefixes
        for i in range(1, len(first) + 1):
            prefix = first[:i]
            if all(s.lower().startswith(prefix) for s in strings):
                common.append(prefix)

        return common[-3:] if common else []  # Return last 3

    def _calculate_same_person_probability(self, emails: List[str]) -> float:
        """Calculate probability that emails belong to same person"""
        if len(emails) < 2:
            return 1.0

        score = 0.0

        # Extract usernames
        usernames = [self._extract_username(e) for e in emails]

        # Check for similar usernames
        unique_usernames = set(usernames)
        if len(unique_usernames) == 1:
            score += 0.5  # Same username

        # Check for common patterns
        common_patterns = self._find_common_substrings(usernames)
        if common_patterns:
            score += 0.3

        # Check domains
        domains = [e.split('@')[1] for e in emails if '@' in e]
        unique_domains = set(domains)
        if len(unique_domains) == 1:
            score += 0.2  # Same domain

        return min(score, 1.0)

    def export_correlation(self, result: Dict[str, Any], format: str = 'json') -> str:
        """
        Export correlation results

        Args:
            result: Correlation result
            format: Export format

        Returns:
            Exported data
        """
        if format == 'json':
            return json.dumps(result, indent=2)
        elif format == 'text':
            return self._format_text_correlation(result)
        else:
            raise ValueError(f"Unsupported format: {format}")

    def _format_text_correlation(self, result: Dict[str, Any]) -> str:
        """Format correlation as text"""
        lines = []
        lines.append("=" * 70)
        lines.append("EMAIL CORRELATION REPORT")
        lines.append("=" * 70)
        lines.append(f"\nPrimary Email: {result.get('email')}")
        lines.append(f"Username: {result.get('username')}")
        lines.append(f"Confidence Score: {result.get('confidence_score', 0):.2%}")

        related_emails = result.get('related_emails', [])
        if related_emails:
            lines.append(f"\nRelated Emails ({len(related_emails)}):")
            for email in related_emails[:10]:
                lines.append(f"  - {email}")

        related_usernames = result.get('related_usernames', [])
        if related_usernames:
            lines.append(f"\nRelated Usernames ({len(related_usernames)}):")
            for username in related_usernames[:10]:
                lines.append(f"  - {username}")

        social_media = result.get('social_media_accounts', [])
        if social_media:
            lines.append(f"\nSocial Media Accounts ({len(social_media)}):")
            for account in social_media:
                status = "✓" if account.get('exists') else "?"
                lines.append(f"  {status} {account['platform']}: {account.get('url', 'N/A')}")

        return '\n'.join(lines)


if __name__ == "__main__":
    # Example usage
    correlator = EmailCorrelator()

    # Sample data
    sample_data = {
        'accounts': [
            {'platform': 'twitter', 'username': 'johndoe', 'exists': True},
            {'platform': 'github', 'username': 'john.doe', 'exists': True},
        ],
        'breaches': [],
        'social_media': []
    }

    # Correlate
    result = correlator.correlate("john.doe@example.com", sample_data)
    print(json.dumps(result, indent=2))

    # Link accounts
    linked = correlator.link_accounts([
        "john.doe@example.com",
        "johndoe@gmail.com",
        "j.doe@company.com"
    ])
    print(json.dumps(linked, indent=2))
