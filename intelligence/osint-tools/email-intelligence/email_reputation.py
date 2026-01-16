"""
Email Reputation Analysis
EmailRep.io integration, spam score, malicious activity check
"""

import requests
import json
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import logging
from dataclasses import dataclass
import hashlib


@dataclass
class ReputationScore:
    """Email reputation score"""
    email: str
    reputation: str  # high, medium, low, none
    suspicious: bool
    malicious: bool
    spam_score: int  # 0-100
    first_seen: Optional[str]
    last_seen: Optional[str]
    days_since_creation: Optional[int]
    blacklisted: bool
    malware_activity: bool
    phishing_activity: bool
    credentials_leaked: bool
    data_breach: bool
    profiles: List[str]
    details: Dict[str, Any]


class EmailReputation:
    """
    Email Reputation Analysis System
    Checks reputation, spam scores, and malicious activity
    """

    EMAILREP_API = "https://emailrep.io"

    # Known blacklist providers
    BLACKLISTS = [
        'spamhaus.org',
        'barracudacentral.org',
        'spamcop.net',
        'sorbs.net',
        'uceprotect.net',
        'bl.spamcop.net',
        'zen.spamhaus.org',
        'dnsbl.sorbs.net'
    ]

    def __init__(self, api_key: Optional[str] = None, cache_ttl: int = 3600):
        """
        Initialize Email Reputation system

        Args:
            api_key: EmailRep.io API key (optional for basic usage)
            cache_ttl: Cache time-to-live in seconds
        """
        self.api_key = api_key
        self.cache_ttl = cache_ttl
        self.cache = {}
        self.logger = self._setup_logging()

    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration"""
        logger = logging.getLogger('EmailReputation')
        logger.setLevel(logging.INFO)

        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)

        return logger

    def check(self, email: str, use_cache: bool = True) -> Dict[str, Any]:
        """
        Check email reputation

        Args:
            email: Email to check
            use_cache: Use cached results if available

        Returns:
            Reputation information
        """
        email = email.lower().strip()

        # Check cache
        if use_cache:
            cached = self._get_from_cache(email)
            if cached:
                self.logger.info(f"Using cached reputation for {email}")
                return cached

        # Check EmailRep.io
        emailrep_data = self._check_emailrep(email)

        # Check additional sources
        blacklist_status = self._check_blacklists(email)
        haveibeenpwned_data = self._check_haveibeenpwned(email)

        # Combine results
        result = self._combine_results(email, emailrep_data, blacklist_status, haveibeenpwned_data)

        # Cache result
        self._add_to_cache(email, result)

        return result

    def _check_emailrep(self, email: str) -> Dict[str, Any]:
        """
        Check email reputation via EmailRep.io

        Args:
            email: Email to check

        Returns:
            EmailRep.io response data
        """
        try:
            url = f"{self.EMAILREP_API}/{email}"
            headers = {}

            if self.api_key:
                headers['Key'] = self.api_key

            response = requests.get(url, headers=headers, timeout=10)

            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                return {'error': 'Email not found in database'}
            else:
                self.logger.warning(f"EmailRep.io returned status {response.status_code}")
                return {}

        except requests.RequestException as e:
            self.logger.error(f"EmailRep.io API error: {str(e)}")
            return {}

    def _check_blacklists(self, email: str) -> Dict[str, Any]:
        """
        Check email domain against blacklists

        Args:
            email: Email to check

        Returns:
            Blacklist check results
        """
        try:
            domain = email.split('@')[1]

            blacklisted = []

            # Check domain-based blacklists
            for blacklist in self.BLACKLISTS:
                if self._check_single_blacklist(domain, blacklist):
                    blacklisted.append(blacklist)

            return {
                'blacklisted': len(blacklisted) > 0,
                'blacklists': blacklisted,
                'total_blacklists_checked': len(self.BLACKLISTS)
            }

        except Exception as e:
            self.logger.error(f"Blacklist check error: {str(e)}")
            return {'blacklisted': False, 'blacklists': [], 'error': str(e)}

    def _check_single_blacklist(self, domain: str, blacklist: str) -> bool:
        """
        Check domain against single blacklist

        Args:
            domain: Domain to check
            blacklist: Blacklist provider

        Returns:
            True if blacklisted
        """
        try:
            import dns.resolver

            query = f"{domain}.{blacklist}"
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2
            resolver.lifetime = 2

            try:
                answers = resolver.resolve(query, 'A')
                return True  # Listed if resolves
            except dns.resolver.NXDOMAIN:
                return False  # Not listed
            except:
                return False

        except Exception as e:
            self.logger.debug(f"Blacklist check error for {blacklist}: {str(e)}")
            return False

    def _check_haveibeenpwned(self, email: str) -> Dict[str, Any]:
        """
        Check if email appears in data breaches (HIBP-style check)

        Args:
            email: Email to check

        Returns:
            Breach information
        """
        # Note: This is a placeholder. Actual HIBP API requires API key
        # and should be implemented with proper rate limiting

        try:
            # For demo purposes, return empty results
            # In production, implement actual HIBP API integration
            return {
                'breaches': [],
                'breach_count': 0,
                'pastes': [],
                'paste_count': 0
            }
        except Exception as e:
            self.logger.error(f"HIBP check error: {str(e)}")
            return {'breaches': [], 'breach_count': 0}

    def _combine_results(self,
                        email: str,
                        emailrep_data: Dict,
                        blacklist_data: Dict,
                        breach_data: Dict) -> Dict[str, Any]:
        """
        Combine results from all sources

        Args:
            email: Email address
            emailrep_data: EmailRep.io data
            blacklist_data: Blacklist check data
            breach_data: Breach data

        Returns:
            Combined reputation data
        """
        # Extract EmailRep.io data
        reputation = emailrep_data.get('reputation', 'none')
        suspicious = emailrep_data.get('suspicious', False)

        # Calculate spam score
        spam_score = self._calculate_spam_score(emailrep_data, blacklist_data)

        # Determine if malicious
        malicious = (
            emailrep_data.get('details', {}).get('malicious_activity', False) or
            emailrep_data.get('details', {}).get('credentials_leaked', False) or
            blacklist_data.get('blacklisted', False)
        )

        # Extract details
        details = emailrep_data.get('details', {})

        return {
            'email': email,
            'reputation': reputation,
            'suspicious': suspicious,
            'malicious': malicious,
            'spam_score': spam_score,
            'first_seen': emailrep_data.get('first_seen'),
            'last_seen': emailrep_data.get('last_seen'),
            'days_since_creation': emailrep_data.get('days_since_domain_creation'),
            'blacklisted': blacklist_data.get('blacklisted', False),
            'blacklists': blacklist_data.get('blacklists', []),
            'malware_activity': details.get('malware_activity', False),
            'phishing_activity': details.get('phishing_activity', False),
            'credentials_leaked': details.get('credentials_leaked', False),
            'data_breach': details.get('data_breach', False),
            'breach_count': breach_data.get('breach_count', 0),
            'profiles': emailrep_data.get('references', 0),
            'spam': details.get('spam', False),
            'spoofable': details.get('spoofable', False),
            'deliverable': details.get('deliverable', True),
            'accept_all': details.get('accept_all', False),
            'valid_mx': details.get('valid_mx', True),
            'primary_mx': details.get('primary_mx'),
            'domain_reputation': details.get('domain_reputation', 'none'),
            'new_domain': details.get('new_domain', False),
            'domain_exists': emailrep_data.get('domain_exists', True),
            'free_provider': details.get('free_provider', False),
            'disposable': details.get('disposable', False),
            'custom_grammar': details.get('custom_grammar', False),
            'honeypot': details.get('honeypot', False),
            'dark_web': details.get('dark_web', False),
            'check_timestamp': datetime.now().isoformat()
        }

    def _calculate_spam_score(self, emailrep_data: Dict, blacklist_data: Dict) -> int:
        """
        Calculate spam score (0-100)

        Args:
            emailrep_data: EmailRep.io data
            blacklist_data: Blacklist data

        Returns:
            Spam score
        """
        score = 0
        details = emailrep_data.get('details', {})

        # Reputation-based scoring
        reputation = emailrep_data.get('reputation', 'none')
        if reputation == 'low':
            score += 40
        elif reputation == 'medium':
            score += 20
        elif reputation == 'high':
            score -= 10

        # Activity-based scoring
        if details.get('spam', False):
            score += 30
        if details.get('malicious_activity', False):
            score += 25
        if details.get('phishing_activity', False):
            score += 25
        if details.get('credentials_leaked', False):
            score += 20

        # Blacklist scoring
        if blacklist_data.get('blacklisted', False):
            score += 30

        # Domain-based scoring
        if details.get('new_domain', False):
            score += 15
        if details.get('disposable', False):
            score += 25
        if details.get('suspicious', False):
            score += 20

        return min(max(score, 0), 100)

    def _get_from_cache(self, email: str) -> Optional[Dict[str, Any]]:
        """Get cached reputation data"""
        if email in self.cache:
            cached_data, timestamp = self.cache[email]
            if datetime.now() - timestamp < timedelta(seconds=self.cache_ttl):
                return cached_data
            else:
                del self.cache[email]
        return None

    def _add_to_cache(self, email: str, data: Dict[str, Any]) -> None:
        """Add reputation data to cache"""
        self.cache[email] = (data, datetime.now())

    def clear_cache(self) -> None:
        """Clear reputation cache"""
        self.cache.clear()
        self.logger.info("Cache cleared")

    def get_risk_assessment(self, email: str) -> Dict[str, Any]:
        """
        Get comprehensive risk assessment

        Args:
            email: Email to assess

        Returns:
            Risk assessment
        """
        reputation = self.check(email)

        risk_factors = []
        risk_score = 0

        # Evaluate risk factors
        if reputation.get('malicious'):
            risk_factors.append('Malicious activity detected')
            risk_score += 40

        if reputation.get('suspicious'):
            risk_factors.append('Suspicious behavior detected')
            risk_score += 25

        if reputation.get('blacklisted'):
            risk_factors.append('Listed on spam blacklists')
            risk_score += 30

        if reputation.get('credentials_leaked'):
            risk_factors.append('Credentials leaked in breach')
            risk_score += 20

        if reputation.get('phishing_activity'):
            risk_factors.append('Phishing activity detected')
            risk_score += 35

        if reputation.get('disposable'):
            risk_factors.append('Disposable email address')
            risk_score += 15

        # Determine risk level
        if risk_score >= 75:
            risk_level = 'CRITICAL'
        elif risk_score >= 50:
            risk_level = 'HIGH'
        elif risk_score >= 25:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'

        return {
            'email': email,
            'risk_level': risk_level,
            'risk_score': min(risk_score, 100),
            'risk_factors': risk_factors,
            'spam_score': reputation.get('spam_score', 0),
            'reputation': reputation.get('reputation', 'none'),
            'recommendation': self._get_recommendation(risk_level),
            'assessment_timestamp': datetime.now().isoformat()
        }

    def _get_recommendation(self, risk_level: str) -> str:
        """Get recommendation based on risk level"""
        recommendations = {
            'CRITICAL': 'DO NOT ENGAGE - Block immediately and report',
            'HIGH': 'CAUTION - Verify through alternative means before engaging',
            'MEDIUM': 'WARNING - Proceed with caution and enhanced verification',
            'LOW': 'ACCEPTABLE - Standard verification procedures apply'
        }
        return recommendations.get(risk_level, 'Unknown risk level')

    def batch_check(self, emails: List[str]) -> List[Dict[str, Any]]:
        """
        Check reputation for multiple emails

        Args:
            emails: List of emails to check

        Returns:
            List of reputation results
        """
        results = []
        for email in emails:
            try:
                result = self.check(email)
                results.append(result)
            except Exception as e:
                self.logger.error(f"Failed to check {email}: {str(e)}")
                results.append({'email': email, 'error': str(e)})

        return results


if __name__ == "__main__":
    # Example usage
    reputation = EmailReputation(api_key='YOUR_API_KEY')

    # Single check
    result = reputation.check("test@example.com")
    print(json.dumps(result, indent=2))

    # Risk assessment
    assessment = reputation.get_risk_assessment("suspicious@example.com")
    print(json.dumps(assessment, indent=2))

    # Batch check
    emails = ["user1@example.com", "user2@example.com", "user3@example.com"]
    results = reputation.batch_check(emails)
    print(f"Checked {len(results)} emails")
