"""
WHOIS Analyzer - Domain Registration Intelligence
Comprehensive WHOIS lookup and analysis
"""

import whois
import re
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any
import socket


class WhoisAnalyzer:
    """
    WHOIS intelligence gathering and analysis
    Extracts domain registration and ownership information
    """

    def __init__(self):
        """Initialize WHOIS analyzer"""
        self.logger = logging.getLogger('WhoisAnalyzer')
        self.privacy_services = [
            'privacy protect',
            'whois guard',
            'domains by proxy',
            'perfect privacy',
            'private registration',
            'contact privacy',
            'redacted for privacy',
            'data protected',
            'gdpr masked'
        ]

    def analyze(self, domain: str) -> Dict[str, Any]:
        """
        Perform comprehensive WHOIS analysis

        Args:
            domain: Target domain name

        Returns:
            WHOIS intelligence data
        """
        self.logger.info(f"Analyzing WHOIS for {domain}")

        results = {
            'domain': domain,
            'timestamp': datetime.utcnow().isoformat(),
            'registered': False,
            'registrar': None,
            'registrant': {},
            'admin': {},
            'tech': {},
            'dates': {},
            'nameservers': [],
            'status': [],
            'privacy_service': False,
            'privacy_service_name': None,
            'raw_whois': None
        }

        try:
            # Perform WHOIS lookup
            w = whois.whois(domain)

            if w.domain_name:
                results['registered'] = True

                # Registrar information
                results['registrar'] = w.registrar

                # Registration dates
                results['dates'] = {
                    'created': self._format_date(w.creation_date),
                    'updated': self._format_date(w.updated_date),
                    'expires': self._format_date(w.expiration_date),
                    'age_days': self._calculate_age(w.creation_date)
                }

                # Registrant information
                results['registrant'] = {
                    'name': w.name,
                    'organization': w.org,
                    'email': self._extract_email(w.emails),
                    'country': w.country
                }

                # Nameservers
                if w.name_servers:
                    if isinstance(w.name_servers, list):
                        results['nameservers'] = [ns.lower() for ns in w.name_servers]
                    else:
                        results['nameservers'] = [w.name_servers.lower()]

                # Domain status
                if w.status:
                    if isinstance(w.status, list):
                        results['status'] = w.status
                    else:
                        results['status'] = [w.status]

                # Privacy service detection
                privacy_detected, service_name = self._detect_privacy_service(w)
                results['privacy_service'] = privacy_detected
                results['privacy_service_name'] = service_name

                # Raw WHOIS text
                results['raw_whois'] = str(w.text) if hasattr(w, 'text') else None

        except Exception as e:
            self.logger.error(f"WHOIS lookup failed for {domain}: {e}")
            results['error'] = str(e)

        return results

    def _format_date(self, date_value) -> Optional[str]:
        """Format date value to ISO string"""
        if not date_value:
            return None

        try:
            # Handle list of dates (take first one)
            if isinstance(date_value, list):
                date_value = date_value[0]

            # Convert to ISO format
            if isinstance(date_value, datetime):
                return date_value.isoformat()
            elif isinstance(date_value, str):
                return date_value

        except Exception:
            pass

        return None

    def _calculate_age(self, creation_date) -> Optional[int]:
        """Calculate domain age in days"""
        if not creation_date:
            return None

        try:
            if isinstance(creation_date, list):
                creation_date = creation_date[0]

            if isinstance(creation_date, datetime):
                age = datetime.now() - creation_date
                return age.days
        except Exception:
            pass

        return None

    def _extract_email(self, emails) -> Optional[str]:
        """Extract primary email from WHOIS data"""
        if not emails:
            return None

        if isinstance(emails, list):
            return emails[0] if emails else None

        return str(emails)

    def _detect_privacy_service(self, whois_data) -> tuple:
        """
        Detect if domain uses privacy protection service

        Returns:
            (is_privacy_service: bool, service_name: str)
        """
        # Check all text fields
        text_fields = [
            str(whois_data.name or ''),
            str(whois_data.org or ''),
            str(whois_data.emails or ''),
            str(whois_data.registrant or ''),
            str(whois_data.text or '') if hasattr(whois_data, 'text') else ''
        ]

        combined_text = ' '.join(text_fields).lower()

        for service in self.privacy_services:
            if service in combined_text:
                return True, service.title()

        return False, None

    def check_availability(self, domain: str) -> bool:
        """
        Check if domain is available for registration

        Args:
            domain: Domain name to check

        Returns:
            True if available, False if registered
        """
        try:
            w = whois.whois(domain)
            return not bool(w.domain_name)
        except Exception:
            # If WHOIS fails, assume domain might be available
            return True

    def get_expiration_info(self, domain: str) -> Dict[str, Any]:
        """
        Get domain expiration information

        Args:
            domain: Target domain

        Returns:
            Expiration information and warnings
        """
        results = {
            'domain': domain,
            'expires': None,
            'days_until_expiration': None,
            'warning': None
        }

        try:
            w = whois.whois(domain)

            if w.expiration_date:
                exp_date = w.expiration_date
                if isinstance(exp_date, list):
                    exp_date = exp_date[0]

                results['expires'] = exp_date.isoformat()

                days_left = (exp_date - datetime.now()).days
                results['days_until_expiration'] = days_left

                # Generate warnings
                if days_left < 0:
                    results['warning'] = 'Domain has expired!'
                elif days_left < 30:
                    results['warning'] = f'Domain expires in {days_left} days - renew soon!'
                elif days_left < 90:
                    results['warning'] = f'Domain expires in {days_left} days'

        except Exception as e:
            results['error'] = str(e)

        return results

    def compare_whois(self, domain1: str, domain2: str) -> Dict[str, Any]:
        """
        Compare WHOIS information between two domains

        Args:
            domain1: First domain
            domain2: Second domain

        Returns:
            Comparison results
        """
        whois1 = self.analyze(domain1)
        whois2 = self.analyze(domain2)

        comparison = {
            'domains': [domain1, domain2],
            'same_registrar': whois1.get('registrar') == whois2.get('registrar'),
            'same_registrant': (
                whois1.get('registrant', {}).get('email') ==
                whois2.get('registrant', {}).get('email')
            ),
            'same_nameservers': (
                set(whois1.get('nameservers', [])) ==
                set(whois2.get('nameservers', []))
            ),
            'similar_creation_date': self._dates_similar(
                whois1.get('dates', {}).get('created'),
                whois2.get('dates', {}).get('created')
            ),
            'details': {
                domain1: whois1,
                domain2: whois2
            }
        }

        # Calculate similarity score
        score = sum([
            comparison['same_registrar'],
            comparison['same_registrant'],
            comparison['same_nameservers'],
            comparison['similar_creation_date']
        ])

        comparison['similarity_score'] = score / 4 * 100

        return comparison

    def _dates_similar(self, date1: Optional[str],
                       date2: Optional[str],
                       threshold_days: int = 30) -> bool:
        """Check if two dates are similar (within threshold)"""
        if not date1 or not date2:
            return False

        try:
            d1 = datetime.fromisoformat(date1)
            d2 = datetime.fromisoformat(date2)
            diff = abs((d1 - d2).days)
            return diff <= threshold_days
        except Exception:
            return False

    def get_nameserver_info(self, domain: str) -> Dict[str, Any]:
        """
        Get detailed nameserver information

        Args:
            domain: Target domain

        Returns:
            Nameserver details including IPs
        """
        results = {
            'domain': domain,
            'nameservers': []
        }

        try:
            w = whois.whois(domain)

            if w.name_servers:
                nameservers = w.name_servers if isinstance(w.name_servers, list) else [w.name_servers]

                for ns in nameservers:
                    ns_info = {
                        'hostname': ns.lower(),
                        'ip_addresses': []
                    }

                    # Resolve nameserver IP
                    try:
                        ip_addresses = socket.getaddrinfo(ns, None)
                        ns_info['ip_addresses'] = list(set([ip[4][0] for ip in ip_addresses]))
                    except Exception as e:
                        ns_info['error'] = str(e)

                    results['nameservers'].append(ns_info)

        except Exception as e:
            results['error'] = str(e)

        return results


def main():
    """Example usage"""
    analyzer = WhoisAnalyzer()

    # Analyze domain
    results = analyzer.analyze("example.com")
    print(f"Domain: {results['domain']}")
    print(f"Registered: {results['registered']}")
    print(f"Registrar: {results['registrar']}")
    print(f"Privacy Service: {results['privacy_service']}")
    print(f"Nameservers: {results['nameservers']}")

    # Check expiration
    exp_info = analyzer.get_expiration_info("example.com")
    print(f"\nExpiration: {exp_info['expires']}")
    print(f"Days until expiration: {exp_info['days_until_expiration']}")

    if exp_info.get('warning'):
        print(f"Warning: {exp_info['warning']}")


if __name__ == "__main__":
    main()
