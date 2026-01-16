"""
WHOIS Intelligence Module
Domain registration and ownership intelligence gathering
"""

import logging
import whois
import requests
from typing import Dict, Optional, List
import json
from datetime import datetime
import socket


class WhoisIntelligence:
    """WHOIS Data Intelligence"""

    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize WHOIS Intelligence module

        Args:
            config: Configuration dictionary
        """
        self.logger = logging.getLogger(__name__)
        self.config = config or {}

        # API keys for enhanced WHOIS services
        self.whoisxml_key = self.config.get('whoisxml_key')
        self.domaintools_key = self.config.get('domaintools_key')

        # Cache
        self.cache = {}

    def lookup(self, domain: str, historical: bool = False) -> Dict:
        """
        Perform comprehensive WHOIS lookup

        Args:
            domain: Domain name to lookup
            historical: Include historical WHOIS data

        Returns:
            Dictionary with WHOIS intelligence
        """
        # Clean domain
        domain = self._clean_domain(domain)

        # Check cache
        if domain in self.cache and not historical:
            return self.cache[domain]

        result = {
            'domain': domain,
            'timestamp': datetime.now().isoformat(),
            'whois_data': {},
            'registrant': {},
            'registrar': {},
            'dates': {},
            'nameservers': [],
            'status': [],
            'privacy_protected': False,
            'historical': []
        }

        try:
            # Basic WHOIS lookup
            whois_data = self._basic_whois(domain)
            result['whois_data'] = whois_data

            # Parse registrant information
            result['registrant'] = self._parse_registrant(whois_data)

            # Parse registrar information
            result['registrar'] = self._parse_registrar(whois_data)

            # Parse dates
            result['dates'] = self._parse_dates(whois_data)

            # Parse nameservers
            result['nameservers'] = self._parse_nameservers(whois_data)

            # Parse status
            result['status'] = self._parse_status(whois_data)

            # Detect privacy protection
            result['privacy_protected'] = self._detect_privacy(whois_data)

            # Get historical data if requested
            if historical:
                result['historical'] = self._get_historical_whois(domain)

            # Enhanced lookup with premium APIs
            if self.whoisxml_key:
                enhanced = self._whoisxml_lookup(domain)
                result['enhanced'] = enhanced

        except Exception as e:
            self.logger.error(f"WHOIS lookup error for {domain}: {e}")
            result['error'] = str(e)

        # Cache result
        if not historical:
            self.cache[domain] = result

        return result

    def _clean_domain(self, domain: str) -> str:
        """Clean and normalize domain name"""
        # Remove protocol
        domain = domain.replace('http://', '').replace('https://', '')

        # Remove path
        domain = domain.split('/')[0]

        # Remove port
        domain = domain.split(':')[0]

        # Remove www
        if domain.startswith('www.'):
            domain = domain[4:]

        return domain.lower()

    def _basic_whois(self, domain: str) -> Dict:
        """Perform basic WHOIS lookup"""
        try:
            w = whois.whois(domain)

            # Convert to dict, handling various formats
            if isinstance(w, dict):
                return w
            else:
                return {
                    'domain_name': w.domain_name,
                    'registrar': w.registrar,
                    'whois_server': w.whois_server,
                    'creation_date': w.creation_date,
                    'expiration_date': w.expiration_date,
                    'updated_date': w.updated_date,
                    'status': w.status,
                    'nameservers': w.name_servers,
                    'emails': w.emails,
                    'registrant_name': w.name,
                    'registrant_org': w.org,
                    'registrant_address': w.address,
                    'registrant_city': w.city,
                    'registrant_state': w.state,
                    'registrant_zipcode': w.zipcode,
                    'registrant_country': w.country
                }
        except Exception as e:
            self.logger.error(f"Basic WHOIS lookup failed: {e}")
            return {}

    def _parse_registrant(self, whois_data: Dict) -> Dict:
        """Parse registrant information"""
        return {
            'name': whois_data.get('registrant_name') or whois_data.get('name'),
            'organization': whois_data.get('registrant_org') or whois_data.get('org'),
            'email': self._get_first(whois_data.get('emails')),
            'phone': whois_data.get('registrant_phone'),
            'address': whois_data.get('registrant_address') or whois_data.get('address'),
            'city': whois_data.get('registrant_city') or whois_data.get('city'),
            'state': whois_data.get('registrant_state') or whois_data.get('state'),
            'postal_code': whois_data.get('registrant_zipcode') or whois_data.get('zipcode'),
            'country': whois_data.get('registrant_country') or whois_data.get('country')
        }

    def _parse_registrar(self, whois_data: Dict) -> Dict:
        """Parse registrar information"""
        return {
            'name': whois_data.get('registrar'),
            'whois_server': whois_data.get('whois_server'),
            'url': whois_data.get('registrar_url'),
            'abuse_email': whois_data.get('registrar_abuse_contact_email'),
            'abuse_phone': whois_data.get('registrar_abuse_contact_phone')
        }

    def _parse_dates(self, whois_data: Dict) -> Dict:
        """Parse important dates"""
        dates = {
            'creation_date': None,
            'expiration_date': None,
            'updated_date': None
        }

        for key in ['creation_date', 'expiration_date', 'updated_date']:
            date_value = whois_data.get(key)
            if date_value:
                # Handle list of dates (take first)
                if isinstance(date_value, list):
                    date_value = date_value[0]

                # Convert to ISO format
                if hasattr(date_value, 'isoformat'):
                    dates[key] = date_value.isoformat()
                else:
                    dates[key] = str(date_value)

        return dates

    def _parse_nameservers(self, whois_data: Dict) -> List[str]:
        """Parse nameservers"""
        nameservers = whois_data.get('nameservers') or whois_data.get('name_servers') or []

        if isinstance(nameservers, str):
            nameservers = [nameservers]

        # Clean and normalize
        return [ns.lower().strip() for ns in nameservers if ns]

    def _parse_status(self, whois_data: Dict) -> List[str]:
        """Parse domain status"""
        status = whois_data.get('status') or []

        if isinstance(status, str):
            status = [status]

        return [s.strip() for s in status if s]

    def _detect_privacy(self, whois_data: Dict) -> bool:
        """Detect if domain uses privacy protection"""
        privacy_indicators = [
            'privacy', 'private', 'proxy', 'protected',
            'whoisguard', 'domainproxy', 'contact privacy'
        ]

        # Check registrant info
        registrant_name = str(whois_data.get('registrant_name', '')).lower()
        registrant_org = str(whois_data.get('org', '')).lower()
        registrant_email = str(self._get_first(whois_data.get('emails', []))).lower()

        for indicator in privacy_indicators:
            if (indicator in registrant_name or
                indicator in registrant_org or
                indicator in registrant_email):
                return True

        return False

    def _get_first(self, value) -> Optional[str]:
        """Get first item from list or return value"""
        if isinstance(value, list) and value:
            return value[0]
        return value

    def _get_historical_whois(self, domain: str) -> List[Dict]:
        """
        Get historical WHOIS data

        This would integrate with services like:
        - DomainTools
        - WhoisXML API Historical
        - SecurityTrails
        """
        historical = []

        try:
            if self.domaintools_key:
                # DomainTools historical WHOIS
                url = f"https://api.domaintools.com/v1/{domain}/whois/history"
                params = {'api_key': self.domaintools_key}

                response = requests.get(url, params=params, timeout=30)
                response.raise_for_status()
                data = response.json()

                for record in data.get('history', []):
                    historical.append({
                        'date': record.get('date'),
                        'registrant': record.get('registrant'),
                        'registrar': record.get('registrar'),
                        'nameservers': record.get('nameservers')
                    })

        except Exception as e:
            self.logger.error(f"Historical WHOIS lookup error: {e}")

        return historical

    def _whoisxml_lookup(self, domain: str) -> Dict:
        """Enhanced WHOIS lookup using WhoisXML API"""
        try:
            url = "https://www.whoisxmlapi.com/whoisserver/WhoisService"
            params = {
                'apiKey': self.whoisxml_key,
                'domainName': domain,
                'outputFormat': 'JSON'
            }

            response = requests.get(url, params=params, timeout=30)
            response.raise_for_status()
            data = response.json()

            return {
                'registrant': data.get('WhoisRecord', {}).get('registrant'),
                'administrative': data.get('WhoisRecord', {}).get('administrativeContact'),
                'technical': data.get('WhoisRecord', {}).get('technicalContact'),
                'audit': data.get('WhoisRecord', {}).get('audit'),
                'estimated_domain_age': data.get('WhoisRecord', {}).get('estimatedDomainAge'),
                'contact_email': data.get('WhoisRecord', {}).get('contactEmail')
            }
        except Exception as e:
            self.logger.error(f"WhoisXML lookup error: {e}")
            return {}

    def check_availability(self, domain: str) -> Dict:
        """
        Check if domain is available for registration

        Args:
            domain: Domain to check

        Returns:
            Availability information
        """
        result = {
            'domain': domain,
            'available': False,
            'registered': False,
            'expires': None
        }

        try:
            whois_data = self._basic_whois(domain)

            if whois_data and whois_data.get('domain_name'):
                result['registered'] = True
                result['available'] = False

                expiration = whois_data.get('expiration_date')
                if expiration:
                    if isinstance(expiration, list):
                        expiration = expiration[0]
                    result['expires'] = expiration.isoformat() if hasattr(expiration, 'isoformat') else str(expiration)
            else:
                result['available'] = True
                result['registered'] = False

        except Exception as e:
            # If WHOIS fails, domain might be available
            self.logger.info(f"Domain {domain} might be available: {e}")
            result['available'] = True

        return result

    def get_related_domains(self, domain: str) -> List[str]:
        """
        Find related domains (same registrant, similar names, etc.)

        Args:
            domain: Domain to find relations for

        Returns:
            List of related domains
        """
        related = []

        try:
            # Get WHOIS data
            whois_data = self.lookup(domain)

            # Extract registrant email
            registrant_email = whois_data.get('registrant', {}).get('email')

            if registrant_email and self.domaintools_key:
                # Use DomainTools reverse WHOIS
                url = f"https://api.domaintools.com/v1/reverse-whois"
                params = {
                    'api_key': self.domaintools_key,
                    'terms': registrant_email
                }

                response = requests.get(url, params=params, timeout=30)
                response.raise_for_status()
                data = response.json()

                related = data.get('domains', [])

        except Exception as e:
            self.logger.error(f"Related domains lookup error: {e}")

        return related

    def monitor_domain(self, domain: str) -> Dict:
        """
        Monitor domain for changes

        Args:
            domain: Domain to monitor

        Returns:
            Monitoring information
        """
        current = self.lookup(domain)

        # Check if we have previous data
        cache_key = f"{domain}_history"
        previous = self.cache.get(cache_key)

        changes = {
            'domain': domain,
            'monitored_at': datetime.now().isoformat(),
            'changes_detected': False,
            'changes': []
        }

        if previous:
            # Compare registrant
            if current['registrant'] != previous['registrant']:
                changes['changes'].append({
                    'type': 'registrant',
                    'old': previous['registrant'],
                    'new': current['registrant']
                })

            # Compare nameservers
            if set(current['nameservers']) != set(previous['nameservers']):
                changes['changes'].append({
                    'type': 'nameservers',
                    'old': previous['nameservers'],
                    'new': current['nameservers']
                })

            # Compare dates
            if current['dates'] != previous['dates']:
                changes['changes'].append({
                    'type': 'dates',
                    'old': previous['dates'],
                    'new': current['dates']
                })

            changes['changes_detected'] = len(changes['changes']) > 0

        # Store current as history
        self.cache[cache_key] = current

        return changes

    def batch_lookup(self, domains: List[str]) -> List[Dict]:
        """Batch WHOIS lookup for multiple domains"""
        results = []
        for domain in domains:
            try:
                result = self.lookup(domain)
                results.append(result)
            except Exception as e:
                self.logger.error(f"Batch lookup failed for {domain}: {e}")
                results.append({'domain': domain, 'error': str(e)})
        return results


if __name__ == "__main__":
    # Example usage
    whois_intel = WhoisIntelligence({
        'whoisxml_key': 'your_key_here'
    })

    # WHOIS lookup
    result = whois_intel.lookup("google.com")
    print(json.dumps(result, indent=2, default=str))

    # Check availability
    availability = whois_intel.check_availability("example-domain-12345.com")
    print(f"Available: {availability['available']}")
