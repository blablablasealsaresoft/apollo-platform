"""
IP Geolocation Module
Comprehensive IP address geolocation and intelligence gathering
"""

import logging
import requests
import socket
from typing import Dict, Optional, List
from datetime import datetime, timedelta
import json
from pathlib import Path
import geoip2.database
import geoip2.errors


class IPGeolocation:
    """IP Geolocation and Intelligence"""

    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize IP Geolocation module

        Args:
            config: Configuration dictionary
        """
        self.logger = logging.getLogger(__name__)
        self.config = config or {}

        # API keys
        self.ipinfo_token = self.config.get('ipinfo_token')
        self.ipgeolocation_key = self.config.get('ipgeolocation_key')
        self.ip2location_key = self.config.get('ip2location_key')

        # MaxMind database path
        self.maxmind_db_path = self.config.get('maxmind_db_path', './GeoLite2-City.mmdb')

        # Cache
        self.cache = {}
        self.cache_ttl = self.config.get('cache_ttl', 3600)

        # Initialize MaxMind reader
        self.maxmind_reader = None
        self._init_maxmind()

    def _init_maxmind(self):
        """Initialize MaxMind GeoIP2 database reader"""
        try:
            if Path(self.maxmind_db_path).exists():
                self.maxmind_reader = geoip2.database.Reader(self.maxmind_db_path)
                self.logger.info("MaxMind GeoIP2 database loaded")
            else:
                self.logger.warning(f"MaxMind database not found at {self.maxmind_db_path}")
        except Exception as e:
            self.logger.error(f"Failed to load MaxMind database: {e}")

    def geolocate(self, ip: str, sources: Optional[List[str]] = None) -> Dict:
        """
        Geolocate IP address using multiple sources

        Args:
            ip: IP address to geolocate
            sources: List of sources to use (maxmind, ipinfo, ipgeolocation, ip2location)

        Returns:
            Dictionary with comprehensive IP intelligence
        """
        # Validate IP
        if not self._validate_ip(ip):
            return {'error': 'Invalid IP address'}

        # Check cache
        if ip in self.cache:
            cache_time, cache_data = self.cache[ip]
            if datetime.now() - cache_time < timedelta(seconds=self.cache_ttl):
                self.logger.info(f"Returning cached data for {ip}")
                return cache_data

        result = {
            'ip': ip,
            'timestamp': datetime.now().isoformat(),
            'location': {},
            'network': {},
            'security': {},
            'sources': []
        }

        # Determine sources to use
        if sources is None:
            sources = ['maxmind', 'ipinfo', 'ipgeolocation', 'ip2location']

        # Query each source
        for source in sources:
            try:
                if source == 'maxmind' and self.maxmind_reader:
                    data = self._query_maxmind(ip)
                    self._merge_data(result, data, 'maxmind')
                elif source == 'ipinfo' and self.ipinfo_token:
                    data = self._query_ipinfo(ip)
                    self._merge_data(result, data, 'ipinfo')
                elif source == 'ipgeolocation' and self.ipgeolocation_key:
                    data = self._query_ipgeolocation(ip)
                    self._merge_data(result, data, 'ipgeolocation')
                elif source == 'ip2location' and self.ip2location_key:
                    data = self._query_ip2location(ip)
                    self._merge_data(result, data, 'ip2location')
            except Exception as e:
                self.logger.error(f"Error querying {source} for {ip}: {e}")

        # Add DNS reverse lookup
        result['hostname'] = self._reverse_dns(ip)

        # Detect VPN/Proxy
        result['security']['is_vpn'] = self._detect_vpn(result)
        result['security']['is_proxy'] = self._detect_proxy(result)
        result['security']['is_tor'] = self._detect_tor(ip)

        # Cache result
        self.cache[ip] = (datetime.now(), result)

        return result

    def _validate_ip(self, ip: str) -> bool:
        """Validate IP address format"""
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            try:
                socket.inet_pton(socket.AF_INET6, ip)
                return True
            except socket.error:
                return False

    def _query_maxmind(self, ip: str) -> Dict:
        """Query MaxMind GeoIP2 database"""
        try:
            response = self.maxmind_reader.city(ip)

            return {
                'location': {
                    'latitude': response.location.latitude,
                    'longitude': response.location.longitude,
                    'accuracy_radius': response.location.accuracy_radius,
                    'city': response.city.name,
                    'country': response.country.name,
                    'country_code': response.country.iso_code,
                    'continent': response.continent.name,
                    'postal_code': response.postal.code,
                    'timezone': response.location.time_zone
                },
                'network': {
                    'asn': None,  # Not in free version
                    'isp': None
                }
            }
        except geoip2.errors.AddressNotFoundError:
            self.logger.warning(f"IP {ip} not found in MaxMind database")
            return {}
        except Exception as e:
            self.logger.error(f"MaxMind query error: {e}")
            return {}

    def _query_ipinfo(self, ip: str) -> Dict:
        """Query IPinfo.io API"""
        try:
            url = f"https://ipinfo.io/{ip}/json"
            headers = {'Authorization': f'Bearer {self.ipinfo_token}'}

            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            data = response.json()

            # Parse location
            loc = data.get('loc', '').split(',')
            lat, lon = (float(loc[0]), float(loc[1])) if len(loc) == 2 else (None, None)

            return {
                'location': {
                    'latitude': lat,
                    'longitude': lon,
                    'city': data.get('city'),
                    'region': data.get('region'),
                    'country': data.get('country'),
                    'postal_code': data.get('postal'),
                    'timezone': data.get('timezone')
                },
                'network': {
                    'hostname': data.get('hostname'),
                    'org': data.get('org'),
                    'asn': data.get('asn', {}).get('asn') if isinstance(data.get('asn'), dict) else None
                },
                'security': {
                    'is_vpn': data.get('privacy', {}).get('vpn', False),
                    'is_proxy': data.get('privacy', {}).get('proxy', False),
                    'is_tor': data.get('privacy', {}).get('tor', False),
                    'is_hosting': data.get('privacy', {}).get('hosting', False)
                }
            }
        except Exception as e:
            self.logger.error(f"IPinfo query error: {e}")
            return {}

    def _query_ipgeolocation(self, ip: str) -> Dict:
        """Query IPGeolocation.io API"""
        try:
            url = f"https://api.ipgeolocation.io/ipgeo"
            params = {
                'apiKey': self.ipgeolocation_key,
                'ip': ip,
                'fields': 'geo,security,isp'
            }

            response = requests.get(url, params=params, timeout=10)
            response.raise_for_status()
            data = response.json()

            return {
                'location': {
                    'latitude': float(data.get('latitude', 0)) if data.get('latitude') else None,
                    'longitude': float(data.get('longitude', 0)) if data.get('longitude') else None,
                    'city': data.get('city'),
                    'region': data.get('state_prov'),
                    'country': data.get('country_name'),
                    'country_code': data.get('country_code2'),
                    'postal_code': data.get('zipcode'),
                    'timezone': data.get('time_zone', {}).get('name')
                },
                'network': {
                    'isp': data.get('isp'),
                    'organization': data.get('organization'),
                    'asn': data.get('asn')
                },
                'security': {
                    'is_proxy': data.get('security', {}).get('is_proxy', False),
                    'proxy_type': data.get('security', {}).get('proxy_type'),
                    'is_tor': data.get('security', {}).get('is_tor', False),
                    'is_threat': data.get('security', {}).get('is_known_attacker', False)
                }
            }
        except Exception as e:
            self.logger.error(f"IPGeolocation query error: {e}")
            return {}

    def _query_ip2location(self, ip: str) -> Dict:
        """Query IP2Location API"""
        try:
            url = f"https://api.ip2location.io/"
            params = {
                'key': self.ip2location_key,
                'ip': ip,
                'format': 'json'
            }

            response = requests.get(url, params=params, timeout=10)
            response.raise_for_status()
            data = response.json()

            return {
                'location': {
                    'latitude': data.get('latitude'),
                    'longitude': data.get('longitude'),
                    'city': data.get('city_name'),
                    'region': data.get('region_name'),
                    'country': data.get('country_name'),
                    'country_code': data.get('country_code'),
                    'postal_code': data.get('zip_code'),
                    'timezone': data.get('time_zone')
                },
                'network': {
                    'isp': data.get('isp'),
                    'asn': data.get('asn'),
                    'domain': data.get('domain')
                },
                'security': {
                    'is_proxy': data.get('is_proxy', False)
                }
            }
        except Exception as e:
            self.logger.error(f"IP2Location query error: {e}")
            return {}

    def _merge_data(self, result: Dict, new_data: Dict, source: str):
        """Merge data from different sources"""
        if not new_data:
            return

        result['sources'].append(source)

        # Merge location data
        for key, value in new_data.get('location', {}).items():
            if value and not result['location'].get(key):
                result['location'][key] = value

        # Merge network data
        for key, value in new_data.get('network', {}).items():
            if value and not result['network'].get(key):
                result['network'][key] = value

        # Merge security data
        for key, value in new_data.get('security', {}).items():
            if value and not result['security'].get(key):
                result['security'][key] = value

    def _reverse_dns(self, ip: str) -> Optional[str]:
        """Perform reverse DNS lookup"""
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except socket.herror:
            return None
        except Exception as e:
            self.logger.error(f"Reverse DNS error: {e}")
            return None

    def _detect_vpn(self, result: Dict) -> bool:
        """Detect if IP is from VPN"""
        # Check security flags from various sources
        is_vpn = result['security'].get('is_vpn', False)

        # Check for known VPN ISPs
        isp = result['network'].get('isp', '').lower()
        vpn_keywords = ['vpn', 'virtual private', 'proxy', 'anonymous']

        if any(keyword in isp for keyword in vpn_keywords):
            return True

        return is_vpn

    def _detect_proxy(self, result: Dict) -> bool:
        """Detect if IP is from proxy"""
        return result['security'].get('is_proxy', False)

    def _detect_tor(self, ip: str) -> bool:
        """Detect if IP is Tor exit node"""
        try:
            # Query Tor exit node list (simplified)
            # In production, maintain local copy of exit node list
            url = f"https://check.torproject.org/cgi-bin/TorBulkExitList.py?ip={ip}"
            response = requests.get(url, timeout=5)
            return ip in response.text
        except Exception as e:
            self.logger.error(f"Tor detection error: {e}")
            return False

    def get_asn_info(self, ip: str) -> Dict:
        """Get detailed ASN information"""
        try:
            url = f"https://api.iptoasn.com/v1/as/ip/{ip}"
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            data = response.json()

            return {
                'asn': data.get('as_number'),
                'as_name': data.get('as_description'),
                'country_code': data.get('as_country_code'),
                'announced': data.get('announced', False)
            }
        except Exception as e:
            self.logger.error(f"ASN lookup error: {e}")
            return {}

    def get_ip_reputation(self, ip: str) -> Dict:
        """Check IP reputation across multiple databases"""
        reputation = {
            'ip': ip,
            'blacklisted': False,
            'sources': [],
            'threat_level': 'unknown'
        }

        # Check AbuseIPDB
        try:
            if self.config.get('abuseipdb_key'):
                url = "https://api.abuseipdb.com/api/v2/check"
                headers = {
                    'Key': self.config['abuseipdb_key'],
                    'Accept': 'application/json'
                }
                params = {'ipAddress': ip, 'maxAgeInDays': 90}

                response = requests.get(url, headers=headers, params=params, timeout=10)
                response.raise_for_status()
                data = response.json()['data']

                reputation['abuse_confidence'] = data.get('abuseConfidenceScore')
                reputation['total_reports'] = data.get('totalReports')
                reputation['blacklisted'] = data.get('abuseConfidenceScore', 0) > 50
                reputation['sources'].append('abuseipdb')
        except Exception as e:
            self.logger.error(f"AbuseIPDB check error: {e}")

        return reputation

    def batch_geolocate(self, ip_list: List[str]) -> List[Dict]:
        """Batch geolocate multiple IPs"""
        results = []
        for ip in ip_list:
            try:
                result = self.geolocate(ip)
                results.append(result)
            except Exception as e:
                self.logger.error(f"Batch geolocation failed for {ip}: {e}")
                results.append({'ip': ip, 'error': str(e)})
        return results

    def __del__(self):
        """Cleanup MaxMind reader"""
        if self.maxmind_reader:
            self.maxmind_reader.close()


if __name__ == "__main__":
    # Example usage
    ip_geo = IPGeolocation({
        'ipinfo_token': 'your_token_here',
        'cache_ttl': 3600
    })

    # Geolocate single IP
    result = ip_geo.geolocate("8.8.8.8")
    print(json.dumps(result, indent=2))

    # Batch geolocate
    ips = ["8.8.8.8", "1.1.1.1", "208.67.222.222"]
    batch_results = ip_geo.batch_geolocate(ips)
    for r in batch_results:
        print(f"{r['ip']}: {r.get('location', {}).get('city', 'Unknown')}")
