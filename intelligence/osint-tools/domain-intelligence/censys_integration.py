"""
Censys Integration - Censys Search Engine Integration
Internet-wide scanning and certificate intelligence
"""

import requests
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
import base64


class CensysIntel:
    """
    Censys intelligence gathering
    Internet-wide scanning data and certificate transparency
    """

    def __init__(self, api_id: str, api_secret: str):
        """
        Initialize Censys integration

        Args:
            api_id: Censys API ID
            api_secret: Censys API Secret
        """
        self.logger = logging.getLogger('CensysIntel')
        self.api_id = api_id
        self.api_secret = api_secret
        self.base_url = "https://search.censys.io/api/v2"

        # Create auth header
        credentials = f"{api_id}:{api_secret}"
        encoded = base64.b64encode(credentials.encode()).decode()
        self.headers = {
            'Authorization': f'Basic {encoded}',
            'Content-Type': 'application/json'
        }

    def search_domain(self, domain: str) -> Dict[str, Any]:
        """
        Search for hosts associated with domain

        Args:
            domain: Target domain

        Returns:
            Censys search results
        """
        self.logger.info(f"Searching Censys for domain: {domain}")

        results = {
            'domain': domain,
            'timestamp': datetime.utcnow().isoformat(),
            'hosts': [],
            'total_results': 0,
            'certificates': []
        }

        try:
            # Search for hosts
            query = f"services.dns.names: {domain}"
            host_results = self._search_hosts(query)

            results['total_results'] = host_results.get('total', 0)
            results['hosts'] = host_results.get('hosts', [])

            # Search for certificates
            cert_results = self.search_certificates(domain)
            results['certificates'] = cert_results.get('certificates', [])

        except Exception as e:
            self.logger.error(f"Censys domain search failed: {e}")
            results['error'] = str(e)

        return results

    def search_ip(self, ip_address: str) -> Dict[str, Any]:
        """
        Get information about IP address

        Args:
            ip_address: Target IP address

        Returns:
            Censys host information
        """
        self.logger.info(f"Looking up IP in Censys: {ip_address}")

        results = {
            'ip': ip_address,
            'timestamp': datetime.utcnow().isoformat(),
            'services': [],
            'protocols': [],
            'location': {},
            'autonomous_system': {},
            'dns': {},
            'metadata': {}
        }

        try:
            url = f"{self.base_url}/hosts/{ip_address}"
            response = requests.get(url, headers=self.headers, timeout=30)

            if response.status_code == 200:
                data = response.json()
                host = data.get('result', {})

                # Services
                services = host.get('services', [])
                for service in services:
                    service_info = {
                        'port': service.get('port'),
                        'service_name': service.get('service_name'),
                        'transport_protocol': service.get('transport_protocol'),
                        'extended_service_name': service.get('extended_service_name'),
                        'software': []
                    }

                    # Software detection
                    if 'software' in service:
                        for sw in service['software']:
                            service_info['software'].append({
                                'product': sw.get('product'),
                                'vendor': sw.get('vendor'),
                                'version': sw.get('version')
                            })

                    results['services'].append(service_info)

                # Protocols
                results['protocols'] = list(set([
                    s.get('transport_protocol') for s in services
                    if s.get('transport_protocol')
                ]))

                # Location
                location = host.get('location', {})
                results['location'] = {
                    'country': location.get('country'),
                    'country_code': location.get('country_code'),
                    'city': location.get('city'),
                    'province': location.get('province'),
                    'postal_code': location.get('postal_code'),
                    'timezone': location.get('timezone'),
                    'coordinates': location.get('coordinates', {})
                }

                # Autonomous System
                autonomous_system = host.get('autonomous_system', {})
                results['autonomous_system'] = {
                    'asn': autonomous_system.get('asn'),
                    'name': autonomous_system.get('name'),
                    'description': autonomous_system.get('description'),
                    'country_code': autonomous_system.get('country_code')
                }

                # DNS
                dns = host.get('dns', {})
                results['dns'] = {
                    'reverse_dns': dns.get('reverse_dns', {}).get('names', []),
                    'names': dns.get('names', [])
                }

                # Metadata
                results['metadata'] = {
                    'last_updated': host.get('last_updated_at'),
                    'operating_system': host.get('operating_system', {}).get('product')
                }

            elif response.status_code == 404:
                results['error'] = 'IP address not found in Censys'
            else:
                results['error'] = f"HTTP {response.status_code}: {response.text}"

        except Exception as e:
            self.logger.error(f"Censys IP lookup failed: {e}")
            results['error'] = str(e)

        return results

    def _search_hosts(self, query: str, per_page: int = 50) -> Dict[str, Any]:
        """
        Search hosts with query

        Args:
            query: Censys search query
            per_page: Results per page

        Returns:
            Search results
        """
        results = {
            'total': 0,
            'hosts': []
        }

        try:
            url = f"{self.base_url}/hosts/search"
            params = {
                'q': query,
                'per_page': per_page
            }

            response = requests.get(url, headers=self.headers, params=params, timeout=30)

            if response.status_code == 200:
                data = response.json()
                results['total'] = data.get('result', {}).get('total', 0)

                for hit in data.get('result', {}).get('hits', []):
                    host_info = {
                        'ip': hit.get('ip'),
                        'services': hit.get('services', []),
                        'location': hit.get('location', {}),
                        'autonomous_system': hit.get('autonomous_system', {}),
                        'last_updated': hit.get('last_updated_at')
                    }
                    results['hosts'].append(host_info)

        except Exception as e:
            self.logger.error(f"Censys host search failed: {e}")

        return results

    def search_certificates(self, domain: str) -> Dict[str, Any]:
        """
        Search for SSL/TLS certificates

        Args:
            domain: Target domain

        Returns:
            Certificate search results
        """
        self.logger.info(f"Searching certificates for: {domain}")

        results = {
            'domain': domain,
            'timestamp': datetime.utcnow().isoformat(),
            'total': 0,
            'certificates': []
        }

        try:
            url = f"{self.base_url}/certificates/search"
            params = {
                'q': f"names: {domain}",
                'per_page': 50
            }

            response = requests.get(url, headers=self.headers, params=params, timeout=30)

            if response.status_code == 200:
                data = response.json()
                results['total'] = data.get('result', {}).get('total', 0)

                for hit in data.get('result', {}).get('hits', []):
                    cert_info = {
                        'fingerprint_sha256': hit.get('fingerprint_sha256'),
                        'names': hit.get('names', []),
                        'issuer': hit.get('parsed', {}).get('issuer', {}),
                        'subject': hit.get('parsed', {}).get('subject', {}),
                        'validity': hit.get('parsed', {}).get('validity', {}),
                        'signature_algorithm': hit.get('parsed', {}).get('signature_algorithm', {})
                    }
                    results['certificates'].append(cert_info)

        except Exception as e:
            self.logger.error(f"Certificate search failed: {e}")
            results['error'] = str(e)

        return results

    def get_certificate_details(self, fingerprint: str) -> Dict[str, Any]:
        """
        Get detailed certificate information

        Args:
            fingerprint: Certificate SHA256 fingerprint

        Returns:
            Certificate details
        """
        results = {
            'fingerprint': fingerprint,
            'timestamp': datetime.utcnow().isoformat()
        }

        try:
            url = f"{self.base_url}/certificates/{fingerprint}"
            response = requests.get(url, headers=self.headers, timeout=30)

            if response.status_code == 200:
                data = response.json()
                results.update(data.get('result', {}))
            else:
                results['error'] = f"HTTP {response.status_code}"

        except Exception as e:
            results['error'] = str(e)

        return results

    def search_services(self, service_name: str, port: Optional[int] = None) -> Dict[str, Any]:
        """
        Search for specific service

        Args:
            service_name: Service name (e.g., "HTTP", "SSH")
            port: Specific port (optional)

        Returns:
            Service search results
        """
        query = f"services.service_name: {service_name}"
        if port:
            query += f" AND services.port: {port}"

        self.logger.info(f"Searching for service: {query}")

        results = {
            'service': service_name,
            'port': port,
            'timestamp': datetime.utcnow().isoformat(),
            'hosts': []
        }

        try:
            host_results = self._search_hosts(query)
            results.update(host_results)
        except Exception as e:
            results['error'] = str(e)

        return results

    def search_software(self, product: str, version: Optional[str] = None) -> Dict[str, Any]:
        """
        Search for hosts running specific software

        Args:
            product: Software product name
            version: Software version (optional)

        Returns:
            Search results
        """
        query = f"services.software.product: {product}"
        if version:
            query += f" AND services.software.version: {version}"

        self.logger.info(f"Searching for software: {query}")

        return self._search_hosts(query)

    def search_vulnerability(self, cve_id: str) -> Dict[str, Any]:
        """
        Search for hosts with specific vulnerability

        Args:
            cve_id: CVE identifier

        Returns:
            Vulnerable hosts
        """
        query = f"services.vulnerabilities.cve: {cve_id}"

        self.logger.info(f"Searching for vulnerability: {cve_id}")

        results = {
            'cve': cve_id,
            'timestamp': datetime.utcnow().isoformat()
        }

        try:
            host_results = self._search_hosts(query)
            results.update(host_results)
        except Exception as e:
            results['error'] = str(e)

        return results

    def get_account_info(self) -> Dict[str, Any]:
        """
        Get Censys account information

        Returns:
            Account quota and usage
        """
        results = {}

        try:
            url = f"{self.base_url}/account"
            response = requests.get(url, headers=self.headers, timeout=30)

            if response.status_code == 200:
                data = response.json()
                results = data.get('result', {})

        except Exception as e:
            results['error'] = str(e)

        return results

    def aggregate_search(self, query: str, field: str) -> Dict[str, Any]:
        """
        Perform aggregate search

        Args:
            query: Search query
            field: Field to aggregate on

        Returns:
            Aggregation results
        """
        results = {
            'query': query,
            'field': field,
            'timestamp': datetime.utcnow().isoformat(),
            'buckets': []
        }

        try:
            url = f"{self.base_url}/hosts/aggregate"
            data = {
                'query': query,
                'field': field,
                'num_buckets': 50
            }

            response = requests.post(url, headers=self.headers, json=data, timeout=30)

            if response.status_code == 200:
                resp_data = response.json()
                results['total'] = resp_data.get('result', {}).get('total', 0)
                results['buckets'] = resp_data.get('result', {}).get('buckets', [])

        except Exception as e:
            results['error'] = str(e)

        return results

    def search_by_asn(self, asn: int) -> Dict[str, Any]:
        """
        Search for hosts in specific ASN

        Args:
            asn: Autonomous System Number

        Returns:
            Hosts in ASN
        """
        query = f"autonomous_system.asn: {asn}"

        self.logger.info(f"Searching for ASN: {asn}")

        results = {
            'asn': asn,
            'timestamp': datetime.utcnow().isoformat()
        }

        try:
            host_results = self._search_hosts(query)
            results.update(host_results)
        except Exception as e:
            results['error'] = str(e)

        return results

    def search_by_country(self, country_code: str) -> Dict[str, Any]:
        """
        Search for hosts in specific country

        Args:
            country_code: Two-letter country code (e.g., 'US')

        Returns:
            Hosts in country
        """
        query = f"location.country_code: {country_code}"

        self.logger.info(f"Searching for country: {country_code}")

        return self._search_hosts(query)


def main():
    """Example usage"""
    # Initialize with API credentials
    censys = CensysIntel('YOUR_API_ID', 'YOUR_API_SECRET')

    # Search for domain
    domain_results = censys.search_domain("example.com")
    print(f"Total hosts: {domain_results['total_results']}")
    print(f"Certificates found: {len(domain_results['certificates'])}")

    # Search for IP
    ip_results = censys.search_ip("8.8.8.8")
    print(f"\nIP: {ip_results['ip']}")
    print(f"Location: {ip_results['location']}")
    print(f"Services: {len(ip_results['services'])}")

    # Search certificates
    cert_results = censys.search_certificates("example.com")
    print(f"\nCertificates: {cert_results['total']}")

    # Get account info
    account = censys.get_account_info()
    print(f"\nAccount: {account}")


if __name__ == "__main__":
    main()
