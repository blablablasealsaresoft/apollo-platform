"""
Shodan Integration - Shodan Search Engine Integration
Internet-connected device and vulnerability intelligence
"""

import shodan
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime


class ShodanIntel:
    """
    Shodan intelligence gathering
    Search for internet-connected devices, services, and vulnerabilities
    """

    def __init__(self, api_key: str):
        """
        Initialize Shodan integration

        Args:
            api_key: Shodan API key
        """
        self.logger = logging.getLogger('ShodanIntel')
        self.api_key = api_key
        self.api = shodan.Shodan(api_key)

    def search_domain(self, domain: str) -> Dict[str, Any]:
        """
        Search for hosts associated with domain

        Args:
            domain: Target domain

        Returns:
            Shodan search results
        """
        self.logger.info(f"Searching Shodan for domain: {domain}")

        results = {
            'domain': domain,
            'timestamp': datetime.utcnow().isoformat(),
            'hosts': [],
            'total_results': 0,
            'vulnerabilities': [],
            'services': set(),
            'ports': set(),
            'countries': set()
        }

        try:
            # Search for domain
            search_results = self.api.search(f"hostname:{domain}")

            results['total_results'] = search_results['total']

            for result in search_results['matches']:
                host_info = self._parse_host_result(result)
                results['hosts'].append(host_info)

                # Aggregate data
                if host_info.get('port'):
                    results['ports'].add(host_info['port'])

                if host_info.get('product'):
                    results['services'].add(host_info['product'])

                if host_info.get('country'):
                    results['countries'].add(host_info['country'])

                # Collect vulnerabilities
                if host_info.get('vulns'):
                    results['vulnerabilities'].extend(host_info['vulns'])

            # Convert sets to lists for JSON serialization
            results['services'] = list(results['services'])
            results['ports'] = sorted(list(results['ports']))
            results['countries'] = list(results['countries'])

        except shodan.APIError as e:
            self.logger.error(f"Shodan API error: {e}")
            results['error'] = str(e)
        except Exception as e:
            self.logger.error(f"Shodan search failed: {e}")
            results['error'] = str(e)

        return results

    def search_ip(self, ip_address: str) -> Dict[str, Any]:
        """
        Get information about IP address

        Args:
            ip_address: Target IP address

        Returns:
            Shodan host information
        """
        self.logger.info(f"Looking up IP in Shodan: {ip_address}")

        results = {
            'ip': ip_address,
            'timestamp': datetime.utcnow().isoformat(),
            'hostnames': [],
            'ports': [],
            'services': [],
            'vulnerabilities': [],
            'location': {},
            'organization': None,
            'isp': None,
            'asn': None,
            'os': None
        }

        try:
            # Get host information
            host = self.api.host(ip_address)

            # Basic info
            results['hostnames'] = host.get('hostnames', [])
            results['organization'] = host.get('org')
            results['isp'] = host.get('isp')
            results['asn'] = host.get('asn')
            results['os'] = host.get('os')

            # Location
            results['location'] = {
                'country': host.get('country_name'),
                'country_code': host.get('country_code'),
                'city': host.get('city'),
                'latitude': host.get('latitude'),
                'longitude': host.get('longitude')
            }

            # Ports and services
            results['ports'] = host.get('ports', [])

            for service in host.get('data', []):
                service_info = {
                    'port': service.get('port'),
                    'transport': service.get('transport'),
                    'product': service.get('product'),
                    'version': service.get('version'),
                    'banner': service.get('data', '')[:200]  # Truncate banner
                }
                results['services'].append(service_info)

            # Vulnerabilities
            vulns = host.get('vulns', [])
            if vulns:
                results['vulnerabilities'] = self._get_vulnerability_details(vulns)

        except shodan.APIError as e:
            self.logger.error(f"Shodan API error: {e}")
            results['error'] = str(e)
        except Exception as e:
            self.logger.error(f"Shodan IP lookup failed: {e}")
            results['error'] = str(e)

        return results

    def search_organization(self, organization: str) -> Dict[str, Any]:
        """
        Search for organization's internet-facing assets

        Args:
            organization: Organization name

        Returns:
            Organization's assets
        """
        self.logger.info(f"Searching Shodan for organization: {organization}")

        results = {
            'organization': organization,
            'timestamp': datetime.utcnow().isoformat(),
            'total_results': 0,
            'hosts': [],
            'services_summary': {},
            'vulnerability_summary': {}
        }

        try:
            search_results = self.api.search(f"org:{organization}")

            results['total_results'] = search_results['total']

            for result in search_results['matches']:
                host_info = self._parse_host_result(result)
                results['hosts'].append(host_info)

        except shodan.APIError as e:
            self.logger.error(f"Shodan API error: {e}")
            results['error'] = str(e)

        return results

    def search_vulnerability(self, cve_id: str) -> Dict[str, Any]:
        """
        Search for hosts vulnerable to specific CVE

        Args:
            cve_id: CVE identifier (e.g., CVE-2021-44228)

        Returns:
            Vulnerable hosts
        """
        self.logger.info(f"Searching for vulnerability: {cve_id}")

        results = {
            'cve': cve_id,
            'timestamp': datetime.utcnow().isoformat(),
            'total_results': 0,
            'vulnerable_hosts': []
        }

        try:
            search_results = self.api.search(f"vuln:{cve_id}")

            results['total_results'] = search_results['total']

            for result in search_results['matches']:
                host_info = {
                    'ip': result.get('ip_str'),
                    'port': result.get('port'),
                    'organization': result.get('org'),
                    'country': result.get('location', {}).get('country_name'),
                    'product': result.get('product'),
                    'version': result.get('version')
                }
                results['vulnerable_hosts'].append(host_info)

        except shodan.APIError as e:
            self.logger.error(f"Shodan API error: {e}")
            results['error'] = str(e)

        return results

    def _parse_host_result(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Parse Shodan host result"""
        return {
            'ip': result.get('ip_str'),
            'port': result.get('port'),
            'transport': result.get('transport'),
            'product': result.get('product'),
            'version': result.get('version'),
            'hostname': result.get('hostnames', [None])[0] if result.get('hostnames') else None,
            'organization': result.get('org'),
            'isp': result.get('isp'),
            'country': result.get('location', {}).get('country_name'),
            'city': result.get('location', {}).get('city'),
            'os': result.get('os'),
            'banner': result.get('data', '')[:200],
            'vulns': list(result.get('vulns', [])),
            'timestamp': result.get('timestamp')
        }

    def _get_vulnerability_details(self, cve_list: List[str]) -> List[Dict[str, Any]]:
        """Get details for CVE list"""
        vulnerabilities = []

        for cve in cve_list[:10]:  # Limit to first 10 to avoid rate limits
            try:
                # Note: Shodan API doesn't provide CVE details directly
                # This would require additional API like NVD
                vulnerabilities.append({
                    'cve': cve,
                    'severity': 'unknown',
                    'description': f'Vulnerability {cve} detected'
                })
            except Exception:
                continue

        return vulnerabilities

    def get_account_info(self) -> Dict[str, Any]:
        """
        Get Shodan account information

        Returns:
            Account info including API credits
        """
        try:
            info = self.api.info()
            return {
                'plan': info.get('plan'),
                'query_credits': info.get('query_credits'),
                'scan_credits': info.get('scan_credits'),
                'monitored_ips': info.get('monitored_ips')
            }
        except Exception as e:
            return {'error': str(e)}

    def search_product(self, product_name: str, version: Optional[str] = None) -> Dict[str, Any]:
        """
        Search for specific product/service

        Args:
            product_name: Product name (e.g., "Apache", "nginx")
            version: Specific version (optional)

        Returns:
            Search results
        """
        query = f"product:{product_name}"
        if version:
            query += f" version:{version}"

        self.logger.info(f"Searching for product: {query}")

        results = {
            'product': product_name,
            'version': version,
            'timestamp': datetime.utcnow().isoformat(),
            'total_results': 0,
            'hosts': []
        }

        try:
            search_results = self.api.search(query)
            results['total_results'] = search_results['total']

            for result in search_results['matches']:
                host_info = self._parse_host_result(result)
                results['hosts'].append(host_info)

        except shodan.APIError as e:
            results['error'] = str(e)

        return results

    def search_ssl_cert(self, domain: str) -> Dict[str, Any]:
        """
        Search for SSL certificates

        Args:
            domain: Domain to search

        Returns:
            SSL certificate information
        """
        results = {
            'domain': domain,
            'timestamp': datetime.utcnow().isoformat(),
            'certificates': []
        }

        try:
            search_results = self.api.search(f"ssl:{domain}")

            for result in search_results['matches']:
                cert_info = {
                    'ip': result.get('ip_str'),
                    'port': result.get('port'),
                    'organization': result.get('org'),
                    'ssl': result.get('ssl', {})
                }
                results['certificates'].append(cert_info)

        except shodan.APIError as e:
            results['error'] = str(e)

        return results

    def get_dns_info(self, domain: str) -> Dict[str, Any]:
        """
        Get DNS information from Shodan

        Args:
            domain: Target domain

        Returns:
            DNS information
        """
        try:
            dns_info = self.api.dns.domain_info(domain)
            return dns_info
        except Exception as e:
            return {'error': str(e)}


def main():
    """Example usage"""
    # Initialize with API key
    shodan_intel = ShodanIntel('YOUR_SHODAN_API_KEY')

    # Search for domain
    results = shodan_intel.search_domain("example.com")
    print(f"Total results: {results['total_results']}")
    print(f"Unique ports: {results['ports']}")
    print(f"Services: {results['services']}")

    # Search for IP
    ip_results = shodan_intel.search_ip("8.8.8.8")
    print(f"\nIP: {ip_results['ip']}")
    print(f"Organization: {ip_results['organization']}")
    print(f"Location: {ip_results['location']}")

    # Get account info
    account = shodan_intel.get_account_info()
    print(f"\nAPI Credits: {account.get('query_credits')}")


if __name__ == "__main__":
    main()
