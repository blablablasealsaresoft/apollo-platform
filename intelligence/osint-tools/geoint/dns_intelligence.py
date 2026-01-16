"""
DNS Intelligence Module
DNS records analysis and intelligence gathering
"""

import logging
import dns.resolver
import dns.reversename
import dns.zone
import dns.query
import requests
from typing import Dict, Optional, List
import json
from datetime import datetime
import socket


class DNSIntelligence:
    """DNS Intelligence and Analysis"""

    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize DNS Intelligence module

        Args:
            config: Configuration dictionary
        """
        self.logger = logging.getLogger(__name__)
        self.config = config or {}

        # API keys
        self.securitytrails_key = self.config.get('securitytrails_key')
        self.virustotal_key = self.config.get('virustotal_key')

        # DNS resolvers
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 10
        self.resolver.lifetime = 10

        # Custom DNS servers if configured
        if self.config.get('dns_servers'):
            self.resolver.nameservers = self.config['dns_servers']

        # Cache
        self.cache = {}

    def analyze(self, domain: str, include_subdomains: bool = False) -> Dict:
        """
        Comprehensive DNS analysis

        Args:
            domain: Domain to analyze
            include_subdomains: Include subdomain enumeration

        Returns:
            Dictionary with DNS intelligence
        """
        # Clean domain
        domain = self._clean_domain(domain)

        # Check cache
        if domain in self.cache and not include_subdomains:
            return self.cache[domain]

        result = {
            'domain': domain,
            'timestamp': datetime.now().isoformat(),
            'records': {},
            'nameservers': [],
            'mail_servers': [],
            'ip_addresses': [],
            'subdomains': [],
            'zone_transfer': None,
            'dnssec': False,
            'historical': {}
        }

        try:
            # Query all record types
            result['records'] = self._query_all_records(domain)

            # Extract specific information
            result['nameservers'] = self._get_nameservers(domain)
            result['mail_servers'] = self._get_mail_servers(domain)
            result['ip_addresses'] = self._get_ip_addresses(domain)

            # Check DNSSEC
            result['dnssec'] = self._check_dnssec(domain)

            # Try zone transfer
            if result['nameservers']:
                result['zone_transfer'] = self._attempt_zone_transfer(domain, result['nameservers'])

            # Subdomain enumeration
            if include_subdomains:
                result['subdomains'] = self._enumerate_subdomains(domain)

            # Historical DNS (if API available)
            if self.securitytrails_key:
                result['historical'] = self._get_historical_dns(domain)

        except Exception as e:
            self.logger.error(f"DNS analysis error for {domain}: {e}")
            result['error'] = str(e)

        # Cache result
        if not include_subdomains:
            self.cache[domain] = result

        return result

    def _clean_domain(self, domain: str) -> str:
        """Clean and normalize domain name"""
        domain = domain.replace('http://', '').replace('https://', '')
        domain = domain.split('/')[0].split(':')[0]
        if domain.startswith('www.'):
            domain = domain[4:]
        return domain.lower()

    def _query_all_records(self, domain: str) -> Dict:
        """Query all DNS record types"""
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'PTR', 'SRV', 'CAA']
        records = {}

        for record_type in record_types:
            try:
                answers = self.resolver.resolve(domain, record_type)
                records[record_type] = [str(rdata) for rdata in answers]
            except dns.resolver.NoAnswer:
                records[record_type] = []
            except dns.resolver.NXDOMAIN:
                self.logger.warning(f"Domain {domain} does not exist")
                records[record_type] = []
            except Exception as e:
                self.logger.debug(f"No {record_type} records for {domain}: {e}")
                records[record_type] = []

        return records

    def _get_nameservers(self, domain: str) -> List[Dict]:
        """Get nameserver information"""
        nameservers = []

        try:
            answers = self.resolver.resolve(domain, 'NS')
            for rdata in answers:
                ns = str(rdata).rstrip('.')
                ns_info = {
                    'hostname': ns,
                    'ip_addresses': []
                }

                # Resolve nameserver IP
                try:
                    ns_answers = self.resolver.resolve(ns, 'A')
                    ns_info['ip_addresses'] = [str(ip) for ip in ns_answers]
                except Exception as e:
                    self.logger.debug(f"Could not resolve nameserver {ns}: {e}")

                nameservers.append(ns_info)

        except Exception as e:
            self.logger.error(f"Nameserver lookup error: {e}")

        return nameservers

    def _get_mail_servers(self, domain: str) -> List[Dict]:
        """Get mail server information"""
        mail_servers = []

        try:
            answers = self.resolver.resolve(domain, 'MX')
            for rdata in answers:
                mx = str(rdata.exchange).rstrip('.')
                mx_info = {
                    'hostname': mx,
                    'priority': rdata.preference,
                    'ip_addresses': []
                }

                # Resolve MX IP
                try:
                    mx_answers = self.resolver.resolve(mx, 'A')
                    mx_info['ip_addresses'] = [str(ip) for ip in mx_answers]
                except Exception as e:
                    self.logger.debug(f"Could not resolve mail server {mx}: {e}")

                mail_servers.append(mx_info)

            # Sort by priority
            mail_servers.sort(key=lambda x: x['priority'])

        except Exception as e:
            self.logger.error(f"MX lookup error: {e}")

        return mail_servers

    def _get_ip_addresses(self, domain: str) -> List[Dict]:
        """Get IP addresses for domain"""
        ip_addresses = []

        # IPv4
        try:
            answers = self.resolver.resolve(domain, 'A')
            for rdata in answers:
                ip_addresses.append({
                    'version': 4,
                    'address': str(rdata)
                })
        except Exception as e:
            self.logger.debug(f"A record lookup error: {e}")

        # IPv6
        try:
            answers = self.resolver.resolve(domain, 'AAAA')
            for rdata in answers:
                ip_addresses.append({
                    'version': 6,
                    'address': str(rdata)
                })
        except Exception as e:
            self.logger.debug(f"AAAA record lookup error: {e}")

        return ip_addresses

    def _check_dnssec(self, domain: str) -> bool:
        """Check if domain uses DNSSEC"""
        try:
            # Try to get DNSKEY records
            answers = self.resolver.resolve(domain, 'DNSKEY')
            return len(answers) > 0
        except Exception:
            return False

    def _attempt_zone_transfer(self, domain: str, nameservers: List[Dict]) -> Dict:
        """
        Attempt DNS zone transfer (AXFR)

        Note: Zone transfers are usually restricted
        """
        result = {
            'possible': False,
            'nameserver': None,
            'records': []
        }

        for ns_info in nameservers:
            for ns_ip in ns_info.get('ip_addresses', []):
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=10))

                    result['possible'] = True
                    result['nameserver'] = ns_ip

                    # Extract all records
                    for name, node in zone.nodes.items():
                        for rdataset in node.rdatasets:
                            result['records'].append({
                                'name': str(name),
                                'type': dns.rdatatype.to_text(rdataset.rdtype),
                                'ttl': rdataset.ttl,
                                'data': [str(rdata) for rdata in rdataset]
                            })

                    self.logger.warning(f"Zone transfer successful on {ns_ip} for {domain}")
                    return result

                except Exception as e:
                    self.logger.debug(f"Zone transfer failed on {ns_ip}: {e}")

        return result

    def _enumerate_subdomains(self, domain: str) -> List[Dict]:
        """
        Enumerate subdomains using multiple techniques

        Techniques:
        1. Common subdomain brute force
        2. Certificate Transparency logs
        3. SecurityTrails API
        4. VirusTotal API
        """
        subdomains = []
        found = set()

        # 1. Brute force common subdomains
        common_subs = [
            'www', 'mail', 'ftp', 'smtp', 'pop', 'imap',
            'webmail', 'admin', 'api', 'dev', 'stage', 'staging',
            'test', 'demo', 'blog', 'shop', 'store', 'portal',
            'vpn', 'remote', 'cloud', 'app', 'mobile', 'cdn'
        ]

        for sub in common_subs:
            subdomain = f"{sub}.{domain}"
            try:
                answers = self.resolver.resolve(subdomain, 'A')
                if subdomain not in found:
                    found.add(subdomain)
                    subdomains.append({
                        'subdomain': subdomain,
                        'ip_addresses': [str(ip) for ip in answers],
                        'source': 'brute_force'
                    })
            except Exception:
                pass

        # 2. Certificate Transparency
        ct_subs = self._query_certificate_transparency(domain)
        for sub in ct_subs:
            if sub not in found:
                found.add(sub)
                subdomains.append({
                    'subdomain': sub,
                    'source': 'certificate_transparency'
                })

        # 3. SecurityTrails
        if self.securitytrails_key:
            st_subs = self._securitytrails_subdomains(domain)
            for sub in st_subs:
                if sub not in found:
                    found.add(sub)
                    subdomains.append({
                        'subdomain': sub,
                        'source': 'securitytrails'
                    })

        # 4. VirusTotal
        if self.virustotal_key:
            vt_subs = self._virustotal_subdomains(domain)
            for sub in vt_subs:
                if sub not in found:
                    found.add(sub)
                    subdomains.append({
                        'subdomain': sub,
                        'source': 'virustotal'
                    })

        return subdomains

    def _query_certificate_transparency(self, domain: str) -> List[str]:
        """Query Certificate Transparency logs for subdomains"""
        subdomains = []

        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            data = response.json()

            for entry in data:
                name_value = entry.get('name_value', '')
                for sub in name_value.split('\n'):
                    sub = sub.strip().lower()
                    if sub.endswith(domain) and sub not in subdomains:
                        subdomains.append(sub)

        except Exception as e:
            self.logger.error(f"Certificate Transparency query error: {e}")

        return subdomains

    def _securitytrails_subdomains(self, domain: str) -> List[str]:
        """Get subdomains from SecurityTrails API"""
        subdomains = []

        try:
            url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
            headers = {'APIKEY': self.securitytrails_key}

            response = requests.get(url, headers=headers, timeout=30)
            response.raise_for_status()
            data = response.json()

            for sub in data.get('subdomains', []):
                subdomains.append(f"{sub}.{domain}")

        except Exception as e:
            self.logger.error(f"SecurityTrails API error: {e}")

        return subdomains

    def _virustotal_subdomains(self, domain: str) -> List[str]:
        """Get subdomains from VirusTotal API"""
        subdomains = []

        try:
            url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
            headers = {'x-apikey': self.virustotal_key}

            response = requests.get(url, headers=headers, timeout=30)
            response.raise_for_status()
            data = response.json()

            for item in data.get('data', []):
                subdomain = item.get('id')
                if subdomain:
                    subdomains.append(subdomain)

        except Exception as e:
            self.logger.error(f"VirusTotal API error: {e}")

        return subdomains

    def _get_historical_dns(self, domain: str) -> Dict:
        """Get historical DNS records"""
        historical = {
            'a_records': [],
            'mx_records': [],
            'ns_records': [],
            'txt_records': []
        }

        try:
            if self.securitytrails_key:
                url = f"https://api.securitytrails.com/v1/history/{domain}/dns/a"
                headers = {'APIKEY': self.securitytrails_key}

                response = requests.get(url, headers=headers, timeout=30)
                response.raise_for_status()
                data = response.json()

                historical['a_records'] = data.get('records', [])

        except Exception as e:
            self.logger.error(f"Historical DNS lookup error: {e}")

        return historical

    def reverse_dns(self, ip: str) -> Optional[str]:
        """Perform reverse DNS lookup"""
        try:
            addr = dns.reversename.from_address(ip)
            answers = self.resolver.resolve(addr, 'PTR')
            return str(answers[0]).rstrip('.')
        except Exception as e:
            self.logger.debug(f"Reverse DNS lookup failed for {ip}: {e}")
            return None

    def check_dns_propagation(self, domain: str, record_type: str = 'A') -> Dict:
        """
        Check DNS propagation across multiple DNS servers

        Args:
            domain: Domain to check
            record_type: Record type to check

        Returns:
            Propagation status across multiple servers
        """
        dns_servers = {
            'Google': '8.8.8.8',
            'Cloudflare': '1.1.1.1',
            'Quad9': '9.9.9.9',
            'OpenDNS': '208.67.222.222',
            'Level3': '4.2.2.2'
        }

        results = {
            'domain': domain,
            'record_type': record_type,
            'servers': {}
        }

        for name, server_ip in dns_servers.items():
            try:
                temp_resolver = dns.resolver.Resolver()
                temp_resolver.nameservers = [server_ip]
                temp_resolver.timeout = 5
                temp_resolver.lifetime = 5

                answers = temp_resolver.resolve(domain, record_type)
                results['servers'][name] = {
                    'status': 'resolved',
                    'records': [str(rdata) for rdata in answers]
                }
            except Exception as e:
                results['servers'][name] = {
                    'status': 'failed',
                    'error': str(e)
                }

        return results

    def batch_analyze(self, domains: List[str]) -> List[Dict]:
        """Batch DNS analysis for multiple domains"""
        results = []
        for domain in domains:
            try:
                result = self.analyze(domain)
                results.append(result)
            except Exception as e:
                self.logger.error(f"Batch analysis failed for {domain}: {e}")
                results.append({'domain': domain, 'error': str(e)})
        return results


if __name__ == "__main__":
    # Example usage
    dns_intel = DNSIntelligence({
        'securitytrails_key': 'your_key_here'
    })

    # Analyze domain
    result = dns_intel.analyze("google.com", include_subdomains=True)
    print(json.dumps(result, indent=2))

    # Check propagation
    propagation = dns_intel.check_dns_propagation("google.com", "A")
    print(json.dumps(propagation, indent=2))
