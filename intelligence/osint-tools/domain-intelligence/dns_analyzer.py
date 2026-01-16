"""
DNS Analyzer - DNS Intelligence and Analysis
Comprehensive DNS record analysis and historical tracking
"""

import dns.resolver
import dns.reversename
import dns.zone
import dns.query
import requests
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
import json


class DNSAnalyzer:
    """
    DNS intelligence gathering and analysis
    Supports current and historical DNS lookups
    """

    def __init__(self, securitytrails_api_key: Optional[str] = None):
        """
        Initialize DNS analyzer

        Args:
            securitytrails_api_key: API key for SecurityTrails historical DNS
        """
        self.logger = logging.getLogger('DNSAnalyzer')
        self.securitytrails_key = securitytrails_api_key
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5
        self.resolver.lifetime = 10

        # Common DNS record types
        self.record_types = [
            'A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME',
            'SOA', 'PTR', 'SRV', 'CAA', 'DNSKEY'
        ]

    def analyze(self, domain: str, include_historical: bool = False) -> Dict[str, Any]:
        """
        Perform comprehensive DNS analysis

        Args:
            domain: Target domain name
            include_historical: Include historical DNS data (requires API key)

        Returns:
            Complete DNS intelligence
        """
        self.logger.info(f"Analyzing DNS for {domain}")

        results = {
            'domain': domain,
            'timestamp': datetime.utcnow().isoformat(),
            'records': {},
            'dnssec_enabled': False,
            'nameservers': [],
            'mail_servers': [],
            'txt_records': [],
            'caa_records': [],
            'zone_transfer_vulnerable': False,
            'historical': {}
        }

        # Query all record types
        for record_type in self.record_types:
            try:
                records = self.query_record(domain, record_type)
                if records:
                    results['records'][record_type] = records
            except Exception as e:
                self.logger.debug(f"No {record_type} record for {domain}: {e}")

        # Extract key information
        results['nameservers'] = results['records'].get('NS', [])

        # MX Records with priority
        if 'MX' in results['records']:
            results['mail_servers'] = self._parse_mx_records(results['records']['MX'])

        # TXT Records
        results['txt_records'] = results['records'].get('TXT', [])

        # CAA Records
        results['caa_records'] = results['records'].get('CAA', [])

        # Check DNSSEC
        results['dnssec_enabled'] = 'DNSKEY' in results['records']

        # Check zone transfer vulnerability
        results['zone_transfer_vulnerable'] = self.check_zone_transfer(domain)

        # Historical DNS (if API key available)
        if include_historical and self.securitytrails_key:
            try:
                results['historical'] = self.get_historical_dns(domain)
            except Exception as e:
                self.logger.error(f"Historical DNS lookup failed: {e}")
                results['historical'] = {'error': str(e)}

        # DNS propagation check
        results['propagation'] = self.check_propagation(domain)

        return results

    def query_record(self, domain: str, record_type: str) -> List[str]:
        """
        Query specific DNS record type

        Args:
            domain: Target domain
            record_type: DNS record type (A, AAAA, MX, etc.)

        Returns:
            List of record values
        """
        try:
            answers = self.resolver.resolve(domain, record_type)

            records = []
            for rdata in answers:
                if record_type == 'MX':
                    records.append(f"{rdata.preference} {rdata.exchange}")
                elif record_type == 'TXT':
                    # Combine TXT record parts
                    txt_value = ''.join([s.decode() if isinstance(s, bytes) else s for s in rdata.strings])
                    records.append(txt_value)
                elif record_type == 'SOA':
                    records.append(f"mname={rdata.mname} rname={rdata.rname}")
                elif record_type == 'SRV':
                    records.append(f"{rdata.priority} {rdata.weight} {rdata.port} {rdata.target}")
                elif record_type == 'CAA':
                    records.append(f"{rdata.flags} {rdata.tag} {rdata.value}")
                else:
                    records.append(str(rdata))

            return records

        except dns.resolver.NoAnswer:
            return []
        except dns.resolver.NXDOMAIN:
            raise Exception(f"Domain {domain} does not exist")
        except dns.exception.Timeout:
            raise Exception(f"DNS query timeout for {domain}")
        except Exception as e:
            raise Exception(f"DNS query failed: {e}")

    def _parse_mx_records(self, mx_records: List[str]) -> List[Dict[str, Any]]:
        """Parse MX records into structured format"""
        mail_servers = []

        for record in mx_records:
            parts = record.split()
            if len(parts) >= 2:
                mail_servers.append({
                    'priority': int(parts[0]),
                    'hostname': parts[1].rstrip('.')
                })

        # Sort by priority
        mail_servers.sort(key=lambda x: x['priority'])

        return mail_servers

    def reverse_lookup(self, ip_address: str) -> Optional[str]:
        """
        Perform reverse DNS lookup

        Args:
            ip_address: IP address to lookup

        Returns:
            Hostname or None
        """
        try:
            addr = dns.reversename.from_address(ip_address)
            hostname = str(self.resolver.resolve(addr, 'PTR')[0])
            return hostname.rstrip('.')
        except Exception as e:
            self.logger.debug(f"Reverse lookup failed for {ip_address}: {e}")
            return None

    def check_zone_transfer(self, domain: str) -> bool:
        """
        Check if domain is vulnerable to zone transfer (AXFR)

        Args:
            domain: Target domain

        Returns:
            True if vulnerable, False otherwise
        """
        try:
            # Get nameservers
            nameservers = self.query_record(domain, 'NS')

            for ns in nameservers:
                ns = ns.rstrip('.')
                try:
                    # Attempt zone transfer
                    zone = dns.zone.from_xfr(dns.query.xfr(ns, domain))
                    if zone:
                        self.logger.warning(f"Zone transfer possible from {ns}!")
                        return True
                except Exception:
                    continue

            return False

        except Exception as e:
            self.logger.debug(f"Zone transfer check failed: {e}")
            return False

    def get_historical_dns(self, domain: str) -> Dict[str, Any]:
        """
        Get historical DNS records from SecurityTrails

        Args:
            domain: Target domain

        Returns:
            Historical DNS data
        """
        if not self.securitytrails_key:
            return {'error': 'SecurityTrails API key not configured'}

        headers = {
            'APIKEY': self.securitytrails_key,
            'Content-Type': 'application/json'
        }

        results = {
            'historical_ips': [],
            'historical_mx': [],
            'historical_ns': []
        }

        # Historical A records
        try:
            url = f'https://api.securitytrails.com/v1/history/{domain}/dns/a'
            response = requests.get(url, headers=headers, timeout=10)

            if response.status_code == 200:
                data = response.json()
                results['historical_ips'] = data.get('records', [])
        except Exception as e:
            self.logger.error(f"Failed to get historical A records: {e}")

        # Historical MX records
        try:
            url = f'https://api.securitytrails.com/v1/history/{domain}/dns/mx'
            response = requests.get(url, headers=headers, timeout=10)

            if response.status_code == 200:
                data = response.json()
                results['historical_mx'] = data.get('records', [])
        except Exception as e:
            self.logger.error(f"Failed to get historical MX records: {e}")

        # Historical NS records
        try:
            url = f'https://api.securitytrails.com/v1/history/{domain}/dns/ns'
            response = requests.get(url, headers=headers, timeout=10)

            if response.status_code == 200:
                data = response.json()
                results['historical_ns'] = data.get('records', [])
        except Exception as e:
            self.logger.error(f"Failed to get historical NS records: {e}")

        return results

    def check_propagation(self, domain: str,
                         dns_servers: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Check DNS propagation across multiple DNS servers

        Args:
            domain: Target domain
            dns_servers: List of DNS servers to check (optional)

        Returns:
            Propagation status
        """
        if not dns_servers:
            # Common public DNS servers
            dns_servers = [
                '8.8.8.8',      # Google
                '1.1.1.1',      # Cloudflare
                '208.67.222.222',  # OpenDNS
                '8.26.56.26'    # Comodo
            ]

        results = {
            'domain': domain,
            'servers': {},
            'consistent': True,
            'unique_ips': set()
        }

        for server in dns_servers:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [server]

            try:
                answers = resolver.resolve(domain, 'A')
                ips = [str(rdata) for rdata in answers]
                results['servers'][server] = {
                    'ips': ips,
                    'status': 'success'
                }
                results['unique_ips'].update(ips)
            except Exception as e:
                results['servers'][server] = {
                    'ips': [],
                    'status': 'failed',
                    'error': str(e)
                }

        # Check consistency
        results['unique_ips'] = list(results['unique_ips'])
        if len(results['unique_ips']) > 1:
            results['consistent'] = False

        return results

    def analyze_spf(self, domain: str) -> Dict[str, Any]:
        """
        Analyze SPF (Sender Policy Framework) record

        Args:
            domain: Target domain

        Returns:
            SPF analysis
        """
        results = {
            'domain': domain,
            'has_spf': False,
            'spf_record': None,
            'mechanisms': [],
            'include_count': 0,
            'warnings': []
        }

        try:
            txt_records = self.query_record(domain, 'TXT')

            for record in txt_records:
                if record.startswith('v=spf1'):
                    results['has_spf'] = True
                    results['spf_record'] = record

                    # Parse mechanisms
                    parts = record.split()
                    for part in parts[1:]:  # Skip 'v=spf1'
                        if part.startswith('include:'):
                            results['mechanisms'].append(part)
                            results['include_count'] += 1
                        elif part in ['~all', '-all', '+all', '?all']:
                            results['mechanisms'].append(part)

                    # Check for issues
                    if results['include_count'] > 10:
                        results['warnings'].append('Too many DNS lookups (>10)')

                    if '+all' in results['mechanisms']:
                        results['warnings'].append('Permissive policy (+all) - security risk')

                    if len(record) > 255:
                        results['warnings'].append('SPF record too long (>255 chars)')

                    break

        except Exception as e:
            results['error'] = str(e)

        return results

    def analyze_dmarc(self, domain: str) -> Dict[str, Any]:
        """
        Analyze DMARC (Domain-based Message Authentication) record

        Args:
            domain: Target domain

        Returns:
            DMARC analysis
        """
        results = {
            'domain': domain,
            'has_dmarc': False,
            'dmarc_record': None,
            'policy': None,
            'subdomain_policy': None,
            'percentage': None,
            'rua': [],
            'ruf': []
        }

        try:
            # DMARC records are in _dmarc subdomain
            dmarc_domain = f"_dmarc.{domain}"
            txt_records = self.query_record(dmarc_domain, 'TXT')

            for record in txt_records:
                if record.startswith('v=DMARC1'):
                    results['has_dmarc'] = True
                    results['dmarc_record'] = record

                    # Parse tags
                    tags = record.split(';')
                    for tag in tags:
                        tag = tag.strip()
                        if tag.startswith('p='):
                            results['policy'] = tag.split('=')[1]
                        elif tag.startswith('sp='):
                            results['subdomain_policy'] = tag.split('=')[1]
                        elif tag.startswith('pct='):
                            results['percentage'] = int(tag.split('=')[1])
                        elif tag.startswith('rua='):
                            results['rua'] = tag.split('=')[1].split(',')
                        elif tag.startswith('ruf='):
                            results['ruf'] = tag.split('=')[1].split(',')

                    break

        except Exception as e:
            results['error'] = str(e)

        return results


def main():
    """Example usage"""
    analyzer = DNSAnalyzer()

    # Analyze DNS
    results = analyzer.analyze("example.com")
    print(f"Domain: {results['domain']}")
    print(f"\nA Records: {results['records'].get('A', [])}")
    print(f"MX Records: {results['mail_servers']}")
    print(f"NS Records: {results['nameservers']}")
    print(f"DNSSEC Enabled: {results['dnssec_enabled']}")

    # Check SPF
    spf = analyzer.analyze_spf("example.com")
    print(f"\nSPF Record: {spf['spf_record']}")

    # Check DMARC
    dmarc = analyzer.analyze_dmarc("example.com")
    print(f"DMARC Policy: {dmarc['policy']}")


if __name__ == "__main__":
    main()
