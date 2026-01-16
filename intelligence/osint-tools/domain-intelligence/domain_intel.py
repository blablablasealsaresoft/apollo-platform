"""
Domain Intelligence - Main Domain Investigation Module
Comprehensive domain and network intelligence gathering
"""

import asyncio
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any
from concurrent.futures import ThreadPoolExecutor
import socket
import ssl

from whois_analyzer import WhoisAnalyzer
from dns_analyzer import DNSAnalyzer
from subdomain_enumerator import SubdomainEnumerator
from ssl_analyzer import SSLAnalyzer
from tech_profiler import TechProfiler
from shodan_integration import ShodanIntel
from censys_integration import CensysIntel


class DomainIntelligence:
    """
    Main domain intelligence gathering system
    Orchestrates all domain investigation modules
    """

    def __init__(self, config: Optional[Dict[str, str]] = None):
        """
        Initialize domain intelligence system

        Args:
            config: API keys and configuration
                {
                    'shodan_api_key': 'xxx',
                    'censys_api_id': 'xxx',
                    'censys_api_secret': 'xxx',
                    'securitytrails_api_key': 'xxx',
                    'virustotal_api_key': 'xxx',
                    'builtwith_api_key': 'xxx'
                }
        """
        self.config = config or {}
        self.logger = self._setup_logging()

        # Initialize modules
        self.whois = WhoisAnalyzer()
        self.dns = DNSAnalyzer(self.config.get('securitytrails_api_key'))
        self.subdomain = SubdomainEnumerator(
            virustotal_key=self.config.get('virustotal_api_key')
        )
        self.ssl = SSLAnalyzer()
        self.tech = TechProfiler(self.config.get('builtwith_api_key'))

        # Optional modules (require API keys)
        self.shodan = None
        if self.config.get('shodan_api_key'):
            self.shodan = ShodanIntel(self.config['shodan_api_key'])

        self.censys = None
        if self.config.get('censys_api_id') and self.config.get('censys_api_secret'):
            self.censys = CensysIntel(
                self.config['censys_api_id'],
                self.config['censys_api_secret']
            )

    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration"""
        logger = logging.getLogger('DomainIntelligence')
        logger.setLevel(logging.INFO)

        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

        return logger

    def investigate(self, domain: str, full_scan: bool = True) -> Dict[str, Any]:
        """
        Perform comprehensive domain investigation

        Args:
            domain: Target domain name
            full_scan: If True, perform all checks including slow operations

        Returns:
            Complete domain intelligence profile
        """
        self.logger.info(f"Starting investigation for domain: {domain}")

        results = {
            'domain': domain,
            'timestamp': datetime.utcnow().isoformat(),
            'whois': {},
            'dns': {},
            'subdomains': [],
            'ssl': {},
            'technology': {},
            'shodan': {},
            'censys': {},
            'metadata': {
                'scan_type': 'full' if full_scan else 'quick',
                'modules_used': []
            }
        }

        # WHOIS Investigation
        try:
            self.logger.info("Gathering WHOIS information...")
            results['whois'] = self.whois.analyze(domain)
            results['metadata']['modules_used'].append('whois')
        except Exception as e:
            self.logger.error(f"WHOIS analysis failed: {e}")
            results['whois'] = {'error': str(e)}

        # DNS Investigation
        try:
            self.logger.info("Analyzing DNS records...")
            results['dns'] = self.dns.analyze(domain, include_historical=full_scan)
            results['metadata']['modules_used'].append('dns')
        except Exception as e:
            self.logger.error(f"DNS analysis failed: {e}")
            results['dns'] = {'error': str(e)}

        # Subdomain Enumeration
        if full_scan:
            try:
                self.logger.info("Enumerating subdomains...")
                results['subdomains'] = self.subdomain.enumerate(domain)
                results['metadata']['modules_used'].append('subdomain')
            except Exception as e:
                self.logger.error(f"Subdomain enumeration failed: {e}")
                results['subdomains'] = {'error': str(e)}

        # SSL/TLS Analysis
        try:
            self.logger.info("Analyzing SSL/TLS configuration...")
            results['ssl'] = self.ssl.analyze(domain)
            results['metadata']['modules_used'].append('ssl')
        except Exception as e:
            self.logger.error(f"SSL analysis failed: {e}")
            results['ssl'] = {'error': str(e)}

        # Technology Profiling
        try:
            self.logger.info("Profiling technology stack...")
            results['technology'] = self.tech.profile(domain)
            results['metadata']['modules_used'].append('technology')
        except Exception as e:
            self.logger.error(f"Technology profiling failed: {e}")
            results['technology'] = {'error': str(e)}

        # Shodan Intelligence
        if self.shodan and full_scan:
            try:
                self.logger.info("Gathering Shodan intelligence...")
                results['shodan'] = self.shodan.search_domain(domain)
                results['metadata']['modules_used'].append('shodan')
            except Exception as e:
                self.logger.error(f"Shodan search failed: {e}")
                results['shodan'] = {'error': str(e)}

        # Censys Intelligence
        if self.censys and full_scan:
            try:
                self.logger.info("Gathering Censys intelligence...")
                results['censys'] = self.censys.search_domain(domain)
                results['metadata']['modules_used'].append('censys')
            except Exception as e:
                self.logger.error(f"Censys search failed: {e}")
                results['censys'] = {'error': str(e)}

        # Add summary
        results['summary'] = self._generate_summary(results)

        self.logger.info(f"Investigation complete for {domain}")
        return results

    def investigate_ip(self, ip_address: str) -> Dict[str, Any]:
        """
        Investigate IP address

        Args:
            ip_address: Target IP address

        Returns:
            IP intelligence profile
        """
        self.logger.info(f"Starting IP investigation: {ip_address}")

        results = {
            'ip': ip_address,
            'timestamp': datetime.utcnow().isoformat(),
            'reverse_dns': {},
            'ssl': {},
            'shodan': {},
            'censys': {}
        }

        # Reverse DNS
        try:
            hostname = socket.gethostbyaddr(ip_address)[0]
            results['reverse_dns'] = {
                'hostname': hostname,
                'found': True
            }
        except socket.herror:
            results['reverse_dns'] = {'found': False}
        except Exception as e:
            results['reverse_dns'] = {'error': str(e)}

        # SSL Analysis (if HTTPS is running)
        try:
            results['ssl'] = self.ssl.analyze_ip(ip_address)
        except Exception as e:
            results['ssl'] = {'error': str(e)}

        # Shodan
        if self.shodan:
            try:
                results['shodan'] = self.shodan.search_ip(ip_address)
            except Exception as e:
                results['shodan'] = {'error': str(e)}

        # Censys
        if self.censys:
            try:
                results['censys'] = self.censys.search_ip(ip_address)
            except Exception as e:
                results['censys'] = {'error': str(e)}

        return results

    def quick_scan(self, domain: str) -> Dict[str, Any]:
        """
        Perform quick domain scan (essential info only)

        Args:
            domain: Target domain

        Returns:
            Quick scan results
        """
        return self.investigate(domain, full_scan=False)

    def _generate_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate investigation summary"""
        summary = {
            'domain': results.get('domain'),
            'registered': False,
            'registrar': None,
            'nameservers': [],
            'ip_addresses': [],
            'subdomain_count': 0,
            'ssl_valid': False,
            'technologies': [],
            'risk_indicators': []
        }

        # WHOIS summary
        if results.get('whois') and not results['whois'].get('error'):
            summary['registered'] = True
            summary['registrar'] = results['whois'].get('registrar')

        # DNS summary
        if results.get('dns') and not results['dns'].get('error'):
            dns_data = results['dns']
            if 'records' in dns_data:
                records = dns_data['records']
                summary['ip_addresses'] = records.get('A', []) + records.get('AAAA', [])
                summary['nameservers'] = records.get('NS', [])

        # Subdomain summary
        if isinstance(results.get('subdomains'), list):
            summary['subdomain_count'] = len(results['subdomains'])

        # SSL summary
        if results.get('ssl') and not results['ssl'].get('error'):
            ssl_data = results['ssl']
            summary['ssl_valid'] = ssl_data.get('valid', False)

        # Technology summary
        if results.get('technology') and not results['technology'].get('error'):
            tech_data = results['technology']
            summary['technologies'] = tech_data.get('technologies', [])

        # Risk indicators
        if results.get('whois', {}).get('privacy_service'):
            summary['risk_indicators'].append('Privacy service detected')

        if results.get('ssl', {}).get('vulnerabilities'):
            summary['risk_indicators'].append('SSL vulnerabilities found')

        if results.get('dns', {}).get('dnssec_enabled') == False:
            summary['risk_indicators'].append('DNSSEC not enabled')

        return summary

    def export_report(self, results: Dict[str, Any],
                     filename: str, format: str = 'json') -> None:
        """
        Export investigation results

        Args:
            results: Investigation results
            filename: Output filename
            format: Export format (json, html, txt)
        """
        if format == 'json':
            with open(filename, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            self.logger.info(f"Report exported to {filename}")

        elif format == 'html':
            html_content = self._generate_html_report(results)
            with open(filename, 'w') as f:
                f.write(html_content)
            self.logger.info(f"HTML report exported to {filename}")

        elif format == 'txt':
            txt_content = self._generate_text_report(results)
            with open(filename, 'w') as f:
                f.write(txt_content)
            self.logger.info(f"Text report exported to {filename}")

    def _generate_html_report(self, results: Dict[str, Any]) -> str:
        """Generate HTML report"""
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Domain Intelligence Report - {results['domain']}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color: #333; }}
        h2 {{ color: #666; border-bottom: 2px solid #ddd; }}
        .section {{ margin: 20px 0; }}
        .info {{ background: #f5f5f5; padding: 10px; margin: 5px 0; }}
        .risk {{ background: #ffe6e6; padding: 10px; margin: 5px 0; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background: #4CAF50; color: white; }}
    </style>
</head>
<body>
    <h1>Domain Intelligence Report</h1>
    <div class="info">
        <strong>Domain:</strong> {results['domain']}<br>
        <strong>Scan Date:</strong> {results['timestamp']}<br>
        <strong>Scan Type:</strong> {results['metadata']['scan_type']}
    </div>

    <div class="section">
        <h2>Summary</h2>
        {self._format_dict_as_html(results.get('summary', {}))}
    </div>

    <div class="section">
        <h2>WHOIS Information</h2>
        {self._format_dict_as_html(results.get('whois', {}))}
    </div>

    <div class="section">
        <h2>DNS Records</h2>
        {self._format_dict_as_html(results.get('dns', {}))}
    </div>

    <div class="section">
        <h2>SSL/TLS Analysis</h2>
        {self._format_dict_as_html(results.get('ssl', {}))}
    </div>

    <div class="section">
        <h2>Technology Profile</h2>
        {self._format_dict_as_html(results.get('technology', {}))}
    </div>
</body>
</html>
"""
        return html

    def _format_dict_as_html(self, data: Dict) -> str:
        """Format dictionary as HTML"""
        html = "<table>"
        for key, value in data.items():
            html += f"<tr><th>{key}</th><td>{value}</td></tr>"
        html += "</table>"
        return html

    def _generate_text_report(self, results: Dict[str, Any]) -> str:
        """Generate text report"""
        lines = [
            "=" * 80,
            "DOMAIN INTELLIGENCE REPORT",
            "=" * 80,
            f"Domain: {results['domain']}",
            f"Scan Date: {results['timestamp']}",
            f"Scan Type: {results['metadata']['scan_type']}",
            "=" * 80,
            "",
            "SUMMARY",
            "-" * 80
        ]

        for key, value in results.get('summary', {}).items():
            lines.append(f"{key}: {value}")

        lines.extend(["", "WHOIS INFORMATION", "-" * 80])
        for key, value in results.get('whois', {}).items():
            lines.append(f"{key}: {value}")

        lines.extend(["", "DNS RECORDS", "-" * 80])
        for key, value in results.get('dns', {}).items():
            lines.append(f"{key}: {value}")

        return "\n".join(lines)


def main():
    """Example usage"""
    # Initialize with API keys
    config = {
        'shodan_api_key': 'YOUR_SHODAN_KEY',
        'censys_api_id': 'YOUR_CENSYS_ID',
        'censys_api_secret': 'YOUR_CENSYS_SECRET',
        'virustotal_api_key': 'YOUR_VT_KEY'
    }

    # Create domain intelligence instance
    domain_intel = DomainIntelligence(config)

    # Investigate domain
    results = domain_intel.investigate("example.com")

    # Print summary
    print(json.dumps(results['summary'], indent=2))

    # Export full report
    domain_intel.export_report(results, "domain_report.json", format='json')
    domain_intel.export_report(results, "domain_report.html", format='html')


if __name__ == "__main__":
    main()
