"""
Vulnerability Scanner Module
Detect security vulnerabilities, misconfigurations, and SSL/TLS issues
"""

import asyncio
import aiohttp
import ssl
import socket
import logging
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime
import re
import certifi
from OpenSSL import SSL, crypto
import hashlib


@dataclass
class Vulnerability:
    """Container for vulnerability information"""
    title: str
    severity: str  # critical, high, medium, low, info
    description: str
    cve: Optional[str] = None
    cvss_score: Optional[float] = None
    affected_component: Optional[str] = None
    remediation: Optional[str] = None
    references: Optional[List[str]] = None


class VulnerabilityScanner:
    """
    Advanced vulnerability scanner for web applications and infrastructure
    """

    # Security headers that should be present
    SECURITY_HEADERS = {
        'Strict-Transport-Security': {
            'required': True,
            'description': 'HSTS header missing - site vulnerable to SSL stripping',
            'severity': 'medium'
        },
        'X-Frame-Options': {
            'required': True,
            'description': 'X-Frame-Options header missing - vulnerable to clickjacking',
            'severity': 'medium'
        },
        'X-Content-Type-Options': {
            'required': True,
            'description': 'X-Content-Type-Options header missing - vulnerable to MIME sniffing',
            'severity': 'low'
        },
        'Content-Security-Policy': {
            'required': True,
            'description': 'CSP header missing - vulnerable to XSS attacks',
            'severity': 'medium'
        },
        'X-XSS-Protection': {
            'required': False,
            'description': 'X-XSS-Protection header missing (deprecated but recommended)',
            'severity': 'info'
        },
        'Referrer-Policy': {
            'required': False,
            'description': 'Referrer-Policy header missing - potential information leakage',
            'severity': 'info'
        },
        'Permissions-Policy': {
            'required': False,
            'description': 'Permissions-Policy header missing',
            'severity': 'info'
        }
    }

    # Dangerous headers that should NOT be present
    DANGEROUS_HEADERS = {
        'Server': {
            'description': 'Server header reveals software version',
            'severity': 'info'
        },
        'X-Powered-By': {
            'description': 'X-Powered-By header reveals technology stack',
            'severity': 'info'
        },
        'X-AspNet-Version': {
            'description': 'X-AspNet-Version header reveals framework version',
            'severity': 'info'
        },
        'X-AspNetMvc-Version': {
            'description': 'X-AspNetMvc-Version header reveals framework version',
            'severity': 'info'
        }
    }

    # Known vulnerable software versions (simplified CVE database)
    CVE_DATABASE = {
        'Apache': {
            '2.4.49': {
                'cve': 'CVE-2021-41773',
                'severity': 'critical',
                'cvss': 9.8,
                'description': 'Path traversal and RCE vulnerability',
                'remediation': 'Upgrade to Apache 2.4.51 or later'
            },
            '2.4.50': {
                'cve': 'CVE-2021-42013',
                'severity': 'critical',
                'cvss': 9.8,
                'description': 'Path traversal and RCE vulnerability',
                'remediation': 'Upgrade to Apache 2.4.51 or later'
            }
        },
        'nginx': {
            '1.20.0': {
                'cve': 'CVE-2021-23017',
                'severity': 'high',
                'cvss': 7.7,
                'description': 'Off-by-one buffer overflow in resolver',
                'remediation': 'Upgrade to nginx 1.20.1 or later'
            }
        },
        'OpenSSH': {
            '7.4': {
                'cve': 'CVE-2018-15473',
                'severity': 'medium',
                'cvss': 5.3,
                'description': 'Username enumeration vulnerability',
                'remediation': 'Upgrade to OpenSSH 7.8 or later'
            }
        }
    }

    def __init__(self, config: Dict):
        """Initialize vulnerability scanner"""
        self.config = config.get('vuln', {})
        self.timeout = config.get('timeout', 30)
        self.logger = logging.getLogger('VulnScanner')

        self.user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'

    async def scan(
        self,
        domain: str,
        open_ports: Optional[List[Dict]] = None,
        technologies: Optional[List[Dict]] = None
    ) -> Dict:
        """
        Scan for vulnerabilities

        Args:
            domain: Target domain
            open_ports: List of open ports
            technologies: List of detected technologies

        Returns:
            Dictionary containing vulnerabilities and SSL info
        """
        self.logger.info(f"Starting vulnerability scan for {domain}")

        results = {
            'vulnerabilities': [],
            'ssl_info': []
        }

        # SSL/TLS analysis
        if self.config.get('ssl_check', True):
            ssl_results = await self._check_ssl_tls(domain)
            results['ssl_info'].extend(ssl_results['ssl_info'])
            results['vulnerabilities'].extend(ssl_results['vulnerabilities'])

        # Security headers check
        if self.config.get('headers_check', True):
            header_vulns = await self._check_security_headers(domain)
            results['vulnerabilities'].extend(header_vulns)

        # CVE matching against detected technologies
        if self.config.get('cve_matching', True) and technologies:
            cve_vulns = self._match_cves(technologies)
            results['vulnerabilities'].extend(cve_vulns)

        # Common misconfigurations
        misconfig_vulns = await self._check_misconfigurations(domain)
        results['vulnerabilities'].extend(misconfig_vulns)

        # Convert vulnerabilities to dict format
        results['vulnerabilities'] = [
            self._vuln_to_dict(v) for v in results['vulnerabilities']
        ]

        self.logger.info(f"Found {len(results['vulnerabilities'])} potential vulnerabilities")
        return results

    async def _check_ssl_tls(self, domain: str) -> Dict:
        """
        Check SSL/TLS configuration and certificate

        Args:
            domain: Target domain

        Returns:
            Dictionary with SSL info and vulnerabilities
        """
        ssl_info = []
        vulnerabilities = []

        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            # Connect and get certificate
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    protocol = ssock.version()

                    # Extract certificate information
                    cert_info = {
                        'host': domain,
                        'protocol': protocol,
                        'cipher': cipher[0] if cipher else None,
                        'valid': True,
                        'issuer': dict(x[0] for x in cert.get('issuer', [])),
                        'subject': dict(x[0] for x in cert.get('subject', [])),
                        'not_before': cert.get('notBefore'),
                        'not_after': cert.get('notAfter'),
                        'expires': cert.get('notAfter')
                    }

                    # Check certificate validity
                    not_after = datetime.strptime(cert.get('notAfter'), '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (not_after - datetime.now()).days

                    if days_until_expiry < 0:
                        cert_info['valid'] = False
                        vulnerabilities.append(Vulnerability(
                            title='Expired SSL Certificate',
                            severity='critical',
                            description=f'SSL certificate expired on {cert.get("notAfter")}',
                            affected_component='SSL/TLS',
                            remediation='Renew SSL certificate immediately'
                        ))
                    elif days_until_expiry < 30:
                        vulnerabilities.append(Vulnerability(
                            title='SSL Certificate Expiring Soon',
                            severity='medium',
                            description=f'SSL certificate expires in {days_until_expiry} days',
                            affected_component='SSL/TLS',
                            remediation='Renew SSL certificate'
                        ))

                    # Check for weak protocols
                    if protocol in ['TLSv1', 'TLSv1.1', 'SSLv2', 'SSLv3']:
                        vulnerabilities.append(Vulnerability(
                            title='Weak SSL/TLS Protocol',
                            severity='high',
                            description=f'Server supports weak protocol: {protocol}',
                            affected_component='SSL/TLS',
                            remediation='Disable support for TLSv1.0, TLSv1.1, and earlier protocols'
                        ))

                    # Check for weak ciphers
                    if cipher and any(weak in cipher[0] for weak in ['RC4', 'DES', 'MD5', 'NULL']):
                        vulnerabilities.append(Vulnerability(
                            title='Weak Cipher Suite',
                            severity='high',
                            description=f'Server uses weak cipher: {cipher[0]}',
                            affected_component='SSL/TLS',
                            remediation='Configure server to use strong cipher suites only'
                        ))

                    ssl_info.append(cert_info)

        except ssl.SSLError as e:
            self.logger.warning(f"SSL error for {domain}: {e}")
            vulnerabilities.append(Vulnerability(
                title='SSL Configuration Error',
                severity='high',
                description=f'SSL/TLS configuration error: {str(e)}',
                affected_component='SSL/TLS',
                remediation='Review SSL/TLS configuration'
            ))
        except socket.timeout:
            self.logger.warning(f"Timeout connecting to {domain}:443")
        except Exception as e:
            self.logger.error(f"Error checking SSL for {domain}: {e}")

        return {
            'ssl_info': ssl_info,
            'vulnerabilities': vulnerabilities
        }

    async def _check_security_headers(self, domain: str) -> List[Vulnerability]:
        """
        Check for missing or misconfigured security headers

        Args:
            domain: Target domain

        Returns:
            List of header-related vulnerabilities
        """
        vulnerabilities = []

        urls_to_check = [
            f"https://{domain}",
            f"http://{domain}"
        ]

        for url in urls_to_check:
            try:
                async with aiohttp.ClientSession() as session:
                    headers = {'User-Agent': self.user_agent}

                    async with session.get(
                        url,
                        headers=headers,
                        timeout=self.timeout,
                        allow_redirects=True,
                        ssl=False
                    ) as response:
                        response_headers = response.headers

                        # Check for missing security headers
                        for header_name, header_info in self.SECURITY_HEADERS.items():
                            if header_name not in response_headers:
                                if header_info['required']:
                                    vulnerabilities.append(Vulnerability(
                                        title=f'Missing Security Header: {header_name}',
                                        severity=header_info['severity'],
                                        description=header_info['description'],
                                        affected_component='HTTP Headers',
                                        remediation=f'Add {header_name} header to HTTP responses'
                                    ))

                        # Check for dangerous headers
                        for header_name, header_info in self.DANGEROUS_HEADERS.items():
                            if header_name in response_headers:
                                vulnerabilities.append(Vulnerability(
                                    title=f'Information Disclosure: {header_name}',
                                    severity=header_info['severity'],
                                    description=f"{header_info['description']}: {response_headers[header_name]}",
                                    affected_component='HTTP Headers',
                                    remediation=f'Remove or obfuscate {header_name} header'
                                ))

                        # Check HTTPS enforcement
                        if url.startswith('http://') and 'Strict-Transport-Security' not in response_headers:
                            vulnerabilities.append(Vulnerability(
                                title='HTTP Accessible Without HTTPS Redirect',
                                severity='medium',
                                description='Site is accessible over HTTP without automatic redirect to HTTPS',
                                affected_component='HTTP Configuration',
                                remediation='Configure automatic redirect from HTTP to HTTPS and enable HSTS'
                            ))

                        break  # Only check first successful URL

            except aiohttp.ClientError as e:
                self.logger.debug(f"Connection error for {url}: {e}")
            except asyncio.TimeoutError:
                self.logger.debug(f"Timeout connecting to {url}")
            except Exception as e:
                self.logger.error(f"Error checking headers for {url}: {e}")

        return vulnerabilities

    def _match_cves(self, technologies: List[Dict]) -> List[Vulnerability]:
        """
        Match detected technologies against CVE database

        Args:
            technologies: List of detected technologies

        Returns:
            List of CVE-related vulnerabilities
        """
        vulnerabilities = []

        for tech in technologies:
            tech_name = tech.get('name')
            tech_version = tech.get('version')

            if not tech_version:
                continue

            # Check if technology is in CVE database
            if tech_name in self.CVE_DATABASE:
                version_vulns = self.CVE_DATABASE[tech_name]

                # Check for exact version match
                if tech_version in version_vulns:
                    vuln_info = version_vulns[tech_version]

                    vulnerabilities.append(Vulnerability(
                        title=f'{tech_name} {tech_version} - {vuln_info["cve"]}',
                        severity=vuln_info['severity'],
                        description=vuln_info['description'],
                        cve=vuln_info['cve'],
                        cvss_score=vuln_info['cvss'],
                        affected_component=f'{tech_name} {tech_version}',
                        remediation=vuln_info['remediation'],
                        references=[f'https://cve.mitre.org/cgi-bin/cvename.cgi?name={vuln_info["cve"]}']
                    ))

                # Check for version range vulnerabilities (simplified)
                # In production, use proper version comparison
                for vuln_version, vuln_info in version_vulns.items():
                    if self._is_vulnerable_version(tech_version, vuln_version):
                        vulnerabilities.append(Vulnerability(
                            title=f'{tech_name} - Potential {vuln_info["cve"]}',
                            severity=vuln_info['severity'],
                            description=f'Version {tech_version} may be affected by: {vuln_info["description"]}',
                            cve=vuln_info['cve'],
                            cvss_score=vuln_info['cvss'],
                            affected_component=f'{tech_name} {tech_version}',
                            remediation=vuln_info['remediation']
                        ))

        return vulnerabilities

    def _is_vulnerable_version(self, current_version: str, vuln_version: str) -> bool:
        """
        Check if current version is vulnerable (simplified version comparison)

        Args:
            current_version: Current version string
            vuln_version: Vulnerable version string

        Returns:
            True if potentially vulnerable
        """
        try:
            # Simple version comparison (in production, use packaging.version)
            current_parts = [int(x) for x in current_version.split('.') if x.isdigit()]
            vuln_parts = [int(x) for x in vuln_version.split('.') if x.isdigit()]

            # Pad shorter version with zeros
            max_len = max(len(current_parts), len(vuln_parts))
            current_parts += [0] * (max_len - len(current_parts))
            vuln_parts += [0] * (max_len - len(vuln_parts))

            # Compare versions
            return current_parts <= vuln_parts

        except:
            return False

    async def _check_misconfigurations(self, domain: str) -> List[Vulnerability]:
        """
        Check for common security misconfigurations

        Args:
            domain: Target domain

        Returns:
            List of misconfiguration vulnerabilities
        """
        vulnerabilities = []

        # Common paths that should not be accessible
        sensitive_paths = [
            '/.git/config',
            '/.env',
            '/.aws/credentials',
            '/config.php',
            '/phpinfo.php',
            '/.htaccess',
            '/web.config',
            '/backup.sql',
            '/database.sql',
            '/.DS_Store',
            '/server-status',
            '/admin',
            '/administrator',
            '/.svn/entries'
        ]

        for path in sensitive_paths:
            url = f"https://{domain}{path}"

            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, timeout=10, ssl=False) as response:
                        if response.status == 200:
                            vulnerabilities.append(Vulnerability(
                                title=f'Sensitive File Exposed: {path}',
                                severity='high',
                                description=f'Sensitive file or directory accessible at {path}',
                                affected_component='Web Server Configuration',
                                remediation=f'Restrict access to {path} or remove it from web root'
                            ))

            except:
                pass  # File not accessible (expected)

        # Check for directory listing
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"https://{domain}/", timeout=10, ssl=False) as response:
                    content = await response.text()

                    if 'Index of /' in content or 'Directory Listing For' in content:
                        vulnerabilities.append(Vulnerability(
                            title='Directory Listing Enabled',
                            severity='medium',
                            description='Web server is configured to show directory listings',
                            affected_component='Web Server Configuration',
                            remediation='Disable directory listing in web server configuration'
                        ))
        except:
            pass

        return vulnerabilities

    def _vuln_to_dict(self, vuln: Vulnerability) -> Dict:
        """Convert Vulnerability object to dictionary"""
        return {
            'title': vuln.title,
            'severity': vuln.severity,
            'description': vuln.description,
            'cve': vuln.cve,
            'cvss_score': vuln.cvss_score,
            'affected_component': vuln.affected_component,
            'remediation': vuln.remediation,
            'references': vuln.references
        }


async def main():
    """Test vulnerability scanner"""
    config = {
        'vuln': {
            'ssl_check': True,
            'headers_check': True,
            'cve_matching': True
        },
        'timeout': 30
    }

    scanner = VulnerabilityScanner(config)

    # Mock technologies for testing
    technologies = [
        {'name': 'Apache', 'version': '2.4.49', 'category': 'Web Server'},
        {'name': 'nginx', 'version': '1.20.0', 'category': 'Web Server'}
    ]

    results = await scanner.scan('example.com', technologies=technologies)

    print(f"\nFound {len(results['vulnerabilities'])} vulnerabilities:")
    for vuln in results['vulnerabilities']:
        print(f"  [{vuln['severity'].upper()}] {vuln['title']}")
        print(f"    {vuln['description']}")


if __name__ == '__main__':
    asyncio.run(main())
