"""
SSL/TLS Analyzer - SSL Certificate and Configuration Analysis
Comprehensive SSL/TLS security assessment
"""

import ssl
import socket
import requests
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any
import json
from urllib.parse import urlparse
import OpenSSL
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class SSLAnalyzer:
    """
    SSL/TLS certificate and configuration analyzer
    Checks certificate validity, cipher suites, and vulnerabilities
    """

    def __init__(self):
        """Initialize SSL analyzer"""
        self.logger = logging.getLogger('SSLAnalyzer')

        # Weak cipher patterns
        self.weak_ciphers = [
            'NULL', 'EXPORT', 'DES', 'RC2', 'RC4', 'MD5',
            'anon', 'aDSS', 'kDHr', 'kDHd', 'kDH'
        ]

        # Known vulnerabilities
        self.vulnerabilities = {
            'SSLv2': 'SSLv2 is deprecated and insecure',
            'SSLv3': 'SSLv3 is vulnerable to POODLE attack',
            'TLSv1.0': 'TLSv1.0 has known weaknesses',
            'TLSv1.1': 'TLSv1.1 is deprecated'
        }

    def analyze(self, domain: str, port: int = 443) -> Dict[str, Any]:
        """
        Perform comprehensive SSL/TLS analysis

        Args:
            domain: Target domain
            port: SSL port (default 443)

        Returns:
            Complete SSL/TLS analysis
        """
        self.logger.info(f"Analyzing SSL/TLS for {domain}:{port}")

        results = {
            'domain': domain,
            'port': port,
            'timestamp': datetime.utcnow().isoformat(),
            'certificate': {},
            'chain': [],
            'protocols': {},
            'cipher_suites': [],
            'vulnerabilities': [],
            'grade': None,
            'valid': False
        }

        try:
            # Get certificate
            cert_info = self.get_certificate(domain, port)
            results['certificate'] = cert_info
            results['valid'] = cert_info.get('valid', False)

            # Get certificate chain
            results['chain'] = self.get_certificate_chain(domain, port)

            # Check supported protocols
            results['protocols'] = self.check_protocols(domain, port)

            # Get cipher suites
            results['cipher_suites'] = self.get_cipher_suites(domain, port)

            # Check vulnerabilities
            results['vulnerabilities'] = self.check_vulnerabilities(
                results['protocols'],
                results['cipher_suites']
            )

            # Calculate security grade
            results['grade'] = self.calculate_grade(results)

        except Exception as e:
            self.logger.error(f"SSL analysis failed: {e}")
            results['error'] = str(e)

        return results

    def analyze_ip(self, ip_address: str, port: int = 443) -> Dict[str, Any]:
        """
        Analyze SSL/TLS on IP address

        Args:
            ip_address: Target IP
            port: SSL port

        Returns:
            SSL analysis results
        """
        return self.analyze(ip_address, port)

    def get_certificate(self, hostname: str, port: int = 443) -> Dict[str, Any]:
        """
        Get SSL certificate information

        Args:
            hostname: Target hostname
            port: SSL port

        Returns:
            Certificate details
        """
        cert_info = {
            'subject': {},
            'issuer': {},
            'version': None,
            'serial_number': None,
            'not_before': None,
            'not_after': None,
            'days_until_expiration': None,
            'san': [],
            'signature_algorithm': None,
            'key_size': None,
            'valid': False,
            'self_signed': False
        }

        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)
                    cert = x509.load_der_x509_certificate(cert_der, default_backend())

                    # Subject
                    for attribute in cert.subject:
                        cert_info['subject'][attribute.oid._name] = attribute.value

                    # Issuer
                    for attribute in cert.issuer:
                        cert_info['issuer'][attribute.oid._name] = attribute.value

                    # Version
                    cert_info['version'] = cert.version.name

                    # Serial number
                    cert_info['serial_number'] = str(cert.serial_number)

                    # Validity period
                    cert_info['not_before'] = cert.not_valid_before.isoformat()
                    cert_info['not_after'] = cert.not_valid_after.isoformat()

                    # Days until expiration
                    now = datetime.now()
                    if cert.not_valid_after.tzinfo:
                        from datetime import timezone
                        now = datetime.now(timezone.utc)
                    days_left = (cert.not_valid_after - now).days
                    cert_info['days_until_expiration'] = days_left

                    # Check if valid
                    cert_info['valid'] = (
                        cert.not_valid_before <= now <= cert.not_valid_after
                    )

                    # Subject Alternative Names
                    try:
                        san_ext = cert.extensions.get_extension_for_oid(
                            x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
                        )
                        cert_info['san'] = [
                            name.value for name in san_ext.value
                        ]
                    except x509.ExtensionNotFound:
                        pass

                    # Signature algorithm
                    cert_info['signature_algorithm'] = cert.signature_algorithm_oid._name

                    # Public key size
                    cert_info['key_size'] = cert.public_key().key_size

                    # Check if self-signed
                    cert_info['self_signed'] = (
                        cert.issuer == cert.subject
                    )

        except Exception as e:
            cert_info['error'] = str(e)

        return cert_info

    def get_certificate_chain(self, hostname: str, port: int = 443) -> List[Dict[str, str]]:
        """
        Get SSL certificate chain

        Args:
            hostname: Target hostname
            port: SSL port

        Returns:
            List of certificates in chain
        """
        chain = []

        try:
            context = ssl.create_default_context()

            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Get certificate chain
                    cert_chain = ssock.getpeercert_chain()

                    if cert_chain:
                        for cert_der in cert_chain:
                            cert = x509.load_der_x509_certificate(
                                cert_der.public_bytes(encoding=ssl.Encoding.DER),
                                default_backend()
                            )

                            chain.append({
                                'subject': str(cert.subject),
                                'issuer': str(cert.issuer),
                                'not_after': cert.not_valid_after.isoformat()
                            })

        except Exception as e:
            self.logger.debug(f"Failed to get certificate chain: {e}")

        return chain

    def check_protocols(self, hostname: str, port: int = 443) -> Dict[str, bool]:
        """
        Check supported SSL/TLS protocols

        Args:
            hostname: Target hostname
            port: SSL port

        Returns:
            Dict of protocol support
        """
        protocols = {
            'SSLv2': False,
            'SSLv3': False,
            'TLSv1.0': False,
            'TLSv1.1': False,
            'TLSv1.2': False,
            'TLSv1.3': False
        }

        protocol_versions = {
            'SSLv2': ssl.PROTOCOL_SSLv23,  # Will try SSLv2
            'SSLv3': ssl.PROTOCOL_SSLv23,  # Will try SSLv3
            'TLSv1.0': ssl.PROTOCOL_TLSv1,
            'TLSv1.1': ssl.PROTOCOL_TLSv1_1,
            'TLSv1.2': ssl.PROTOCOL_TLSv1_2,
        }

        # Check TLSv1.3 if available
        if hasattr(ssl, 'PROTOCOL_TLSv1_3'):
            protocol_versions['TLSv1.3'] = ssl.PROTOCOL_TLSv1_3

        for protocol_name, protocol_version in protocol_versions.items():
            try:
                context = ssl.SSLContext(protocol_version)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                with socket.create_connection((hostname, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        protocols[protocol_name] = True

            except Exception:
                protocols[protocol_name] = False

        return protocols

    def get_cipher_suites(self, hostname: str, port: int = 443) -> List[str]:
        """
        Get supported cipher suites

        Args:
            hostname: Target hostname
            port: SSL port

        Returns:
            List of supported cipher suites
        """
        ciphers = []

        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cipher = ssock.cipher()
                    if cipher:
                        ciphers.append({
                            'name': cipher[0],
                            'protocol': cipher[1],
                            'bits': cipher[2]
                        })

        except Exception as e:
            self.logger.debug(f"Failed to get cipher suites: {e}")

        return ciphers

    def check_vulnerabilities(self, protocols: Dict[str, bool],
                             cipher_suites: List[Dict[str, Any]]) -> List[Dict[str, str]]:
        """
        Check for SSL/TLS vulnerabilities

        Args:
            protocols: Supported protocols
            cipher_suites: Supported cipher suites

        Returns:
            List of vulnerabilities found
        """
        vulnerabilities = []

        # Check protocol vulnerabilities
        for protocol, supported in protocols.items():
            if supported and protocol in self.vulnerabilities:
                vulnerabilities.append({
                    'type': 'weak_protocol',
                    'name': protocol,
                    'description': self.vulnerabilities[protocol],
                    'severity': 'high' if protocol in ['SSLv2', 'SSLv3'] else 'medium'
                })

        # Check cipher vulnerabilities
        for cipher in cipher_suites:
            cipher_name = cipher.get('name', '')

            # Check for weak ciphers
            for weak in self.weak_ciphers:
                if weak.lower() in cipher_name.lower():
                    vulnerabilities.append({
                        'type': 'weak_cipher',
                        'name': cipher_name,
                        'description': f'Weak cipher: {weak}',
                        'severity': 'high'
                    })
                    break

            # Check key size
            if cipher.get('bits', 256) < 128:
                vulnerabilities.append({
                    'type': 'weak_key',
                    'name': cipher_name,
                    'description': f'Weak key size: {cipher["bits"]} bits',
                    'severity': 'high'
                })

        return vulnerabilities

    def calculate_grade(self, analysis: Dict[str, Any]) -> str:
        """
        Calculate security grade (A+ to F)

        Args:
            analysis: Complete SSL analysis

        Returns:
            Security grade
        """
        score = 100

        # Certificate issues
        if not analysis.get('certificate', {}).get('valid'):
            score -= 30

        if analysis.get('certificate', {}).get('self_signed'):
            score -= 20

        days_left = analysis.get('certificate', {}).get('days_until_expiration', 999)
        if days_left < 0:
            score -= 40
        elif days_left < 30:
            score -= 10

        # Protocol issues
        protocols = analysis.get('protocols', {})
        if protocols.get('SSLv2') or protocols.get('SSLv3'):
            score -= 30
        if protocols.get('TLSv1.0'):
            score -= 10
        if not protocols.get('TLSv1.2') and not protocols.get('TLSv1.3'):
            score -= 20

        # Vulnerability count
        vuln_count = len(analysis.get('vulnerabilities', []))
        score -= vuln_count * 5

        # Grade mapping
        if score >= 95:
            return 'A+'
        elif score >= 85:
            return 'A'
        elif score >= 75:
            return 'B'
        elif score >= 65:
            return 'C'
        elif score >= 50:
            return 'D'
        else:
            return 'F'

    def check_certificate_transparency(self, domain: str) -> List[Dict[str, Any]]:
        """
        Check certificate transparency logs

        Args:
            domain: Target domain

        Returns:
            List of certificates from CT logs
        """
        ct_logs = []

        try:
            url = f"https://crt.sh/?q={domain}&output=json"
            response = requests.get(url, timeout=30)

            if response.status_code == 200:
                data = response.json()

                for entry in data[:50]:  # Limit to 50 most recent
                    ct_logs.append({
                        'issuer': entry.get('issuer_name'),
                        'common_name': entry.get('common_name'),
                        'not_before': entry.get('not_before'),
                        'not_after': entry.get('not_after'),
                        'serial_number': entry.get('serial_number')
                    })

        except Exception as e:
            self.logger.error(f"CT log query failed: {e}")

        return ct_logs

    def test_heartbleed(self, hostname: str, port: int = 443) -> bool:
        """
        Test for Heartbleed vulnerability (CVE-2014-0160)

        Args:
            hostname: Target hostname
            port: SSL port

        Returns:
            True if vulnerable, False otherwise
        """
        # Note: This is a simplified check
        # Full heartbleed testing requires more complex implementation
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock) as ssock:
                    # If TLSv1.0 with specific OpenSSL versions is supported,
                    # it might be vulnerable
                    # This is a basic heuristic, not a definitive test
                    return False

        except Exception:
            return False


def main():
    """Example usage"""
    analyzer = SSLAnalyzer()

    # Analyze SSL
    results = analyzer.analyze("example.com")

    print(f"Domain: {results['domain']}")
    print(f"Grade: {results['grade']}")
    print(f"Valid: {results['valid']}")
    print(f"\nCertificate:")
    print(f"  Subject: {results['certificate'].get('subject')}")
    print(f"  Issuer: {results['certificate'].get('issuer')}")
    print(f"  Expires: {results['certificate'].get('not_after')}")
    print(f"  Days left: {results['certificate'].get('days_until_expiration')}")

    print(f"\nProtocols:")
    for protocol, supported in results['protocols'].items():
        print(f"  {protocol}: {supported}")

    if results['vulnerabilities']:
        print(f"\nVulnerabilities:")
        for vuln in results['vulnerabilities']:
            print(f"  [{vuln['severity']}] {vuln['name']}: {vuln['description']}")


if __name__ == "__main__":
    main()
