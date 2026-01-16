"""
BBOT Reconnaissance System - Test Suite
Unit tests and integration tests for all modules
"""

import asyncio
import unittest
from unittest.mock import Mock, patch, AsyncMock
import json
from pathlib import Path

from bbot_integration import BBOTScanner, ScanResult
from subdomain_enum import SubdomainEnumerator, SubdomainResult
from port_scanner import PortScanner, PortResult
from tech_detector import TechnologyDetector, Technology
from vuln_scanner import VulnerabilityScanner, Vulnerability


class TestSubdomainEnumerator(unittest.TestCase):
    """Test subdomain enumeration functionality"""

    def setUp(self):
        self.config = {
            'subdomain': {
                'sources': ['crtsh'],
                'brute_force': False,
                'wordlist_size': 'small'
            },
            'timeout': 30
        }
        self.enumerator = SubdomainEnumerator(self.config)

    def test_initialization(self):
        """Test enumerator initialization"""
        self.assertIsNotNone(self.enumerator)
        self.assertEqual(self.enumerator.timeout, 30)

    def test_wordlist_generation(self):
        """Test wordlist generation"""
        small = self.enumerator._get_small_wordlist()
        medium = self.enumerator._get_medium_wordlist()
        large = self.enumerator._get_large_wordlist()

        self.assertGreater(len(small), 0)
        self.assertGreater(len(medium), len(small))
        self.assertGreater(len(large), len(medium))

        # Check expected entries
        self.assertIn('www', small)
        self.assertIn('mail', small)

    def test_wildcard_check(self):
        """Test wildcard DNS detection"""
        async def run_test():
            # This will likely return False for most domains
            has_wildcard = await self.enumerator._check_wildcard('example.com')
            self.assertIsInstance(has_wildcard, bool)

        asyncio.run(run_test())


class TestPortScanner(unittest.TestCase):
    """Test port scanning functionality"""

    def setUp(self):
        self.config = {
            'port': {
                'common_ports': True,
                'service_detection': True
            },
            'timeout': 5,
            'max_threads': 50
        }
        self.scanner = PortScanner(self.config)

    def test_initialization(self):
        """Test scanner initialization"""
        self.assertIsNotNone(self.scanner)
        self.assertEqual(self.scanner.timeout, 5)

    def test_port_definitions(self):
        """Test port definitions"""
        self.assertIn(80, self.scanner.COMMON_PORTS)
        self.assertIn(443, self.scanner.COMMON_PORTS)
        self.assertEqual(self.scanner.COMMON_PORTS[80], 'http')
        self.assertEqual(self.scanner.COMMON_PORTS[443], 'https')

    def test_banner_parsing(self):
        """Test banner parsing"""
        # Test HTTP server parsing
        http_banner = "HTTP/1.1 200 OK\r\nServer: nginx/1.20.1\r\n"
        result = self.scanner._parse_banner(http_banner, 80)
        self.assertIsNotNone(result)
        self.assertEqual(result.get('service'), 'nginx')

        # Test SSH banner parsing
        ssh_banner = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
        result = self.scanner._parse_banner(ssh_banner, 22)
        self.assertIsNotNone(result)
        self.assertEqual(result.get('service'), 'ssh')

    def test_port_result_conversion(self):
        """Test PortResult to dict conversion"""
        port_result = PortResult(
            host='example.com',
            port=80,
            state='open',
            service='http',
            version='nginx/1.20.1'
        )

        result_dict = self.scanner._port_result_to_dict(port_result)

        self.assertEqual(result_dict['host'], 'example.com')
        self.assertEqual(result_dict['port'], 80)
        self.assertEqual(result_dict['state'], 'open')
        self.assertEqual(result_dict['service'], 'http')


class TestTechnologyDetector(unittest.TestCase):
    """Test technology detection functionality"""

    def setUp(self):
        self.config = {
            'tech': {
                'deep_scan': True,
                'wappalyzer': True,
                'header_analysis': True
            },
            'timeout': 30
        }
        self.detector = TechnologyDetector(self.config)

    def test_initialization(self):
        """Test detector initialization"""
        self.assertIsNotNone(self.detector)
        self.assertEqual(self.detector.timeout, 30)

    def test_technology_signatures(self):
        """Test technology signature database"""
        self.assertIn('React', self.detector.TECH_SIGNATURES)
        self.assertIn('WordPress', self.detector.TECH_SIGNATURES)
        self.assertIn('nginx', self.detector.TECH_SIGNATURES)

        # Check signature structure
        react_sig = self.detector.TECH_SIGNATURES['React']
        self.assertIn('category', react_sig)
        self.assertIn('patterns', react_sig)
        self.assertEqual(react_sig['category'], 'JavaScript Framework')

    def test_version_extraction(self):
        """Test version number extraction"""
        # Test various version formats
        version = self.detector._extract_version('nginx/1.20.1')
        self.assertEqual(version, '1.20.1')

        version = self.detector._extract_version('Apache/2.4.49')
        self.assertEqual(version, '2.4.49')

        version = self.detector._extract_version('v3.2.1')
        self.assertEqual(version, '3.2.1')

    def test_url_building(self):
        """Test URL building"""
        urls = self.detector._build_urls('example.com', None)

        self.assertIn('https://example.com', urls)
        self.assertIn('http://example.com', urls)

        # Test with open ports
        open_ports = [
            {'host': 'example.com', 'port': 8080},
            {'host': 'example.com', 'port': 8443}
        ]

        urls = self.detector._build_urls('example.com', open_ports)
        self.assertIn('http://example.com:8080', urls)
        self.assertIn('https://example.com:8443', urls)


class TestVulnerabilityScanner(unittest.TestCase):
    """Test vulnerability scanning functionality"""

    def setUp(self):
        self.config = {
            'vuln': {
                'ssl_check': True,
                'headers_check': True,
                'cve_matching': True
            },
            'timeout': 30
        }
        self.scanner = VulnerabilityScanner(self.config)

    def test_initialization(self):
        """Test scanner initialization"""
        self.assertIsNotNone(self.scanner)
        self.assertEqual(self.scanner.timeout, 30)

    def test_security_headers(self):
        """Test security header definitions"""
        self.assertIn('Strict-Transport-Security', self.scanner.SECURITY_HEADERS)
        self.assertIn('Content-Security-Policy', self.scanner.SECURITY_HEADERS)
        self.assertIn('X-Frame-Options', self.scanner.SECURITY_HEADERS)

        hsts = self.scanner.SECURITY_HEADERS['Strict-Transport-Security']
        self.assertTrue(hsts['required'])
        self.assertEqual(hsts['severity'], 'medium')

    def test_dangerous_headers(self):
        """Test dangerous header definitions"""
        self.assertIn('Server', self.scanner.DANGEROUS_HEADERS)
        self.assertIn('X-Powered-By', self.scanner.DANGEROUS_HEADERS)

    def test_cve_database(self):
        """Test CVE database"""
        self.assertIn('Apache', self.scanner.CVE_DATABASE)
        self.assertIn('nginx', self.scanner.CVE_DATABASE)

        apache_vulns = self.scanner.CVE_DATABASE['Apache']
        self.assertIn('2.4.49', apache_vulns)

        vuln = apache_vulns['2.4.49']
        self.assertEqual(vuln['cve'], 'CVE-2021-41773')
        self.assertEqual(vuln['severity'], 'critical')
        self.assertEqual(vuln['cvss'], 9.8)

    def test_cve_matching(self):
        """Test CVE matching"""
        technologies = [
            {'name': 'Apache', 'version': '2.4.49', 'category': 'Web Server'}
        ]

        vulns = self.scanner._match_cves(technologies)

        self.assertGreater(len(vulns), 0)
        found_cve = any(v.cve == 'CVE-2021-41773' for v in vulns)
        self.assertTrue(found_cve)

    def test_version_comparison(self):
        """Test vulnerable version comparison"""
        # Test exact match
        self.assertTrue(self.scanner._is_vulnerable_version('2.4.49', '2.4.49'))

        # Test lower version
        self.assertTrue(self.scanner._is_vulnerable_version('2.4.48', '2.4.49'))

        # Test higher version
        self.assertFalse(self.scanner._is_vulnerable_version('2.4.50', '2.4.49'))

    def test_vulnerability_to_dict(self):
        """Test Vulnerability to dict conversion"""
        vuln = Vulnerability(
            title='Test Vulnerability',
            severity='high',
            description='Test description',
            cve='CVE-2021-12345',
            cvss_score=7.5,
            affected_component='Test Component',
            remediation='Update to latest version'
        )

        vuln_dict = self.scanner._vuln_to_dict(vuln)

        self.assertEqual(vuln_dict['title'], 'Test Vulnerability')
        self.assertEqual(vuln_dict['severity'], 'high')
        self.assertEqual(vuln_dict['cve'], 'CVE-2021-12345')
        self.assertEqual(vuln_dict['cvss_score'], 7.5)


class TestBBOTScanner(unittest.TestCase):
    """Test main BBOT scanner integration"""

    def setUp(self):
        self.scanner = BBOTScanner()

    def test_initialization(self):
        """Test scanner initialization"""
        self.assertIsNotNone(self.scanner)
        self.assertIsNotNone(self.scanner.config)
        self.assertIsNotNone(self.scanner.logger)

    def test_config_loading(self):
        """Test configuration loading"""
        # Test default config
        config = self.scanner._load_config(None)
        self.assertIn('timeout', config)
        self.assertIn('modules', config)
        self.assertIn('subdomain', config)
        self.assertIn('port', config)

    def test_module_initialization(self):
        """Test module initialization"""
        self.assertIsNotNone(self.scanner.subdomain_enum)
        self.assertIsNotNone(self.scanner.port_scanner)
        self.assertIsNotNone(self.scanner.tech_detector)
        self.assertIsNotNone(self.scanner.vuln_scanner)

    def test_severity_breakdown(self):
        """Test severity breakdown calculation"""
        vulnerabilities = [
            {'severity': 'critical'},
            {'severity': 'high'},
            {'severity': 'high'},
            {'severity': 'medium'},
            {'severity': 'low'},
            {'severity': 'info'}
        ]

        breakdown = self.scanner._get_severity_breakdown(vulnerabilities)

        self.assertEqual(breakdown['critical'], 1)
        self.assertEqual(breakdown['high'], 2)
        self.assertEqual(breakdown['medium'], 1)
        self.assertEqual(breakdown['low'], 1)
        self.assertEqual(breakdown['info'], 1)

    def test_top_technologies(self):
        """Test top technologies extraction"""
        technologies = [
            {'name': 'nginx'},
            {'name': 'React'},
            {'name': 'WordPress'},
        ]

        top = self.scanner._get_top_technologies(technologies, limit=2)

        self.assertEqual(len(top), 2)
        self.assertIn('nginx', top)
        self.assertIn('React', top)

    def test_critical_findings(self):
        """Test critical findings extraction"""
        scan_result = ScanResult(
            domain='test.com',
            timestamp='2026-01-14T10:00:00',
            subdomains=[],
            ports=[{'port': 3306}, {'port': 6379}],
            technologies=[],
            vulnerabilities=[
                {'severity': 'critical', 'title': 'Critical Vuln'},
                {'severity': 'high', 'title': 'High Vuln'}
            ],
            ssl_info=[{'valid': False}],
            metadata={}
        )

        findings = self.scanner._get_critical_findings(scan_result)

        self.assertGreater(len(findings), 0)

        # Should detect critical vulns
        critical_finding = any('critical/high' in f for f in findings)
        self.assertTrue(critical_finding)

        # Should detect invalid SSL
        ssl_finding = any('SSL' in f for f in findings)
        self.assertTrue(ssl_finding)

        # Should detect sensitive ports
        port_finding = any('sensitive ports' in f for f in findings)
        self.assertTrue(port_finding)


class TestIntegration(unittest.TestCase):
    """Integration tests for complete workflows"""

    def test_scan_result_structure(self):
        """Test ScanResult data structure"""
        result = ScanResult(
            domain='test.com',
            timestamp='2026-01-14T10:00:00',
            subdomains=[],
            ports=[],
            technologies=[],
            vulnerabilities=[],
            ssl_info=[],
            metadata={}
        )

        self.assertEqual(result.domain, 'test.com')
        self.assertEqual(result.timestamp, '2026-01-14T10:00:00')
        self.assertIsInstance(result.subdomains, list)
        self.assertIsInstance(result.ports, list)

    def test_config_presets(self):
        """Test configuration presets"""
        scanner = BBOTScanner()

        # Verify preset structure in config
        if 'presets' in scanner.config:
            self.assertIn('quick', scanner.config['presets'])
            self.assertIn('standard', scanner.config['presets'])
            self.assertIn('deep', scanner.config['presets'])


def run_tests():
    """Run all tests"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestSubdomainEnumerator))
    suite.addTests(loader.loadTestsFromTestCase(TestPortScanner))
    suite.addTests(loader.loadTestsFromTestCase(TestTechnologyDetector))
    suite.addTests(loader.loadTestsFromTestCase(TestVulnerabilityScanner))
    suite.addTests(loader.loadTestsFromTestCase(TestBBOTScanner))
    suite.addTests(loader.loadTestsFromTestCase(TestIntegration))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    return result.wasSuccessful()


if __name__ == '__main__':
    print("\n" + "="*80)
    print("BBOT RECONNAISSANCE SYSTEM - TEST SUITE")
    print("="*80 + "\n")

    success = run_tests()

    print("\n" + "="*80)
    if success:
        print("ALL TESTS PASSED")
    else:
        print("SOME TESTS FAILED")
    print("="*80 + "\n")

    exit(0 if success else 1)
