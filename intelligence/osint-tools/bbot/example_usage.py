"""
BBOT Reconnaissance System - Example Usage
Demonstrates various scanning scenarios and use cases
"""

import asyncio
import json
from pathlib import Path

from bbot_integration import BBOTScanner
from subdomain_enum import SubdomainEnumerator
from port_scanner import PortScanner
from tech_detector import TechnologyDetector
from vuln_scanner import VulnerabilityScanner


def example_1_basic_scan():
    """Example 1: Basic domain reconnaissance"""
    print("\n" + "="*80)
    print("EXAMPLE 1: Basic Domain Reconnaissance")
    print("="*80 + "\n")

    # Initialize scanner with default configuration
    scanner = BBOTScanner()

    # Perform basic scan
    result = scanner.scan_domain_sync("example.com")

    # Display results
    print(f"Domain: {result.domain}")
    print(f"Scan completed at: {result.timestamp}")
    print(f"\nResults:")
    print(f"  - Subdomains found: {len(result.subdomains)}")
    print(f"  - Open ports: {len(result.ports)}")
    print(f"  - Technologies detected: {len(result.technologies)}")
    print(f"  - Vulnerabilities found: {len(result.vulnerabilities)}")


def example_2_custom_config():
    """Example 2: Scan with custom configuration"""
    print("\n" + "="*80)
    print("EXAMPLE 2: Custom Configuration Scan")
    print("="*80 + "\n")

    # Initialize with custom config file
    scanner = BBOTScanner(config_path='bbot_config.yaml')

    # Perform deep scan
    result = scanner.scan_domain_sync(
        domain="example.com",
        modules=["subdomain", "port", "tech", "vuln"],
        deep_scan=True
    )

    # Get summary
    summary = scanner.get_summary(result)
    print(json.dumps(summary, indent=2))


async def example_3_async_scan():
    """Example 3: Asynchronous scanning"""
    print("\n" + "="*80)
    print("EXAMPLE 3: Asynchronous Scanning")
    print("="*80 + "\n")

    scanner = BBOTScanner()

    # Perform async scan
    result = await scanner.scan_domain(
        domain="example.com",
        modules=["subdomain", "port"],
        deep_scan=False
    )

    print(f"Scan completed asynchronously")
    print(f"Found {len(result.subdomains)} subdomains")
    print(f"Found {len(result.ports)} open ports")


async def example_4_multiple_domains():
    """Example 4: Scan multiple domains"""
    print("\n" + "="*80)
    print("EXAMPLE 4: Multiple Domain Scanning")
    print("="*80 + "\n")

    scanner = BBOTScanner()

    # List of domains to scan
    domains = [
        "example.com",
        "example.org",
        "example.net"
    ]

    # Scan all domains in parallel
    results = await scanner.scan_multiple_domains(
        domains,
        modules=["subdomain"],
        parallel=True
    )

    # Display results
    for domain, result in results.items():
        if result:
            print(f"{domain}: {len(result.subdomains)} subdomains")
        else:
            print(f"{domain}: Scan failed")


async def example_5_subdomain_only():
    """Example 5: Subdomain enumeration only"""
    print("\n" + "="*80)
    print("EXAMPLE 5: Subdomain Enumeration Only")
    print("="*80 + "\n")

    config = {
        'subdomain': {
            'sources': ['crtsh', 'hackertarget'],
            'brute_force': False,
            'wordlist_size': 'small'
        },
        'timeout': 30
    }

    enumerator = SubdomainEnumerator(config)
    subdomains = await enumerator.enumerate("example.com", deep_scan=False)

    print(f"Found {len(subdomains)} subdomains:")
    for i, subdomain in enumerate(subdomains[:10], 1):
        ip_list = ', '.join(subdomain['ip_addresses']) if subdomain['ip_addresses'] else 'N/A'
        print(f"  {i}. {subdomain['subdomain']} -> {ip_list}")

    if len(subdomains) > 10:
        print(f"  ... and {len(subdomains) - 10} more")


async def example_6_port_scanning():
    """Example 6: Port scanning specific targets"""
    print("\n" + "="*80)
    print("EXAMPLE 6: Port Scanning")
    print("="*80 + "\n")

    config = {
        'port': {
            'common_ports': True,
            'service_detection': True
        },
        'timeout': 5,
        'max_threads': 100
    }

    scanner = PortScanner(config)

    # Scan specific host
    print("Scanning example.com...")
    results = await scanner.scan_host("example.com", deep_scan=False)

    print(f"\nFound {len(results)} open ports:")
    for result in results:
        service_info = result['service']
        if result.get('version'):
            service_info += f" ({result['version']})"
        print(f"  {result['port']}/tcp - {service_info}")

    # Scan specific ports
    print("\nScanning specific ports on example.com...")
    specific_results = await scanner.scan_specific_ports(
        "example.com",
        [80, 443, 8080, 8443]
    )

    for result in specific_results:
        print(f"  Port {result['port']}: {result['state']}")


async def example_7_technology_detection():
    """Example 7: Technology stack detection"""
    print("\n" + "="*80)
    print("EXAMPLE 7: Technology Detection")
    print("="*80 + "\n")

    config = {
        'tech': {
            'deep_scan': True,
            'wappalyzer': True,
            'header_analysis': True
        },
        'timeout': 30
    }

    detector = TechnologyDetector(config)
    technologies = await detector.detect("example.com")

    print(f"Detected {len(technologies)} technologies:\n")

    # Group by category
    by_category = {}
    for tech in technologies:
        category = tech['category']
        if category not in by_category:
            by_category[category] = []
        by_category[category].append(tech)

    for category, techs in by_category.items():
        print(f"{category}:")
        for tech in techs:
            version_info = f" v{tech['version']}" if tech.get('version') else ""
            confidence = f"[{tech['confidence']}%]"
            print(f"  - {tech['name']}{version_info} {confidence}")
        print()


async def example_8_vulnerability_scanning():
    """Example 8: Vulnerability assessment"""
    print("\n" + "="*80)
    print("EXAMPLE 8: Vulnerability Scanning")
    print("="*80 + "\n")

    config = {
        'vuln': {
            'ssl_check': True,
            'headers_check': True,
            'cve_matching': True
        },
        'timeout': 30
    }

    scanner = VulnerabilityScanner(config)

    # Mock technologies for demonstration
    technologies = [
        {'name': 'nginx', 'version': '1.20.0', 'category': 'Web Server'},
        {'name': 'Apache', 'version': '2.4.49', 'category': 'Web Server'}
    ]

    results = await scanner.scan("example.com", technologies=technologies)

    print(f"Found {len(results['vulnerabilities'])} potential vulnerabilities:\n")

    # Group by severity
    by_severity = {
        'critical': [],
        'high': [],
        'medium': [],
        'low': [],
        'info': []
    }

    for vuln in results['vulnerabilities']:
        severity = vuln['severity'].lower()
        by_severity[severity].append(vuln)

    for severity in ['critical', 'high', 'medium', 'low', 'info']:
        vulns = by_severity[severity]
        if vulns:
            print(f"{severity.upper()} ({len(vulns)}):")
            for vuln in vulns:
                print(f"  - {vuln['title']}")
                if vuln.get('cve'):
                    print(f"    CVE: {vuln['cve']}")
                if vuln.get('remediation'):
                    print(f"    Fix: {vuln['remediation']}")
            print()

    # SSL information
    if results['ssl_info']:
        print(f"SSL/TLS Information:")
        for ssl_info in results['ssl_info']:
            print(f"  Host: {ssl_info['host']}")
            print(f"  Valid: {ssl_info['valid']}")
            print(f"  Protocol: {ssl_info.get('protocol', 'N/A')}")
            print(f"  Cipher: {ssl_info.get('cipher', 'N/A')}")
            print()


async def example_9_comprehensive_recon():
    """Example 9: Comprehensive reconnaissance workflow"""
    print("\n" + "="*80)
    print("EXAMPLE 9: Comprehensive Reconnaissance Workflow")
    print("="*80 + "\n")

    domain = "example.com"
    scanner = BBOTScanner(config_path='bbot_config.yaml')

    # Phase 1: Subdomain enumeration
    print(f"[*] Phase 1: Enumerating subdomains for {domain}...")
    result_phase1 = await scanner.scan_domain(
        domain,
        modules=["subdomain"],
        deep_scan=False
    )
    print(f"[+] Found {len(result_phase1.subdomains)} subdomains\n")

    # Phase 2: Port scanning
    print(f"[*] Phase 2: Scanning ports on {domain}...")
    result_phase2 = await scanner.scan_domain(
        domain,
        modules=["port"],
        deep_scan=False
    )
    print(f"[+] Found {len(result_phase2.ports)} open ports\n")

    # Phase 3: Technology detection
    print(f"[*] Phase 3: Detecting technologies...")
    result_phase3 = await scanner.scan_domain(
        domain,
        modules=["tech"],
        deep_scan=True
    )
    print(f"[+] Detected {len(result_phase3.technologies)} technologies\n")

    # Phase 4: Vulnerability assessment
    print(f"[*] Phase 4: Assessing vulnerabilities...")
    final_result = await scanner.scan_domain(
        domain,
        modules=["subdomain", "port", "tech", "vuln"],
        deep_scan=True
    )
    print(f"[+] Found {len(final_result.vulnerabilities)} potential vulnerabilities\n")

    # Generate summary report
    summary = scanner.get_summary(final_result)

    print("\n" + "="*80)
    print(f"FINAL SUMMARY - {domain}")
    print("="*80)
    print(f"\nStatistics:")
    print(f"  Subdomains: {summary['statistics']['subdomains_found']}")
    print(f"  Open Ports: {summary['statistics']['open_ports']}")
    print(f"  Technologies: {summary['statistics']['technologies_detected']}")
    print(f"  Vulnerabilities: {summary['statistics']['vulnerabilities_found']}")

    print(f"\nVulnerability Breakdown:")
    for severity, count in summary['severity_breakdown'].items():
        if count > 0:
            print(f"  {severity.capitalize()}: {count}")

    if summary.get('critical_findings'):
        print(f"\nCritical Findings:")
        for finding in summary['critical_findings']:
            print(f"  [!] {finding}")

    print(f"\nTop Technologies:")
    for tech in summary['top_technologies'][:5]:
        print(f"  - {tech}")

    print(f"\nScan Duration: {summary['duration']:.2f} seconds")


def example_10_custom_output():
    """Example 10: Custom output handling"""
    print("\n" + "="*80)
    print("EXAMPLE 10: Custom Output Handling")
    print("="*80 + "\n")

    scanner = BBOTScanner()

    # Perform scan
    result = scanner.scan_domain_sync("example.com")

    # Custom JSON export
    output_data = {
        'scan_info': {
            'domain': result.domain,
            'timestamp': result.timestamp,
            'duration': result.metadata.get('duration_seconds', 0)
        },
        'findings': {
            'subdomains': [s['subdomain'] for s in result.subdomains],
            'open_ports': [f"{p['host']}:{p['port']}" for p in result.ports],
            'technologies': [t['name'] for t in result.technologies],
            'vulnerability_count': len(result.vulnerabilities)
        }
    }

    # Save custom format
    custom_output = Path('./custom_output.json')
    with open(custom_output, 'w') as f:
        json.dump(output_data, f, indent=2)

    print(f"Custom output saved to: {custom_output}")
    print(f"\nCustom output preview:")
    print(json.dumps(output_data, indent=2))


# Main execution
if __name__ == '__main__':
    print("\n" + "="*80)
    print("BBOT RECONNAISSANCE SYSTEM - USAGE EXAMPLES")
    print("="*80)

    # Synchronous examples
    print("\n\n### SYNCHRONOUS EXAMPLES ###\n")

    # Example 1: Basic scan
    example_1_basic_scan()

    # Example 2: Custom configuration
    # example_2_custom_config()  # Uncomment to run

    # Example 10: Custom output
    # example_10_custom_output()  # Uncomment to run

    # Asynchronous examples
    print("\n\n### ASYNCHRONOUS EXAMPLES ###\n")

    # Example 3: Async scan
    # asyncio.run(example_3_async_scan())  # Uncomment to run

    # Example 4: Multiple domains
    # asyncio.run(example_4_multiple_domains())  # Uncomment to run

    # Example 5: Subdomain enumeration
    # asyncio.run(example_5_subdomain_only())  # Uncomment to run

    # Example 6: Port scanning
    # asyncio.run(example_6_port_scanning())  # Uncomment to run

    # Example 7: Technology detection
    # asyncio.run(example_7_technology_detection())  # Uncomment to run

    # Example 8: Vulnerability scanning
    # asyncio.run(example_8_vulnerability_scanning())  # Uncomment to run

    # Example 9: Comprehensive reconnaissance
    # asyncio.run(example_9_comprehensive_recon())  # Uncomment to run

    print("\n\n" + "="*80)
    print("Examples complete! Uncomment specific examples to run them.")
    print("="*80 + "\n")
