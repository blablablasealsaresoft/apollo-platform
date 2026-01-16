"""
Domain Intelligence - Example Usage
Demonstrates all features of the domain intelligence system
"""

import json
from domain_intel import DomainIntelligence
from whois_analyzer import WhoisAnalyzer
from dns_analyzer import DNSAnalyzer
from subdomain_enumerator import SubdomainEnumerator
from ssl_analyzer import SSLAnalyzer
from tech_profiler import TechProfiler


def example_full_investigation():
    """Example: Full domain investigation"""
    print("\n" + "="*70)
    print("FULL DOMAIN INVESTIGATION")
    print("="*70)

    # Configure API keys
    config = {
        'shodan_api_key': 'YOUR_SHODAN_KEY',
        'censys_api_id': 'YOUR_CENSYS_ID',
        'censys_api_secret': 'YOUR_CENSYS_SECRET',
        'virustotal_api_key': 'YOUR_VT_KEY',
        'securitytrails_api_key': 'YOUR_ST_KEY',
        'builtwith_api_key': 'YOUR_BW_KEY'
    }

    # Initialize
    intel = DomainIntelligence(config)

    # Investigate
    target = "example.com"
    print(f"\nInvestigating: {target}")

    results = intel.investigate(target, full_scan=True)

    # Print summary
    summary = results['summary']
    print(f"\nSummary:")
    print(f"  Registered: {summary['registered']}")
    print(f"  Registrar: {summary['registrar']}")
    print(f"  IP Addresses: {', '.join(summary['ip_addresses'][:3])}")
    print(f"  Subdomains: {summary['subdomain_count']}")
    print(f"  SSL Valid: {summary['ssl_valid']}")
    print(f"  Technologies: {', '.join(summary['technologies'][:5])}")

    if summary['risk_indicators']:
        print(f"\n  Risk Indicators:")
        for risk in summary['risk_indicators']:
            print(f"    - {risk}")

    # Export
    intel.export_report(results, f"{target}_full_report.json", format='json')
    intel.export_report(results, f"{target}_full_report.html", format='html')

    print(f"\nReports saved!")


def example_quick_scan():
    """Example: Quick domain scan"""
    print("\n" + "="*70)
    print("QUICK DOMAIN SCAN")
    print("="*70)

    intel = DomainIntelligence()
    target = "example.com"

    print(f"\nQuick scanning: {target}")
    results = intel.quick_scan(target)

    print(f"\nQuick Results:")
    print(f"  Registrar: {results.get('whois', {}).get('registrar')}")
    print(f"  IPs: {results.get('dns', {}).get('records', {}).get('A', [])}")
    print(f"  SSL Grade: {results.get('ssl', {}).get('grade')}")


def example_whois_analysis():
    """Example: WHOIS analysis"""
    print("\n" + "="*70)
    print("WHOIS ANALYSIS")
    print("="*70)

    analyzer = WhoisAnalyzer()

    # Analyze domain
    print("\nAnalyzing WHOIS for example.com...")
    results = analyzer.analyze("example.com")

    print(f"\nWHOIS Results:")
    print(f"  Registered: {results['registered']}")
    print(f"  Registrar: {results['registrar']}")
    print(f"  Created: {results['dates']['created']}")
    print(f"  Expires: {results['dates']['expires']}")
    print(f"  Age (days): {results['dates']['age_days']}")
    print(f"  Privacy Service: {results['privacy_service']}")
    print(f"  Nameservers: {results['nameservers'][:3]}")

    # Check expiration
    exp_info = analyzer.get_expiration_info("example.com")
    print(f"\nExpiration Info:")
    print(f"  Days until expiration: {exp_info['days_until_expiration']}")
    if exp_info.get('warning'):
        print(f"  Warning: {exp_info['warning']}")

    # Compare domains
    print("\nComparing domains...")
    comparison = analyzer.compare_whois("example.com", "example.org")
    print(f"  Similarity Score: {comparison['similarity_score']}%")
    print(f"  Same Registrar: {comparison['same_registrar']}")


def example_dns_analysis():
    """Example: DNS analysis"""
    print("\n" + "="*70)
    print("DNS ANALYSIS")
    print("="*70)

    analyzer = DNSAnalyzer()

    # Analyze DNS
    print("\nAnalyzing DNS for example.com...")
    results = analyzer.analyze("example.com")

    print(f"\nDNS Records:")
    for record_type, values in results['records'].items():
        print(f"  {record_type}: {values[:3]}")

    print(f"\nMail Servers:")
    for mx in results['mail_servers']:
        print(f"  Priority {mx['priority']}: {mx['hostname']}")

    print(f"\nDNSSEC Enabled: {results['dnssec_enabled']}")
    print(f"Zone Transfer Vulnerable: {results['zone_transfer_vulnerable']}")

    # Check SPF
    print("\nChecking SPF...")
    spf = analyzer.analyze_spf("example.com")
    if spf['has_spf']:
        print(f"  SPF Record: {spf['spf_record']}")
        if spf['warnings']:
            print(f"  Warnings: {', '.join(spf['warnings'])}")

    # Check DMARC
    print("\nChecking DMARC...")
    dmarc = analyzer.analyze_dmarc("example.com")
    if dmarc['has_dmarc']:
        print(f"  Policy: {dmarc['policy']}")
        print(f"  Subdomain Policy: {dmarc['subdomain_policy']}")

    # Reverse lookup
    print("\nReverse DNS lookup for 8.8.8.8...")
    hostname = analyzer.reverse_lookup("8.8.8.8")
    print(f"  Hostname: {hostname}")


def example_subdomain_enumeration():
    """Example: Subdomain enumeration"""
    print("\n" + "="*70)
    print("SUBDOMAIN ENUMERATION")
    print("="*70)

    enumerator = SubdomainEnumerator()

    # Enumerate subdomains
    print("\nEnumerating subdomains for example.com...")
    print("Methods: Certificate Transparency, DNS Brute Force")

    subdomains = enumerator.enumerate(
        "example.com",
        methods=['crtsh', 'brute']
    )

    print(f"\nFound {len(subdomains)} subdomains:")
    for sub in subdomains[:10]:  # Show first 10
        ips = ', '.join(sub.get('ip_addresses', [])[:2])
        print(f"  {sub['subdomain']} -> {ips}")
        if sub.get('http_status'):
            print(f"    HTTP: {sub['http_status']}, HTTPS: {sub.get('https_status')}")

    # Check for takeover
    print("\nChecking for subdomain takeover vulnerabilities...")
    vulnerable = enumerator.search_subdomain_takeover(subdomains)
    if vulnerable:
        print(f"  Found {len(vulnerable)} potentially vulnerable subdomains:")
        for vuln in vulnerable:
            print(f"    {vuln['subdomain']} -> {vuln['service']}")
    else:
        print("  No obvious vulnerabilities found")

    # Export
    enumerator.export_subdomains(subdomains, "subdomains.json", format='json')
    print("\nSubdomains exported to subdomains.json")


def example_ssl_analysis():
    """Example: SSL/TLS analysis"""
    print("\n" + "="*70)
    print("SSL/TLS ANALYSIS")
    print("="*70)

    analyzer = SSLAnalyzer()

    # Analyze SSL
    print("\nAnalyzing SSL for example.com...")
    results = analyzer.analyze("example.com")

    print(f"\nSSL Results:")
    print(f"  Grade: {results['grade']}")
    print(f"  Valid: {results['valid']}")

    cert = results['certificate']
    print(f"\nCertificate:")
    print(f"  Subject: {cert.get('subject')}")
    print(f"  Issuer: {cert.get('issuer')}")
    print(f"  Valid Until: {cert.get('not_after')}")
    print(f"  Days Left: {cert.get('days_until_expiration')}")
    print(f"  Self-Signed: {cert.get('self_signed')}")
    print(f"  Key Size: {cert.get('key_size')} bits")
    print(f"  Signature: {cert.get('signature_algorithm')}")

    print(f"\nProtocols:")
    for protocol, supported in results['protocols'].items():
        status = "✓" if supported else "✗"
        print(f"  {status} {protocol}")

    if results['vulnerabilities']:
        print(f"\nVulnerabilities Found:")
        for vuln in results['vulnerabilities']:
            print(f"  [{vuln['severity'].upper()}] {vuln['name']}")
            print(f"    {vuln['description']}")

    # Certificate Transparency
    print("\nChecking Certificate Transparency logs...")
    ct_logs = analyzer.check_certificate_transparency("example.com")
    print(f"  Found {len(ct_logs)} certificates in CT logs")


def example_technology_profiling():
    """Example: Technology profiling"""
    print("\n" + "="*70)
    print("TECHNOLOGY PROFILING")
    print("="*70)

    profiler = TechProfiler()

    # Profile technology
    print("\nProfiling technology for example.com...")
    results = profiler.profile("example.com", use_api=False)

    print(f"\nTechnology Stack:")
    print(f"  CMS: {results['cms'] or 'Not detected'}")
    print(f"  Frameworks: {', '.join(results['frameworks']) or 'None detected'}")
    print(f"  JavaScript Libraries: {', '.join(results['javascript_libraries'][:5])}")
    print(f"  Server: {', '.join(results['servers'])}")
    print(f"  Analytics: {', '.join(results['analytics'])}")
    print(f"  CDN: {', '.join(results['cdn'])}")

    print(f"\nMetadata:")
    metadata = results['metadata']
    print(f"  Title: {metadata.get('title')}")
    print(f"  Generator: {metadata.get('generator')}")

    # Security headers
    print("\nScanning security headers...")
    security = profiler.scan_security_headers("example.com")
    print(f"  Security Score: {security['security_score']:.0f}%")

    if security['missing_headers']:
        print(f"  Missing Headers:")
        for header in security['missing_headers']:
            print(f"    - {header}")

    # WAF detection
    print("\nDetecting WAF...")
    waf = profiler.detect_waf("example.com")
    if waf['waf_detected']:
        print(f"  WAF: {waf['waf_name']} ({waf['confidence']} confidence)")
    else:
        print(f"  No WAF detected")

    # Server fingerprint
    print("\nServer fingerprinting...")
    server = profiler.fingerprint_server("example.com")
    print(f"  Server: {server.get('server')}")
    print(f"  Powered By: {server.get('powered_by')}")
    print(f"  Language: {server.get('programming_language')}")


def example_ip_investigation():
    """Example: IP address investigation"""
    print("\n" + "="*70)
    print("IP ADDRESS INVESTIGATION")
    print("="*70)

    intel = DomainIntelligence()

    # Investigate IP
    print("\nInvestigating IP: 8.8.8.8")
    results = intel.investigate_ip("8.8.8.8")

    print(f"\nIP Investigation Results:")
    print(f"  IP: {results['ip']}")
    print(f"  Hostname: {results['reverse_dns'].get('hostname', 'None')}")

    if results.get('ssl'):
        print(f"  SSL Grade: {results['ssl'].get('grade')}")

    print(json.dumps(results, indent=2, default=str))


def example_batch_investigation():
    """Example: Batch domain investigation"""
    print("\n" + "="*70)
    print("BATCH DOMAIN INVESTIGATION")
    print("="*70)

    intel = DomainIntelligence()

    domains = ["example.com", "example.org", "example.net"]

    results = {}
    for domain in domains:
        print(f"\nInvestigating {domain}...")
        results[domain] = intel.quick_scan(domain)

    print(f"\nBatch Investigation Complete!")
    print(f"Processed {len(domains)} domains")

    # Save batch results
    with open("batch_results.json", "w") as f:
        json.dump(results, f, indent=2, default=str)

    print("Results saved to batch_results.json")


def main():
    """Run all examples"""
    print("\n" + "="*70)
    print("DOMAIN INTELLIGENCE SYSTEM - EXAMPLES")
    print("="*70)

    examples = [
        ("Full Investigation", example_full_investigation),
        ("Quick Scan", example_quick_scan),
        ("WHOIS Analysis", example_whois_analysis),
        ("DNS Analysis", example_dns_analysis),
        ("Subdomain Enumeration", example_subdomain_enumeration),
        ("SSL Analysis", example_ssl_analysis),
        ("Technology Profiling", example_technology_profiling),
        ("IP Investigation", example_ip_investigation),
        ("Batch Investigation", example_batch_investigation)
    ]

    print("\nAvailable Examples:")
    for i, (name, _) in enumerate(examples, 1):
        print(f"  {i}. {name}")

    print("\nTo run a specific example, call the function directly:")
    print("  example_whois_analysis()")
    print("  example_dns_analysis()")
    print("  etc.")

    print("\nNote: Update API keys in config before running full examples")


if __name__ == "__main__":
    # Run individual examples (uncomment to test)

    # example_whois_analysis()
    # example_dns_analysis()
    # example_subdomain_enumeration()
    # example_ssl_analysis()
    # example_technology_profiling()

    # Show menu
    main()
