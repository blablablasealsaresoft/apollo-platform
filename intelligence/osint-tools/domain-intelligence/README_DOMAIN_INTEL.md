# Domain & Network Intelligence System

Comprehensive domain and network intelligence gathering toolkit for OSINT investigations.

## Overview

This system provides advanced domain reconnaissance capabilities including:
- WHOIS analysis and registration tracking
- DNS enumeration and historical records
- Subdomain discovery via multiple techniques
- SSL/TLS certificate analysis
- Technology stack profiling
- Shodan integration for internet-wide scanning
- Censys integration for certificate intelligence

## Components

### 1. Domain Intelligence (domain_intel.py)
Main orchestrator that combines all modules for comprehensive domain investigation.

**Features:**
- Full domain profiling
- Quick scan mode
- Multiple export formats (JSON, HTML, TXT)
- Risk assessment and grading
- Summary generation

**Example:**
```python
from domain_intel import DomainIntelligence

# Initialize with API keys
config = {
    'shodan_api_key': 'YOUR_SHODAN_KEY',
    'censys_api_id': 'YOUR_CENSYS_ID',
    'censys_api_secret': 'YOUR_CENSYS_SECRET',
    'virustotal_api_key': 'YOUR_VT_KEY',
    'securitytrails_api_key': 'YOUR_ST_KEY',
    'builtwith_api_key': 'YOUR_BW_KEY'
}

domain_intel = DomainIntelligence(config)

# Full investigation
results = domain_intel.investigate("target.com")

# Quick scan (essential info only)
quick_results = domain_intel.quick_scan("target.com")

# Export report
domain_intel.export_report(results, "report.json", format='json')
domain_intel.export_report(results, "report.html", format='html')

# Investigate IP address
ip_results = domain_intel.investigate_ip("8.8.8.8")
```

### 2. WHOIS Analyzer (whois_analyzer.py)
Domain registration and ownership intelligence.

**Features:**
- Registration details extraction
- Privacy service detection
- Expiration tracking and warnings
- Domain availability checking
- WHOIS comparison between domains
- Nameserver information

**Example:**
```python
from whois_analyzer import WhoisAnalyzer

analyzer = WhoisAnalyzer()

# Analyze domain
results = analyzer.analyze("example.com")
print(f"Registrar: {results['registrar']}")
print(f"Privacy: {results['privacy_service']}")
print(f"Expires: {results['dates']['expires']}")

# Check expiration
exp_info = analyzer.get_expiration_info("example.com")
if exp_info['warning']:
    print(f"Warning: {exp_info['warning']}")

# Compare domains
comparison = analyzer.compare_whois("domain1.com", "domain2.com")
print(f"Similarity: {comparison['similarity_score']}%")

# Check availability
available = analyzer.check_availability("newdomain.com")
```

### 3. DNS Analyzer (dns_analyzer.py)
DNS record analysis and historical tracking.

**Features:**
- All DNS record types (A, AAAA, MX, NS, TXT, CNAME, SOA, CAA, etc.)
- Historical DNS via SecurityTrails API
- DNS propagation checking
- Zone transfer vulnerability testing
- SPF/DMARC analysis
- Reverse DNS lookup

**Example:**
```python
from dns_analyzer import DNSAnalyzer

analyzer = DNSAnalyzer(securitytrails_api_key='YOUR_KEY')

# Analyze DNS
results = analyzer.analyze("example.com", include_historical=True)
print(f"A Records: {results['records']['A']}")
print(f"MX Records: {results['mail_servers']}")
print(f"DNSSEC: {results['dnssec_enabled']}")

# Check specific record
a_records = analyzer.query_record("example.com", "A")

# Reverse lookup
hostname = analyzer.reverse_lookup("8.8.8.8")

# Check DNS propagation
propagation = analyzer.check_propagation("example.com")

# Analyze SPF
spf = analyzer.analyze_spf("example.com")
print(f"SPF: {spf['spf_record']}")

# Analyze DMARC
dmarc = analyzer.analyze_dmarc("example.com")
print(f"DMARC Policy: {dmarc['policy']}")
```

### 4. Subdomain Enumerator (subdomain_enumerator.py)
Multi-source subdomain discovery.

**Features:**
- Certificate Transparency (crt.sh)
- DNS brute forcing with wordlist
- VirusTotal API integration
- Chaos dataset integration
- Subdomain verification and enrichment
- Subdomain takeover detection
- Multiple export formats

**Example:**
```python
from subdomain_enumerator import SubdomainEnumerator

enumerator = SubdomainEnumerator(
    virustotal_key='YOUR_VT_KEY',
    chaos_key='YOUR_CHAOS_KEY'
)

# Enumerate subdomains
subdomains = enumerator.enumerate("example.com")
print(f"Found {len(subdomains)} subdomains")

# Use specific methods
subdomains = enumerator.enumerate(
    "example.com",
    methods=['crtsh', 'brute', 'virustotal']
)

# Check for takeover vulnerabilities
vulnerable = enumerator.search_subdomain_takeover(subdomains)
if vulnerable:
    print(f"Potentially vulnerable: {len(vulnerable)}")

# Export results
enumerator.export_subdomains(subdomains, "subs.json", format='json')
enumerator.export_subdomains(subdomains, "subs.txt", format='txt')
enumerator.export_subdomains(subdomains, "subs.csv", format='csv')
```

### 5. SSL Analyzer (ssl_analyzer.py)
SSL/TLS certificate and configuration security analysis.

**Features:**
- Certificate details extraction
- Certificate chain validation
- Protocol version detection
- Cipher suite enumeration
- Vulnerability scanning (SSLv2/v3, weak ciphers, etc.)
- Security grading (A+ to F)
- Certificate Transparency log checking
- Expiration tracking

**Example:**
```python
from ssl_analyzer import SSLAnalyzer

analyzer = SSLAnalyzer()

# Analyze SSL
results = analyzer.analyze("example.com")
print(f"Grade: {results['grade']}")
print(f"Valid: {results['valid']}")
print(f"Days until expiration: {results['certificate']['days_until_expiration']}")

# Check protocols
protocols = results['protocols']
print(f"TLSv1.3 supported: {protocols['TLSv1.3']}")

# Check vulnerabilities
if results['vulnerabilities']:
    for vuln in results['vulnerabilities']:
        print(f"[{vuln['severity']}] {vuln['description']}")

# Certificate Transparency
ct_logs = analyzer.check_certificate_transparency("example.com")

# Analyze specific port
results = analyzer.analyze("example.com", port=8443)
```

### 6. Technology Profiler (tech_profiler.py)
Web technology stack detection.

**Features:**
- CMS detection (WordPress, Joomla, Drupal, etc.)
- Framework identification (Laravel, Django, Rails, etc.)
- JavaScript library detection
- Server fingerprinting
- Analytics platform detection
- CDN identification
- Security header analysis
- WAF detection

**Example:**
```python
from tech_profiler import TechProfiler

profiler = TechProfiler(builtwith_api_key='YOUR_KEY')

# Profile technology
results = profiler.profile("example.com")
print(f"CMS: {results['cms']}")
print(f"Frameworks: {results['frameworks']}")
print(f"JavaScript: {results['javascript_libraries']}")
print(f"Server: {results['servers']}")

# Quick CMS detection
cms = profiler.detect_cms("example.com")

# Security headers
security = profiler.scan_security_headers("example.com")
print(f"Security Score: {security['security_score']}%")
print(f"Missing: {security['missing_headers']}")

# WAF detection
waf = profiler.detect_waf("example.com")
if waf['waf_detected']:
    print(f"WAF: {waf['waf_name']}")

# Server fingerprinting
server = profiler.fingerprint_server("example.com")
```

### 7. Shodan Integration (shodan_integration.py)
Internet-wide device and vulnerability scanning via Shodan.

**Features:**
- Domain and IP host discovery
- Service enumeration
- Vulnerability detection
- Organization asset mapping
- Product/version searching
- SSL certificate discovery
- DNS information

**Example:**
```python
from shodan_integration import ShodanIntel

shodan = ShodanIntel('YOUR_SHODAN_API_KEY')

# Search domain
results = shodan.search_domain("example.com")
print(f"Total hosts: {results['total_results']}")
print(f"Ports: {results['ports']}")
print(f"Services: {results['services']}")

# Search IP
ip_info = shodan.search_ip("8.8.8.8")
print(f"Organization: {ip_info['organization']}")
print(f"Services: {len(ip_info['services'])}")

# Search organization
org_results = shodan.search_organization("Google LLC")

# Search vulnerability
vuln_results = shodan.search_vulnerability("CVE-2021-44228")

# Search product
product_results = shodan.search_product("Apache", version="2.4.49")

# Get account info
account = shodan.get_account_info()
print(f"Credits: {account['query_credits']}")
```

### 8. Censys Integration (censys_integration.py)
Internet-wide scanning and certificate intelligence via Censys.

**Features:**
- Host discovery and enumeration
- Certificate transparency search
- Service and software detection
- Autonomous System (AS) tracking
- Vulnerability searching
- Geographic analysis
- Aggregate queries

**Example:**
```python
from censys_integration import CensysIntel

censys = CensysIntel('YOUR_API_ID', 'YOUR_API_SECRET')

# Search domain
results = censys.search_domain("example.com")
print(f"Hosts: {len(results['hosts'])}")
print(f"Certificates: {len(results['certificates'])}")

# Search IP
ip_info = censys.search_ip("8.8.8.8")
print(f"Services: {len(ip_info['services'])}")
print(f"Location: {ip_info['location']}")

# Search certificates
certs = censys.search_certificates("example.com")

# Search by service
service_results = censys.search_services("HTTP", port=80)

# Search by software
software_results = censys.search_software("nginx", version="1.18.0")

# Search vulnerability
vuln_results = censys.search_vulnerability("CVE-2021-44228")

# Search by ASN
asn_results = censys.search_by_asn(15169)  # Google

# Aggregate search
agg_results = censys.aggregate_search(
    "services.service_name: HTTP",
    "services.software.product"
)
```

## Installation

### Requirements
```bash
pip install python-whois dnspython requests beautifulsoup4 shodan
pip install pyOpenSSL cryptography
```

### Optional Requirements
For full functionality:
```bash
# For advanced SSL analysis
pip install pyOpenSSL cryptography

# For Shodan integration
pip install shodan

# For enhanced parsing
pip install beautifulsoup4 lxml
```

### API Keys Required

To use all features, obtain API keys from:

1. **Shodan** (shodan.io)
   - Sign up for free or paid plan
   - Get API key from account dashboard

2. **Censys** (censys.io)
   - Create free account
   - Get API ID and Secret from account settings

3. **VirusTotal** (virustotal.com)
   - Free account provides 500 requests/day
   - Get API key from user settings

4. **SecurityTrails** (securitytrails.com)
   - Free tier available
   - Get API key from account dashboard

5. **BuiltWith** (builtwith.com)
   - Paid service
   - API key from account settings

6. **Chaos** (chaos.projectdiscovery.io)
   - Free for personal use
   - API key from ProjectDiscovery account

## Complete Investigation Example

```python
from domain_intel import DomainIntelligence

# Configure all API keys
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

# Full investigation
target = "target.com"
results = intel.investigate(target, full_scan=True)

# Print summary
print(f"\n{'='*60}")
print(f"DOMAIN INTELLIGENCE REPORT: {target}")
print(f"{'='*60}")

summary = results['summary']
print(f"\nRegistered: {summary['registered']}")
print(f"Registrar: {summary['registrar']}")
print(f"IP Addresses: {', '.join(summary['ip_addresses'][:5])}")
print(f"Subdomains Found: {summary['subdomain_count']}")
print(f"SSL Valid: {summary['ssl_valid']}")
print(f"Technologies: {', '.join(summary['technologies'][:10])}")

if summary['risk_indicators']:
    print(f"\nRisk Indicators:")
    for risk in summary['risk_indicators']:
        print(f"  - {risk}")

# Export full report
intel.export_report(results, f"{target}_report.json", format='json')
intel.export_report(results, f"{target}_report.html", format='html')

print(f"\nFull report saved to {target}_report.json and {target}_report.html")
```

## Output Formats

### JSON Export
Complete structured data with all findings:
```json
{
  "domain": "example.com",
  "timestamp": "2024-01-01T00:00:00",
  "whois": {...},
  "dns": {...},
  "subdomains": [...],
  "ssl": {...},
  "technology": {...},
  "shodan": {...},
  "censys": {...},
  "summary": {...}
}
```

### HTML Export
Professional HTML report with:
- Executive summary
- Detailed findings by category
- Risk indicators
- Recommendations
- Visual formatting

### Text Export
Plain text report for terminal viewing or logging.

## Performance Optimization

### Quick Scan Mode
For rapid reconnaissance:
```python
results = intel.quick_scan("target.com")
# Skips: subdomain enumeration, historical DNS, Shodan, Censys
```

### Parallel Processing
Most modules use threading for concurrent operations:
- Subdomain verification: 20 threads
- DNS brute force: 10 threads
- Multiple API calls in parallel

### Caching
Consider implementing caching for repeated queries:
```python
import functools
from datetime import timedelta

@functools.lru_cache(maxsize=100)
def cached_whois(domain):
    return analyzer.analyze(domain)
```

## Security Considerations

1. **API Key Security**
   - Store API keys in environment variables
   - Never commit keys to version control
   - Use `.env` files with proper `.gitignore`

2. **Rate Limiting**
   - Respect API rate limits
   - Implement exponential backoff
   - Monitor API quota usage

3. **Legal Compliance**
   - Ensure authorization before scanning
   - Follow responsible disclosure
   - Comply with terms of service

4. **Data Privacy**
   - Handle WHOIS data responsibly
   - Respect privacy protection services
   - Comply with GDPR where applicable

## Troubleshooting

### Common Issues

1. **WHOIS Lookup Fails**
   ```python
   # Some domains use different WHOIS servers
   # Try manual WHOIS server specification
   ```

2. **DNS Timeout**
   ```python
   # Increase timeout
   analyzer.resolver.timeout = 10
   analyzer.resolver.lifetime = 20
   ```

3. **SSL Connection Error**
   ```python
   # Some servers have strict SSL requirements
   # Try different ports or protocols
   ```

4. **API Rate Limit**
   ```python
   # Implement delays between requests
   import time
   time.sleep(1)  # 1 second delay
   ```

## Best Practices

1. **Staged Investigation**
   - Start with quick scan
   - Expand to full scan if needed
   - Focus on specific modules for deep dive

2. **Result Validation**
   - Cross-reference findings
   - Verify critical information
   - Check multiple sources

3. **Resource Management**
   - Monitor API quotas
   - Cache results when possible
   - Use rate limiting

4. **Documentation**
   - Save all reports
   - Track investigation timeline
   - Document findings clearly

## Integration Examples

### With Threat Intelligence Platform
```python
from domain_intel import DomainIntelligence

def investigate_ioc(domain):
    intel = DomainIntelligence(config)
    results = intel.investigate(domain)

    # Extract IOCs
    iocs = {
        'ips': results['summary']['ip_addresses'],
        'subdomains': [s['subdomain'] for s in results['subdomains']],
        'nameservers': results['summary']['nameservers']
    }

    return iocs
```

### With Incident Response
```python
def rapid_assessment(domain):
    intel = DomainIntelligence(config)
    results = intel.quick_scan(domain)

    # Quick risk assessment
    risk_score = 0
    if results['whois'].get('privacy_service'):
        risk_score += 2
    if not results['ssl'].get('valid'):
        risk_score += 3
    if results['dns'].get('zone_transfer_vulnerable'):
        risk_score += 5

    return {
        'domain': domain,
        'risk_score': risk_score,
        'immediate_concerns': results['summary']['risk_indicators']
    }
```

## License

This tool is part of the Apollo OSINT Intelligence Framework.

## Disclaimer

This tool is for authorized security research and investigation only. Users are responsible for complying with all applicable laws and regulations. Unauthorized scanning or data collection may be illegal in your jurisdiction.

## Support

For issues, questions, or contributions:
- Review module documentation
- Check example usage
- Verify API key configuration
- Ensure all dependencies are installed

## Version History

- v1.0.0 - Initial release
  - Complete domain intelligence suite
  - All 8 modules implemented
  - Multi-source data aggregation
  - Export functionality
