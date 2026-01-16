# Quick Start Guide - Domain Intelligence System

## Installation

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Configure API Keys
Copy the example config and add your API keys:
```bash
cp config.example.json config.json
# Edit config.json with your API keys
```

## Basic Usage

### Quick Investigation (No API Keys Required)
```python
from domain_intel import DomainIntelligence

# Initialize without API keys
intel = DomainIntelligence()

# Quick scan (WHOIS, DNS, SSL, Tech)
results = intel.quick_scan("example.com")

# Print summary
print(f"Registrar: {results['summary']['registrar']}")
print(f"IPs: {results['summary']['ip_addresses']}")
print(f"SSL Valid: {results['summary']['ssl_valid']}")
```

### Full Investigation (With API Keys)
```python
from domain_intel import DomainIntelligence

# Configure API keys
config = {
    'shodan_api_key': 'YOUR_KEY',
    'censys_api_id': 'YOUR_ID',
    'censys_api_secret': 'YOUR_SECRET',
    'virustotal_api_key': 'YOUR_KEY'
}

intel = DomainIntelligence(config)

# Full investigation
results = intel.investigate("target.com", full_scan=True)

# Export reports
intel.export_report(results, "report.json", format='json')
intel.export_report(results, "report.html", format='html')
```

## Individual Module Usage

### WHOIS Analysis
```python
from whois_analyzer import WhoisAnalyzer

analyzer = WhoisAnalyzer()
whois_data = analyzer.analyze("example.com")

print(f"Registrar: {whois_data['registrar']}")
print(f"Expires: {whois_data['dates']['expires']}")
print(f"Privacy: {whois_data['privacy_service']}")
```

### DNS Analysis
```python
from dns_analyzer import DNSAnalyzer

analyzer = DNSAnalyzer()
dns_data = analyzer.analyze("example.com")

print(f"A Records: {dns_data['records']['A']}")
print(f"MX Records: {dns_data['mail_servers']}")
print(f"Nameservers: {dns_data['nameservers']}")
```

### Subdomain Enumeration
```python
from subdomain_enumerator import SubdomainEnumerator

enumerator = SubdomainEnumerator()
subdomains = enumerator.enumerate("example.com", methods=['crtsh', 'brute'])

for sub in subdomains[:10]:
    print(f"{sub['subdomain']} -> {sub['ip_addresses']}")
```

### SSL Analysis
```python
from ssl_analyzer import SSLAnalyzer

analyzer = SSLAnalyzer()
ssl_data = analyzer.analyze("example.com")

print(f"Grade: {ssl_data['grade']}")
print(f"Valid: {ssl_data['valid']}")
print(f"Days left: {ssl_data['certificate']['days_until_expiration']}")
```

### Technology Profiling
```python
from tech_profiler import TechProfiler

profiler = TechProfiler()
tech_data = profiler.profile("example.com")

print(f"CMS: {tech_data['cms']}")
print(f"Server: {tech_data['servers']}")
print(f"Frameworks: {tech_data['frameworks']}")
```

### Shodan Integration
```python
from shodan_integration import ShodanIntel

shodan = ShodanIntel('YOUR_API_KEY')
results = shodan.search_domain("example.com")

print(f"Total hosts: {results['total_results']}")
print(f"Ports: {results['ports']}")
print(f"Services: {results['services']}")
```

### Censys Integration
```python
from censys_integration import CensysIntel

censys = CensysIntel('YOUR_API_ID', 'YOUR_API_SECRET')
results = censys.search_domain("example.com")

print(f"Hosts: {len(results['hosts'])}")
print(f"Certificates: {len(results['certificates'])}")
```

## Common Use Cases

### 1. Phishing Domain Investigation
```python
intel = DomainIntelligence()
results = intel.investigate("suspicious-domain.com")

# Check registration age
age = results['whois']['dates']['age_days']
if age < 30:
    print("WARNING: Domain is very new!")

# Check privacy service
if results['whois']['privacy_service']:
    print("WARNING: Privacy service detected")

# Check SSL
if not results['ssl']['valid']:
    print("WARNING: Invalid SSL certificate")
```

### 2. Threat Intelligence Enrichment
```python
def enrich_ioc(domain):
    intel = DomainIntelligence()
    results = intel.quick_scan(domain)

    return {
        'domain': domain,
        'ips': results['summary']['ip_addresses'],
        'nameservers': results['summary']['nameservers'],
        'registrar': results['summary']['registrar'],
        'ssl_valid': results['summary']['ssl_valid'],
        'risk_score': len(results['summary']['risk_indicators'])
    }
```

### 3. Asset Discovery
```python
# Find all assets for organization
enumerator = SubdomainEnumerator(virustotal_key='YOUR_KEY')
subdomains = enumerator.enumerate("company.com", methods=['crtsh', 'virustotal'])

# Analyze each subdomain
for sub in subdomains:
    ssl = SSLAnalyzer()
    ssl_data = ssl.analyze(sub['subdomain'])
    print(f"{sub['subdomain']}: SSL Grade {ssl_data['grade']}")
```

### 4. Security Assessment
```python
profiler = TechProfiler()

# Check security headers
security = profiler.scan_security_headers("example.com")
print(f"Security Score: {security['security_score']}%")

if security['missing_headers']:
    print("Missing security headers:")
    for header in security['missing_headers']:
        print(f"  - {header}")
```

## Output Examples

### JSON Output
```json
{
  "domain": "example.com",
  "summary": {
    "registered": true,
    "registrar": "Example Registrar",
    "ip_addresses": ["93.184.216.34"],
    "subdomain_count": 25,
    "ssl_valid": true,
    "technologies": ["Apache", "PHP"],
    "risk_indicators": []
  }
}
```

### Console Output
```
================================================================
DOMAIN INTELLIGENCE REPORT: example.com
================================================================

Summary:
  Registered: True
  Registrar: Example Registrar
  IP Addresses: 93.184.216.34
  Subdomains: 25
  SSL Valid: True
  SSL Grade: A
  Technologies: Apache, PHP, jQuery, Bootstrap

WHOIS:
  Created: 2020-01-01
  Expires: 2025-01-01
  Privacy Service: No

DNS:
  A Records: 93.184.216.34
  MX Records: mail.example.com
  Nameservers: ns1.example.com, ns2.example.com

SSL/TLS:
  Grade: A
  Protocol: TLSv1.3
  Certificate Valid: Yes
  Expires: 2024-12-31
  Days Left: 120

Technology:
  CMS: WordPress
  Server: Apache/2.4.41
  Framework: PHP 7.4
```

## Tips

1. **Start with Quick Scan**: Use `quick_scan()` first to get basic info without API keys
2. **Use API Keys Wisely**: Many APIs have rate limits - use caching when possible
3. **Export Reports**: Always save reports for future reference
4. **Verify Results**: Cross-reference findings from multiple sources
5. **Respect Rate Limits**: Add delays between requests for bulk operations

## Troubleshooting

### Import Errors
```bash
# Make sure all dependencies are installed
pip install -r requirements.txt
```

### API Errors
```python
# Check API key validity
from shodan_integration import ShodanIntel
shodan = ShodanIntel('YOUR_KEY')
info = shodan.get_account_info()
print(f"Credits remaining: {info['query_credits']}")
```

### Timeout Errors
```python
# Increase timeout
from dns_analyzer import DNSAnalyzer
analyzer = DNSAnalyzer()
analyzer.resolver.timeout = 10  # Increase timeout
analyzer.resolver.lifetime = 20
```

## Next Steps

1. Read the full documentation in `README_DOMAIN_INTEL.md`
2. Review examples in `example_usage.py`
3. Configure API keys in `config.json`
4. Start with quick scans and expand to full investigations
5. Integrate with your existing security tools

## Support

For detailed documentation, see `README_DOMAIN_INTEL.md`

For examples, see `example_usage.py`

For API configuration, see `config.example.json`
