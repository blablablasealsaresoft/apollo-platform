# BBOT Reconnaissance System

A comprehensive, production-ready reconnaissance system for domain intelligence gathering. BBOT integrates multiple OSINT techniques including subdomain enumeration, port scanning, technology detection, and vulnerability assessment.

## Features

### 1. Subdomain Enumeration
- **Passive Sources**: Certificate Transparency (crt.sh), VirusTotal, HackerTarget
- **Active Techniques**: DNS brute forcing with customizable wordlists
- **Advanced Features**:
  - Wildcard DNS detection
  - Zone transfer attempts (AXFR)
  - Reverse DNS lookups
  - DNS record collection (A, AAAA, CNAME, MX, TXT)

### 2. Port Scanning
- **Asynchronous Scanning**: High-performance concurrent port scanning
- **Service Detection**: Banner grabbing and version fingerprinting
- **Coverage Options**:
  - Common ports (default)
  - Top 1000 ports
  - Full range (1-65535)
  - Custom port lists
- **Protocol Support**: TCP (UDP planned)

### 3. Technology Detection
- **Web Technologies**: Frameworks (React, Angular, Vue.js, Django, Flask, Laravel)
- **CMS Detection**: WordPress, Joomla, Drupal, Magento, Shopify
- **Server Identification**: nginx, Apache, IIS
- **CDN Detection**: Cloudflare, Akamai, Fastly
- **Analytics**: Google Analytics, Tag Manager
- **Detection Methods**: Headers, meta tags, scripts, cookies, patterns

### 4. Vulnerability Scanning
- **SSL/TLS Analysis**:
  - Certificate validation and expiry checking
  - Weak protocol detection (SSLv3, TLSv1.0, TLSv1.1)
  - Weak cipher detection
  - Certificate information extraction
- **Security Headers**:
  - HSTS, CSP, X-Frame-Options, X-Content-Type-Options
  - Information disclosure headers
  - Best practice recommendations
- **CVE Matching**: Match detected software versions against CVE database
- **Misconfiguration Detection**:
  - Exposed sensitive files (.git, .env, config files)
  - Directory listing
  - Default credentials (optional)

## Installation

### Prerequisites
```bash
# Python 3.8 or higher
python --version

# Required packages
pip install aiohttp asyncio beautifulsoup4 dnspython PyYAML pyOpenSSL certifi
```

### Setup
```bash
# Clone or navigate to the BBOT directory
cd C:\SECURE_THREAT_INTEL\YoureGunnaHAveToShootMeToStopME\apollo\intelligence\osint-tools\bbot\

# Install dependencies
pip install -r requirements.txt  # Create this file with the packages above

# Verify installation
python bbot_integration.py --help
```

## Usage

### Basic Usage

```python
from bbot_integration import BBOTScanner

# Initialize scanner
scanner = BBOTScanner()

# Perform basic scan
result = scanner.scan_domain_sync("target.com")

# Access results
print(f"Subdomains found: {len(result.subdomains)}")
print(f"Open ports: {len(result.ports)}")
print(f"Technologies: {len(result.technologies)}")
print(f"Vulnerabilities: {len(result.vulnerabilities)}")
```

### Advanced Usage

```python
from bbot_integration import BBOTScanner

# Initialize with custom config
scanner = BBOTScanner(config_path='bbot_config.yaml')

# Perform deep scan with specific modules
result = scanner.scan_domain_sync(
    domain="target.com",
    modules=["subdomain", "port", "tech", "vuln"],
    deep_scan=True
)

# Get summary statistics
summary = scanner.get_summary(result)
print(summary)
```

### Asynchronous Usage

```python
import asyncio
from bbot_integration import BBOTScanner

async def main():
    scanner = BBOTScanner()

    # Scan single domain
    result = await scanner.scan_domain("target.com", deep_scan=True)

    # Scan multiple domains in parallel
    domains = ["target1.com", "target2.com", "target3.com"]
    results = await scanner.scan_multiple_domains(domains, parallel=True)

    for domain, result in results.items():
        if result:
            print(f"{domain}: {len(result.vulnerabilities)} vulnerabilities")

asyncio.run(main())
```

### Command-Line Usage

```bash
# Basic scan
python bbot_integration.py target.com

# Deep scan with all modules
python bbot_integration.py target.com --deep

# Specific modules only
python bbot_integration.py target.com --modules subdomain port

# Custom configuration
python bbot_integration.py target.com --config custom_config.yaml

# Custom output directory
python bbot_integration.py target.com --output ./custom_results
```

## Module-Specific Usage

### Subdomain Enumeration

```python
from subdomain_enum import SubdomainEnumerator

config = {
    'subdomain': {
        'sources': ['crtsh', 'hackertarget', 'virustotal'],
        'brute_force': True,
        'wordlist_size': 'medium'
    },
    'timeout': 30
}

enumerator = SubdomainEnumerator(config)
subdomains = await enumerator.enumerate("target.com", deep_scan=True)

for subdomain in subdomains:
    print(f"{subdomain['subdomain']} -> {subdomain['ip_addresses']}")
```

### Port Scanning

```python
from port_scanner import PortScanner

config = {
    'port': {
        'common_ports': True,
        'service_detection': True
    },
    'timeout': 5
}

scanner = PortScanner(config)

# Scan specific host
results = await scanner.scan_host("target.com", deep_scan=False)

# Scan port range
results = await scanner.scan_port_range("target.com", 1, 1000)

# Scan specific ports
results = await scanner.scan_specific_ports("target.com", [80, 443, 8080, 8443])

for result in results:
    print(f"{result['port']}/tcp - {result['service']} - {result.get('version', 'N/A')}")
```

### Technology Detection

```python
from tech_detector import TechnologyDetector

config = {
    'tech': {
        'deep_scan': True,
        'wappalyzer': True,
        'header_analysis': True
    },
    'timeout': 30
}

detector = TechnologyDetector(config)
technologies = await detector.detect("target.com")

for tech in technologies:
    version_info = f"v{tech['version']}" if tech.get('version') else ""
    print(f"{tech['name']} [{tech['category']}] {version_info}")
```

### Vulnerability Scanning

```python
from vuln_scanner import VulnerabilityScanner

config = {
    'vuln': {
        'ssl_check': True,
        'headers_check': True,
        'cve_matching': True
    },
    'timeout': 30
}

scanner = VulnerabilityScanner(config)

# Provide detected technologies for CVE matching
technologies = [
    {'name': 'Apache', 'version': '2.4.49', 'category': 'Web Server'}
]

results = await scanner.scan("target.com", technologies=technologies)

for vuln in results['vulnerabilities']:
    print(f"[{vuln['severity'].upper()}] {vuln['title']}")
    print(f"  {vuln['description']}")
    if vuln.get('remediation'):
        print(f"  Fix: {vuln['remediation']}")
```

## Configuration

### Configuration File (bbot_config.yaml)

The configuration file allows you to customize all aspects of the reconnaissance:

```yaml
# Enable/disable modules
modules:
  subdomain: true
  port: true
  tech: true
  vuln: true

# Subdomain enumeration settings
subdomain:
  sources: [crtsh, hackertarget, virustotal]
  brute_force: true
  wordlist_size: medium

# Port scanning settings
port:
  common_ports: true
  service_detection: true
  top_ports: 1000

# Technology detection settings
tech:
  deep_scan: true
  wappalyzer: true
  header_analysis: true

# Vulnerability scanning settings
vuln:
  ssl_check: true
  headers_check: true
  cve_matching: true
  misconfig_check: true
```

### Scan Presets

Pre-configured scan profiles for different scenarios:

```python
# Quick scan - Fast, passive only
scanner.scan_domain_sync("target.com", modules=["subdomain"])

# Standard scan - Balanced reconnaissance
scanner.scan_domain_sync("target.com", modules=["subdomain", "port", "tech"])

# Deep scan - Comprehensive, all modules
scanner.scan_domain_sync("target.com", deep_scan=True)

# Stealth scan - Low detection profile
# Configure in bbot_config.yaml with rate limiting
```

## Output Formats

### JSON Output
```json
{
  "domain": "target.com",
  "timestamp": "2026-01-14T10:30:00",
  "subdomains": [...],
  "ports": [...],
  "technologies": [...],
  "vulnerabilities": [...],
  "ssl_info": [...],
  "metadata": {...}
}
```

### Text Report
```
================================================================================
BBOT RECONNAISSANCE REPORT
================================================================================

Domain: target.com
Scan Time: 2026-01-14T10:30:00
Duration: 45.32 seconds
Modules: subdomain, port, tech, vuln

--------------------------------------------------------------------------------
SUBDOMAINS (15)
--------------------------------------------------------------------------------
  - www.target.com -> 93.184.216.34
  - mail.target.com -> 93.184.216.35
  ...

--------------------------------------------------------------------------------
OPEN PORTS (5)
--------------------------------------------------------------------------------
  - target.com:80 (http)
  - target.com:443 (https) - nginx 1.20.1
  ...

--------------------------------------------------------------------------------
VULNERABILITIES (3)
--------------------------------------------------------------------------------
  [HIGH] Missing Security Header: Strict-Transport-Security
    HSTS header missing - site vulnerable to SSL stripping
  ...
```

## API Reference

### BBOTScanner Class

#### `__init__(config_path: Optional[str] = None)`
Initialize the BBOT scanner with optional configuration file.

#### `scan_domain(domain: str, modules: Optional[List[str]] = None, deep_scan: bool = False) -> ScanResult`
Asynchronous domain scan returning comprehensive results.

#### `scan_domain_sync(domain: str, modules: Optional[List[str]] = None, deep_scan: bool = False) -> ScanResult`
Synchronous wrapper for scan_domain.

#### `scan_multiple_domains(domains: List[str], modules: Optional[List[str]] = None, deep_scan: bool = False, parallel: bool = True) -> Dict[str, ScanResult]`
Scan multiple domains concurrently.

#### `get_summary(scan_result: ScanResult) -> Dict`
Generate summary statistics from scan results.

### ScanResult Dataclass

```python
@dataclass
class ScanResult:
    domain: str
    timestamp: str
    subdomains: List[Dict]
    ports: List[Dict]
    technologies: List[Dict]
    vulnerabilities: List[Dict]
    ssl_info: List[Dict]
    metadata: Dict
```

## Performance Tuning

### Concurrent Scanning
```python
# Adjust in configuration
config = {
    'max_threads': 200,  # Increase concurrent operations
    'timeout': 15,       # Reduce timeout for faster scanning
}
```

### Rate Limiting
```python
# For stealth operations
config = {
    'rate_limit': 10,  # Limit to 10 requests/second
}
```

### Memory Optimization
```python
# For large-scale scans
config = {
    'advanced': {
        'max_memory_mb': 2048,
        'result_cache_size': 20000
    }
}
```

## Security Considerations

### Legal and Ethical Usage
- **Authorization Required**: Only scan domains you own or have explicit permission to test
- **Respect Rate Limits**: Don't overwhelm target systems
- **Check Terms of Service**: Ensure scanning complies with target's ToS
- **Data Privacy**: Handle discovered data responsibly

### Operational Security
- **Use Proxies**: Configure proxies for sensitive operations
- **Rate Limiting**: Avoid detection with appropriate rate limits
- **Stealth Mode**: Use passive enumeration only when necessary

## Troubleshooting

### Common Issues

#### DNS Resolution Failures
```python
# Configure custom DNS servers
config = {
    'network': {
        'dns_servers': ['8.8.8.8', '1.1.1.1']
    }
}
```

#### SSL Certificate Errors
```python
# Disable SSL verification (not recommended for production)
# Already configured in code with ssl=False
```

#### Timeout Issues
```python
# Increase timeouts
config = {
    'timeout': 60,
    'network': {
        'connect_timeout': 20,
        'read_timeout': 60
    }
}
```

## Examples

### Complete Reconnaissance Example

```python
import asyncio
from bbot_integration import BBOTScanner

async def comprehensive_recon(domain):
    # Initialize scanner
    scanner = BBOTScanner(config_path='bbot_config.yaml')

    # Phase 1: Quick subdomain discovery
    print(f"[*] Phase 1: Subdomain enumeration for {domain}")
    quick_result = await scanner.scan_domain(
        domain,
        modules=["subdomain"],
        deep_scan=False
    )
    print(f"[+] Found {len(quick_result.subdomains)} subdomains")

    # Phase 2: Port scanning on discovered targets
    print(f"[*] Phase 2: Port scanning")
    port_result = await scanner.scan_domain(
        domain,
        modules=["port"],
        deep_scan=True
    )
    print(f"[+] Found {len(port_result.ports)} open ports")

    # Phase 3: Technology detection
    print(f"[*] Phase 3: Technology stack detection")
    tech_result = await scanner.scan_domain(
        domain,
        modules=["tech"],
        deep_scan=True
    )
    print(f"[+] Detected {len(tech_result.technologies)} technologies")

    # Phase 4: Vulnerability assessment
    print(f"[*] Phase 4: Vulnerability scanning")
    full_result = await scanner.scan_domain(
        domain,
        modules=["subdomain", "port", "tech", "vuln"],
        deep_scan=True
    )

    # Generate summary
    summary = scanner.get_summary(full_result)

    # Print critical findings
    print(f"\n{'='*80}")
    print(f"RECONNAISSANCE SUMMARY - {domain}")
    print(f"{'='*80}")
    print(f"Subdomains: {summary['statistics']['subdomains_found']}")
    print(f"Open Ports: {summary['statistics']['open_ports']}")
    print(f"Technologies: {summary['statistics']['technologies_detected']}")
    print(f"Vulnerabilities: {summary['statistics']['vulnerabilities_found']}")

    print(f"\nSeverity Breakdown:")
    for severity, count in summary['severity_breakdown'].items():
        if count > 0:
            print(f"  {severity.upper()}: {count}")

    print(f"\nCritical Findings:")
    for finding in summary['critical_findings']:
        print(f"  [!] {finding}")

    return full_result

# Run reconnaissance
if __name__ == '__main__':
    target_domain = "example.com"
    result = asyncio.run(comprehensive_recon(target_domain))
```

## Roadmap

### Planned Features
- [ ] Additional passive enumeration sources (SecurityTrails, Shodan)
- [ ] UDP port scanning
- [ ] OS fingerprinting improvements
- [ ] Automated exploit suggestion
- [ ] Integration with vulnerability databases (NVD, Exploit-DB)
- [ ] Web application scanning (SQLi, XSS detection)
- [ ] Screenshot capture
- [ ] HTML/PDF report generation
- [ ] REST API interface
- [ ] Web dashboard

## Contributing

Contributions are welcome! Areas for improvement:
- Additional technology fingerprints
- More CVE entries in vulnerability database
- Performance optimizations
- Additional enumeration sources
- Bug fixes and documentation improvements

## License

This tool is provided for educational and authorized security testing purposes only.

## Disclaimer

**IMPORTANT**: This tool is designed for security professionals and researchers to assess their own systems or systems they have explicit permission to test. Unauthorized scanning of systems you don't own or have permission to test is illegal and unethical. The authors assume no liability for misuse of this tool.

## Support

For issues, questions, or contributions:
- Review the documentation
- Check existing issues
- Submit detailed bug reports with reproduction steps
- Include configuration and error logs

---

**Version**: 1.0.0
**Last Updated**: 2026-01-14
**Maintainer**: Apollo Intelligence Platform
