# BBOT Quick Start Guide

## Installation

```bash
# Navigate to BBOT directory
cd C:\SECURE_THREAT_INTEL\YoureGunnaHAveToShootMeToStopME\apollo\intelligence\osint-tools\bbot\

# Install dependencies
pip install -r requirements.txt
```

## Quick Usage Examples

### 1. Basic Scan (Simplest)

```python
from bbot_integration import BBOTScanner

scanner = BBOTScanner()
result = scanner.scan_domain_sync("target.com")

print(f"Subdomains: {len(result.subdomains)}")
print(f"Open ports: {len(result.ports)}")
print(f"Vulnerabilities: {len(result.vulnerabilities)}")
```

### 2. Deep Scan (Comprehensive)

```python
from bbot_integration import BBOTScanner

scanner = BBOTScanner(config_path='bbot_config.yaml')

result = scanner.scan_domain_sync(
    domain="target.com",
    modules=["subdomain", "port", "tech", "vuln"],
    deep_scan=True
)

summary = scanner.get_summary(result)
print(summary)
```

### 3. Command Line

```bash
# Basic scan
python bbot_integration.py target.com

# Deep scan
python bbot_integration.py target.com --deep

# Specific modules
python bbot_integration.py target.com --modules subdomain port
```

### 4. Subdomain Enumeration Only

```python
from subdomain_enum import SubdomainEnumerator

config = {
    'subdomain': {
        'sources': ['crtsh', 'hackertarget'],
        'brute_force': False
    },
    'timeout': 30
}

enumerator = SubdomainEnumerator(config)
subdomains = await enumerator.enumerate("target.com")
```

### 5. Port Scanning Only

```python
from port_scanner import PortScanner

config = {
    'port': {'common_ports': True, 'service_detection': True},
    'timeout': 5
}

scanner = PortScanner(config)
results = await scanner.scan_host("target.com")
```

## Common Scan Scenarios

### Passive Reconnaissance (Stealth)
```python
scanner = BBOTScanner()
result = scanner.scan_domain_sync(
    "target.com",
    modules=["subdomain"],  # Passive only
    deep_scan=False
)
```

### Active Port Discovery
```python
scanner = BBOTScanner()
result = scanner.scan_domain_sync(
    "target.com",
    modules=["subdomain", "port"],
    deep_scan=True
)
```

### Full Security Assessment
```python
scanner = BBOTScanner()
result = scanner.scan_domain_sync(
    "target.com",
    modules=["subdomain", "port", "tech", "vuln"],
    deep_scan=True
)
```

## Configuration Tips

### Fast Scan (Quick Results)
Edit `bbot_config.yaml`:
```yaml
timeout: 10
max_threads: 200
subdomain:
  brute_force: false
port:
  common_ports: true
```

### Thorough Scan (Maximum Coverage)
```yaml
timeout: 60
max_threads: 50
subdomain:
  brute_force: true
  wordlist_size: large
port:
  top_ports: 5000
  service_detection: true
```

### Stealth Scan (Low Detection)
```yaml
timeout: 30
rate_limit: 10
max_threads: 10
subdomain:
  sources: [crtsh]  # Passive only
  brute_force: false
```

## Output Files

Results are saved to `./results/` directory:
- `{domain}_{timestamp}.json` - Full JSON results
- `{domain}_{timestamp}_report.txt` - Human-readable report

## Common Issues

### DNS Resolution Fails
```python
config = {
    'network': {
        'dns_servers': ['8.8.8.8', '1.1.1.1']
    }
}
scanner = BBOTScanner(config_path='bbot_config.yaml')
```

### Timeout Issues
```python
config = {
    'timeout': 60,  # Increase timeout
    'max_threads': 50  # Reduce concurrency
}
```

### Permission Errors (Port Scanning)
Run as administrator/root for full port scanning capabilities.

## Security Warning

**CRITICAL**: Only scan domains you own or have explicit permission to test. Unauthorized scanning is illegal.

## Next Steps

- Read full documentation: `README_BBOT.md`
- Review examples: `example_usage.py`
- Customize configuration: `bbot_config.yaml`
- Run comprehensive scan: `python bbot_integration.py --deep yourdomain.com`

## Support

For issues or questions, review:
1. README_BBOT.md (full documentation)
2. example_usage.py (10 detailed examples)
3. bbot_config.yaml (configuration options)
