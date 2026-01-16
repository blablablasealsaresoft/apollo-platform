# IoT Intelligence System

Comprehensive IoT device intelligence, discovery, and vulnerability assessment suite for security research and threat intelligence operations.

## Overview

The IoT Intelligence System provides a complete toolkit for discovering, analyzing, and assessing IoT devices across networks and the internet. This suite combines multiple specialized modules for device fingerprinting, vulnerability scanning, network mapping, and real-time camera access.

## Components

### 1. IoT Intelligence Core (`iot_intel.py`)

Main intelligence system providing comprehensive device discovery and analysis.

**Features:**
- Multi-source device discovery
- Organization-based targeting
- Subnet scanning
- Risk scoring and analysis
- Network topology mapping
- Vulnerability correlation
- Comprehensive reporting

**Example Usage:**
```python
from iot_intel import IoTIntelligence

# Initialize
iot = IoTIntelligence()

# Discover devices by organization
devices = iot.discover_devices(
    target_org="Target Company",
    device_types=["webcam", "router", "nas"],
    max_devices=100
)

# Show high-risk devices
for device in devices[:5]:
    print(f"Device: {device.device_type}")
    print(f"IP: {device.ip}:{device.port}")
    print(f"Risk Score: {device.risk_score:.1f}")
    print(f"Vulnerabilities: {len(device.vulnerabilities)}")

# Map network topology
networks = iot.map_network_topology()

# Generate report
report = iot.generate_report(
    output_file="iot_report.json",
    include_topology=True
)
```

### 2. Shodan IoT Scanner (`shodan_iot.py`)

Internet-wide IoT device discovery via Shodan search engine.

**Features:**
- Webcam discovery
- Router identification
- IoT device enumeration
- Vulnerability detection
- Geographic distribution analysis
- Organization-based search
- Statistics generation

**Example Usage:**
```python
from shodan_iot import ShodanIoT

# Initialize with API key
shodan = ShodanIoT(api_key="YOUR_API_KEY")

# Search for webcams
webcams = shodan.search_webcams(
    country="US",
    has_screenshot=True,
    max_results=50
)

# Search for vulnerable routers
routers = shodan.search_routers(
    vendor="Cisco",
    vulnerable_only=True,
    max_results=50
)

# Enumerate device types
nas_devices = shodan.enumerate_iot_devices(
    device_type='nas',
    country="US",
    max_results=100
)

# Get geographic distribution
distribution = shodan.get_geographic_distribution('webcam')

# Export results
shodan.export_results("shodan_results.json")
```

### 3. Censys IoT Scanner (`censys_iot.py`)

Internet-wide device scanning with certificate analysis and service fingerprinting.

**Features:**
- Internet-wide device scanning
- SSL/TLS certificate analysis
- Service fingerprinting
- Device enumeration by type
- Vulnerability searching
- Autonomous system analysis
- Comprehensive reporting

**Example Usage:**
```python
from censys_iot import CensysIoT

# Initialize with credentials
censys = CensysIoT(
    api_id="YOUR_API_ID",
    api_secret="YOUR_API_SECRET"
)

# Internet-wide scan
devices = censys.scan_internet(
    query="services.service_name: http",
    max_results=500,
    include_certificates=True
)

# Enumerate webcams
webcams = censys.enumerate_iot_devices(
    device_type='webcam',
    organization="Target Org",
    max_results=100
)

# Analyze certificates
certificates = censys.analyze_certificates(
    domain="example.com",
    expired_only=False,
    self_signed_only=False
)

# Fingerprint services
services = censys.fingerprint_services(
    port=80,
    max_results=500
)

# Search vulnerable devices
vulnerable = censys.search_vulnerable_devices(
    cve="CVE-2021-36260",
    device_type="webcam"
)

# Generate report
report = censys.generate_report("censys_report.json")
```

### 4. Insecam Integration (`insecam_integration.py`)

Live camera access and analysis from Insecam directory.

**Features:**
- Geographic camera search
- Live camera feed access
- Camera metadata extraction
- Feed recording
- Screenshot capture
- KML export for mapping
- Country/city filtering

**Example Usage:**
```python
from insecam_integration import InsecamIntegration

# Initialize
insecam = InsecamIntegration()

# Search cameras by country
cameras = insecam.search_cameras(
    country="US",
    city="New York",
    max_results=50
)

# Search by location
nearby = insecam.get_camera_by_location(
    latitude=40.7128,
    longitude=-74.0060,
    radius_km=5.0
)

# Search by category
traffic_cams = insecam.get_cameras_by_category(
    category='traffic',
    country="US"
)

# Access camera feed
feed_info = insecam.access_camera_feed(cameras[0])

# Record camera
recording = insecam.record_camera_feed(
    cameras[0],
    duration_seconds=60,
    output_path="recording.mp4"
)

# Take screenshot
screenshot = insecam.take_screenshot(
    cameras[0],
    output_path="screenshot.jpg"
)

# Export data
insecam.export_cameras("cameras.json")
insecam.export_kml("cameras.kml")
```

### 5. Device Fingerprinter (`device_fingerprinter.py`)

Advanced device identification through banner grabbing and service analysis.

**Features:**
- Banner grabbing
- Service detection
- Version identification
- OS fingerprinting
- HTTP header analysis
- SSL/TLS information extraction
- Batch fingerprinting
- Vendor/product identification

**Example Usage:**
```python
from device_fingerprinter import DeviceFingerprinter

# Initialize
fingerprinter = DeviceFingerprinter()

# Fingerprint single device
fingerprint = fingerprinter.fingerprint_device(
    ip="192.168.1.100",
    timeout=3.0
)

print(f"Device Type: {fingerprint.device_type}")
print(f"Vendor: {fingerprint.vendor}")
print(f"OS: {fingerprint.os}")
print(f"Confidence: {fingerprint.confidence:.0%}")

# Show detected services
for port, service in fingerprint.services.items():
    print(f"Port {port}: {service['name']}")
    if service['product']:
        print(f"  Product: {service['product']}")

# Batch fingerprinting
ip_list = [f"192.168.1.{i}" for i in range(1, 255)]
fingerprints = fingerprinter.batch_fingerprint(
    ip_list,
    max_workers=20
)

# Export results
fingerprinter.export_fingerprints("fingerprints.json")
```

### 6. IoT Vulnerability Scanner (`iot_vulnerability_scanner.py`)

Comprehensive vulnerability assessment for IoT devices.

**Features:**
- Default credential checking
- Known CVE matching
- Misconfiguration detection
- Risk scoring
- Exploit suggestions
- Remediation advice
- Comprehensive reporting

**Example Usage:**
```python
from iot_vulnerability_scanner import IoTVulnerabilityScanner

# Initialize
scanner = IoTVulnerabilityScanner()

# Scan device
device_info = {
    'ip': '192.168.1.100',
    'hostname': 'camera1.local',
    'device_type': 'webcam',
    'vendor': 'Hikvision',
    'product': 'DS-2CD2142FWD-I',
    'version': '5.4.0',
    'ports': [80, 554, 8000],
}

result = scanner.scan_device(
    device_info['ip'],
    device_info,
    check_credentials=True,
    check_vulnerabilities=True,
    check_misconfigurations=True
)

print(f"Risk Score: {result.risk_score:.1f}/100")
print(f"Vulnerabilities: {len(result.vulnerabilities)}")
print(f"Default Credentials: {len(result.default_credentials_found)}")
print(f"Misconfigurations: {len(result.misconfigurations)}")

# Show vulnerabilities
for vuln in result.vulnerabilities:
    print(f"\n{vuln.cve}: {vuln.title}")
    print(f"Severity: {vuln.severity}")
    print(f"CVSS: {vuln.cvss_score}")
    if vuln.exploit_available:
        print(f"Exploit: {vuln.exploit_db_id}")

# Generate exploit suggestions
exploits = scanner.generate_exploit_suggestions(result)

# Get high-risk devices
high_risk = scanner.get_high_risk_devices(min_risk_score=70.0)

# Generate report
report = scanner.generate_report(
    output_file="vuln_report.json",
    include_exploits=True
)
```

### 7. Network Mapper (`network_mapper.py`)

Network topology mapping and device relationship analysis.

**Features:**
- Device relationship mapping
- Network topology visualization
- Gateway identification
- Subnet analysis
- Device role detection
- Connectivity graphing
- Critical device identification
- Graphviz export

**Example Usage:**
```python
from network_mapper import NetworkMapper

# Initialize
mapper = NetworkMapper()

# Add devices
mapper.add_device(
    ip='192.168.1.1',
    hostname='gateway.local',
    device_type='router',
    vendor='Cisco',
    open_ports=[22, 80, 443]
)

mapper.add_device(
    ip='192.168.1.10',
    hostname='camera1.local',
    device_type='webcam',
    vendor='Hikvision',
    open_ports=[80, 554]
)

# Add connections
mapper.add_connection('192.168.1.1', '192.168.1.10')
mapper.add_connection('192.168.1.1', '192.168.1.20')

# Map network
topology = mapper.map_network(ip_range="192.168.1.0/24")

print(f"Total Devices: {topology.total_devices}")
print(f"Network Segments: {len(topology.segments)}")
print(f"Gateways: {len(topology.gateway_devices)}")

# Identify gateways
gateways = mapper.identify_gateways()

# Analyze subnet
analysis = mapper.analyze_subnet("192.168.1.0/24")
print(f"Subnet Utilization: {analysis['utilization']:.1f}%")
print(f"Device Types: {analysis['device_types']}")

# Find critical devices
critical = mapper.find_critical_devices()

# Get device neighbors
neighbors = mapper.get_device_neighbors('192.168.1.1', depth=2)

# Export topology
mapper.export_topology("topology.json")
mapper.export_graphviz("topology.dot")
```

## Complete Workflow Example

```python
from iot_intel import IoTIntelligence
from shodan_iot import ShodanIoT
from censys_iot import CensysIoT
from insecam_integration import InsecamIntegration
from device_fingerprinter import DeviceFingerprinter
from iot_vulnerability_scanner import IoTVulnerabilityScanner
from network_mapper import NetworkMapper

# Phase 1: Discovery
print("[*] Phase 1: Device Discovery")

# Initialize main intelligence
iot = IoTIntelligence()

# Discover via Shodan
shodan = ShodanIoT(api_key="YOUR_API_KEY")
shodan_devices = shodan.search_webcams(country="US", max_results=50)

# Discover via Censys
censys = CensysIoT(api_id="YOUR_ID", api_secret="YOUR_SECRET")
censys_devices = censys.enumerate_iot_devices('webcam', max_results=50)

# Discover cameras via Insecam
insecam = InsecamIntegration()
cameras = insecam.search_cameras(country="US", max_results=50)

# Phase 2: Fingerprinting
print("[*] Phase 2: Device Fingerprinting")

fingerprinter = DeviceFingerprinter()

device_ips = [d.ip for d in shodan_devices[:10]]
fingerprints = fingerprinter.batch_fingerprint(device_ips)

# Phase 3: Vulnerability Scanning
print("[*] Phase 3: Vulnerability Assessment")

scanner = IoTVulnerabilityScanner()

for fingerprint in fingerprints:
    device_info = {
        'ip': fingerprint.ip,
        'hostname': fingerprint.hostname,
        'device_type': fingerprint.device_type,
        'vendor': fingerprint.vendor,
        'product': fingerprint.product,
        'version': fingerprint.version,
        'ports': fingerprint.open_ports,
    }

    scan_result = scanner.scan_device(fingerprint.ip, device_info)

    if scan_result.risk_score >= 70:
        print(f"HIGH RISK: {fingerprint.ip} - {scan_result.risk_score:.1f}/100")

# Phase 4: Network Mapping
print("[*] Phase 4: Network Topology Mapping")

mapper = NetworkMapper()

# Add discovered devices
for fp in fingerprints:
    mapper.add_device(
        ip=fp.ip,
        hostname=fp.hostname,
        device_type=fp.device_type,
        vendor=fp.vendor,
        open_ports=fp.open_ports
    )

# Map topology
topology = mapper.map_network()

# Identify critical infrastructure
gateways = mapper.identify_gateways()
critical = mapper.find_critical_devices()

# Phase 5: Reporting
print("[*] Phase 5: Report Generation")

# Generate comprehensive reports
iot_report = iot.generate_report("iot_intelligence.json")
shodan_report = shodan.export_results("shodan_results.json")
censys_report = censys.generate_report("censys_results.json")
vuln_report = scanner.generate_report("vulnerabilities.json")
mapper.export_topology("network_topology.json")
mapper.export_graphviz("network_graph.dot")

print("[+] Intelligence gathering complete!")
print(f"  Devices discovered: {len(fingerprints)}")
print(f"  Vulnerabilities found: {vuln_report['summary']['critical_vulnerabilities']}")
print(f"  High-risk devices: {len(scanner.get_high_risk_devices())}")
```

## Data Structures

### IoTDevice
```python
{
    "ip": "203.0.113.45",
    "port": 80,
    "device_type": "webcam",
    "vendor": "Hikvision",
    "model": "DS-2CD2142FWD-I",
    "firmware": "V5.5.0",
    "service": "HTTP",
    "vulnerabilities": ["CVE-2017-7921"],
    "risk_score": 85.0,
    "geolocation": {
        "country": "US",
        "city": "New York"
    }
}
```

### Vulnerability
```python
{
    "cve": "CVE-2017-7921",
    "title": "Authentication Bypass",
    "severity": "CRITICAL",
    "cvss_score": 9.8,
    "exploit_available": true,
    "exploit_db_id": "EDB-43221",
    "remediation": "Update firmware to latest version"
}
```

### NetworkTopology
```python
{
    "total_devices": 50,
    "segments": [
        {
            "subnet": "192.168.1.0/24",
            "gateway": "192.168.1.1",
            "devices": 25
        }
    ],
    "gateway_devices": ["192.168.1.1"],
    "device_graph": {
        "192.168.1.1": ["192.168.1.10", "192.168.1.11"]
    }
}
```

## Security Considerations

### Legal Compliance
- Obtain proper authorization before scanning networks
- Respect terms of service for Shodan/Censys APIs
- Follow responsible disclosure for vulnerabilities
- Comply with local laws regarding network scanning

### Ethical Usage
- Use for authorized security research only
- Do not exploit discovered vulnerabilities
- Protect sensitive data discovered during scans
- Report critical vulnerabilities to vendors

### API Rate Limiting
- Shodan: 1 query/second for paid accounts
- Censys: 120 queries/5 minutes
- Implement exponential backoff
- Cache results when possible

## Performance Optimization

### Scanning Speed
```python
# Use batch operations
fingerprints = fingerprinter.batch_fingerprint(
    ip_list,
    max_workers=20  # Parallel scanning
)

# Limit scan depth
devices = iot.discover_devices(
    target_org="Target",
    max_devices=100  # Limit results
)
```

### Resource Management
```python
# Set timeouts
fingerprint = fingerprinter.fingerprint_device(
    ip="192.168.1.100",
    timeout=2.0  # Quick timeout
)

# Limit port scanning
fingerprinter.common_ports = [80, 443, 22, 23]  # Essential ports only
```

## Troubleshooting

### Common Issues

**Issue**: Shodan API rate limiting
```python
# Solution: Add delay between requests
import time
for query in queries:
    results = shodan.search(query)
    time.sleep(1)  # 1 second delay
```

**Issue**: Network timeouts
```python
# Solution: Increase timeout values
fingerprint = fingerprinter.fingerprint_device(
    ip="192.168.1.100",
    timeout=5.0  # Longer timeout
)
```

**Issue**: Empty results
```python
# Solution: Verify connectivity and permissions
import socket
try:
    socket.create_connection(("8.8.8.8", 53), timeout=3)
    print("Network connectivity OK")
except:
    print("Network connectivity issues")
```

## Integration Examples

### With Threat Intelligence Platform
```python
# Export to STIX format
def export_to_stix(devices):
    stix_objects = []
    for device in devices:
        stix_obj = {
            "type": "observed-data",
            "objects": {
                "0": {
                    "type": "ipv4-addr",
                    "value": device.ip
                }
            }
        }
        stix_objects.append(stix_obj)
    return stix_objects
```

### With SIEM Integration
```python
# Send to Splunk
def send_to_splunk(scan_results):
    for result in scan_results:
        event = {
            "sourcetype": "iot_scan",
            "event": asdict(result)
        }
        # Send to Splunk HEC
```

## Advanced Features

### Custom Device Signatures
```python
# Add custom device signature
fingerprinter.signatures['custom_device'] = {
    'banners': ['custom', 'device'],
    'http_headers': ['Server: Custom'],
    'ports': [8080],
    'device_type': 'custom',
    'vendor': 'Custom Vendor',
}
```

### Custom CVE Database
```python
# Add custom vulnerabilities
scanner.cve_database['custom_vendor'] = [
    {
        'cve': 'CVE-2024-12345',
        'title': 'Custom Vulnerability',
        'severity': 'HIGH',
        'cvss': 8.5,
        'affected_versions': ['< 2.0.0'],
        'exploit_available': False,
    }
]
```

## License

This software is provided for educational and authorized security research purposes only.

## Disclaimer

This toolkit is designed for authorized security research and penetration testing. Unauthorized access to computer systems is illegal. Users are responsible for complying with applicable laws and regulations.

---

**Agent 14: IoT & Device Intelligence - Complete**
