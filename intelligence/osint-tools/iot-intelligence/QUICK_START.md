# IoT Intelligence - Quick Start Guide

## Installation

```bash
cd C:\SECURE_THREAT_INTEL\YoureGunnaHAveToShootMeToStopME\apollo\intelligence\osint-tools\iot-intelligence
```

## Quick Usage

### 1. Basic Device Discovery

```python
from iot_intel import IoTIntelligence

iot = IoTIntelligence()
devices = iot.discover_devices(
    target_org="Target Company",
    device_types=["webcam", "router"],
    max_devices=50
)

for device in devices:
    print(f"{device.ip} - {device.device_type} - Risk: {device.risk_score:.1f}")
```

### 2. Shodan Search

```python
from shodan_iot import ShodanIoT

shodan = ShodanIoT(api_key="YOUR_API_KEY")
webcams = shodan.search_webcams(country="US", max_results=10)

for cam in webcams:
    print(f"{cam.ip} - {cam.product} - {cam.country}")
```

### 3. Device Fingerprinting

```python
from device_fingerprinter import DeviceFingerprinter

fingerprinter = DeviceFingerprinter()
fp = fingerprinter.fingerprint_device("192.168.1.1")

print(f"Device: {fp.device_type}")
print(f"Vendor: {fp.vendor}")
print(f"OS: {fp.os}")
```

### 4. Vulnerability Scanning

```python
from iot_vulnerability_scanner import IoTVulnerabilityScanner

scanner = IoTVulnerabilityScanner()
result = scanner.scan_device(
    ip="192.168.1.100",
    device_info={
        'vendor': 'Hikvision',
        'version': '5.4.0',
        'ports': [80, 554]
    }
)

print(f"Risk Score: {result.risk_score:.1f}")
print(f"Vulnerabilities: {len(result.vulnerabilities)}")
```

### 5. Network Mapping

```python
from network_mapper import NetworkMapper

mapper = NetworkMapper()
mapper.add_device(
    ip="192.168.1.1",
    device_type="router",
    open_ports=[80, 443]
)

topology = mapper.map_network(ip_range="192.168.1.0/24")
print(f"Devices: {topology.total_devices}")
```

## Complete Workflow

Run the example workflow:

```python
python example_full_workflow.py
```

This will:
1. Discover devices from multiple sources
2. Fingerprint all discovered devices
3. Scan for vulnerabilities
4. Map network topology
5. Generate comprehensive reports

## Output Files

The workflow generates:
- `iot_intelligence_report.json` - Main intelligence report
- `vulnerability_report.json` - Vulnerability assessment
- `network_topology.json` - Network map
- `network_topology.dot` - Graphviz visualization
- `executive_summary.json` - Executive summary

## Common Commands

### Search by Organization
```python
devices = iot.discover_devices(target_org="Company Name")
```

### Search by Location
```python
cameras = insecam.get_camera_by_location(40.7128, -74.0060, radius_km=10)
```

### Find Vulnerable Devices
```python
vulnerable = shodan.detect_vulnerabilities(device_type="webcam")
```

### Identify Gateways
```python
gateways = mapper.identify_gateways()
```

## API Keys Required

- **Shodan**: Get from https://account.shodan.io/
- **Censys**: Get from https://censys.io/account

## Legal Notice

Use only on authorized systems. Unauthorized access is illegal.

## Support

See README_IOT_INTEL.md for full documentation.
