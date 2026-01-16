"""
Complete IoT Intelligence Workflow Example
Demonstrates full integration of all IoT intelligence components
"""

from iot_intel import IoTIntelligence
from shodan_iot import ShodanIoT
from censys_iot import CensysIoT
from insecam_integration import InsecamIntegration
from device_fingerprinter import DeviceFingerprinter
from iot_vulnerability_scanner import IoTVulnerabilityScanner
from network_mapper import NetworkMapper
import json
from datetime import datetime


def print_banner(text):
    """Print section banner"""
    print("\n" + "=" * 70)
    print(f"  {text}")
    print("=" * 70)


def main():
    """Complete IoT intelligence workflow"""
    print_banner("IoT Intelligence - Complete Workflow")
    print(f"Started: {datetime.utcnow().isoformat()}")

    # Configuration
    TARGET_ORG = "Target Company"
    TARGET_COUNTRY = "US"
    TARGET_SUBNET = "192.168.1.0/24"

    # Initialize all components
    print("\n[*] Initializing components...")
    iot = IoTIntelligence()
    shodan = ShodanIoT(api_key="YOUR_SHODAN_API_KEY")
    censys = CensysIoT(api_id="YOUR_CENSYS_ID", api_secret="YOUR_CENSYS_SECRET")
    insecam = InsecamIntegration()
    fingerprinter = DeviceFingerprinter()
    scanner = IoTVulnerabilityScanner()
    mapper = NetworkMapper()

    # ========================================================================
    # PHASE 1: DEVICE DISCOVERY
    # ========================================================================
    print_banner("PHASE 1: Device Discovery")

    # Discover via main intelligence system
    print("\n[*] Discovering devices via IoT Intelligence...")
    iot_devices = iot.discover_devices(
        target_org=TARGET_ORG,
        device_types=["webcam", "router", "nas"],
        max_devices=50
    )
    print(f"[+] Found {len(iot_devices)} devices via IoT Intelligence")

    # Discover via Shodan
    print("\n[*] Discovering devices via Shodan...")
    shodan_webcams = shodan.search_webcams(
        country=TARGET_COUNTRY,
        max_results=20
    )
    shodan_routers = shodan.search_routers(
        country=TARGET_COUNTRY,
        max_results=10
    )
    print(f"[+] Found {len(shodan_webcams)} webcams via Shodan")
    print(f"[+] Found {len(shodan_routers)} routers via Shodan")

    # Discover via Censys
    print("\n[*] Discovering devices via Censys...")
    censys_webcams = censys.enumerate_iot_devices(
        device_type='webcam',
        max_results=20
    )
    print(f"[+] Found {len(censys_webcams)} webcams via Censys")

    # Discover cameras via Insecam
    print("\n[*] Discovering cameras via Insecam...")
    insecam_cameras = insecam.search_cameras(
        country=TARGET_COUNTRY,
        max_results=20
    )
    print(f"[+] Found {len(insecam_cameras)} cameras via Insecam")

    # Summary
    total_discovered = (
        len(iot_devices) + len(shodan_webcams) + len(shodan_routers) +
        len(censys_webcams) + len(insecam_cameras)
    )
    print(f"\n[+] Total devices discovered: {total_discovered}")

    # ========================================================================
    # PHASE 2: DEVICE FINGERPRINTING
    # ========================================================================
    print_banner("PHASE 2: Device Fingerprinting")

    # Collect unique IPs from all sources
    device_ips = list(set(
        [d.ip for d in iot_devices[:10]] +
        [d.ip for d in shodan_webcams[:5]] +
        [d.ip for d in censys_webcams[:5]]
    ))

    print(f"\n[*] Fingerprinting {len(device_ips)} unique devices...")
    fingerprints = fingerprinter.batch_fingerprint(
        device_ips[:15],  # Limit to 15 for example
        max_workers=5
    )
    print(f"[+] Successfully fingerprinted {len(fingerprints)} devices")

    # Show sample fingerprints
    print("\n[*] Sample Fingerprints:")
    for fp in fingerprints[:3]:
        print(f"\n  IP: {fp.ip}")
        print(f"  Hostname: {fp.hostname or 'Unknown'}")
        print(f"  Device Type: {fp.device_type or 'Unknown'}")
        print(f"  Vendor: {fp.vendor or 'Unknown'}")
        print(f"  OS: {fp.os or 'Unknown'}")
        print(f"  Confidence: {fp.confidence:.0%}")
        print(f"  Open Ports: {fp.open_ports}")

    # ========================================================================
    # PHASE 3: VULNERABILITY ASSESSMENT
    # ========================================================================
    print_banner("PHASE 3: Vulnerability Assessment")

    print("\n[*] Scanning devices for vulnerabilities...")
    scan_results = []

    for fp in fingerprints:
        device_info = {
            'ip': fp.ip,
            'hostname': fp.hostname,
            'device_type': fp.device_type,
            'vendor': fp.vendor,
            'product': fp.product,
            'version': fp.version,
            'ports': fp.open_ports,
        }

        result = scanner.scan_device(fp.ip, device_info)
        scan_results.append(result)

    print(f"[+] Scanned {len(scan_results)} devices")

    # Analyze results
    vulnerable_devices = [r for r in scan_results if r.vulnerabilities]
    high_risk_devices = [r for r in scan_results if r.risk_score >= 70]
    default_creds = [r for r in scan_results if r.default_credentials_found]

    print(f"\n[+] Vulnerability Summary:")
    print(f"  Vulnerable devices: {len(vulnerable_devices)}")
    print(f"  High-risk devices: {len(high_risk_devices)}")
    print(f"  Devices with default credentials: {len(default_creds)}")

    # Show high-risk devices
    print("\n[*] High-Risk Devices:")
    for result in high_risk_devices[:5]:
        print(f"\n  {result.ip} - {result.vendor or 'Unknown'}")
        print(f"  Risk Score: {result.risk_score:.1f}/100")
        print(f"  Vulnerabilities: {len(result.vulnerabilities)}")
        print(f"  Default Credentials: {'YES' if result.default_credentials_found else 'NO'}")

        # Show vulnerabilities
        for vuln in result.vulnerabilities[:2]:
            print(f"    - {vuln.cve}: {vuln.title} ({vuln.severity})")

        # Show exploit suggestions
        exploits = scanner.generate_exploit_suggestions(result)
        if exploits:
            print(f"    Exploits Available: {len(exploits)}")
            for exploit in exploits[:1]:
                print(f"      - {exploit['title']}")

    # ========================================================================
    # PHASE 4: NETWORK MAPPING
    # ========================================================================
    print_banner("PHASE 4: Network Topology Mapping")

    print("\n[*] Building network topology...")

    # Add fingerprinted devices to mapper
    for fp in fingerprints:
        mapper.add_device(
            ip=fp.ip,
            hostname=fp.hostname,
            device_type=fp.device_type,
            vendor=fp.vendor,
            open_ports=fp.open_ports,
            services=fp.services
        )

    # Map the network
    topology = mapper.map_network(ip_range=TARGET_SUBNET)

    print(f"\n[+] Network Topology:")
    print(f"  Total Devices: {topology.total_devices}")
    print(f"  Network Segments: {len(topology.segments)}")
    print(f"  Gateway Devices: {len(topology.gateway_devices)}")

    # Identify gateways
    gateways = mapper.identify_gateways()
    print(f"\n[*] Gateway Devices:")
    for gateway in gateways:
        print(f"  - {gateway.ip} ({gateway.hostname or 'Unknown'})")
        print(f"    Role: {gateway.role}")
        print(f"    Connections: {len(gateway.connections)}")

    # Find critical devices
    critical_devices = mapper.find_critical_devices()
    print(f"\n[*] Critical Devices: {len(critical_devices)}")
    for device in critical_devices[:3]:
        print(f"  - {device.ip} ({device.role})")
        print(f"    Connections: {len(device.connections)}")
        print(f"    Services: {len(device.services)}")

    # Analyze subnets
    for segment in topology.segments[:3]:
        print(f"\n[*] Subnet Analysis: {segment.subnet}")
        analysis = mapper.analyze_subnet(segment.subnet)
        print(f"  Total Devices: {analysis['total_devices']}")
        print(f"  Gateway: {analysis['gateway'] or 'None'}")
        print(f"  Utilization: {analysis['utilization']:.1f}%")
        print(f"  Device Types: {analysis['device_types']}")

    # ========================================================================
    # PHASE 5: CAMERA ANALYSIS
    # ========================================================================
    print_banner("PHASE 5: Camera Feed Analysis")

    print("\n[*] Analyzing camera feeds...")

    # Get geographic distribution
    cam_distribution = shodan.get_geographic_distribution('webcam')
    print(f"\n[+] Camera Geographic Distribution (Top 5):")
    for country, count in list(cam_distribution.items())[:5]:
        print(f"  {country}: {count:,} cameras")

    # Access sample camera feeds
    if insecam_cameras:
        print(f"\n[*] Sample Camera Information:")
        for camera in insecam_cameras[:3]:
            print(f"\n  Camera: {camera.camera_id}")
            print(f"  Location: {camera.city}, {camera.country}")
            print(f"  Manufacturer: {camera.manufacturer}")
            print(f"  Resolution: {camera.resolution}")
            print(f"  Category: {camera.category}")
            print(f"  Status: {'Online' if camera.is_online else 'Offline'}")

            # Get metadata
            metadata = insecam.get_camera_metadata(camera)
            print(f"  Coordinates: {metadata['location']['coordinates']}")

    # ========================================================================
    # PHASE 6: REPORTING
    # ========================================================================
    print_banner("PHASE 6: Report Generation")

    print("\n[*] Generating comprehensive reports...")

    # Generate all reports
    reports = {}

    # IoT Intelligence report
    reports['iot_intelligence'] = iot.generate_report(
        output_file="iot_intelligence_report.json",
        include_topology=True
    )

    # Shodan report
    reports['shodan'] = shodan.export_results(
        output_file="shodan_results.json"
    )

    # Censys report
    reports['censys'] = censys.generate_report(
        output_file="censys_results.json"
    )

    # Insecam report
    reports['insecam'] = insecam.export_cameras(
        output_file="insecam_cameras.json"
    )

    # Fingerprinting report
    reports['fingerprints'] = fingerprinter.export_fingerprints(
        output_file="device_fingerprints.json"
    )

    # Vulnerability report
    reports['vulnerabilities'] = scanner.generate_report(
        output_file="vulnerability_report.json",
        include_exploits=True
    )

    # Network topology
    reports['topology'] = mapper.export_topology(
        output_file="network_topology.json"
    )

    # Export network graph
    mapper.export_graphviz("network_topology.dot")
    insecam.export_kml("cameras.kml")

    print("[+] All reports generated successfully")

    # ========================================================================
    # PHASE 7: EXECUTIVE SUMMARY
    # ========================================================================
    print_banner("EXECUTIVE SUMMARY")

    summary = {
        'scan_completed_at': datetime.utcnow().isoformat(),
        'target_organization': TARGET_ORG,
        'target_country': TARGET_COUNTRY,
        'discovery': {
            'total_devices_discovered': total_discovered,
            'unique_devices_fingerprinted': len(fingerprints),
            'cameras_found': len(insecam_cameras),
        },
        'vulnerabilities': {
            'devices_scanned': len(scan_results),
            'vulnerable_devices': len(vulnerable_devices),
            'high_risk_devices': len(high_risk_devices),
            'default_credentials_found': len(default_creds),
            'critical_vulnerabilities': sum(
                len([v for v in r.vulnerabilities if v.severity == 'CRITICAL'])
                for r in scan_results
            ),
            'high_vulnerabilities': sum(
                len([v for v in r.vulnerabilities if v.severity == 'HIGH'])
                for r in scan_results
            ),
        },
        'network': {
            'total_devices': topology.total_devices,
            'network_segments': len(topology.segments),
            'gateway_devices': len(topology.gateway_devices),
            'critical_devices': len(critical_devices),
        },
        'risk_assessment': {
            'average_risk_score': sum(r.risk_score for r in scan_results) / len(scan_results) if scan_results else 0,
            'highest_risk_score': max((r.risk_score for r in scan_results), default=0),
            'overall_risk_level': 'HIGH' if len(high_risk_devices) > 0 else 'MEDIUM',
        },
    }

    print(f"\n{'=' * 70}")
    print("DISCOVERY SUMMARY")
    print(f"{'=' * 70}")
    print(f"  Total Devices Discovered: {summary['discovery']['total_devices_discovered']}")
    print(f"  Devices Fingerprinted: {summary['discovery']['unique_devices_fingerprinted']}")
    print(f"  Cameras Found: {summary['discovery']['cameras_found']}")

    print(f"\n{'=' * 70}")
    print("VULNERABILITY SUMMARY")
    print(f"{'=' * 70}")
    print(f"  Devices Scanned: {summary['vulnerabilities']['devices_scanned']}")
    print(f"  Vulnerable Devices: {summary['vulnerabilities']['vulnerable_devices']}")
    print(f"  High-Risk Devices: {summary['vulnerabilities']['high_risk_devices']}")
    print(f"  Critical Vulnerabilities: {summary['vulnerabilities']['critical_vulnerabilities']}")
    print(f"  High Vulnerabilities: {summary['vulnerabilities']['high_vulnerabilities']}")
    print(f"  Default Credentials Found: {summary['vulnerabilities']['default_credentials_found']}")

    print(f"\n{'=' * 70}")
    print("NETWORK SUMMARY")
    print(f"{'=' * 70}")
    print(f"  Total Devices: {summary['network']['total_devices']}")
    print(f"  Network Segments: {summary['network']['network_segments']}")
    print(f"  Gateway Devices: {summary['network']['gateway_devices']}")
    print(f"  Critical Devices: {summary['network']['critical_devices']}")

    print(f"\n{'=' * 70}")
    print("RISK ASSESSMENT")
    print(f"{'=' * 70}")
    print(f"  Average Risk Score: {summary['risk_assessment']['average_risk_score']:.1f}/100")
    print(f"  Highest Risk Score: {summary['risk_assessment']['highest_risk_score']:.1f}/100")
    print(f"  Overall Risk Level: {summary['risk_assessment']['overall_risk_level']}")

    # Save executive summary
    with open('executive_summary.json', 'w') as f:
        json.dump(summary, f, indent=2)
    print("\n[+] Executive summary saved to executive_summary.json")

    # List all generated files
    print(f"\n{'=' * 70}")
    print("GENERATED FILES")
    print(f"{'=' * 70}")
    generated_files = [
        "iot_intelligence_report.json",
        "shodan_results.json",
        "censys_results.json",
        "insecam_cameras.json",
        "device_fingerprints.json",
        "vulnerability_report.json",
        "network_topology.json",
        "network_topology.dot",
        "cameras.kml",
        "executive_summary.json",
    ]
    for filename in generated_files:
        print(f"  - {filename}")

    print_banner("IoT Intelligence Workflow Complete")
    print(f"Completed: {datetime.utcnow().isoformat()}")


if __name__ == "__main__":
    main()
