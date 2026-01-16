"""
IoT Intelligence - Main IoT Device Intelligence System
Provides comprehensive IoT device discovery, analysis, and attribution
"""

import socket
import asyncio
import json
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
from dataclasses import dataclass, asdict
import ipaddress
import concurrent.futures
from collections import defaultdict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class IoTDevice:
    """IoT device information"""
    ip: str
    port: int
    device_type: str
    vendor: Optional[str] = None
    model: Optional[str] = None
    firmware: Optional[str] = None
    service: Optional[str] = None
    banner: Optional[str] = None
    vulnerabilities: List[str] = None
    geolocation: Optional[Dict] = None
    organization: Optional[str] = None
    asn: Optional[str] = None
    hostname: Optional[str] = None
    protocols: List[str] = None
    risk_score: float = 0.0
    discovered_at: str = None
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.vulnerabilities is None:
            self.vulnerabilities = []
        if self.protocols is None:
            self.protocols = []
        if self.metadata is None:
            self.metadata = {}
        if self.discovered_at is None:
            self.discovered_at = datetime.utcnow().isoformat()


@dataclass
class IoTNetwork:
    """IoT network topology"""
    network_id: str
    subnet: str
    gateway: Optional[str] = None
    devices: List[IoTDevice] = None
    topology: Dict[str, List[str]] = None
    organization: Optional[str] = None
    country: Optional[str] = None
    asn: Optional[str] = None
    discovered_at: str = None

    def __post_init__(self):
        if self.devices is None:
            self.devices = []
        if self.topology is None:
            self.topology = {}
        if self.discovered_at is None:
            self.discovered_at = datetime.utcnow().isoformat()


class IoTIntelligence:
    """
    Main IoT Intelligence System
    Comprehensive device discovery, vulnerability scanning, and attribution
    """

    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize IoT Intelligence

        Args:
            config: Configuration dictionary with API keys and settings
        """
        self.config = config or {}
        self.devices = []
        self.networks = []
        self.device_cache = {}

        # Device type signatures
        self.device_signatures = {
            'webcam': ['camera', 'webcam', 'ipcam', 'dvr', 'nvr', 'axis', 'hikvision', 'dahua'],
            'router': ['router', 'gateway', 'modem', 'netgear', 'linksys', 'cisco', 'mikrotik'],
            'nas': ['nas', 'storage', 'synology', 'qnap', 'buffalo', 'netapp'],
            'printer': ['printer', 'print', 'xerox', 'hp', 'canon', 'epson'],
            'smart_home': ['smart', 'alexa', 'nest', 'hue', 'iot', 'home automation'],
            'industrial': ['scada', 'plc', 'hmi', 'modbus', 'siemens', 'schneider'],
            'medical': ['medical', 'hospital', 'patient', 'healthcare', 'diagnostic'],
            'pos': ['pos', 'point of sale', 'cash register', 'payment'],
        }

        # Common IoT ports
        self.iot_ports = {
            80: 'HTTP',
            81: 'HTTP Alt',
            443: 'HTTPS',
            554: 'RTSP',
            8080: 'HTTP Proxy',
            8081: 'HTTP Alt',
            8443: 'HTTPS Alt',
            5000: 'UPnP',
            37777: 'Dahua DVR',
            9000: 'HTTP Alt',
            23: 'Telnet',
            22: 'SSH',
            21: 'FTP',
            502: 'Modbus',
            1883: 'MQTT',
            5683: 'CoAP',
        }

    def discover_devices(
        self,
        target_org: Optional[str] = None,
        target_ip: Optional[str] = None,
        target_subnet: Optional[str] = None,
        device_types: Optional[List[str]] = None,
        max_devices: int = 1000,
        scan_ports: bool = True
    ) -> List[IoTDevice]:
        """
        Discover IoT devices based on criteria

        Args:
            target_org: Target organization name
            target_ip: Specific IP to scan
            target_subnet: Subnet to scan (CIDR notation)
            device_types: List of device types to look for
            max_devices: Maximum number of devices to return
            scan_ports: Whether to perform port scanning

        Returns:
            List of discovered IoT devices
        """
        logger.info(f"Starting IoT device discovery")
        discovered = []

        try:
            # Discover from different sources
            if target_subnet:
                discovered.extend(self._scan_subnet(target_subnet, device_types, scan_ports))

            if target_ip:
                device = self._scan_single_ip(target_ip, scan_ports)
                if device:
                    discovered.append(device)

            if target_org:
                # Simulate organization-based discovery
                discovered.extend(self._discover_by_organization(target_org, device_types))

            # Filter by device types if specified
            if device_types:
                discovered = [d for d in discovered if d.device_type in device_types]

            # Calculate risk scores
            for device in discovered:
                device.risk_score = self._calculate_risk_score(device)

            # Sort by risk score (highest first)
            discovered.sort(key=lambda x: x.risk_score, reverse=True)

            # Limit results
            discovered = discovered[:max_devices]

            self.devices.extend(discovered)
            logger.info(f"Discovered {len(discovered)} IoT devices")

            return discovered

        except Exception as e:
            logger.error(f"Error discovering devices: {e}")
            return []

    def _scan_subnet(
        self,
        subnet: str,
        device_types: Optional[List[str]] = None,
        scan_ports: bool = True
    ) -> List[IoTDevice]:
        """Scan a subnet for IoT devices"""
        devices = []

        try:
            network = ipaddress.ip_network(subnet, strict=False)
            logger.info(f"Scanning subnet {subnet} ({network.num_addresses} addresses)")

            # Limit scan to reasonable size
            hosts = list(network.hosts())[:254]

            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                futures = {
                    executor.submit(self._scan_single_ip, str(ip), scan_ports): ip
                    for ip in hosts
                }

                for future in concurrent.futures.as_completed(futures):
                    try:
                        device = future.result(timeout=5)
                        if device:
                            devices.append(device)
                    except Exception as e:
                        continue

            logger.info(f"Found {len(devices)} devices in subnet")

        except Exception as e:
            logger.error(f"Error scanning subnet: {e}")

        return devices

    def _scan_single_ip(self, ip: str, scan_ports: bool = True) -> Optional[IoTDevice]:
        """Scan a single IP for IoT device"""
        try:
            # Check if IP is reachable
            hostname = None
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except:
                pass

            if scan_ports:
                # Scan common IoT ports
                open_ports = []
                for port in [80, 443, 554, 8080, 23, 22]:
                    if self._check_port(ip, port, timeout=1):
                        open_ports.append(port)

                if not open_ports:
                    return None

                # Use first open port for device info
                port = open_ports[0]
                banner = self._grab_banner(ip, port)

                # Identify device type
                device_type = self._identify_device_type(banner, hostname)

                device = IoTDevice(
                    ip=ip,
                    port=port,
                    device_type=device_type,
                    hostname=hostname,
                    banner=banner,
                    protocols=[self.iot_ports.get(p, f'Port {p}') for p in open_ports]
                )

                return device

        except Exception as e:
            logger.debug(f"Error scanning {ip}: {e}")

        return None

    def _check_port(self, ip: str, port: int, timeout: float = 2.0) -> bool:
        """Check if a port is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False

    def _grab_banner(self, ip: str, port: int, timeout: float = 2.0) -> Optional[str]:
        """Grab banner from a service"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))

            # Try HTTP request for web services
            if port in [80, 443, 8080, 8081, 8443]:
                sock.send(b'GET / HTTP/1.1\r\nHost: ' + ip.encode() + b'\r\n\r\n')

            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()

            return banner if banner else None

        except Exception as e:
            logger.debug(f"Error grabbing banner from {ip}:{port}: {e}")
            return None

    def _identify_device_type(self, banner: Optional[str], hostname: Optional[str]) -> str:
        """Identify device type from banner and hostname"""
        text = (banner or '').lower() + ' ' + (hostname or '').lower()

        for device_type, signatures in self.device_signatures.items():
            for sig in signatures:
                if sig in text:
                    return device_type

        return 'unknown'

    def _discover_by_organization(
        self,
        org_name: str,
        device_types: Optional[List[str]] = None
    ) -> List[IoTDevice]:
        """Discover devices by organization (simulated)"""
        logger.info(f"Discovering devices for organization: {org_name}")

        # Simulated discovery results
        devices = [
            IoTDevice(
                ip="203.0.113.45",
                port=80,
                device_type="webcam",
                vendor="Hikvision",
                model="DS-2CD2142FWD-I",
                firmware="V5.5.0",
                service="HTTP",
                banner="Hikvision-Webs",
                organization=org_name,
                hostname=f"cam-entrance.{org_name.lower().replace(' ', '')}.com",
                protocols=["HTTP", "RTSP"],
                vulnerabilities=["CVE-2017-7921"],
                geolocation={"country": "US", "city": "New York", "lat": 40.7128, "lon": -74.0060}
            ),
            IoTDevice(
                ip="203.0.113.67",
                port=443,
                device_type="router",
                vendor="Cisco",
                model="RV320",
                firmware="1.4.2.22",
                service="HTTPS",
                banner="Cisco Small Business",
                organization=org_name,
                hostname=f"router-main.{org_name.lower().replace(' ', '')}.com",
                protocols=["HTTPS", "SSH"],
                vulnerabilities=["CVE-2019-1653"],
                geolocation={"country": "US", "city": "New York", "lat": 40.7128, "lon": -74.0060}
            ),
            IoTDevice(
                ip="203.0.113.89",
                port=8080,
                device_type="nas",
                vendor="Synology",
                model="DS218+",
                firmware="DSM 6.2",
                service="HTTP",
                banner="Synology DiskStation",
                organization=org_name,
                hostname=f"nas-backup.{org_name.lower().replace(' ', '')}.com",
                protocols=["HTTP", "HTTPS", "FTP"],
                vulnerabilities=[],
                geolocation={"country": "US", "city": "New York", "lat": 40.7128, "lon": -74.0060}
            ),
        ]

        # Filter by device types if specified
        if device_types:
            devices = [d for d in devices if d.device_type in device_types]

        return devices

    def _calculate_risk_score(self, device: IoTDevice) -> float:
        """Calculate risk score for a device"""
        score = 0.0

        # Vulnerabilities increase risk
        score += len(device.vulnerabilities) * 30.0

        # High-risk device types
        high_risk_types = ['webcam', 'router', 'industrial', 'medical', 'pos']
        if device.device_type in high_risk_types:
            score += 20.0

        # Insecure protocols
        insecure_protocols = ['HTTP', 'Telnet', 'FTP']
        for protocol in device.protocols:
            if protocol in insecure_protocols:
                score += 10.0

        # Internet-facing adds risk
        if device.ip and not self._is_private_ip(device.ip):
            score += 15.0

        # Unknown vendor/model adds risk
        if not device.vendor:
            score += 5.0

        return min(score, 100.0)

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private"""
        try:
            return ipaddress.ip_address(ip).is_private
        except:
            return False

    def map_network_topology(
        self,
        devices: Optional[List[IoTDevice]] = None
    ) -> List[IoTNetwork]:
        """
        Map network topology from devices

        Args:
            devices: List of devices to map (uses self.devices if None)

        Returns:
            List of IoT networks with topology
        """
        devices = devices or self.devices

        # Group devices by subnet
        subnet_groups = defaultdict(list)
        for device in devices:
            try:
                ip = ipaddress.ip_address(device.ip)
                # Group by /24 subnet
                subnet = str(ipaddress.ip_network(f"{ip}/24", strict=False))
                subnet_groups[subnet].append(device)
            except:
                continue

        # Create network objects
        networks = []
        for subnet, subnet_devices in subnet_groups.items():
            network = IoTNetwork(
                network_id=f"net_{subnet.replace('/', '_')}",
                subnet=subnet,
                devices=subnet_devices,
                organization=subnet_devices[0].organization if subnet_devices else None
            )

            # Identify gateway (likely router)
            for device in subnet_devices:
                if device.device_type == 'router':
                    network.gateway = device.ip
                    break

            # Build topology (simplified)
            topology = {}
            if network.gateway:
                topology[network.gateway] = [d.ip for d in subnet_devices if d.ip != network.gateway]

            network.topology = topology
            networks.append(network)

        self.networks = networks
        logger.info(f"Mapped {len(networks)} networks")

        return networks

    def get_device_vulnerabilities(self, device: IoTDevice) -> List[Dict]:
        """
        Get detailed vulnerability information for a device

        Args:
            device: IoT device to check

        Returns:
            List of vulnerability details
        """
        vulnerabilities = []

        for cve in device.vulnerabilities:
            vuln = {
                'cve': cve,
                'device': f"{device.vendor} {device.model}",
                'severity': 'HIGH',
                'description': f'Known vulnerability in {device.vendor} {device.model}',
                'exploitation': 'Active exploits available',
                'remediation': 'Update firmware to latest version'
            }
            vulnerabilities.append(vuln)

        return vulnerabilities

    def generate_report(
        self,
        output_file: str = "iot_intelligence_report.json",
        include_topology: bool = True
    ) -> Dict:
        """
        Generate comprehensive IoT intelligence report

        Args:
            output_file: Output file path
            include_topology: Whether to include network topology

        Returns:
            Report dictionary
        """
        report = {
            'generated_at': datetime.utcnow().isoformat(),
            'summary': {
                'total_devices': len(self.devices),
                'device_types': self._count_device_types(),
                'vulnerable_devices': len([d for d in self.devices if d.vulnerabilities]),
                'high_risk_devices': len([d for d in self.devices if d.risk_score >= 70]),
                'networks': len(self.networks)
            },
            'devices': [asdict(d) for d in self.devices],
            'high_risk_devices': [
                asdict(d) for d in sorted(self.devices, key=lambda x: x.risk_score, reverse=True)[:10]
            ]
        }

        if include_topology and self.networks:
            report['networks'] = [asdict(n) for n in self.networks]

        # Save to file
        try:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            logger.info(f"Report saved to {output_file}")
        except Exception as e:
            logger.error(f"Error saving report: {e}")

        return report

    def _count_device_types(self) -> Dict[str, int]:
        """Count devices by type"""
        counts = defaultdict(int)
        for device in self.devices:
            counts[device.device_type] += 1
        return dict(counts)

    def search_devices(
        self,
        device_type: Optional[str] = None,
        vendor: Optional[str] = None,
        min_risk_score: float = 0.0,
        has_vulnerabilities: bool = False
    ) -> List[IoTDevice]:
        """
        Search discovered devices by criteria

        Args:
            device_type: Filter by device type
            vendor: Filter by vendor
            min_risk_score: Minimum risk score
            has_vulnerabilities: Only show devices with vulnerabilities

        Returns:
            Filtered list of devices
        """
        results = self.devices

        if device_type:
            results = [d for d in results if d.device_type == device_type]

        if vendor:
            results = [d for d in results if d.vendor and vendor.lower() in d.vendor.lower()]

        if min_risk_score > 0:
            results = [d for d in results if d.risk_score >= min_risk_score]

        if has_vulnerabilities:
            results = [d for d in results if d.vulnerabilities]

        return results


def main():
    """Example usage"""
    print("IoT Intelligence System")
    print("=" * 50)

    # Initialize
    iot = IoTIntelligence()

    # Discover devices
    print("\n[*] Discovering IoT devices...")
    devices = iot.discover_devices(
        target_org="Target Company",
        device_types=["webcam", "router", "nas"],
        max_devices=100
    )

    print(f"\n[+] Discovered {len(devices)} devices")

    # Show high-risk devices
    print("\n[*] High-risk devices:")
    for device in devices[:5]:
        print(f"\n  Device: {device.device_type}")
        print(f"  IP: {device.ip}:{device.port}")
        print(f"  Vendor: {device.vendor} {device.model}")
        print(f"  Vulnerabilities: {len(device.vulnerabilities)}")
        print(f"  Risk Score: {device.risk_score:.1f}")

    # Map network topology
    print("\n[*] Mapping network topology...")
    networks = iot.map_network_topology()

    for network in networks:
        print(f"\n  Network: {network.subnet}")
        print(f"  Gateway: {network.gateway}")
        print(f"  Devices: {len(network.devices)}")

    # Generate report
    print("\n[*] Generating report...")
    report = iot.generate_report()
    print(f"[+] Report saved with {report['summary']['total_devices']} devices")

    # Search examples
    print("\n[*] Searching for vulnerable webcams...")
    vulnerable_cams = iot.search_devices(
        device_type="webcam",
        has_vulnerabilities=True
    )
    print(f"[+] Found {len(vulnerable_cams)} vulnerable webcams")


if __name__ == "__main__":
    main()
