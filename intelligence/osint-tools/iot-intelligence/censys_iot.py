"""
Censys IoT - Internet-wide IoT Device Scanning via Censys
Certificate analysis, service fingerprinting, and device enumeration
"""

import json
import logging
from typing import Dict, List, Optional, Any, Set
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from collections import defaultdict
import hashlib

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class CensysDevice:
    """Censys device scan result"""
    ip: str
    ports: List[int]
    services: Dict[int, str]
    protocols: List[str]
    certificates: List[Dict] = None
    autonomous_system: Optional[Dict] = None
    location: Optional[Dict] = None
    device_type: Optional[str] = None
    manufacturer: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    operating_system: Optional[str] = None
    vulnerabilities: List[str] = None
    tags: List[str] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.certificates is None:
            self.certificates = []
        if self.vulnerabilities is None:
            self.vulnerabilities = []
        if self.tags is None:
            self.tags = []
        if self.metadata is None:
            self.metadata = {}
        if self.last_seen is None:
            self.last_seen = datetime.utcnow().isoformat()


@dataclass
class Certificate:
    """SSL/TLS Certificate information"""
    fingerprint: str
    subject: Dict[str, str]
    issuer: Dict[str, str]
    valid_from: str
    valid_to: str
    serial_number: str
    signature_algorithm: str
    public_key_algorithm: str
    key_size: int
    san: List[str] = None
    is_self_signed: bool = False
    is_expired: bool = False
    is_wildcard: bool = False

    def __post_init__(self):
        if self.san is None:
            self.san = []


class CensysIoT:
    """
    Censys IoT Device Scanner
    Internet-wide device scanning and analysis
    """

    def __init__(self, api_id: Optional[str] = None, api_secret: Optional[str] = None):
        """
        Initialize Censys IoT

        Args:
            api_id: Censys API ID
            api_secret: Censys API Secret
        """
        self.api_id = api_id
        self.api_secret = api_secret
        self.devices = []
        self.certificates = []

        # IoT device fingerprints
        self.device_fingerprints = {
            'webcam': {
                'ports': [80, 81, 443, 554, 8080, 8081],
                'services': ['http', 'https', 'rtsp'],
                'banners': ['camera', 'webcam', 'ipcam', 'dvr', 'nvr', 'hikvision', 'dahua', 'axis'],
                'paths': ['/webcam.html', '/view.html', '/live.htm'],
            },
            'router': {
                'ports': [80, 443, 8080, 8443, 23, 22],
                'services': ['http', 'https', 'telnet', 'ssh'],
                'banners': ['router', 'gateway', 'modem', 'cisco', 'mikrotik', 'netgear'],
                'paths': ['/login.html', '/admin.html', '/setup.cgi'],
            },
            'nas': {
                'ports': [80, 443, 5000, 5001, 8080],
                'services': ['http', 'https', 'smb', 'nfs'],
                'banners': ['nas', 'storage', 'synology', 'qnap', 'diskstation'],
                'paths': ['/webman/index.cgi'],
            },
            'industrial': {
                'ports': [102, 502, 2404, 44818, 47808],
                'services': ['modbus', 's7', 'bacnet'],
                'banners': ['scada', 'plc', 'hmi', 'siemens', 'schneider'],
                'paths': [],
            },
            'printer': {
                'ports': [80, 443, 515, 631, 9100],
                'services': ['http', 'https', 'ipp', 'lpd'],
                'banners': ['printer', 'print server', 'hp', 'xerox', 'canon'],
                'paths': ['/hp/device/this.LCDispatcher'],
            },
        }

    def scan_internet(
        self,
        query: str,
        max_results: int = 1000,
        include_certificates: bool = True
    ) -> List[CensysDevice]:
        """
        Perform internet-wide scan

        Args:
            query: Censys search query
            max_results: Maximum results to return
            include_certificates: Include certificate analysis

        Returns:
            List of discovered devices
        """
        logger.info(f"Executing Censys scan: {query}")

        devices = self._execute_scan(query, max_results)

        if include_certificates:
            self._analyze_certificates(devices)

        logger.info(f"Scan completed: {len(devices)} devices found")
        return devices

    def search_by_service(
        self,
        service: str,
        country: Optional[str] = None,
        asn: Optional[str] = None,
        max_results: int = 500
    ) -> List[CensysDevice]:
        """
        Search devices by service type

        Args:
            service: Service name (e.g., 'http', 'ssh', 'telnet')
            country: Filter by country code
            asn: Filter by ASN
            max_results: Maximum results

        Returns:
            List of devices running the service
        """
        logger.info(f"Searching for devices running {service}")

        query_parts = [f'services.service_name: {service}']

        if country:
            query_parts.append(f'location.country: {country}')
        if asn:
            query_parts.append(f'autonomous_system.asn: {asn}')

        query = ' AND '.join(query_parts)

        devices = self._execute_scan(query, max_results)

        logger.info(f"Found {len(devices)} devices running {service}")
        return devices

    def enumerate_iot_devices(
        self,
        device_type: str,
        organization: Optional[str] = None,
        max_results: int = 500
    ) -> List[CensysDevice]:
        """
        Enumerate IoT devices by type

        Args:
            device_type: Type of device (webcam, router, nas, etc.)
            organization: Filter by organization
            max_results: Maximum results

        Returns:
            List of IoT devices
        """
        logger.info(f"Enumerating {device_type} devices")

        if device_type not in self.device_fingerprints:
            logger.error(f"Unknown device type: {device_type}")
            return []

        fingerprint = self.device_fingerprints[device_type]

        # Build query based on fingerprint
        query_parts = []

        # Add port conditions
        if fingerprint['ports']:
            port_query = ' OR '.join([f'services.port: {p}' for p in fingerprint['ports']])
            query_parts.append(f'({port_query})')

        # Add banner conditions
        if fingerprint['banners']:
            banner_query = ' OR '.join([f'services.banner: {b}' for b in fingerprint['banners'][:3]])
            query_parts.append(f'({banner_query})')

        if organization:
            query_parts.append(f'autonomous_system.organization: "{organization}"')

        query = ' AND '.join(query_parts)

        devices = self._execute_scan(query, max_results)

        # Tag devices with type
        for device in devices:
            device.device_type = device_type

        logger.info(f"Found {len(devices)} {device_type} devices")
        return devices

    def analyze_certificates(
        self,
        domain: Optional[str] = None,
        organization: Optional[str] = None,
        expired_only: bool = False,
        self_signed_only: bool = False,
        max_results: int = 500
    ) -> List[Certificate]:
        """
        Analyze SSL/TLS certificates

        Args:
            domain: Filter by domain in certificate
            organization: Filter by organization in certificate
            expired_only: Only return expired certificates
            self_signed_only: Only return self-signed certificates
            max_results: Maximum results

        Returns:
            List of certificates
        """
        logger.info("Analyzing SSL/TLS certificates")

        query_parts = []

        if domain:
            query_parts.append(f'parsed.names: {domain}')
        if organization:
            query_parts.append(f'parsed.subject.organization: "{organization}"')
        if expired_only:
            query_parts.append(f'parsed.validity.end < {datetime.utcnow().isoformat()}')
        if self_signed_only:
            query_parts.append('parsed.signature.self_signed: true')

        query = ' AND '.join(query_parts) if query_parts else '*'

        certificates = self._scan_certificates(query, max_results)

        logger.info(f"Found {len(certificates)} certificates")
        return certificates

    def fingerprint_services(
        self,
        ip_range: Optional[str] = None,
        port: Optional[int] = None,
        max_results: int = 500
    ) -> Dict[str, List[Dict]]:
        """
        Fingerprint services across the internet

        Args:
            ip_range: IP range to scan (CIDR notation)
            port: Specific port to fingerprint
            max_results: Maximum results

        Returns:
            Dictionary mapping service to list of instances
        """
        logger.info("Fingerprinting services")

        query_parts = []

        if ip_range:
            query_parts.append(f'ip: {ip_range}')
        if port:
            query_parts.append(f'services.port: {port}')

        query = ' AND '.join(query_parts) if query_parts else 'services: *'

        devices = self._execute_scan(query, max_results)

        # Group by service
        service_map = defaultdict(list)
        for device in devices:
            for port, service in device.services.items():
                service_map[service].append({
                    'ip': device.ip,
                    'port': port,
                    'product': device.product,
                    'version': device.version,
                })

        logger.info(f"Found {len(service_map)} unique services")
        return dict(service_map)

    def search_vulnerable_devices(
        self,
        cve: Optional[str] = None,
        device_type: Optional[str] = None,
        max_results: int = 500
    ) -> List[CensysDevice]:
        """
        Search for vulnerable devices

        Args:
            cve: Specific CVE to search for
            device_type: Filter by device type
            max_results: Maximum results

        Returns:
            List of vulnerable devices
        """
        logger.info("Searching for vulnerable devices")

        query_parts = []

        if cve:
            query_parts.append(f'services.vulnerabilities.cve: {cve}')
        else:
            query_parts.append('services.vulnerabilities: *')

        if device_type and device_type in self.device_fingerprints:
            fingerprint = self.device_fingerprints[device_type]
            if fingerprint['banners']:
                banner_query = ' OR '.join([f'services.banner: {b}' for b in fingerprint['banners'][:2]])
                query_parts.append(f'({banner_query})')

        query = ' AND '.join(query_parts)

        devices = self._execute_scan(query, max_results)

        logger.info(f"Found {len(devices)} vulnerable devices")
        return devices

    def _execute_scan(self, query: str, max_results: int) -> List[CensysDevice]:
        """Execute Censys scan (simulated)"""

        devices = []

        # Simulate scan results
        for i in range(min(max_results, 50)):
            # Generate device based on query
            device_type = self._infer_device_type_from_query(query)

            ports = self._generate_ports(device_type)
            services = {port: self._get_service_name(port) for port in ports}

            device = CensysDevice(
                ip=f"{198 + i % 10}.{51 + i % 50}.{100 + i % 150}.{1 + i % 254}",
                ports=ports,
                services=services,
                protocols=['tcp', 'http'] if 80 in ports or 443 in ports else ['tcp'],
                autonomous_system={
                    'asn': f'AS{13335 + i % 10000}',
                    'organization': f'Organization {i % 20}',
                    'country': ['US', 'CN', 'DE', 'GB', 'JP'][i % 5],
                },
                location={
                    'country': ['US', 'CN', 'DE', 'GB', 'JP'][i % 5],
                    'city': ['New York', 'Beijing', 'Berlin', 'London', 'Tokyo'][i % 5],
                    'latitude': 40.7128 + (i % 10) - 5,
                    'longitude': -74.0060 + (i % 10) - 5,
                },
                device_type=device_type,
                manufacturer=self._get_manufacturer(device_type, i),
                product=self._get_product(device_type, i),
                version=f"{1 + i % 5}.{i % 10}.{i % 100}",
                operating_system=self._get_os(device_type, i),
                vulnerabilities=self._generate_vulnerabilities(i),
                tags=self._generate_tags(device_type),
                first_seen=(datetime.utcnow() - timedelta(days=30 + i % 365)).isoformat(),
                last_seen=datetime.utcnow().isoformat(),
            )

            devices.append(device)

        self.devices.extend(devices)
        return devices

    def _infer_device_type_from_query(self, query: str) -> str:
        """Infer device type from query"""
        query_lower = query.lower()

        for device_type, fingerprint in self.device_fingerprints.items():
            for banner in fingerprint['banners']:
                if banner in query_lower:
                    return device_type

        return 'unknown'

    def _generate_ports(self, device_type: str) -> List[int]:
        """Generate ports for device type"""
        if device_type in self.device_fingerprints:
            fingerprint = self.device_fingerprints[device_type]
            return fingerprint['ports'][:3]
        return [80, 443]

    def _get_service_name(self, port: int) -> str:
        """Get service name for port"""
        service_map = {
            80: 'http',
            443: 'https',
            22: 'ssh',
            23: 'telnet',
            21: 'ftp',
            554: 'rtsp',
            8080: 'http-proxy',
            8443: 'https-alt',
            502: 'modbus',
            102: 's7',
            5000: 'upnp',
        }
        return service_map.get(port, f'port-{port}')

    def _get_manufacturer(self, device_type: str, index: int) -> str:
        """Get manufacturer for device type"""
        manufacturers = {
            'webcam': ['Hikvision', 'Dahua', 'AXIS', 'Hanwha', 'Bosch'],
            'router': ['Cisco', 'MikroTik', 'Netgear', 'Linksys', 'TP-Link'],
            'nas': ['Synology', 'QNAP', 'Buffalo', 'Western Digital', 'Netgear'],
            'industrial': ['Siemens', 'Schneider Electric', 'Rockwell', 'ABB', 'Honeywell'],
            'printer': ['HP', 'Canon', 'Xerox', 'Epson', 'Brother'],
        }
        if device_type in manufacturers:
            return manufacturers[device_type][index % len(manufacturers[device_type])]
        return 'Generic'

    def _get_product(self, device_type: str, index: int) -> str:
        """Get product for device type"""
        manufacturer = self._get_manufacturer(device_type, index)
        products = {
            'Hikvision': 'DS-2CD2142FWD-I',
            'Cisco': 'RV320',
            'Synology': 'DiskStation DS218+',
            'Siemens': 'S7-1200',
            'HP': 'LaserJet Pro',
        }
        return products.get(manufacturer, f'{manufacturer} Device')

    def _get_os(self, device_type: str, index: int) -> str:
        """Get operating system"""
        os_options = ['Linux', 'Embedded Linux', 'VxWorks', 'Custom OS', 'RTOS']
        return os_options[index % len(os_options)]

    def _generate_vulnerabilities(self, index: int) -> List[str]:
        """Generate vulnerabilities"""
        if index % 3 == 0:
            return []
        elif index % 3 == 1:
            return [f'CVE-2021-{34000 + index % 10000}']
        else:
            return [f'CVE-2020-{12000 + index % 10000}', f'CVE-2021-{34000 + index % 10000}']

    def _generate_tags(self, device_type: str) -> List[str]:
        """Generate tags for device"""
        base_tags = ['iot', device_type]

        if device_type in ['webcam', 'industrial']:
            base_tags.append('high-risk')

        return base_tags

    def _analyze_certificates(self, devices: List[CensysDevice]):
        """Analyze certificates for devices"""
        for device in devices:
            if 443 in device.ports or 8443 in device.ports:
                cert = self._generate_certificate(device)
                device.certificates.append(cert)
                self.certificates.append(cert)

    def _scan_certificates(self, query: str, max_results: int) -> List[Certificate]:
        """Scan for certificates"""
        certificates = []

        for i in range(min(max_results, 50)):
            cert = Certificate(
                fingerprint=hashlib.sha256(f"cert_{i}".encode()).hexdigest(),
                subject={
                    'common_name': f'device{i}.example.com',
                    'organization': f'Organization {i % 10}',
                    'country': ['US', 'CN', 'DE'][i % 3],
                },
                issuer={
                    'common_name': 'Example CA' if i % 5 != 0 else f'device{i}.example.com',
                    'organization': 'Example CA' if i % 5 != 0 else f'Organization {i % 10}',
                },
                valid_from=(datetime.utcnow() - timedelta(days=365)).isoformat(),
                valid_to=(datetime.utcnow() + timedelta(days=365 if i % 10 != 0 else -10)).isoformat(),
                serial_number=f'{i:032x}',
                signature_algorithm='SHA256-RSA',
                public_key_algorithm='RSA',
                key_size=2048 if i % 3 != 0 else 1024,
                san=[f'device{i}.example.com', f'*.device{i}.example.com'] if i % 4 == 0 else [],
                is_self_signed=(i % 5 == 0),
                is_expired=(i % 10 == 0),
                is_wildcard=(i % 4 == 0),
            )

            certificates.append(cert)

        self.certificates.extend(certificates)
        return certificates

    def _generate_certificate(self, device: CensysDevice) -> Dict:
        """Generate certificate for device"""
        is_expired = device.ip.endswith('0')

        return {
            'fingerprint': hashlib.sha256(device.ip.encode()).hexdigest(),
            'subject_cn': device.product or 'Unknown',
            'issuer_cn': 'Device CA' if not is_expired else 'Self-Signed',
            'valid_from': (datetime.utcnow() - timedelta(days=365)).isoformat(),
            'valid_to': (datetime.utcnow() + timedelta(days=365 if not is_expired else -10)).isoformat(),
            'is_self_signed': is_expired,
            'is_expired': is_expired,
        }

    def generate_report(self, output_file: str = "censys_iot_report.json") -> Dict:
        """Generate comprehensive report"""

        report = {
            'generated_at': datetime.utcnow().isoformat(),
            'summary': {
                'total_devices': len(self.devices),
                'total_certificates': len(self.certificates),
                'device_types': self._count_by_field('device_type'),
                'manufacturers': self._count_by_field('manufacturer'),
                'vulnerable_devices': len([d for d in self.devices if d.vulnerabilities]),
                'countries': self._count_countries(),
            },
            'devices': [asdict(d) for d in self.devices],
            'top_vulnerabilities': self._get_top_vulnerabilities(),
            'certificate_summary': self._summarize_certificates(),
        }

        try:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            logger.info(f"Report saved to {output_file}")
        except Exception as e:
            logger.error(f"Error saving report: {e}")

        return report

    def _count_by_field(self, field: str) -> Dict[str, int]:
        """Count devices by field"""
        counts = defaultdict(int)
        for device in self.devices:
            value = getattr(device, field, None)
            if value:
                counts[value] += 1
        return dict(counts)

    def _count_countries(self) -> Dict[str, int]:
        """Count devices by country"""
        counts = defaultdict(int)
        for device in self.devices:
            if device.location and 'country' in device.location:
                counts[device.location['country']] += 1
        return dict(counts)

    def _get_top_vulnerabilities(self, top_n: int = 10) -> List[Dict]:
        """Get most common vulnerabilities"""
        vuln_counts = defaultdict(int)
        for device in self.devices:
            for vuln in device.vulnerabilities:
                vuln_counts[vuln] += 1

        sorted_vulns = sorted(vuln_counts.items(), key=lambda x: x[1], reverse=True)

        return [
            {'cve': cve, 'count': count}
            for cve, count in sorted_vulns[:top_n]
        ]

    def _summarize_certificates(self) -> Dict:
        """Summarize certificate analysis"""
        if not self.certificates:
            return {}

        return {
            'total': len(self.certificates),
            'self_signed': len([c for c in self.certificates if c.is_self_signed]),
            'expired': len([c for c in self.certificates if c.is_expired]),
            'wildcard': len([c for c in self.certificates if c.is_wildcard]),
            'weak_keys': len([c for c in self.certificates if c.key_size < 2048]),
        }


def main():
    """Example usage"""
    print("Censys IoT Scanner")
    print("=" * 50)

    # Initialize
    censys = CensysIoT(api_id="YOUR_API_ID", api_secret="YOUR_API_SECRET")

    # Internet-wide scan
    print("\n[*] Scanning for IoT devices...")
    devices = censys.scan_internet("services.service_name: http", max_results=20)
    print(f"[+] Found {len(devices)} devices")

    # Enumerate webcams
    print("\n[*] Enumerating webcams...")
    webcams = censys.enumerate_iot_devices('webcam', max_results=10)
    print(f"[+] Found {len(webcams)} webcams")

    for cam in webcams[:3]:
        print(f"\n  IP: {cam.ip}")
        print(f"  Product: {cam.manufacturer} {cam.product}")
        print(f"  Ports: {cam.ports}")
        print(f"  Location: {cam.location.get('city')}, {cam.location.get('country')}")
        print(f"  Vulnerabilities: {len(cam.vulnerabilities)}")

    # Analyze certificates
    print("\n[*] Analyzing SSL/TLS certificates...")
    certificates = censys.analyze_certificates(max_results=10)
    print(f"[+] Found {len(certificates)} certificates")
    print(f"  Self-signed: {len([c for c in certificates if c.is_self_signed])}")
    print(f"  Expired: {len([c for c in certificates if c.is_expired])}")

    # Fingerprint services
    print("\n[*] Fingerprinting services...")
    services = censys.fingerprint_services(port=80, max_results=20)
    print(f"[+] Found {len(services)} unique services")

    # Search vulnerable devices
    print("\n[*] Searching for vulnerable devices...")
    vulnerable = censys.search_vulnerable_devices(max_results=10)
    print(f"[+] Found {len(vulnerable)} vulnerable devices")

    # Generate report
    print("\n[*] Generating report...")
    report = censys.generate_report()
    print(f"[+] Report generated")
    print(f"  Total devices: {report['summary']['total_devices']}")
    print(f"  Vulnerable: {report['summary']['vulnerable_devices']}")


if __name__ == "__main__":
    main()
