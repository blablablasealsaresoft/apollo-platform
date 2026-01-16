"""
Shodan IoT - IoT Device Discovery via Shodan
Discover webcams, routers, and vulnerable IoT devices
"""

import json
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
from dataclasses import dataclass, asdict
from collections import defaultdict
import time

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class ShodanIoTDevice:
    """Shodan IoT device result"""
    ip: str
    port: int
    device_type: str
    product: Optional[str] = None
    version: Optional[str] = None
    organization: Optional[str] = None
    hostname: Optional[str] = None
    domain: Optional[str] = None
    country: Optional[str] = None
    city: Optional[str] = None
    asn: Optional[str] = None
    isp: Optional[str] = None
    banner: Optional[str] = None
    vulnerabilities: List[str] = None
    tags: List[str] = None
    screenshot_url: Optional[str] = None
    last_update: Optional[str] = None
    risk_level: str = "UNKNOWN"
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.vulnerabilities is None:
            self.vulnerabilities = []
        if self.tags is None:
            self.tags = []
        if self.metadata is None:
            self.metadata = {}


class ShodanIoT:
    """
    Shodan IoT Device Discovery
    Find and analyze IoT devices exposed to the internet
    """

    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize Shodan IoT

        Args:
            api_key: Shodan API key (optional for demonstration)
        """
        self.api_key = api_key
        self.devices = []

        # Shodan search queries for IoT devices
        self.device_queries = {
            'webcam': [
                'webcam',
                'camera',
                'DVR',
                'NVR',
                'RTSP',
                'Hikvision',
                'Dahua',
                'AXIS',
                'IP Camera',
                'title:"Network Camera"',
                'Server: Camera Web Server',
            ],
            'router': [
                'router login',
                'admin login',
                'Mikrotik',
                'Cisco',
                'Netgear',
                'Linksys',
                'TP-Link',
                'DD-WRT',
                'OpenWrt',
                'title:"Router"',
            ],
            'nas': [
                'Synology',
                'QNAP',
                'NAS',
                'DiskStation',
                'Network Attached Storage',
                'title:"DSM"',
            ],
            'iot_general': [
                'IoT',
                'smart home',
                'home automation',
                'default password',
            ],
            'industrial': [
                'SCADA',
                'PLC',
                'HMI',
                'Modbus',
                'Siemens',
                'Schneider',
                'industrial control',
            ],
            'printer': [
                'printer',
                'HP',
                'Xerox',
                'Canon',
                'title:"Printer"',
            ],
        }

        # Vulnerable device signatures
        self.vulnerability_signatures = {
            'default_creds': ['default password', 'admin:admin', 'root:root'],
            'outdated': ['EOL', 'end of life', 'unsupported'],
            'exposed': ['unauthenticated', 'no authentication', 'anonymous'],
        }

    def search_webcams(
        self,
        country: Optional[str] = None,
        organization: Optional[str] = None,
        city: Optional[str] = None,
        has_screenshot: bool = False,
        max_results: int = 100
    ) -> List[ShodanIoTDevice]:
        """
        Search for exposed webcams

        Args:
            country: Filter by country code (e.g., 'US', 'CN')
            organization: Filter by organization
            city: Filter by city
            has_screenshot: Only return devices with screenshots
            max_results: Maximum results to return

        Returns:
            List of webcam devices
        """
        logger.info("Searching for webcams on Shodan")

        # Build search query
        query_parts = ['webcam']

        if country:
            query_parts.append(f'country:"{country}"')
        if organization:
            query_parts.append(f'org:"{organization}"')
        if city:
            query_parts.append(f'city:"{city}"')
        if has_screenshot:
            query_parts.append('has_screenshot:true')

        query = ' '.join(query_parts)

        # Execute search (simulated)
        devices = self._execute_search(query, 'webcam', max_results)

        logger.info(f"Found {len(devices)} webcams")
        return devices

    def search_routers(
        self,
        vendor: Optional[str] = None,
        country: Optional[str] = None,
        vulnerable_only: bool = False,
        max_results: int = 100
    ) -> List[ShodanIoTDevice]:
        """
        Search for exposed routers

        Args:
            vendor: Router vendor (e.g., 'Cisco', 'Mikrotik')
            country: Filter by country code
            vulnerable_only: Only return vulnerable routers
            max_results: Maximum results to return

        Returns:
            List of router devices
        """
        logger.info("Searching for routers on Shodan")

        query_parts = ['router']

        if vendor:
            query_parts.append(vendor)
        if country:
            query_parts.append(f'country:"{country}"')
        if vulnerable_only:
            query_parts.append('vuln:*')

        query = ' '.join(query_parts)

        devices = self._execute_search(query, 'router', max_results)

        logger.info(f"Found {len(devices)} routers")
        return devices

    def enumerate_iot_devices(
        self,
        device_type: str,
        country: Optional[str] = None,
        max_results: int = 100
    ) -> List[ShodanIoTDevice]:
        """
        Enumerate IoT devices by type

        Args:
            device_type: Type of device (webcam, router, nas, etc.)
            country: Filter by country
            max_results: Maximum results

        Returns:
            List of IoT devices
        """
        logger.info(f"Enumerating {device_type} devices")

        if device_type not in self.device_queries:
            logger.error(f"Unknown device type: {device_type}")
            return []

        # Try multiple queries for the device type
        all_devices = []
        for query_term in self.device_queries[device_type][:3]:  # Use first 3 queries
            query = query_term
            if country:
                query += f' country:"{country}"'

            devices = self._execute_search(query, device_type, max_results // 3)
            all_devices.extend(devices)

        # Remove duplicates by IP
        unique_devices = {d.ip: d for d in all_devices}.values()

        logger.info(f"Found {len(unique_devices)} unique {device_type} devices")
        return list(unique_devices)

    def detect_vulnerabilities(
        self,
        device_type: Optional[str] = None,
        country: Optional[str] = None,
        max_results: int = 100
    ) -> List[ShodanIoTDevice]:
        """
        Detect vulnerable IoT devices

        Args:
            device_type: Specific device type to check
            country: Filter by country
            max_results: Maximum results

        Returns:
            List of vulnerable devices
        """
        logger.info("Detecting vulnerable IoT devices")

        # Search for devices with known vulnerabilities
        query_parts = []

        if device_type:
            query_parts.append(device_type)
        else:
            query_parts.append('IoT')

        query_parts.append('vuln:*')

        if country:
            query_parts.append(f'country:"{country}"')

        query = ' '.join(query_parts)

        devices = self._execute_search(query, device_type or 'iot', max_results)

        # Filter to only vulnerable devices
        vulnerable = [d for d in devices if d.vulnerabilities]

        logger.info(f"Found {len(vulnerable)} vulnerable devices")
        return vulnerable

    def get_geographic_distribution(
        self,
        device_type: str = 'webcam',
        max_countries: int = 20
    ) -> Dict[str, int]:
        """
        Get geographic distribution of devices

        Args:
            device_type: Type of device
            max_countries: Maximum countries to return

        Returns:
            Dictionary mapping country to device count
        """
        logger.info(f"Getting geographic distribution for {device_type}")

        # Simulated country distribution
        distribution = {
            'US': 15432,
            'CN': 12876,
            'KR': 8934,
            'JP': 6543,
            'DE': 5432,
            'GB': 4567,
            'FR': 3456,
            'BR': 3210,
            'RU': 2987,
            'IN': 2765,
            'IT': 2543,
            'ES': 2234,
            'CA': 1987,
            'AU': 1765,
            'NL': 1543,
            'PL': 1432,
            'SE': 1234,
            'TR': 1123,
            'MX': 1087,
            'TW': 987,
        }

        # Return top countries
        sorted_dist = dict(sorted(distribution.items(), key=lambda x: x[1], reverse=True))
        return dict(list(sorted_dist.items())[:max_countries])

    def search_by_organization(
        self,
        org_name: str,
        device_type: Optional[str] = None,
        max_results: int = 100
    ) -> List[ShodanIoTDevice]:
        """
        Search for devices by organization

        Args:
            org_name: Organization name
            device_type: Specific device type
            max_results: Maximum results

        Returns:
            List of devices belonging to organization
        """
        logger.info(f"Searching devices for organization: {org_name}")

        query_parts = [f'org:"{org_name}"']

        if device_type:
            query_parts.append(device_type)

        query = ' '.join(query_parts)

        devices = self._execute_search(query, device_type or 'iot', max_results)

        logger.info(f"Found {len(devices)} devices for {org_name}")
        return devices

    def _execute_search(
        self,
        query: str,
        device_type: str,
        max_results: int
    ) -> List[ShodanIoTDevice]:
        """Execute Shodan search (simulated)"""

        # Simulated results
        devices = []

        # Generate simulated devices based on device type
        templates = self._get_device_templates(device_type)

        for i in range(min(max_results, len(templates) * 10)):
            template = templates[i % len(templates)]

            device = ShodanIoTDevice(
                ip=f"{203 + i % 10}.{i % 256}.{(i * 7) % 256}.{(i * 13) % 256}",
                port=template['port'],
                device_type=device_type,
                product=template['product'],
                version=template.get('version'),
                organization=f"Organization {i % 10}",
                hostname=f"{device_type}-{i}.example.com",
                country=["US", "CN", "KR", "JP", "DE"][i % 5],
                city=["New York", "Beijing", "Seoul", "Tokyo", "Berlin"][i % 5],
                asn=f"AS{15000 + i % 1000}",
                isp=["Comcast", "China Telecom", "KT", "NTT", "Deutsche Telekom"][i % 5],
                banner=template.get('banner'),
                vulnerabilities=template.get('vulnerabilities', []),
                tags=template.get('tags', []),
                screenshot_url=f"https://example.com/screenshot_{i}.jpg" if i % 3 == 0 else None,
                last_update=datetime.utcnow().isoformat(),
                risk_level=self._calculate_risk_level(template.get('vulnerabilities', []))
            )

            devices.append(device)

        self.devices.extend(devices)
        return devices

    def _get_device_templates(self, device_type: str) -> List[Dict]:
        """Get device templates for simulation"""

        templates = {
            'webcam': [
                {
                    'product': 'Hikvision IP Camera',
                    'version': 'V5.5.0',
                    'port': 80,
                    'banner': 'Hikvision-Webs',
                    'vulnerabilities': ['CVE-2017-7921', 'CVE-2021-36260'],
                    'tags': ['camera', 'iot', 'default-password'],
                },
                {
                    'product': 'Dahua DVR',
                    'version': '2.608.0000.0',
                    'port': 37777,
                    'banner': 'Dahua',
                    'vulnerabilities': ['CVE-2019-3948'],
                    'tags': ['dvr', 'camera', 'iot'],
                },
                {
                    'product': 'AXIS Network Camera',
                    'version': '5.60.1',
                    'port': 80,
                    'banner': 'AXIS/5',
                    'vulnerabilities': [],
                    'tags': ['camera', 'iot'],
                },
            ],
            'router': [
                {
                    'product': 'Cisco RV Series Router',
                    'version': '1.4.2.22',
                    'port': 443,
                    'banner': 'Cisco Small Business',
                    'vulnerabilities': ['CVE-2019-1653'],
                    'tags': ['router', 'iot', 'admin-interface'],
                },
                {
                    'product': 'MikroTik RouterOS',
                    'version': '6.42.7',
                    'port': 8291,
                    'banner': 'MikroTik',
                    'vulnerabilities': ['CVE-2018-14847'],
                    'tags': ['router', 'iot'],
                },
                {
                    'product': 'Netgear Router',
                    'version': '1.0.0.52',
                    'port': 80,
                    'banner': 'Netgear',
                    'vulnerabilities': ['CVE-2020-9377'],
                    'tags': ['router', 'iot', 'default-password'],
                },
            ],
            'nas': [
                {
                    'product': 'Synology DiskStation',
                    'version': 'DSM 6.2',
                    'port': 5000,
                    'banner': 'Synology',
                    'vulnerabilities': [],
                    'tags': ['nas', 'storage'],
                },
                {
                    'product': 'QNAP NAS',
                    'version': '4.4.2',
                    'port': 8080,
                    'banner': 'QNAP',
                    'vulnerabilities': ['CVE-2021-28799'],
                    'tags': ['nas', 'storage', 'iot'],
                },
            ],
            'iot': [
                {
                    'product': 'Generic IoT Device',
                    'version': '1.0',
                    'port': 80,
                    'banner': 'IoT Device',
                    'vulnerabilities': [],
                    'tags': ['iot'],
                },
            ],
        }

        return templates.get(device_type, templates['iot'])

    def _calculate_risk_level(self, vulnerabilities: List[str]) -> str:
        """Calculate risk level based on vulnerabilities"""
        if not vulnerabilities:
            return "LOW"
        elif len(vulnerabilities) == 1:
            return "MEDIUM"
        else:
            return "HIGH"

    def generate_statistics(self) -> Dict[str, Any]:
        """Generate statistics from discovered devices"""

        stats = {
            'total_devices': len(self.devices),
            'by_type': defaultdict(int),
            'by_country': defaultdict(int),
            'by_vendor': defaultdict(int),
            'by_risk_level': defaultdict(int),
            'vulnerable_devices': 0,
            'with_screenshots': 0,
        }

        for device in self.devices:
            stats['by_type'][device.device_type] += 1
            if device.country:
                stats['by_country'][device.country] += 1
            if device.product:
                vendor = device.product.split()[0]
                stats['by_vendor'][vendor] += 1
            stats['by_risk_level'][device.risk_level] += 1

            if device.vulnerabilities:
                stats['vulnerable_devices'] += 1
            if device.screenshot_url:
                stats['with_screenshots'] += 1

        # Convert defaultdicts to regular dicts
        stats['by_type'] = dict(stats['by_type'])
        stats['by_country'] = dict(stats['by_country'])
        stats['by_vendor'] = dict(stats['by_vendor'])
        stats['by_risk_level'] = dict(stats['by_risk_level'])

        return stats

    def export_results(self, output_file: str = "shodan_iot_results.json") -> Dict:
        """Export results to JSON file"""

        results = {
            'generated_at': datetime.utcnow().isoformat(),
            'total_devices': len(self.devices),
            'statistics': self.generate_statistics(),
            'devices': [asdict(d) for d in self.devices],
        }

        try:
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
            logger.info(f"Results exported to {output_file}")
        except Exception as e:
            logger.error(f"Error exporting results: {e}")

        return results


def main():
    """Example usage"""
    print("Shodan IoT Device Discovery")
    print("=" * 50)

    # Initialize
    shodan = ShodanIoT(api_key="YOUR_API_KEY")

    # Search for webcams
    print("\n[*] Searching for webcams in the US...")
    webcams = shodan.search_webcams(country="US", max_results=10)
    print(f"[+] Found {len(webcams)} webcams")

    for cam in webcams[:3]:
        print(f"\n  IP: {cam.ip}:{cam.port}")
        print(f"  Product: {cam.product}")
        print(f"  Location: {cam.city}, {cam.country}")
        print(f"  Vulnerabilities: {len(cam.vulnerabilities)}")
        print(f"  Risk Level: {cam.risk_level}")

    # Search for vulnerable routers
    print("\n[*] Searching for vulnerable routers...")
    routers = shodan.search_routers(vulnerable_only=True, max_results=10)
    print(f"[+] Found {len(routers)} vulnerable routers")

    # Enumerate IoT devices
    print("\n[*] Enumerating NAS devices...")
    nas_devices = shodan.enumerate_iot_devices('nas', max_results=5)
    print(f"[+] Found {len(nas_devices)} NAS devices")

    # Get geographic distribution
    print("\n[*] Getting geographic distribution...")
    distribution = shodan.get_geographic_distribution('webcam')
    print("\n  Top 5 countries:")
    for country, count in list(distribution.items())[:5]:
        print(f"    {country}: {count:,} devices")

    # Generate statistics
    print("\n[*] Generating statistics...")
    stats = shodan.generate_statistics()
    print(f"\n  Total devices: {stats['total_devices']}")
    print(f"  Vulnerable devices: {stats['vulnerable_devices']}")
    print(f"  Devices with screenshots: {stats['with_screenshots']}")

    # Export results
    print("\n[*] Exporting results...")
    shodan.export_results()
    print("[+] Results exported successfully")


if __name__ == "__main__":
    main()
