"""
Device Fingerprinter - IoT Device Identification and Analysis
Banner grabbing, service detection, version identification, and OS fingerprinting
"""

import socket
import ssl
import re
import hashlib
import logging
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
from dataclasses import dataclass, asdict
import json
import concurrent.futures

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class DeviceFingerprint:
    """Device fingerprint result"""
    ip: str
    hostname: Optional[str] = None
    device_type: Optional[str] = None
    vendor: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    os: Optional[str] = None
    os_version: Optional[str] = None
    architecture: Optional[str] = None
    services: Dict[int, Dict] = None
    open_ports: List[int] = None
    banners: Dict[int, str] = None
    http_headers: Optional[Dict] = None
    ssl_info: Optional[Dict] = None
    confidence: float = 0.0
    fingerprinted_at: str = None
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.services is None:
            self.services = {}
        if self.open_ports is None:
            self.open_ports = []
        if self.banners is None:
            self.banners = {}
        if self.metadata is None:
            self.metadata = {}
        if self.fingerprinted_at is None:
            self.fingerprinted_at = datetime.utcnow().isoformat()


class DeviceFingerprinter:
    """
    Device Fingerprinting System
    Identify IoT devices through banner grabbing and service analysis
    """

    def __init__(self):
        """Initialize device fingerprinter"""
        self.fingerprints = []

        # Common IoT ports to scan
        self.common_ports = [
            21,    # FTP
            22,    # SSH
            23,    # Telnet
            80,    # HTTP
            443,   # HTTPS
            554,   # RTSP
            8080,  # HTTP Alt
            8081,  # HTTP Alt
            8443,  # HTTPS Alt
            9000,  # HTTP Alt
            5000,  # UPnP
            37777, # Dahua DVR
            8000,  # HTTP Alt
            8888,  # HTTP Alt
        ]

        # Device signatures database
        self.signatures = {
            'hikvision': {
                'banners': ['hikvision', 'hikvision-webs', 'webserver'],
                'http_headers': ['Server: HikvisionWebServer', 'Server: App-webs'],
                'paths': ['/doc/page/login.asp', '/ISAPI/System/deviceInfo'],
                'device_type': 'webcam',
                'vendor': 'Hikvision',
            },
            'dahua': {
                'banners': ['dahua', 'dh-webs'],
                'http_headers': ['Server: Dahua'],
                'ports': [37777, 80],
                'device_type': 'webcam',
                'vendor': 'Dahua',
            },
            'axis': {
                'banners': ['axis', 'axis network camera'],
                'http_headers': ['Server: AXIS/'],
                'device_type': 'webcam',
                'vendor': 'AXIS Communications',
            },
            'cisco': {
                'banners': ['cisco', 'cisco systems'],
                'http_headers': ['Server: cisco-IOS'],
                'paths': ['/level/15/exec/-/show'],
                'device_type': 'router',
                'vendor': 'Cisco',
            },
            'mikrotik': {
                'banners': ['mikrotik', 'routeros'],
                'http_headers': ['Server: RouterOS'],
                'ports': [8291, 8728],
                'device_type': 'router',
                'vendor': 'MikroTik',
            },
            'netgear': {
                'banners': ['netgear', 'httpd'],
                'http_headers': ['Server: NETGEAR'],
                'device_type': 'router',
                'vendor': 'Netgear',
            },
            'synology': {
                'banners': ['synology', 'diskstation'],
                'http_headers': ['Server: Synology'],
                'paths': ['/webman/index.cgi'],
                'device_type': 'nas',
                'vendor': 'Synology',
            },
            'qnap': {
                'banners': ['qnap'],
                'http_headers': ['Server: http server'],
                'paths': ['/cgi-bin/index.cgi'],
                'device_type': 'nas',
                'vendor': 'QNAP',
            },
        }

        # OS fingerprints
        self.os_signatures = {
            'linux': ['linux', 'gnu/linux', 'ubuntu', 'debian', 'centos', 'redhat'],
            'windows': ['windows', 'microsoft-iis', 'win32', 'winnt'],
            'freebsd': ['freebsd', 'bsd'],
            'vxworks': ['vxworks', 'wind river'],
            'embedded': ['embedded', 'busybox', 'uclibc'],
        }

    def fingerprint_device(
        self,
        ip: str,
        ports: Optional[List[int]] = None,
        timeout: float = 3.0
    ) -> DeviceFingerprint:
        """
        Fingerprint a device

        Args:
            ip: Target IP address
            ports: List of ports to scan (uses common_ports if None)
            timeout: Connection timeout

        Returns:
            Device fingerprint
        """
        logger.info(f"Fingerprinting device: {ip}")

        ports_to_scan = ports or self.common_ports

        # Get hostname
        hostname = self._resolve_hostname(ip)

        # Scan ports
        open_ports = self._scan_ports(ip, ports_to_scan, timeout)

        # Grab banners
        banners = {}
        services = {}
        http_headers = None
        ssl_info = None

        for port in open_ports:
            banner = self._grab_banner(ip, port, timeout)
            if banner:
                banners[port] = banner

            # Detect service
            service_info = self._detect_service(port, banner)
            services[port] = service_info

            # Get HTTP headers if HTTP service
            if port in [80, 8080, 8081, 8000, 8888, 9000] and not http_headers:
                http_headers = self._get_http_headers(ip, port, timeout)

            # Get SSL info if HTTPS
            if port in [443, 8443] and not ssl_info:
                ssl_info = self._get_ssl_info(ip, port, timeout)

        # Identify device
        device_type, vendor, product, version, confidence = self._identify_device(
            banners, http_headers, hostname, open_ports
        )

        # Identify OS
        os_name, os_version = self._identify_os(banners, http_headers)

        fingerprint = DeviceFingerprint(
            ip=ip,
            hostname=hostname,
            device_type=device_type,
            vendor=vendor,
            product=product,
            version=version,
            os=os_name,
            os_version=os_version,
            services=services,
            open_ports=open_ports,
            banners=banners,
            http_headers=http_headers,
            ssl_info=ssl_info,
            confidence=confidence,
        )

        self.fingerprints.append(fingerprint)
        logger.info(f"Fingerprinting completed: {device_type or 'unknown'} ({confidence:.0%} confidence)")

        return fingerprint

    def batch_fingerprint(
        self,
        ip_list: List[str],
        max_workers: int = 10
    ) -> List[DeviceFingerprint]:
        """
        Fingerprint multiple devices in parallel

        Args:
            ip_list: List of IPs to fingerprint
            max_workers: Maximum concurrent workers

        Returns:
            List of device fingerprints
        """
        logger.info(f"Batch fingerprinting {len(ip_list)} devices")

        fingerprints = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(self.fingerprint_device, ip): ip for ip in ip_list}

            for future in concurrent.futures.as_completed(futures):
                try:
                    fingerprint = future.result(timeout=30)
                    fingerprints.append(fingerprint)
                except Exception as e:
                    ip = futures[future]
                    logger.error(f"Error fingerprinting {ip}: {e}")

        logger.info(f"Batch fingerprinting completed: {len(fingerprints)} devices")
        return fingerprints

    def _resolve_hostname(self, ip: str) -> Optional[str]:
        """Resolve IP to hostname"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return None

    def _scan_ports(self, ip: str, ports: List[int], timeout: float) -> List[int]:
        """Scan for open ports"""
        open_ports = []

        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((ip, port))
                sock.close()

                if result == 0:
                    open_ports.append(port)
            except:
                continue

        return open_ports

    def _grab_banner(self, ip: str, port: int, timeout: float) -> Optional[str]:
        """Grab banner from service"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))

            # Send appropriate probe based on port
            if port in [80, 8080, 8081, 8000, 8888, 9000]:
                # HTTP probe
                probe = b'GET / HTTP/1.1\r\nHost: ' + ip.encode() + b'\r\nUser-Agent: Mozilla/5.0\r\n\r\n'
            elif port == 21:
                # FTP - just receive banner
                probe = None
            elif port == 22:
                # SSH - just receive banner
                probe = None
            elif port == 23:
                # Telnet - just receive banner
                probe = None
            else:
                # Generic probe
                probe = b'\r\n'

            if probe:
                sock.send(probe)

            banner = sock.recv(4096).decode('utf-8', errors='ignore')
            sock.close()

            return banner if banner else None

        except Exception as e:
            logger.debug(f"Error grabbing banner from {ip}:{port}: {e}")
            return None

    def _detect_service(self, port: int, banner: Optional[str]) -> Dict[str, Any]:
        """Detect service from port and banner"""
        service = {
            'name': 'unknown',
            'product': None,
            'version': None,
        }

        # Map common ports
        port_map = {
            21: 'ftp',
            22: 'ssh',
            23: 'telnet',
            80: 'http',
            443: 'https',
            554: 'rtsp',
            8080: 'http-proxy',
            8081: 'http-alt',
            8443: 'https-alt',
        }

        service['name'] = port_map.get(port, f'port-{port}')

        if banner:
            banner_lower = banner.lower()

            # Detect SSH
            if 'ssh' in banner_lower:
                service['name'] = 'ssh'
                # Extract version: SSH-2.0-OpenSSH_7.4
                ssh_match = re.search(r'ssh-[\d.]+-([\w\._-]+)', banner_lower)
                if ssh_match:
                    service['product'] = ssh_match.group(1)

            # Detect FTP
            elif 'ftp' in banner_lower:
                service['name'] = 'ftp'
                # Extract FTP server info
                ftp_match = re.search(r'([\w\s]+)\s+ftp.*?server', banner_lower)
                if ftp_match:
                    service['product'] = ftp_match.group(1).strip()

            # Detect HTTP server
            elif 'server:' in banner_lower:
                service['name'] = 'http'
                server_match = re.search(r'server:\s*([^\r\n]+)', banner_lower)
                if server_match:
                    service['product'] = server_match.group(1).strip()

        return service

    def _get_http_headers(self, ip: str, port: int, timeout: float) -> Optional[Dict]:
        """Get HTTP headers"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))

            request = b'HEAD / HTTP/1.1\r\nHost: ' + ip.encode() + b'\r\nUser-Agent: Mozilla/5.0\r\n\r\n'
            sock.send(request)

            response = sock.recv(4096).decode('utf-8', errors='ignore')
            sock.close()

            # Parse headers
            headers = {}
            lines = response.split('\r\n')

            for line in lines[1:]:  # Skip status line
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip()] = value.strip()

            return headers if headers else None

        except Exception as e:
            logger.debug(f"Error getting HTTP headers from {ip}:{port}: {e}")
            return None

    def _get_ssl_info(self, ip: str, port: int, timeout: float) -> Optional[Dict]:
        """Get SSL/TLS information"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((ip, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=ip) as ssock:
                    cert = ssock.getpeercert()

                    ssl_info = {
                        'version': ssock.version(),
                        'cipher': ssock.cipher(),
                        'certificate': {
                            'subject': dict(x[0] for x in cert.get('subject', [])),
                            'issuer': dict(x[0] for x in cert.get('issuer', [])),
                            'version': cert.get('version'),
                            'serial_number': cert.get('serialNumber'),
                            'not_before': cert.get('notBefore'),
                            'not_after': cert.get('notAfter'),
                        }
                    }

                    return ssl_info

        except Exception as e:
            logger.debug(f"Error getting SSL info from {ip}:{port}: {e}")
            return None

    def _identify_device(
        self,
        banners: Dict[int, str],
        http_headers: Optional[Dict],
        hostname: Optional[str],
        ports: List[int]
    ) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str], float]:
        """
        Identify device type, vendor, product, version

        Returns:
            (device_type, vendor, product, version, confidence)
        """
        # Combine all text for analysis
        text_parts = []
        text_parts.extend(banners.values())
        if http_headers:
            text_parts.extend(http_headers.values())
        if hostname:
            text_parts.append(hostname)

        text = ' '.join(text_parts).lower()

        # Check against signatures
        best_match = None
        best_confidence = 0.0

        for sig_name, signature in self.signatures.items():
            confidence = 0.0
            matches = 0
            total_checks = 0

            # Check banners
            if 'banners' in signature:
                total_checks += 1
                for banner_sig in signature['banners']:
                    if banner_sig.lower() in text:
                        matches += 1
                        confidence += 0.4
                        break

            # Check HTTP headers
            if 'http_headers' in signature and http_headers:
                total_checks += 1
                for header_sig in signature['http_headers']:
                    for header_value in http_headers.values():
                        if header_sig.lower() in header_value.lower():
                            matches += 1
                            confidence += 0.3
                            break

            # Check ports
            if 'ports' in signature:
                total_checks += 1
                for sig_port in signature['ports']:
                    if sig_port in ports:
                        matches += 1
                        confidence += 0.2
                        break

            # Normalize confidence
            if total_checks > 0:
                confidence = min(confidence, 1.0)

            if confidence > best_confidence:
                best_confidence = confidence
                best_match = signature

        if best_match:
            # Extract version if possible
            version = self._extract_version(text)

            return (
                best_match.get('device_type'),
                best_match.get('vendor'),
                None,  # product (would need more specific extraction)
                version,
                best_confidence
            )

        return None, None, None, None, 0.0

    def _identify_os(
        self,
        banners: Dict[int, str],
        http_headers: Optional[Dict]
    ) -> Tuple[Optional[str], Optional[str]]:
        """
        Identify operating system

        Returns:
            (os_name, os_version)
        """
        text_parts = list(banners.values())
        if http_headers:
            text_parts.extend(http_headers.values())

        text = ' '.join(text_parts).lower()

        # Check OS signatures
        for os_name, signatures in self.os_signatures.items():
            for sig in signatures:
                if sig in text:
                    # Try to extract version
                    version = self._extract_version(text)
                    return os_name, version

        return None, None

    def _extract_version(self, text: str) -> Optional[str]:
        """Extract version number from text"""
        # Common version patterns
        patterns = [
            r'v?(\d+\.\d+\.\d+\.\d+)',  # x.x.x.x
            r'v?(\d+\.\d+\.\d+)',        # x.x.x
            r'v?(\d+\.\d+)',              # x.x
        ]

        for pattern in patterns:
            match = re.search(pattern, text)
            if match:
                return match.group(1)

        return None

    def export_fingerprints(self, output_file: str = "device_fingerprints.json") -> Dict:
        """Export fingerprints to JSON"""

        export_data = {
            'generated_at': datetime.utcnow().isoformat(),
            'total_devices': len(self.fingerprints),
            'fingerprints': [asdict(f) for f in self.fingerprints],
        }

        try:
            with open(output_file, 'w') as f:
                json.dump(export_data, f, indent=2)
            logger.info(f"Fingerprints exported to {output_file}")
        except Exception as e:
            logger.error(f"Error exporting fingerprints: {e}")

        return export_data


def main():
    """Example usage"""
    print("Device Fingerprinter")
    print("=" * 50)

    # Initialize
    fingerprinter = DeviceFingerprinter()

    # Fingerprint single device
    print("\n[*] Fingerprinting device...")
    ip = "192.168.1.1"  # Example IP
    fingerprint = fingerprinter.fingerprint_device(ip)

    print(f"\n[+] Fingerprint Results:")
    print(f"  IP: {fingerprint.ip}")
    print(f"  Hostname: {fingerprint.hostname or 'Unknown'}")
    print(f"  Device Type: {fingerprint.device_type or 'Unknown'}")
    print(f"  Vendor: {fingerprint.vendor or 'Unknown'}")
    print(f"  OS: {fingerprint.os or 'Unknown'}")
    print(f"  Confidence: {fingerprint.confidence:.0%}")
    print(f"  Open Ports: {fingerprint.open_ports}")

    # Show services
    if fingerprint.services:
        print(f"\n  Services:")
        for port, service in fingerprint.services.items():
            print(f"    Port {port}: {service['name']}")
            if service['product']:
                print(f"      Product: {service['product']}")

    # Batch fingerprinting
    print("\n[*] Batch fingerprinting...")
    ip_list = [f"192.168.1.{i}" for i in range(1, 6)]
    fingerprints = fingerprinter.batch_fingerprint(ip_list, max_workers=3)
    print(f"[+] Fingerprinted {len(fingerprints)} devices")

    # Export results
    print("\n[*] Exporting fingerprints...")
    fingerprinter.export_fingerprints()
    print("[+] Export completed")


if __name__ == "__main__":
    main()
