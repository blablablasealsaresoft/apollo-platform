"""
Advanced Asynchronous Port Scanner
High-performance port scanning with service detection and version fingerprinting
"""

import asyncio
import socket
import struct
import logging
from typing import List, Dict, Set, Optional, Tuple
from dataclasses import dataclass
import re
from datetime import datetime
import random


@dataclass
class PortResult:
    """Container for port scan results"""
    host: str
    port: int
    state: str
    service: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None
    protocol: str = 'tcp'
    os_hint: Optional[str] = None


class PortScanner:
    """
    Advanced asynchronous port scanner with service detection
    """

    # Common ports by service
    COMMON_PORTS = {
        21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
        80: 'http', 110: 'pop3', 143: 'imap', 443: 'https', 445: 'smb',
        3306: 'mysql', 3389: 'rdp', 5432: 'postgresql', 5900: 'vnc',
        6379: 'redis', 8080: 'http-proxy', 8443: 'https-alt', 27017: 'mongodb',
        1433: 'mssql', 5984: 'couchdb', 9200: 'elasticsearch', 11211: 'memcached',
        50000: 'db2', 1521: 'oracle', 7001: 'weblogic', 9000: 'fastcgi',
        8888: 'http-alt', 9090: 'openfire', 161: 'snmp', 162: 'snmp-trap',
        389: 'ldap', 636: 'ldaps', 873: 'rsync', 3690: 'svn', 5000: 'upnp',
        8000: 'http-alt2', 10000: 'webmin'
    }

    # Service fingerprinting probes
    SERVICE_PROBES = {
        'http': b'GET / HTTP/1.0\r\nHost: {}\r\n\r\n',
        'ftp': b'',
        'ssh': b'',
        'smtp': b'EHLO scanner.local\r\n',
        'mysql': b'',
        'redis': b'INFO\r\n',
        'telnet': b'',
        'pop3': b'',
        'imap': b''
    }

    # Top 1000 ports (Nmap default)
    TOP_1000_PORTS = [
        1, 3, 4, 6, 7, 9, 13, 17, 19, 20, 21, 22, 23, 24, 25, 26, 30, 32, 33,
        37, 42, 43, 49, 53, 70, 79, 80, 81, 82, 83, 84, 85, 88, 89, 90, 99,
        100, 106, 109, 110, 111, 113, 119, 125, 135, 139, 143, 144, 146, 161,
        163, 179, 199, 211, 212, 222, 254, 255, 256, 259, 264, 280, 301, 306,
        311, 340, 366, 389, 406, 407, 416, 417, 425, 427, 443, 444, 445, 458,
        464, 465, 481, 497, 500, 512, 513, 514, 515, 524, 541, 543, 544, 545,
        548, 554, 555, 563, 587, 593, 616, 617, 625, 631, 636, 646, 648, 666,
        667, 668, 683, 687, 691, 700, 705, 711, 714, 720, 722, 726, 749, 765,
        777, 783, 787, 800, 801, 808, 843, 873, 880, 888, 898, 900, 901, 902,
        903, 911, 912, 981, 987, 990, 992, 993, 995, 999, 1000, 1001, 1002,
        1007, 1009, 1010, 1011, 1021, 1022, 1023, 1024, 1025, 1026, 1027, 1028,
        1029, 1030, 1031, 1032, 1033, 1034, 1035, 1036, 1037, 1038, 1039, 1040,
        8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090,
        8443, 8888, 9000, 9001, 9090, 9100, 9200, 9999, 10000
    ]

    def __init__(self, config: Dict):
        """Initialize port scanner"""
        self.config = config.get('port', {})
        self.timeout = config.get('timeout', 5)
        self.logger = logging.getLogger('PortScanner')

        # Concurrent scan limit
        self.max_concurrent = config.get('max_threads', 100)
        self.semaphore = asyncio.Semaphore(self.max_concurrent)

    async def scan_targets(
        self,
        targets: List[str],
        deep_scan: bool = False
    ) -> List[Dict]:
        """
        Scan multiple targets for open ports

        Args:
            targets: List of target hosts/IPs
            deep_scan: Enable comprehensive scanning

        Returns:
            List of open ports with service information
        """
        self.logger.info(f"Starting port scan on {len(targets)} targets")

        all_results = []

        for target in targets:
            try:
                results = await self.scan_host(target, deep_scan)
                all_results.extend(results)
            except Exception as e:
                self.logger.error(f"Failed to scan {target}: {e}")

        self.logger.info(f"Scan complete. Found {len(all_results)} open ports")
        return all_results

    async def scan_host(
        self,
        host: str,
        deep_scan: bool = False
    ) -> List[Dict]:
        """
        Scan a single host for open ports

        Args:
            host: Target host/IP
            deep_scan: Enable comprehensive scanning

        Returns:
            List of open ports with service information
        """
        self.logger.info(f"Scanning host: {host}")

        # Determine port range
        if deep_scan and self.config.get('full_scan', False):
            ports = range(1, 65536)  # Full port range
        elif self.config.get('common_ports', True):
            ports = list(self.COMMON_PORTS.keys())
        else:
            top_n = self.config.get('top_ports', 1000)
            ports = self.TOP_1000_PORTS[:top_n]

        # Scan ports
        tasks = [self._scan_port(host, port) for port in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Filter open ports
        open_ports = []
        for result in results:
            if isinstance(result, PortResult) and result.state == 'open':
                open_ports.append(result)

        # Service detection if enabled
        if self.config.get('service_detection', True) and open_ports:
            self.logger.info(f"Performing service detection on {len(open_ports)} open ports")
            await self._detect_services(open_ports)

        # Convert to dict format
        return [self._port_result_to_dict(pr) for pr in open_ports]

    async def _scan_port(self, host: str, port: int) -> Optional[PortResult]:
        """
        Scan a single port on a host

        Args:
            host: Target host
            port: Port number

        Returns:
            PortResult if port is open, None otherwise
        """
        async with self.semaphore:
            try:
                # Create socket connection
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=self.timeout
                )

                # Port is open
                writer.close()
                await writer.wait_closed()

                service = self.COMMON_PORTS.get(port, f'unknown-{port}')

                return PortResult(
                    host=host,
                    port=port,
                    state='open',
                    service=service,
                    protocol='tcp'
                )

            except asyncio.TimeoutError:
                return None  # Port filtered or no response
            except (ConnectionRefusedError, OSError):
                return None  # Port closed
            except Exception as e:
                self.logger.debug(f"Error scanning {host}:{port} - {e}")
                return None

    async def _detect_services(self, port_results: List[PortResult]):
        """
        Detect services and grab banners from open ports

        Args:
            port_results: List of PortResult objects for open ports
        """
        tasks = [self._grab_banner(pr) for pr in port_results]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _grab_banner(self, port_result: PortResult):
        """
        Grab banner from open port and detect service/version

        Args:
            port_result: PortResult object to update with banner info
        """
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(port_result.host, port_result.port),
                timeout=self.timeout
            )

            # Send probe if available for this service
            service_name = port_result.service
            if service_name in self.SERVICE_PROBES:
                probe = self.SERVICE_PROBES[service_name]
                if b'{}' in probe:
                    probe = probe.replace(b'{}', port_result.host.encode())
                writer.write(probe)
                await writer.drain()

            # Read banner
            try:
                banner = await asyncio.wait_for(
                    reader.read(1024),
                    timeout=3
                )

                if banner:
                    banner_str = banner.decode('utf-8', errors='ignore').strip()
                    port_result.banner = banner_str

                    # Parse banner for service/version
                    service_info = self._parse_banner(banner_str, port_result.port)
                    if service_info:
                        port_result.service = service_info.get('service', port_result.service)
                        port_result.version = service_info.get('version')
                        port_result.os_hint = service_info.get('os_hint')

            except asyncio.TimeoutError:
                pass  # No banner received

            writer.close()
            await writer.wait_closed()

        except Exception as e:
            self.logger.debug(f"Banner grab failed for {port_result.host}:{port_result.port} - {e}")

    def _parse_banner(self, banner: str, port: int) -> Optional[Dict]:
        """
        Parse service banner to extract service name and version

        Args:
            banner: Banner string
            port: Port number (for context)

        Returns:
            Dictionary with service info
        """
        info = {}

        # HTTP server detection
        if 'HTTP' in banner or port in [80, 443, 8080, 8443]:
            http_match = re.search(r'Server:\s*([^\r\n]+)', banner, re.IGNORECASE)
            if http_match:
                server = http_match.group(1)
                info['service'] = 'http'
                info['version'] = server

                # Detect specific servers
                if 'nginx' in server.lower():
                    info['service'] = 'nginx'
                    version_match = re.search(r'nginx/([\d.]+)', server, re.IGNORECASE)
                    if version_match:
                        info['version'] = version_match.group(1)
                elif 'apache' in server.lower():
                    info['service'] = 'apache'
                    version_match = re.search(r'Apache/([\d.]+)', server, re.IGNORECASE)
                    if version_match:
                        info['version'] = version_match.group(1)
                elif 'iis' in server.lower():
                    info['service'] = 'iis'
                    info['os_hint'] = 'Windows'

        # SSH detection
        elif 'SSH' in banner or port == 22:
            ssh_match = re.search(r'SSH-([\d.]+)-([^\s\r\n]+)', banner)
            if ssh_match:
                info['service'] = 'ssh'
                info['version'] = ssh_match.group(2)

                if 'OpenSSH' in banner:
                    version_match = re.search(r'OpenSSH_([\d.p]+)', banner)
                    if version_match:
                        info['version'] = f"OpenSSH {version_match.group(1)}"

                # OS detection from SSH banner
                if 'Ubuntu' in banner:
                    info['os_hint'] = 'Ubuntu Linux'
                elif 'Debian' in banner:
                    info['os_hint'] = 'Debian Linux'
                elif 'raspbian' in banner.lower():
                    info['os_hint'] = 'Raspbian'

        # FTP detection
        elif 'FTP' in banner or port == 21:
            info['service'] = 'ftp'
            version_match = re.search(r'(\w+)\s+([\d.]+)', banner)
            if version_match:
                info['version'] = f"{version_match.group(1)} {version_match.group(2)}"

        # SMTP detection
        elif 'SMTP' in banner or port in [25, 587]:
            info['service'] = 'smtp'
            version_match = re.search(r'(\w+)\s+SMTP', banner)
            if version_match:
                info['version'] = version_match.group(1)

        # MySQL detection
        elif port == 3306:
            info['service'] = 'mysql'
            if 'mysql' in banner.lower():
                version_match = re.search(r'([\d.]+)', banner)
                if version_match:
                    info['version'] = version_match.group(1)

        # PostgreSQL detection
        elif port == 5432:
            info['service'] = 'postgresql'

        # Redis detection
        elif 'redis_version' in banner.lower() or port == 6379:
            info['service'] = 'redis'
            version_match = re.search(r'redis_version:([\d.]+)', banner, re.IGNORECASE)
            if version_match:
                info['version'] = version_match.group(1)

        # MongoDB detection
        elif port == 27017:
            info['service'] = 'mongodb'

        # Elasticsearch detection
        elif port == 9200:
            info['service'] = 'elasticsearch'

        return info if info else None

    def _port_result_to_dict(self, port_result: PortResult) -> Dict:
        """Convert PortResult to dictionary"""
        return {
            'host': port_result.host,
            'port': port_result.port,
            'state': port_result.state,
            'service': port_result.service,
            'version': port_result.version,
            'banner': port_result.banner,
            'protocol': port_result.protocol,
            'os_hint': port_result.os_hint
        }

    async def scan_port_range(
        self,
        host: str,
        start_port: int,
        end_port: int
    ) -> List[Dict]:
        """
        Scan a range of ports on a host

        Args:
            host: Target host
            start_port: Starting port number
            end_port: Ending port number

        Returns:
            List of open ports
        """
        ports = range(start_port, end_port + 1)
        tasks = [self._scan_port(host, port) for port in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        open_ports = [
            self._port_result_to_dict(r)
            for r in results
            if isinstance(r, PortResult) and r.state == 'open'
        ]

        return open_ports

    async def scan_specific_ports(
        self,
        host: str,
        ports: List[int]
    ) -> List[Dict]:
        """
        Scan specific ports on a host

        Args:
            host: Target host
            ports: List of port numbers to scan

        Returns:
            List of open ports
        """
        tasks = [self._scan_port(host, port) for port in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        open_ports = [
            self._port_result_to_dict(r)
            for r in results
            if isinstance(r, PortResult) and r.state == 'open'
        ]

        if self.config.get('service_detection', True) and open_ports:
            # Convert back to PortResult for service detection
            port_results = [
                PortResult(**{k: v for k, v in p.items() if k in ['host', 'port', 'state', 'service', 'protocol']})
                for p in open_ports
            ]
            await self._detect_services(port_results)
            open_ports = [self._port_result_to_dict(pr) for pr in port_results]

        return open_ports


async def main():
    """Test port scanner"""
    config = {
        'port': {
            'common_ports': True,
            'service_detection': True
        },
        'timeout': 5,
        'max_threads': 100
    }

    scanner = PortScanner(config)
    results = await scanner.scan_host('scanme.nmap.org', deep_scan=False)

    print(f"\nFound {len(results)} open ports:")
    for result in results:
        port_info = f"{result['port']}/tcp"
        service_info = f"{result['service']}"
        if result.get('version'):
            service_info += f" ({result['version']})"
        print(f"  {port_info:15} {service_info}")


if __name__ == '__main__':
    asyncio.run(main())
