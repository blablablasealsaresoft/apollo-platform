"""
Port Scanner Module - Red Team Edition
======================================

High-performance asynchronous port scanning with service detection.
Designed for red team reconnaissance operations.

Features:
- Fast async TCP connect scanning
- Service version detection via banner grabbing
- Configurable port ranges and presets
- Rate limiting and stealth options

Author: Apollo Red Team Toolkit
Version: 2.0.0
"""

import asyncio
import socket
import logging
import re
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class PortResult:
    """Container for port scan result"""
    host: str
    port: int
    state: str
    service: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None
    protocol: str = 'tcp'


class PortScanner:
    """
    Advanced asynchronous port scanner with service detection

    Features:
    - High-speed async TCP scanning
    - Service fingerprinting via banners
    - Configurable scan profiles
    - Rate limiting support
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
        8000: 'http-alt2', 10000: 'webmin', 2049: 'nfs', 111: 'rpc',
        135: 'msrpc', 139: 'netbios', 512: 'rexec', 513: 'rlogin', 514: 'rsh',
        993: 'imaps', 995: 'pop3s', 465: 'smtps', 587: 'submission'
    }

    # Service detection probes
    SERVICE_PROBES = {
        'http': b'GET / HTTP/1.0\r\nHost: {}\r\n\r\n',
        'https': b'',
        'ftp': b'',
        'ssh': b'',
        'smtp': b'EHLO scanner.local\r\n',
        'mysql': b'',
        'redis': b'INFO\r\n',
        'telnet': b'',
        'pop3': b'',
        'imap': b''
    }

    # Port scan presets
    PRESETS = {
        'quick': [21, 22, 23, 25, 80, 110, 143, 443, 445, 3389, 8080],
        'common': list(COMMON_PORTS.keys()),
        'web': [80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9000],
        'database': [1433, 1521, 3306, 5432, 6379, 9200, 27017, 11211],
        'full': list(range(1, 1025)),  # Top 1024 ports
    }

    def __init__(
        self,
        timeout: float = 3.0,
        max_concurrent: int = 100,
        service_detection: bool = True
    ):
        """
        Initialize port scanner

        Args:
            timeout: Connection timeout in seconds
            max_concurrent: Maximum concurrent connections
            service_detection: Enable service detection via banner grabbing
        """
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.service_detection = service_detection
        self.semaphore = asyncio.Semaphore(max_concurrent)

    async def scan(
        self,
        target: str,
        ports: Optional[List[int]] = None,
        preset: Optional[str] = None
    ) -> List[PortResult]:
        """
        Scan ports on target

        Args:
            target: Target IP or hostname
            ports: List of ports to scan
            preset: Use preset port list (quick, common, web, database, full)

        Returns:
            List of PortResult objects for open ports
        """
        # Determine ports to scan
        if ports is None:
            if preset and preset in self.PRESETS:
                ports = self.PRESETS[preset]
            else:
                ports = list(self.COMMON_PORTS.keys())

        logger.info(f"Scanning {len(ports)} ports on {target}")
        start_time = datetime.now()

        # Resolve hostname to IP
        try:
            ip = socket.gethostbyname(target)
        except socket.gaierror:
            logger.error(f"Could not resolve hostname: {target}")
            return []

        # Scan all ports concurrently
        tasks = [self._scan_port(ip, port) for port in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Filter open ports
        open_ports = []
        for result in results:
            if isinstance(result, PortResult) and result.state == 'open':
                open_ports.append(result)

        # Service detection
        if self.service_detection and open_ports:
            logger.info(f"Performing service detection on {len(open_ports)} open ports")
            await self._detect_services(open_ports, target)

        duration = (datetime.now() - start_time).total_seconds()
        logger.info(f"Scan completed in {duration:.2f}s. Found {len(open_ports)} open ports")

        return open_ports

    async def scan_hosts(
        self,
        targets: List[str],
        ports: Optional[List[int]] = None,
        preset: Optional[str] = None
    ) -> Dict[str, List[PortResult]]:
        """
        Scan multiple hosts

        Args:
            targets: List of target hosts
            ports: List of ports to scan
            preset: Use preset port list

        Returns:
            Dictionary mapping hosts to their scan results
        """
        logger.info(f"Scanning {len(targets)} hosts")

        results = {}
        for target in targets:
            try:
                target_results = await self.scan(target, ports, preset)
                results[target] = target_results
            except Exception as e:
                logger.error(f"Failed to scan {target}: {e}")
                results[target] = []

        return results

    async def _scan_port(self, host: str, port: int) -> Optional[PortResult]:
        """
        Scan a single port

        Args:
            host: Target host
            port: Port number

        Returns:
            PortResult if port is open, None otherwise
        """
        async with self.semaphore:
            try:
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
                logger.debug(f"Error scanning {host}:{port} - {e}")
                return None

    async def _detect_services(self, port_results: List[PortResult], hostname: str):
        """
        Detect services via banner grabbing

        Args:
            port_results: List of PortResult objects
            hostname: Original hostname for HTTP Host header
        """
        tasks = [self._grab_banner(pr, hostname) for pr in port_results]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _grab_banner(self, port_result: PortResult, hostname: str):
        """
        Grab service banner and detect version

        Args:
            port_result: PortResult to update
            hostname: Original hostname for HTTP Host header
        """
        try:
            async with self.semaphore:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(port_result.host, port_result.port),
                    timeout=self.timeout
                )

                # Send probe based on service type
                service_name = port_result.service
                if service_name in self.SERVICE_PROBES:
                    probe = self.SERVICE_PROBES[service_name]
                    if b'{}' in probe:
                        probe = probe.replace(b'{}', hostname.encode())
                    if probe:
                        writer.write(probe)
                        await writer.drain()

                # Read banner
                try:
                    banner = await asyncio.wait_for(reader.read(1024), timeout=3)

                    if banner:
                        banner_str = banner.decode('utf-8', errors='ignore').strip()
                        port_result.banner = banner_str[:500]  # Limit banner length

                        # Parse banner for service/version
                        service_info = self._parse_banner(banner_str, port_result.port)
                        if service_info:
                            port_result.service = service_info.get('service', port_result.service)
                            port_result.version = service_info.get('version')

                except asyncio.TimeoutError:
                    pass  # No banner received

                writer.close()
                await writer.wait_closed()

        except Exception as e:
            logger.debug(f"Banner grab failed for {port_result.host}:{port_result.port} - {e}")

    def _parse_banner(self, banner: str, port: int) -> Optional[Dict]:
        """
        Parse service banner to extract service and version

        Args:
            banner: Banner string
            port: Port number for context

        Returns:
            Dictionary with service info or None
        """
        info = {}

        # HTTP detection
        if 'HTTP' in banner or port in [80, 443, 8080, 8443]:
            http_match = re.search(r'Server:\s*([^\r\n]+)', banner, re.IGNORECASE)
            if http_match:
                server = http_match.group(1)
                info['service'] = 'http'

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
                    version_match = re.search(r'IIS/([\d.]+)', server, re.IGNORECASE)
                    if version_match:
                        info['version'] = version_match.group(1)
                else:
                    info['version'] = server

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

        # FTP detection
        elif 'FTP' in banner or port == 21:
            info['service'] = 'ftp'
            # Extract server info from banner
            if '220' in banner:
                version_match = re.search(r'220[- ](.+)', banner)
                if version_match:
                    info['version'] = version_match.group(1)[:100]

        # SMTP detection
        elif 'SMTP' in banner or port in [25, 587]:
            info['service'] = 'smtp'
            if '220' in banner:
                version_match = re.search(r'220[- ](.+)', banner)
                if version_match:
                    info['version'] = version_match.group(1)[:100]

        # MySQL detection
        elif port == 3306:
            info['service'] = 'mysql'
            if 'mysql' in banner.lower():
                version_match = re.search(r'([\d.]+)', banner)
                if version_match:
                    info['version'] = version_match.group(1)

        # Redis detection
        elif 'redis_version' in banner.lower() or port == 6379:
            info['service'] = 'redis'
            version_match = re.search(r'redis_version:([\d.]+)', banner, re.IGNORECASE)
            if version_match:
                info['version'] = version_match.group(1)

        # MongoDB detection
        elif port == 27017:
            info['service'] = 'mongodb'

        # PostgreSQL detection
        elif port == 5432:
            info['service'] = 'postgresql'

        # Elasticsearch detection
        elif port == 9200:
            info['service'] = 'elasticsearch'
            if '"version"' in banner:
                version_match = re.search(r'"number"\s*:\s*"([\d.]+)"', banner)
                if version_match:
                    info['version'] = version_match.group(1)

        return info if info else None

    async def scan_range(
        self,
        target: str,
        start_port: int,
        end_port: int
    ) -> List[PortResult]:
        """
        Scan a range of ports

        Args:
            target: Target host
            start_port: Starting port
            end_port: Ending port

        Returns:
            List of open ports
        """
        ports = list(range(start_port, end_port + 1))
        return await self.scan(target, ports)

    def to_dict(self, result: PortResult) -> Dict:
        """Convert PortResult to dictionary"""
        return {
            'host': result.host,
            'port': result.port,
            'state': result.state,
            'service': result.service,
            'version': result.version,
            'banner': result.banner,
            'protocol': result.protocol
        }


# Convenience function
async def quick_port_scan(target: str) -> List[Dict]:
    """Quick port scan using common ports"""
    scanner = PortScanner()
    results = await scanner.scan(target, preset='quick')
    return [scanner.to_dict(r) for r in results]


if __name__ == '__main__':
    import sys

    async def main():
        if len(sys.argv) < 2:
            print("Usage: python port_scanner.py <target> [preset]")
            print("Presets: quick, common, web, database, full")
            return

        target = sys.argv[1]
        preset = sys.argv[2] if len(sys.argv) > 2 else 'common'

        scanner = PortScanner()
        results = await scanner.scan(target, preset=preset)

        print(f"\nFound {len(results)} open ports:")
        for result in results:
            port_info = f"{result.port}/tcp"
            service_info = f"{result.service}"
            if result.version:
                service_info += f" ({result.version})"
            print(f"  {port_info:15} {service_info}")

    asyncio.run(main())
