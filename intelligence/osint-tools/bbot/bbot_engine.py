"""
BBOT Engine - Comprehensive OSINT Reconnaissance
Subdomain enumeration, port scanning, tech detection, vulnerability scanning
"""

import asyncio
import logging
import subprocess
import json
from typing import Dict, List, Optional, Set, Any
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class BBOTTarget:
    """Target for BBOT reconnaissance"""
    domain: str
    ips: List[str] = field(default_factory=list)
    subdomains: Set[str] = field(default_factory=set)
    ports: Dict[str, List[int]] = field(default_factory=dict)
    technologies: Dict[str, List[str]] = field(default_factory=dict)
    vulnerabilities: List[Dict] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BBOTScanResult:
    """Result from BBOT scan"""
    target: str
    scan_type: str
    start_time: datetime
    end_time: datetime
    duration_seconds: float
    subdomains_found: int
    ips_found: int
    ports_found: int
    technologies_found: int
    vulnerabilities_found: int
    results: BBOTTarget


class BBOTEngine:
    """
    BBOT OSINT Engine
    Comprehensive reconnaissance and intelligence gathering
    """

    def __init__(
        self,
        output_dir: Optional[str] = None,
        max_threads: int = 20,
        timeout: int = 3600
    ):
        self.output_dir = Path(output_dir or "./bbot_results")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.max_threads = max_threads
        self.timeout = timeout

    async def full_scan(
        self,
        target: str,
        scan_types: Optional[List[str]] = None
    ) -> BBOTScanResult:
        """
        Perform full BBOT scan on target

        Args:
            target: Domain or IP to scan
            scan_types: List of scan types (subdomain, port, tech, vuln)

        Returns:
            BBOTScanResult with all findings
        """
        if scan_types is None:
            scan_types = ['subdomain', 'port', 'tech', 'vuln']

        start_time = datetime.now()
        logger.info(f"Starting BBOT full scan on {target}")

        bbot_target = BBOTTarget(domain=target)

        # Run scans based on type
        tasks = []
        if 'subdomain' in scan_types:
            tasks.append(self._subdomain_enumeration(bbot_target))
        if 'port' in scan_types:
            tasks.append(self._port_scanning(bbot_target))
        if 'tech' in scan_types:
            tasks.append(self._technology_detection(bbot_target))
        if 'vuln' in scan_types:
            tasks.append(self._vulnerability_scanning(bbot_target))

        # Execute all scans concurrently
        await asyncio.gather(*tasks)

        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()

        result = BBOTScanResult(
            target=target,
            scan_type=','.join(scan_types),
            start_time=start_time,
            end_time=end_time,
            duration_seconds=duration,
            subdomains_found=len(bbot_target.subdomains),
            ips_found=len(bbot_target.ips),
            ports_found=sum(len(ports) for ports in bbot_target.ports.values()),
            technologies_found=sum(
                len(techs) for techs in bbot_target.technologies.values()
            ),
            vulnerabilities_found=len(bbot_target.vulnerabilities),
            results=bbot_target
        )

        logger.info(
            f"BBOT scan completed in {duration:.2f}s: "
            f"{result.subdomains_found} subdomains, "
            f"{result.ips_found} IPs, "
            f"{result.ports_found} ports, "
            f"{result.technologies_found} technologies, "
            f"{result.vulnerabilities_found} vulnerabilities"
        )

        return result

    async def _subdomain_enumeration(self, target: BBOTTarget):
        """Enumerate subdomains using multiple techniques"""
        logger.info(f"Enumerating subdomains for {target.domain}")

        # Use multiple subdomain enumeration techniques
        techniques = [
            self._enum_subdomains_certspotter(target),
            self._enum_subdomains_crtsh(target),
            self._enum_subdomains_virustotal(target),
            self._enum_subdomains_hackertarget(target),
            self._enum_subdomains_dnsdumpster(target),
            self._enum_subdomains_threatcrowd(target),
        ]

        await asyncio.gather(*techniques, return_exceptions=True)

    async def _enum_subdomains_certspotter(self, target: BBOTTarget):
        """Enumerate subdomains using CertSpotter"""
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                url = f"https://api.certspotter.com/v1/issuances?domain={target.domain}&include_subdomains=true&expand=dns_names"
                async with session.get(url, timeout=30) as response:
                    if response.status == 200:
                        data = await response.json()
                        for cert in data:
                            for name in cert.get('dns_names', []):
                                if name.endswith(target.domain):
                                    target.subdomains.add(name)
                        logger.info(
                            f"CertSpotter: Found {len(target.subdomains)} subdomains"
                        )
        except Exception as e:
            logger.error(f"CertSpotter error: {e}")

    async def _enum_subdomains_crtsh(self, target: BBOTTarget):
        """Enumerate subdomains using crt.sh"""
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                url = f"https://crt.sh/?q=%.{target.domain}&output=json"
                async with session.get(url, timeout=30) as response:
                    if response.status == 200:
                        data = await response.json()
                        for cert in data:
                            name = cert.get('name_value', '')
                            if name and name.endswith(target.domain):
                                # Handle wildcard and multiple names
                                for subdomain in name.split('\n'):
                                    subdomain = subdomain.strip().replace('*.', '')
                                    if subdomain and subdomain.endswith(target.domain):
                                        target.subdomains.add(subdomain)
                        logger.info(
                            f"crt.sh: Total {len(target.subdomains)} subdomains"
                        )
        except Exception as e:
            logger.error(f"crt.sh error: {e}")

    async def _enum_subdomains_virustotal(self, target: BBOTTarget):
        """Enumerate subdomains using VirusTotal (requires API key)"""
        # Placeholder - requires API key
        logger.info("VirusTotal: API key required")

    async def _enum_subdomains_hackertarget(self, target: BBOTTarget):
        """Enumerate subdomains using HackerTarget"""
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                url = f"https://api.hackertarget.com/hostsearch/?q={target.domain}"
                async with session.get(url, timeout=30) as response:
                    if response.status == 200:
                        text = await response.text()
                        for line in text.split('\n'):
                            if ',' in line:
                                subdomain = line.split(',')[0].strip()
                                if subdomain and subdomain.endswith(target.domain):
                                    target.subdomains.add(subdomain)
                        logger.info(
                            f"HackerTarget: Total {len(target.subdomains)} subdomains"
                        )
        except Exception as e:
            logger.error(f"HackerTarget error: {e}")

    async def _enum_subdomains_dnsdumpster(self, target: BBOTTarget):
        """Enumerate subdomains using DNSDumpster"""
        # Requires web scraping - placeholder
        logger.info("DNSDumpster: Requires web scraping")

    async def _enum_subdomains_threatcrowd(self, target: BBOTTarget):
        """Enumerate subdomains using ThreatCrowd"""
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={target.domain}"
                async with session.get(url, timeout=30) as response:
                    if response.status == 200:
                        data = await response.json()
                        for subdomain in data.get('subdomains', []):
                            if subdomain and subdomain.endswith(target.domain):
                                target.subdomains.add(subdomain)
                        logger.info(
                            f"ThreatCrowd: Total {len(target.subdomains)} subdomains"
                        )
        except Exception as e:
            logger.error(f"ThreatCrowd error: {e}")

    async def _port_scanning(self, target: BBOTTarget):
        """Scan ports on discovered IPs"""
        logger.info(f"Scanning ports for {target.domain}")

        # First resolve IPs for domain and subdomains
        await self._resolve_ips(target)

        # Scan common ports
        common_ports = [
            21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 465, 587,
            993, 995, 1433, 3306, 3389, 5432, 5900, 6379, 8000,
            8080, 8443, 8888, 9090, 27017, 27018
        ]

        for ip in target.ips[:50]:  # Limit to first 50 IPs
            open_ports = await self._scan_ports_async(ip, common_ports)
            if open_ports:
                target.ports[ip] = open_ports

    async def _resolve_ips(self, target: BBOTTarget):
        """Resolve IPs for domain and subdomains"""
        import socket

        # Resolve main domain
        try:
            ip = socket.gethostbyname(target.domain)
            target.ips.append(ip)
        except:
            pass

        # Resolve subdomains (limit to first 100)
        for subdomain in list(target.subdomains)[:100]:
            try:
                ip = socket.gethostbyname(subdomain)
                if ip not in target.ips:
                    target.ips.append(ip)
            except:
                pass

    async def _scan_ports_async(
        self,
        ip: str,
        ports: List[int]
    ) -> List[int]:
        """Scan ports asynchronously"""
        open_ports = []

        async def check_port(port: int):
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port),
                    timeout=2
                )
                writer.close()
                await writer.wait_closed()
                return port
            except:
                return None

        results = await asyncio.gather(
            *[check_port(p) for p in ports],
            return_exceptions=True
        )

        open_ports = [p for p in results if p is not None]
        return open_ports

    async def _technology_detection(self, target: BBOTTarget):
        """Detect technologies used on websites"""
        logger.info(f"Detecting technologies for {target.domain}")

        # Check main domain and first 20 subdomains
        domains_to_check = [target.domain] + list(target.subdomains)[:20]

        for domain in domains_to_check:
            techs = await self._detect_tech_single(domain)
            if techs:
                target.technologies[domain] = techs

    async def _detect_tech_single(self, domain: str) -> List[str]:
        """Detect technologies for single domain"""
        technologies = []

        try:
            import aiohttp

            async with aiohttp.ClientSession() as session:
                # Try both HTTP and HTTPS
                for protocol in ['https', 'http']:
                    try:
                        url = f"{protocol}://{domain}"
                        async with session.get(
                            url,
                            timeout=10,
                            allow_redirects=True
                        ) as response:
                            headers = response.headers
                            html = await response.text()

                            # Detect from headers
                            if 'Server' in headers:
                                technologies.append(f"Server: {headers['Server']}")
                            if 'X-Powered-By' in headers:
                                technologies.append(
                                    f"Powered-By: {headers['X-Powered-By']}"
                                )

                            # Detect from HTML
                            if 'wordpress' in html.lower():
                                technologies.append('WordPress')
                            if 'drupal' in html.lower():
                                technologies.append('Drupal')
                            if 'joomla' in html.lower():
                                technologies.append('Joomla')
                            if 'react' in html.lower():
                                technologies.append('React')
                            if 'angular' in html.lower():
                                technologies.append('Angular')
                            if 'vue.js' in html.lower():
                                technologies.append('Vue.js')

                            break  # Success, no need to try other protocol
                    except:
                        continue

        except Exception as e:
            logger.debug(f"Tech detection error for {domain}: {e}")

        return technologies

    async def _vulnerability_scanning(self, target: BBOTTarget):
        """Basic vulnerability scanning"""
        logger.info(f"Scanning vulnerabilities for {target.domain}")

        # Check for common vulnerabilities
        domains_to_check = [target.domain] + list(target.subdomains)[:20]

        for domain in domains_to_check:
            vulns = await self._check_vulns_single(domain)
            target.vulnerabilities.extend(vulns)

    async def _check_vulns_single(self, domain: str) -> List[Dict]:
        """Check vulnerabilities for single domain"""
        vulnerabilities = []

        try:
            import aiohttp
            import ssl

            async with aiohttp.ClientSession() as session:
                # Check for HTTPS
                try:
                    ssl_context = ssl.create_default_context()
                    url = f"https://{domain}"
                    async with session.get(
                        url,
                        timeout=10,
                        ssl=ssl_context
                    ) as response:
                        # Check security headers
                        headers = response.headers

                        if 'Strict-Transport-Security' not in headers:
                            vulnerabilities.append({
                                'domain': domain,
                                'type': 'missing_hsts',
                                'severity': 'medium',
                                'description': 'Missing HSTS header'
                            })

                        if 'X-Frame-Options' not in headers:
                            vulnerabilities.append({
                                'domain': domain,
                                'type': 'missing_xfo',
                                'severity': 'medium',
                                'description': 'Missing X-Frame-Options header'
                            })

                        if 'X-Content-Type-Options' not in headers:
                            vulnerabilities.append({
                                'domain': domain,
                                'type': 'missing_xcto',
                                'severity': 'low',
                                'description': 'Missing X-Content-Type-Options header'
                            })

                except ssl.SSLError as e:
                    vulnerabilities.append({
                        'domain': domain,
                        'type': 'ssl_error',
                        'severity': 'high',
                        'description': f'SSL/TLS error: {str(e)}'
                    })
                except:
                    pass

        except Exception as e:
            logger.debug(f"Vuln check error for {domain}: {e}")

        return vulnerabilities

    def export_results(
        self,
        result: BBOTScanResult,
        format: str = 'json'
    ) -> str:
        """Export scan results"""
        if format == 'json':
            return self._export_json(result)
        elif format == 'txt':
            return self._export_txt(result)
        else:
            raise ValueError(f"Unsupported format: {format}")

    def _export_json(self, result: BBOTScanResult) -> str:
        """Export to JSON"""
        import json
        from dataclasses import asdict

        data = {
            'scan_info': {
                'target': result.target,
                'scan_type': result.scan_type,
                'duration_seconds': result.duration_seconds,
                'start_time': result.start_time.isoformat(),
                'end_time': result.end_time.isoformat()
            },
            'summary': {
                'subdomains_found': result.subdomains_found,
                'ips_found': result.ips_found,
                'ports_found': result.ports_found,
                'technologies_found': result.technologies_found,
                'vulnerabilities_found': result.vulnerabilities_found
            },
            'results': {
                'domain': result.results.domain,
                'subdomains': list(result.results.subdomains),
                'ips': result.results.ips,
                'ports': result.results.ports,
                'technologies': result.results.technologies,
                'vulnerabilities': result.results.vulnerabilities
            }
        }

        return json.dumps(data, indent=2, default=str)

    def _export_txt(self, result: BBOTScanResult) -> str:
        """Export to text"""
        lines = [
            f"BBOT Scan Results for {result.target}",
            f"Duration: {result.duration_seconds:.2f}s",
            "",
            f"Subdomains Found: {result.subdomains_found}",
            *[f"  - {s}" for s in sorted(result.results.subdomains)],
            "",
            f"IPs Found: {result.ips_found}",
            *[f"  - {ip}" for ip in result.results.ips],
            "",
            f"Technologies Detected:",
            *[
                f"  {domain}: {', '.join(techs)}"
                for domain, techs in result.results.technologies.items()
            ],
            "",
            f"Vulnerabilities Found: {result.vulnerabilities_found}",
            *[
                f"  - {v['domain']}: {v['type']} ({v['severity']})"
                for v in result.results.vulnerabilities
            ]
        ]

        return "\n".join(lines)
