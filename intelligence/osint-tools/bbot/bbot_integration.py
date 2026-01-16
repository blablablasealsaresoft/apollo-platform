"""
BBOT Integration Module - Native BBOT Library Support
======================================================

Comprehensive integration with the BBOT (Bighuge BLS OSINT Tool) library
for advanced reconnaissance and subdomain enumeration.

Features:
- Native BBOT scanner integration with presets
- Subdomain enumeration with multiple sources
- Technology detection (Wappalyzer-style)
- Port scanning with service detection
- Vulnerability scanning with CVE correlation
- Result aggregation and Neo4j storage
- Async/await support for long-running scans

Author: Apollo Intelligence Platform
Version: 2.0.0
"""

import asyncio
import logging
import json
import uuid
from typing import Dict, List, Optional, Set, Any, Callable
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from pathlib import Path
from enum import Enum
import hashlib
import yaml

# Try to import native bbot
try:
    from bbot.scanner import Scanner as BBOTNativeScanner
    from bbot.core.event import Event as BBOTEvent
    BBOT_NATIVE_AVAILABLE = True
except ImportError:
    BBOT_NATIVE_AVAILABLE = False

# Import local modules with relative imports
try:
    from .subdomain_enum import SubdomainEnumerator, SubdomainResult
    from .port_scanner import PortScanner, PortResult
    from .tech_detector import TechnologyDetector, Technology
    from .vuln_scanner import VulnerabilityScanner, Vulnerability
except ImportError:
    # Fallback for direct script execution
    from subdomain_enum import SubdomainEnumerator, SubdomainResult
    from port_scanner import PortScanner, PortResult
    from tech_detector import TechnologyDetector, Technology
    from vuln_scanner import VulnerabilityScanner, Vulnerability

logger = logging.getLogger(__name__)


class ScanPreset(Enum):
    """Predefined scan presets for different use cases"""
    PASSIVE = "passive"      # Certificate transparency only, no active probing
    SAFE = "safe"            # Safe passive + minimal active scanning
    STANDARD = "standard"    # Balanced reconnaissance
    AGGRESSIVE = "aggressive"  # Full scanning with brute force
    SUBDOMAIN_ONLY = "subdomain_only"  # Subdomain enumeration only
    WEB_RECON = "web_recon"  # Web-focused reconnaissance


class ScanStatus(Enum):
    """Scan lifecycle status"""
    PENDING = "pending"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class ScanResult:
    """Complete scan result container"""
    scan_id: str
    target: str
    preset: str
    status: str
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    duration_seconds: float = 0.0

    # Results
    subdomains: List[Dict] = field(default_factory=list)
    ip_addresses: List[str] = field(default_factory=list)
    open_ports: List[Dict] = field(default_factory=list)
    technologies: List[Dict] = field(default_factory=list)
    vulnerabilities: List[Dict] = field(default_factory=list)
    ssl_info: List[Dict] = field(default_factory=list)
    dns_records: Dict[str, List[str]] = field(default_factory=dict)

    # Metadata
    raw_events: List[Dict] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    statistics: Dict[str, Any] = field(default_factory=dict)

    # For backward compatibility
    domain: str = ""
    timestamp: str = ""
    ports: List[Dict] = field(default_factory=list)
    metadata: Dict = field(default_factory=dict)

    def __post_init__(self):
        """Set backward-compatible fields"""
        if not self.domain:
            self.domain = self.target
        if not self.timestamp and self.start_time:
            self.timestamp = self.start_time.isoformat()
        if not self.ports:
            self.ports = self.open_ports

    def to_dict(self) -> Dict:
        """Convert result to dictionary"""
        data = asdict(self)
        data['start_time'] = self.start_time.isoformat() if self.start_time else None
        data['end_time'] = self.end_time.isoformat() if self.end_time else None
        return data

    def to_json(self) -> str:
        """Convert result to JSON string"""
        return json.dumps(self.to_dict(), indent=2, default=str)


@dataclass
class ScanConfig:
    """Scan configuration container"""
    preset: ScanPreset = ScanPreset.STANDARD
    modules: List[str] = field(default_factory=list)

    # Subdomain options
    subdomain_sources: List[str] = field(default_factory=lambda: ['crtsh', 'hackertarget'])
    brute_force: bool = False
    wordlist_size: str = 'medium'

    # Port scanning options
    port_scan: bool = True
    common_ports_only: bool = True
    service_detection: bool = True
    custom_ports: List[int] = field(default_factory=list)

    # Technology detection
    tech_detection: bool = True
    deep_tech_scan: bool = False

    # Vulnerability scanning
    vuln_scan: bool = True
    ssl_check: bool = True
    header_check: bool = True
    cve_matching: bool = True

    # Performance
    max_threads: int = 50
    timeout: int = 3600  # 1 hour
    rate_limit: int = 100  # requests per second

    # Scope
    max_subdomains: int = 1000
    max_ports_per_host: int = 100

    @classmethod
    def from_preset(cls, preset: ScanPreset) -> 'ScanConfig':
        """Create config from preset"""
        configs = {
            ScanPreset.PASSIVE: cls(
                preset=preset,
                modules=['subdomain'],
                subdomain_sources=['crtsh'],
                brute_force=False,
                port_scan=False,
                tech_detection=False,
                vuln_scan=False
            ),
            ScanPreset.SAFE: cls(
                preset=preset,
                modules=['subdomain', 'port'],
                subdomain_sources=['crtsh', 'hackertarget'],
                brute_force=False,
                port_scan=True,
                common_ports_only=True,
                tech_detection=True,
                deep_tech_scan=False,
                vuln_scan=False
            ),
            ScanPreset.STANDARD: cls(
                preset=preset,
                modules=['subdomain', 'port', 'tech', 'vuln'],
                subdomain_sources=['crtsh', 'hackertarget', 'virustotal'],
                brute_force=False,
                wordlist_size='small',
                port_scan=True,
                common_ports_only=True,
                service_detection=True,
                tech_detection=True,
                deep_tech_scan=False,
                vuln_scan=True,
                ssl_check=True,
                header_check=True
            ),
            ScanPreset.AGGRESSIVE: cls(
                preset=preset,
                modules=['subdomain', 'port', 'tech', 'vuln'],
                subdomain_sources=['crtsh', 'hackertarget', 'virustotal', 'dnsdumpster'],
                brute_force=True,
                wordlist_size='large',
                port_scan=True,
                common_ports_only=False,
                service_detection=True,
                tech_detection=True,
                deep_tech_scan=True,
                vuln_scan=True,
                ssl_check=True,
                header_check=True,
                cve_matching=True,
                max_subdomains=5000,
                max_ports_per_host=1000
            ),
            ScanPreset.SUBDOMAIN_ONLY: cls(
                preset=preset,
                modules=['subdomain'],
                subdomain_sources=['crtsh', 'hackertarget', 'virustotal'],
                brute_force=True,
                wordlist_size='medium',
                port_scan=False,
                tech_detection=False,
                vuln_scan=False
            ),
            ScanPreset.WEB_RECON: cls(
                preset=preset,
                modules=['subdomain', 'port', 'tech'],
                subdomain_sources=['crtsh', 'hackertarget'],
                brute_force=False,
                port_scan=True,
                custom_ports=[80, 443, 8080, 8443, 8000, 8888],
                tech_detection=True,
                deep_tech_scan=True,
                vuln_scan=True,
                ssl_check=True,
                header_check=True
            )
        }
        return configs.get(preset, cls())


class BBOTScanner:
    """
    BBOT Scanner - Comprehensive Reconnaissance Engine

    Integrates with native BBOT library when available, falls back to
    custom implementation for subdomain enumeration, port scanning,
    technology detection, and vulnerability scanning.

    Usage:
        scanner = BBOTScanner()
        result = await scanner.scan("example.com", preset="standard")

        # Or synchronously
        result = scanner.scan_domain_sync("example.com")
    """

    def __init__(
        self,
        output_dir: Optional[str] = None,
        config_path: Optional[str] = None,
        use_native_bbot: bool = True
    ):
        """
        Initialize BBOT Scanner

        Args:
            output_dir: Directory for scan outputs
            config_path: Path to YAML configuration file
            use_native_bbot: Use native BBOT library if available
        """
        self.output_dir = Path(output_dir or "./bbot_results")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.results_dir = self.output_dir  # Alias for compatibility

        # Setup logging
        self.logger = self._setup_logging()

        # Load configuration
        self.config = self._load_config(config_path)

        # Check native BBOT availability
        self.use_native = use_native_bbot and BBOT_NATIVE_AVAILABLE
        if use_native_bbot and not BBOT_NATIVE_AVAILABLE:
            self.logger.warning(
                "Native BBOT library not available. "
                "Install with: pip install bbot. "
                "Falling back to custom implementation."
            )

        # Initialize component modules
        self.subdomain_enum = SubdomainEnumerator(self.config)
        self.port_scanner = PortScanner(self.config)
        self.tech_detector = TechnologyDetector(self.config)
        self.vuln_scanner = VulnerabilityScanner(self.config)

        # Scan tracking
        self.active_scans: Dict[str, ScanResult] = {}
        self.scan_callbacks: Dict[str, List[Callable]] = {}

        self.logger.info(
            f"BBOTScanner initialized. "
            f"Native BBOT: {'Available' if self.use_native else 'Fallback mode'}. "
            f"Output: {self.output_dir}"
        )

    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration"""
        logger = logging.getLogger('BBOTScanner')
        logger.setLevel(logging.INFO)

        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)

        return logger

    def _load_config(self, config_path: Optional[str]) -> Dict:
        """Load configuration from YAML file"""
        default_config = {
            'timeout': 30,
            'max_threads': 100,
            'rate_limit': 100,
            'output_dir': str(self.output_dir),
            'modules': {
                'subdomain': True,
                'port': True,
                'tech': True,
                'vuln': True
            },
            'subdomain': {
                'sources': ['crtsh', 'hackertarget'],
                'brute_force': False,
                'wordlist_size': 'medium'
            },
            'port': {
                'common_ports': True,
                'service_detection': True
            },
            'tech': {
                'deep_scan': False
            },
            'vuln': {
                'ssl_check': True,
                'headers_check': True,
                'cve_matching': True
            }
        }

        if config_path and Path(config_path).exists():
            try:
                with open(config_path, 'r') as f:
                    loaded_config = yaml.safe_load(f)
                    default_config.update(loaded_config)
            except Exception as e:
                logger.error(f"Failed to load config from {config_path}: {e}")

        return default_config

    async def scan(
        self,
        target: str,
        preset: str = "standard",
        scan_types: Optional[List[str]] = None,
        config: Optional[ScanConfig] = None,
        callback: Optional[Callable[[str, Dict], None]] = None
    ) -> ScanResult:
        """
        Perform comprehensive reconnaissance scan

        Args:
            target: Domain or IP address to scan
            preset: Scan preset (passive, safe, standard, aggressive)
            scan_types: Override scan types (subdomain, port, tech, vuln)
            config: Custom scan configuration
            callback: Callback function for progress updates

        Returns:
            ScanResult with all findings
        """
        # Generate scan ID
        scan_id = str(uuid.uuid4())

        # Create or use provided config
        if config is None:
            try:
                preset_enum = ScanPreset(preset.lower())
                config = ScanConfig.from_preset(preset_enum)
            except ValueError:
                self.logger.warning(f"Unknown preset '{preset}', using standard")
                config = ScanConfig.from_preset(ScanPreset.STANDARD)

        # Override modules if scan_types specified
        if scan_types:
            config.modules = scan_types

        # Initialize result
        result = ScanResult(
            scan_id=scan_id,
            target=target,
            preset=config.preset.value,
            status=ScanStatus.RUNNING.value,
            start_time=datetime.now()
        )
        self.active_scans[scan_id] = result

        # Register callback
        if callback:
            self.scan_callbacks[scan_id] = [callback]

        self.logger.info(
            f"Starting scan {scan_id} for {target} "
            f"with preset {config.preset.value}"
        )

        try:
            # Execute scan based on mode
            if self.use_native:
                await self._run_native_bbot_scan(result, config)
            else:
                await self._run_custom_scan(result, config)

            result.status = ScanStatus.COMPLETED.value

        except Exception as e:
            self.logger.error(f"Scan {scan_id} failed: {e}", exc_info=True)
            result.status = ScanStatus.FAILED.value
            result.errors.append(str(e))

        finally:
            result.end_time = datetime.now()
            if result.start_time:
                result.duration_seconds = (
                    result.end_time - result.start_time
                ).total_seconds()

            # Update metadata
            result.metadata = {
                'scan_type': config.preset.value,
                'modules_run': config.modules,
                'duration_seconds': result.duration_seconds,
                'completed_at': result.end_time.isoformat() if result.end_time else None
            }

            # Calculate statistics
            result.statistics = self._calculate_statistics(result)

            # Save results
            self._save_results(result)

            # Notify callbacks
            self._notify_callbacks(scan_id, 'completed', result.to_dict())

        self.logger.info(
            f"Scan {scan_id} completed in {result.duration_seconds:.2f}s: "
            f"{len(result.subdomains)} subdomains, "
            f"{len(result.open_ports)} ports, "
            f"{len(result.technologies)} technologies, "
            f"{len(result.vulnerabilities)} vulnerabilities"
        )

        return result

    # Backward compatible method
    async def scan_domain(
        self,
        domain: str,
        modules: Optional[List[str]] = None,
        deep_scan: bool = False
    ) -> ScanResult:
        """
        Perform comprehensive domain reconnaissance (backward compatible)

        Args:
            domain: Target domain to scan
            modules: List of modules to run (subdomain, port, tech, vuln)
            deep_scan: Enable deep scanning mode

        Returns:
            ScanResult object with all findings
        """
        preset = "aggressive" if deep_scan else "standard"
        return await self.scan(domain, preset=preset, scan_types=modules)

    def scan_domain_sync(
        self,
        domain: str,
        modules: Optional[List[str]] = None,
        deep_scan: bool = False
    ) -> ScanResult:
        """
        Synchronous wrapper for scan_domain

        Args:
            domain: Target domain to scan
            modules: List of modules to run
            deep_scan: Enable deep scanning mode

        Returns:
            ScanResult object
        """
        return asyncio.run(self.scan_domain(domain, modules, deep_scan))

    async def _run_native_bbot_scan(
        self,
        result: ScanResult,
        config: ScanConfig
    ):
        """Run scan using native BBOT library"""
        self.logger.info("Running scan with native BBOT library")

        # Build BBOT modules list
        bbot_modules = []

        if 'subdomain' in config.modules:
            bbot_modules.extend(['subdomains', 'crt'])
            if config.brute_force:
                bbot_modules.append('dnsbrute')

        if config.port_scan:
            bbot_modules.append('portscan')

        if config.tech_detection:
            bbot_modules.extend(['httpx', 'wappalyzer'])

        if config.vuln_scan:
            bbot_modules.extend(['nuclei'])

        try:
            # Create BBOT scanner
            scanner = BBOTNativeScanner(
                result.target,
                modules=bbot_modules,
                output_dir=str(self.output_dir / result.scan_id)
            )

            # Run scan and process events
            async for event in scanner.async_start():
                self._process_bbot_event(event, result)
                self._notify_callbacks(
                    result.scan_id,
                    'event',
                    {'type': event.type, 'data': str(event.data)}
                )

        except Exception as e:
            self.logger.error(f"Native BBOT scan failed: {e}")
            # Fall back to custom implementation
            self.logger.info("Falling back to custom implementation")
            await self._run_custom_scan(result, config)

    def _process_bbot_event(self, event, result: ScanResult):
        """Process BBOT event and update result"""
        try:
            event_type = event.type.lower()
            event_data = str(event.data)

            # Store raw event
            result.raw_events.append({
                'type': event_type,
                'data': event_data,
                'timestamp': datetime.now().isoformat()
            })

            # Process by type
            if event_type == 'dns_name':
                if event_data not in [s.get('subdomain') for s in result.subdomains]:
                    result.subdomains.append({
                        'subdomain': event_data,
                        'source': 'bbot',
                        'ip_addresses': [],
                        'is_wildcard': False
                    })

            elif event_type == 'ip_address':
                if event_data not in result.ip_addresses:
                    result.ip_addresses.append(event_data)

            elif event_type == 'open_tcp_port':
                parts = event_data.split(':')
                if len(parts) == 2:
                    port_dict = {
                        'host': parts[0],
                        'port': int(parts[1]),
                        'state': 'open',
                        'protocol': 'tcp'
                    }
                    result.open_ports.append(port_dict)
                    result.ports.append(port_dict)

            elif event_type == 'technology':
                result.technologies.append({
                    'name': event_data,
                    'category': 'Unknown',
                    'detection_method': 'bbot'
                })

            elif event_type == 'finding' or event_type == 'vulnerability':
                result.vulnerabilities.append({
                    'title': event_data,
                    'severity': 'unknown',
                    'source': 'bbot'
                })

        except Exception as e:
            self.logger.debug(f"Failed to process BBOT event: {e}")

    async def _run_custom_scan(
        self,
        result: ScanResult,
        config: ScanConfig
    ):
        """Run scan using custom implementation"""
        self.logger.info("Running scan with custom implementation")

        discovered_subdomains: Set[str] = set()
        discovered_ips: Set[str] = set()

        # Phase 1: Subdomain enumeration
        if 'subdomain' in config.modules:
            self._notify_callbacks(
                result.scan_id,
                'phase',
                {'phase': 'subdomain_enumeration', 'status': 'started'}
            )

            subdomain_config = {
                'subdomain': {
                    'sources': config.subdomain_sources,
                    'brute_force': config.brute_force,
                    'wordlist_size': config.wordlist_size
                },
                'timeout': self.config.get('timeout', 30)
            }

            subdomain_enum = SubdomainEnumerator(subdomain_config)
            subdomains = await subdomain_enum.enumerate(
                result.target,
                deep_scan=config.brute_force
            )

            result.subdomains = subdomains
            for sub in subdomains:
                discovered_subdomains.add(sub.get('subdomain', ''))
                discovered_ips.update(sub.get('ip_addresses', []))

            self.logger.info(f"Found {len(subdomains)} subdomains")

        # Phase 2: Port scanning
        if config.port_scan and ('port' in config.modules or 'port' not in config.modules):
            self._notify_callbacks(
                result.scan_id,
                'phase',
                {'phase': 'port_scanning', 'status': 'started'}
            )

            # Build target list
            targets = list(discovered_ips)[:config.max_ports_per_host]
            if not targets and result.target:
                targets = [result.target]

            port_config = {
                'port': {
                    'common_ports': config.common_ports_only,
                    'service_detection': config.service_detection,
                    'custom_ports': config.custom_ports
                },
                'timeout': self.config.get('timeout', 30),
                'max_threads': config.max_threads
            }

            port_scanner = PortScanner(port_config)
            ports = await port_scanner.scan_targets(
                targets,
                deep_scan=not config.common_ports_only
            )

            result.open_ports = ports
            result.ports = ports  # Backward compatibility
            result.ip_addresses = list(discovered_ips)
            self.logger.info(f"Found {len(ports)} open ports")

        # Phase 3: Technology detection
        if config.tech_detection and 'tech' in config.modules:
            self._notify_callbacks(
                result.scan_id,
                'phase',
                {'phase': 'technology_detection', 'status': 'started'}
            )

            tech_config = {
                'tech': {
                    'deep_scan': config.deep_tech_scan
                },
                'timeout': self.config.get('timeout', 30)
            }

            tech_detector = TechnologyDetector(tech_config)
            technologies = await tech_detector.detect(
                result.target,
                result.open_ports
            )

            result.technologies = technologies
            self.logger.info(f"Detected {len(technologies)} technologies")

        # Phase 4: Vulnerability scanning
        if config.vuln_scan and 'vuln' in config.modules:
            self._notify_callbacks(
                result.scan_id,
                'phase',
                {'phase': 'vulnerability_scanning', 'status': 'started'}
            )

            vuln_config = {
                'vuln': {
                    'ssl_check': config.ssl_check,
                    'headers_check': config.header_check,
                    'cve_matching': config.cve_matching
                },
                'timeout': self.config.get('timeout', 30)
            }

            vuln_scanner = VulnerabilityScanner(vuln_config)
            vuln_results = await vuln_scanner.scan(
                result.target,
                result.open_ports,
                result.technologies
            )

            result.vulnerabilities = vuln_results.get('vulnerabilities', [])
            result.ssl_info = vuln_results.get('ssl_info', [])
            self.logger.info(f"Found {len(result.vulnerabilities)} vulnerabilities")

    async def scan_multiple_domains(
        self,
        domains: List[str],
        modules: Optional[List[str]] = None,
        deep_scan: bool = False,
        parallel: bool = True
    ) -> Dict[str, ScanResult]:
        """
        Scan multiple domains

        Args:
            domains: List of domains to scan
            modules: List of modules to run
            deep_scan: Enable deep scanning mode
            parallel: Run scans in parallel

        Returns:
            Dictionary mapping domains to their ScanResult
        """
        self.logger.info(f"Starting multi-domain scan for {len(domains)} domains")

        if parallel:
            tasks = [self.scan_domain(domain, modules, deep_scan) for domain in domains]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            return {
                domain: result if not isinstance(result, Exception) else None
                for domain, result in zip(domains, results)
            }
        else:
            results = {}
            for domain in domains:
                try:
                    results[domain] = await self.scan_domain(domain, modules, deep_scan)
                except Exception as e:
                    self.logger.error(f"Failed to scan {domain}: {e}")
                    results[domain] = None

            return results

    def _calculate_statistics(self, result: ScanResult) -> Dict:
        """Calculate scan statistics"""
        stats = {
            'total_subdomains': len(result.subdomains),
            'total_ips': len(result.ip_addresses),
            'total_open_ports': len(result.open_ports),
            'total_technologies': len(result.technologies),
            'total_vulnerabilities': len(result.vulnerabilities),
            'scan_duration_seconds': result.duration_seconds,
            'errors_count': len(result.errors)
        }

        # Vulnerability severity breakdown
        vuln_severity = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for vuln in result.vulnerabilities:
            severity = vuln.get('severity', 'info').lower()
            if severity in vuln_severity:
                vuln_severity[severity] += 1
        stats['vulnerability_severity'] = vuln_severity

        # Technology categories
        tech_categories = {}
        for tech in result.technologies:
            category = tech.get('category', 'Unknown')
            tech_categories[category] = tech_categories.get(category, 0) + 1
        stats['technology_categories'] = tech_categories

        return stats

    def _save_results(self, result: ScanResult):
        """Save scan results to multiple formats"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        domain_safe = result.target.replace('.', '_')
        base_filename = f"{domain_safe}_{timestamp}"

        scan_dir = self.output_dir / result.scan_id
        scan_dir.mkdir(parents=True, exist_ok=True)

        # Save JSON result
        json_path = scan_dir / 'results.json'
        with open(json_path, 'w') as f:
            json.dump(result.to_dict(), f, indent=2, default=str)
        self.logger.info(f"Results saved to {json_path}")

        # Save subdomains list
        if result.subdomains:
            subdomain_path = scan_dir / 'subdomains.txt'
            with open(subdomain_path, 'w') as f:
                for sub in result.subdomains:
                    f.write(f"{sub.get('subdomain', '')}\n")

        # Save IPs list
        if result.ip_addresses:
            ips_path = scan_dir / 'ips.txt'
            with open(ips_path, 'w') as f:
                for ip in result.ip_addresses:
                    f.write(f"{ip}\n")

        # Save human-readable report
        report_path = scan_dir / 'report.txt'
        self._generate_report(result, report_path)

    def _generate_report(self, scan_result: ScanResult, output_path: Path):
        """Generate human-readable report"""
        with open(output_path, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write(f"BBOT RECONNAISSANCE REPORT\n")
            f.write("=" * 80 + "\n\n")

            f.write(f"Domain: {scan_result.target}\n")
            f.write(f"Scan ID: {scan_result.scan_id}\n")
            f.write(f"Scan Time: {scan_result.start_time}\n")
            f.write(f"Duration: {scan_result.duration_seconds:.2f} seconds\n")
            f.write(f"Preset: {scan_result.preset}\n\n")

            # Subdomains
            if scan_result.subdomains:
                f.write("-" * 80 + "\n")
                f.write(f"SUBDOMAINS ({len(scan_result.subdomains)})\n")
                f.write("-" * 80 + "\n")
                for sub in scan_result.subdomains[:50]:
                    f.write(f"  - {sub.get('subdomain', 'N/A')}")
                    if sub.get('ip_addresses'):
                        f.write(f" -> {', '.join(sub['ip_addresses'])}")
                    f.write("\n")
                f.write("\n")

            # Open Ports
            if scan_result.open_ports:
                f.write("-" * 80 + "\n")
                f.write(f"OPEN PORTS ({len(scan_result.open_ports)})\n")
                f.write("-" * 80 + "\n")
                for port in scan_result.open_ports:
                    f.write(f"  - {port.get('host', 'N/A')}:{port.get('port', 'N/A')}")
                    if port.get('service'):
                        f.write(f" ({port['service']})")
                    if port.get('version'):
                        f.write(f" - {port['version']}")
                    f.write("\n")
                f.write("\n")

            # Technologies
            if scan_result.technologies:
                f.write("-" * 80 + "\n")
                f.write(f"TECHNOLOGIES ({len(scan_result.technologies)})\n")
                f.write("-" * 80 + "\n")
                for tech in scan_result.technologies:
                    f.write(f"  - {tech.get('name', 'N/A')}")
                    if tech.get('version'):
                        f.write(f" v{tech['version']}")
                    if tech.get('category'):
                        f.write(f" [{tech['category']}]")
                    f.write("\n")
                f.write("\n")

            # Vulnerabilities
            if scan_result.vulnerabilities:
                f.write("-" * 80 + "\n")
                f.write(f"VULNERABILITIES ({len(scan_result.vulnerabilities)})\n")
                f.write("-" * 80 + "\n")
                for vuln in scan_result.vulnerabilities:
                    severity = vuln.get('severity', 'UNKNOWN').upper()
                    f.write(f"  [{severity}] {vuln.get('title', 'N/A')}\n")
                    if vuln.get('description'):
                        f.write(f"    {vuln['description']}\n")
                    if vuln.get('cve'):
                        f.write(f"    CVE: {vuln['cve']}\n")
                f.write("\n")

            # SSL/TLS Info
            if scan_result.ssl_info:
                f.write("-" * 80 + "\n")
                f.write(f"SSL/TLS INFORMATION\n")
                f.write("-" * 80 + "\n")
                for ssl in scan_result.ssl_info:
                    f.write(f"  Host: {ssl.get('host', 'N/A')}\n")
                    f.write(f"  Valid: {ssl.get('valid', False)}\n")
                    if ssl.get('issuer'):
                        f.write(f"  Issuer: {ssl['issuer']}\n")
                    if ssl.get('expires'):
                        f.write(f"  Expires: {ssl['expires']}\n")
                    f.write("\n")

            f.write("=" * 80 + "\n")
            f.write("End of Report\n")
            f.write("=" * 80 + "\n")

    def _notify_callbacks(self, scan_id: str, event_type: str, data: Dict):
        """Notify registered callbacks"""
        if scan_id in self.scan_callbacks:
            for callback in self.scan_callbacks[scan_id]:
                try:
                    callback(event_type, data)
                except Exception as e:
                    self.logger.error(f"Callback error: {e}")

    def get_scan_status(self, scan_id: str) -> Optional[Dict]:
        """Get current status of a scan"""
        if scan_id in self.active_scans:
            return self.active_scans[scan_id].to_dict()

        # Check saved results
        result_path = self.output_dir / scan_id / 'results.json'
        if result_path.exists():
            with open(result_path, 'r') as f:
                return json.load(f)

        return None

    def list_scans(self) -> List[Dict]:
        """List all scans"""
        scans = []

        # Add active scans
        for scan_id, result in self.active_scans.items():
            scans.append({
                'scan_id': scan_id,
                'target': result.target,
                'status': result.status,
                'start_time': result.start_time.isoformat() if result.start_time else None
            })

        # Add saved scans
        for scan_dir in self.output_dir.iterdir():
            if scan_dir.is_dir() and scan_dir.name not in self.active_scans:
                result_path = scan_dir / 'results.json'
                if result_path.exists():
                    try:
                        with open(result_path, 'r') as f:
                            data = json.load(f)
                            scans.append({
                                'scan_id': data.get('scan_id'),
                                'target': data.get('target'),
                                'status': data.get('status'),
                                'start_time': data.get('start_time')
                            })
                    except:
                        pass

        return sorted(scans, key=lambda x: x.get('start_time') or '', reverse=True)

    async def cancel_scan(self, scan_id: str) -> bool:
        """Cancel an active scan"""
        if scan_id in self.active_scans:
            result = self.active_scans[scan_id]
            if result.status == ScanStatus.RUNNING.value:
                result.status = ScanStatus.CANCELLED.value
                result.end_time = datetime.now()
                if result.start_time:
                    result.duration_seconds = (
                        result.end_time - result.start_time
                    ).total_seconds()
                self._save_results(result)
                return True
        return False

    async def get_subdomains(self, domain: str) -> List[str]:
        """
        Quick subdomain enumeration without full scan

        Args:
            domain: Domain to enumerate

        Returns:
            List of discovered subdomains
        """
        config = {
            'subdomain': {
                'sources': ['crtsh', 'hackertarget'],
                'brute_force': False
            },
            'timeout': 30
        }

        enumerator = SubdomainEnumerator(config)
        results = await enumerator.enumerate(domain, deep_scan=False)

        return [r.get('subdomain', '') for r in results]

    async def get_technologies(self, domain: str) -> List[Dict]:
        """
        Quick technology detection

        Args:
            domain: Domain to analyze

        Returns:
            List of detected technologies
        """
        config = {
            'tech': {'deep_scan': False},
            'timeout': 30
        }

        detector = TechnologyDetector(config)
        return await detector.detect(domain)

    def get_summary(self, scan_result: ScanResult) -> Dict:
        """
        Generate summary statistics from scan results

        Args:
            scan_result: ScanResult object

        Returns:
            Dictionary with summary statistics
        """
        return {
            'domain': scan_result.target,
            'scan_id': scan_result.scan_id,
            'scan_date': scan_result.start_time.isoformat() if scan_result.start_time else None,
            'duration': scan_result.duration_seconds,
            'status': scan_result.status,
            'statistics': {
                'subdomains_found': len(scan_result.subdomains),
                'open_ports': len(scan_result.open_ports),
                'technologies_detected': len(scan_result.technologies),
                'vulnerabilities_found': len(scan_result.vulnerabilities),
                'ssl_certificates': len(scan_result.ssl_info)
            },
            'severity_breakdown': self._get_severity_breakdown(scan_result.vulnerabilities),
            'top_technologies': self._get_top_technologies(scan_result.technologies),
            'critical_findings': self._get_critical_findings(scan_result)
        }

    def _get_severity_breakdown(self, vulnerabilities: List[Dict]) -> Dict[str, int]:
        """Get vulnerability severity breakdown"""
        breakdown = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'info').lower()
            if severity in breakdown:
                breakdown[severity] += 1
        return breakdown

    def _get_top_technologies(self, technologies: List[Dict], limit: int = 10) -> List[str]:
        """Get top detected technologies"""
        return [tech.get('name', 'Unknown') for tech in technologies[:limit]]

    def _get_critical_findings(self, scan_result: ScanResult) -> List[str]:
        """Extract critical findings"""
        findings = []

        # Check for critical vulnerabilities
        critical_vulns = [
            v for v in scan_result.vulnerabilities
            if v.get('severity', '').lower() in ['critical', 'high']
        ]
        if critical_vulns:
            findings.append(f"Found {len(critical_vulns)} critical/high severity vulnerabilities")

        # Check for expired SSL certificates
        expired_ssl = [
            s for s in scan_result.ssl_info
            if not s.get('valid', True)
        ]
        if expired_ssl:
            findings.append(f"Found {len(expired_ssl)} invalid/expired SSL certificates")

        # Check for sensitive ports
        sensitive_ports = {21, 22, 23, 3306, 5432, 6379, 27017}
        exposed_sensitive = [
            p for p in scan_result.open_ports
            if p.get('port') in sensitive_ports
        ]
        if exposed_sensitive:
            findings.append(f"Found {len(exposed_sensitive)} sensitive ports exposed")

        return findings


# Convenience functions
async def quick_subdomain_scan(domain: str) -> List[str]:
    """Quick subdomain enumeration"""
    scanner = BBOTScanner()
    return await scanner.get_subdomains(domain)


async def quick_tech_scan(domain: str) -> List[Dict]:
    """Quick technology detection"""
    scanner = BBOTScanner()
    return await scanner.get_technologies(domain)


async def full_recon(
    domain: str,
    preset: str = "standard"
) -> ScanResult:
    """Full reconnaissance scan"""
    scanner = BBOTScanner()
    return await scanner.scan(domain, preset=preset)


# CLI interface
def main():
    """Example usage"""
    import argparse

    parser = argparse.ArgumentParser(description='BBOT Reconnaissance Scanner')
    parser.add_argument('domain', help='Target domain to scan')
    parser.add_argument('--config', help='Path to config file')
    parser.add_argument('--modules', nargs='+', choices=['subdomain', 'port', 'tech', 'vuln'],
                        help='Modules to run')
    parser.add_argument('--deep', action='store_true', help='Enable deep scanning')
    parser.add_argument('--preset', '-p',
                        default='standard',
                        choices=['passive', 'safe', 'standard', 'aggressive'],
                        help='Scan preset')
    parser.add_argument('--output', help='Output directory for results')

    args = parser.parse_args()

    # Initialize scanner
    scanner = BBOTScanner(config_path=args.config, output_dir=args.output)

    # Run scan
    result = scanner.scan_domain_sync(
        args.domain,
        modules=args.modules,
        deep_scan=args.deep
    )

    # Print summary
    summary = scanner.get_summary(result)
    print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    main()
