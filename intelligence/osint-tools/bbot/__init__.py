"""
BBOT - Comprehensive Reconnaissance System
===========================================

A production-ready OSINT framework for domain intelligence gathering.

Features:
- Native BBOT library integration with fallback
- Subdomain enumeration (crt.sh, HackerTarget, VirusTotal, DNS brute force)
- Port scanning with service detection
- Technology detection (Wappalyzer-style)
- Vulnerability scanning with CVE correlation
- Multiple scan presets (passive, safe, standard, aggressive)
- Async/await support for concurrent operations
- Neo4j integration for relationship mapping

Usage:
    from intelligence.osint_tools.bbot import BBOTScanner, ScanResult

    # Async usage
    scanner = BBOTScanner()
    result = await scanner.scan("example.com", preset="standard")

    # Sync usage
    result = scanner.scan_domain_sync("example.com")

    # Quick subdomain scan
    subdomains = await scanner.get_subdomains("example.com")
"""

from .bbot_integration import (
    BBOTScanner,
    ScanResult,
    ScanConfig,
    ScanPreset,
    ScanStatus,
    quick_subdomain_scan,
    quick_tech_scan,
    full_recon,
    BBOT_NATIVE_AVAILABLE
)
from .subdomain_enum import SubdomainEnumerator, SubdomainResult
from .port_scanner import PortScanner, PortResult
from .tech_detector import TechnologyDetector, Technology
from .vuln_scanner import VulnerabilityScanner, Vulnerability

__version__ = "2.0.0"
__author__ = "Apollo Intelligence Platform"
__all__ = [
    # Main Scanner
    "BBOTScanner",
    "ScanResult",
    "ScanConfig",
    "ScanPreset",
    "ScanStatus",

    # Subdomain Enumeration
    "SubdomainEnumerator",
    "SubdomainResult",

    # Port Scanning
    "PortScanner",
    "PortResult",

    # Technology Detection
    "TechnologyDetector",
    "Technology",

    # Vulnerability Scanning
    "VulnerabilityScanner",
    "Vulnerability",

    # Convenience functions
    "quick_subdomain_scan",
    "quick_tech_scan",
    "full_recon",

    # Status
    "BBOT_NATIVE_AVAILABLE",
]
