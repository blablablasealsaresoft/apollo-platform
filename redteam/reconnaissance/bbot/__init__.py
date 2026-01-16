"""
BBOT Reconnaissance Module - Red Team Edition
=============================================

Production-ready reconnaissance toolkit with:
- Subdomain enumeration using multiple data sources
- Port scanning with service detection
- Technology fingerprinting
- Screenshot capture
- Vulnerability identification

Supports native BBOT library with fallback to custom implementation.

Author: Apollo Red Team Toolkit
Version: 2.0.0
"""

from .bbot_manager import BBOTManager, BBOTScan
from .subdomain_enum import SubdomainEnumerator, SubdomainResult, quick_subdomain_scan
from .port_scanner import PortScanner, PortResult, quick_port_scan
from .screenshot_capture import ScreenshotCapture, ScreenshotResult, quick_screenshot

__all__ = [
    # Main Manager
    'BBOTManager',
    'BBOTScan',

    # Subdomain Enumeration
    'SubdomainEnumerator',
    'SubdomainResult',
    'quick_subdomain_scan',

    # Port Scanning
    'PortScanner',
    'PortResult',
    'quick_port_scan',

    # Screenshot
    'ScreenshotCapture',
    'ScreenshotResult',
    'quick_screenshot'
]
