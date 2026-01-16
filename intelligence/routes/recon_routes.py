"""
Reconnaissance Routes Module
============================

API endpoints for BBOT reconnaissance operations:
- Subdomain enumeration
- Port scanning
- Technology detection
- Vulnerability scanning

Author: Apollo Intelligence System
Version: 2.0.0
"""

from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
import logging
import asyncio
from datetime import datetime
import uuid

from middleware.auth import JWTBearer
from middleware.rate_limiter import RateLimiter

# Import BBOT modules
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'osint-tools', 'bbot'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'redteam', 'reconnaissance', 'bbot'))

logger = logging.getLogger(__name__)

router = APIRouter()
rate_limiter = RateLimiter(requests_per_minute=30)

# In-memory scan storage (replace with Redis/DB in production)
_scans: Dict[str, Dict] = {}


# Request Models
class ScanRequest(BaseModel):
    """Request model for creating a new scan"""
    name: str = Field(..., description="Scan name for identification")
    targets: List[str] = Field(..., description="List of targets (domains/IPs)")
    preset: Optional[str] = Field('standard', description="Scan preset: passive, safe, standard, aggressive")
    modules: Optional[List[str]] = Field(None, description="Custom modules (overrides preset)")
    threads: Optional[int] = Field(50, description="Number of concurrent threads")
    timeout: Optional[int] = Field(3600, description="Scan timeout in seconds")


class SubdomainRequest(BaseModel):
    """Request model for subdomain enumeration"""
    domain: str = Field(..., description="Target domain")
    sources: Optional[List[str]] = Field(None, description="Data sources: crtsh, hackertarget, certspotter, virustotal")
    brute_force: bool = Field(False, description="Enable DNS brute forcing")
    wordlist: Optional[List[str]] = Field(None, description="Custom wordlist for brute forcing")


class PortScanRequest(BaseModel):
    """Request model for port scanning"""
    target: str = Field(..., description="Target host (IP or hostname)")
    ports: Optional[List[int]] = Field(None, description="List of ports to scan")
    preset: Optional[str] = Field('common', description="Port preset: quick, common, web, database, full")
    service_detection: bool = Field(True, description="Enable service version detection")


class TechDetectionRequest(BaseModel):
    """Request model for technology detection"""
    target: str = Field(..., description="Target URL or domain")
    detailed: bool = Field(True, description="Include detailed analysis")


# Response Models
class ScanResponse(BaseModel):
    """Response model for scan status"""
    scan_id: str
    name: str
    status: str
    targets: List[str]
    preset: Optional[str]
    created_at: str
    started_at: Optional[str]
    completed_at: Optional[str]
    statistics: Optional[Dict] = None
    results: Optional[Dict] = None


class SubdomainResponse(BaseModel):
    """Response model for subdomain enumeration"""
    success: bool
    domain: str
    total_found: int
    duration_seconds: float
    subdomains: List[Dict]


class PortScanResponse(BaseModel):
    """Response model for port scan"""
    success: bool
    target: str
    total_open: int
    duration_seconds: float
    ports: List[Dict]


# Initialize BBOT Manager
_bbot_manager = None


def get_bbot_manager():
    """Get or create BBOT manager instance"""
    global _bbot_manager
    if _bbot_manager is None:
        try:
            from bbot_manager import BBOTManager
            _bbot_manager = BBOTManager()
        except ImportError:
            logger.error("BBOTManager not available")
            raise HTTPException(status_code=500, detail="BBOT Manager not available")
    return _bbot_manager


# ============================================================================
# SCAN ENDPOINTS
# ============================================================================

@router.post("/scan", response_model=ScanResponse)
async def create_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
    token: str = Depends(JWTBearer()),
    rate_limit: None = Depends(rate_limiter)
):
    """
    Create and start a new reconnaissance scan.

    Initiates a BBOT scan against the specified targets with configurable presets:
    - **passive**: Certificate transparency only, no active probing
    - **safe**: Minimal footprint, basic enumeration
    - **standard**: Balanced reconnaissance
    - **aggressive**: Full scanning including brute force and vulnerability checks

    The scan runs in the background. Use GET /scan/{scan_id} to check status.
    """
    try:
        logger.info(f"Creating scan: {request.name} for targets: {request.targets}")

        manager = get_bbot_manager()

        # Create scan
        scan = manager.create_scan(
            name=request.name,
            targets=request.targets,
            preset=request.preset,
            modules=request.modules,
            threads=request.threads,
            timeout=request.timeout
        )

        # Run scan in background
        background_tasks.add_task(run_scan_background, manager, scan.scan_id)

        return ScanResponse(
            scan_id=scan.scan_id,
            name=scan.name,
            status=scan.status,
            targets=scan.targets,
            preset=scan.config.get('preset'),
            created_at=scan.created_at.isoformat(),
            started_at=None,
            completed_at=None
        )

    except Exception as e:
        logger.error(f"Failed to create scan: {e}")
        raise HTTPException(status_code=500, detail=str(e))


async def run_scan_background(manager, scan_id: str):
    """Background task to run scan"""
    try:
        await manager.run_scan_async(scan_id)
    except Exception as e:
        logger.error(f"Background scan failed: {e}")


@router.get("/scan/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: str,
    token: str = Depends(JWTBearer())
):
    """
    Get scan status and results.

    Returns the current status of the scan and results if completed.
    """
    try:
        manager = get_bbot_manager()
        scan = manager.get_scan(scan_id)

        if not scan:
            raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

        return ScanResponse(
            scan_id=scan.scan_id,
            name=scan.name,
            status=scan.status,
            targets=scan.targets,
            preset=scan.config.get('preset'),
            created_at=scan.created_at.isoformat(),
            started_at=scan.started_at.isoformat() if scan.started_at else None,
            completed_at=scan.completed_at.isoformat() if scan.completed_at else None,
            statistics=scan.get_statistics(),
            results=scan.results if scan.status == 'completed' else None
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get scan: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/scan")
async def list_scans(
    token: str = Depends(JWTBearer())
):
    """
    List all scans.

    Returns a list of all scans with their status.
    """
    try:
        manager = get_bbot_manager()
        scans = manager.list_scans()

        return {
            "success": True,
            "total_scans": len(scans),
            "scans": scans
        }

    except Exception as e:
        logger.error(f"Failed to list scans: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/scan/presets")
async def get_presets():
    """
    Get available scan presets.

    Returns the list of available presets with their descriptions.
    """
    try:
        manager = get_bbot_manager()
        return {
            "success": True,
            "presets": manager.get_presets()
        }
    except Exception as e:
        logger.error(f"Failed to get presets: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# SUBDOMAIN ENUMERATION ENDPOINTS
# ============================================================================

@router.post("/subdomains", response_model=SubdomainResponse)
async def enumerate_subdomains(
    request: SubdomainRequest,
    token: str = Depends(JWTBearer()),
    rate_limit: None = Depends(rate_limiter)
):
    """
    Enumerate subdomains for a domain.

    Uses multiple sources for comprehensive subdomain discovery:
    - **crtsh**: Certificate transparency logs
    - **hackertarget**: HackerTarget API
    - **certspotter**: CertSpotter API
    - **virustotal**: VirusTotal API (requires API key)

    Optionally enables DNS brute forcing for deeper enumeration.
    """
    try:
        logger.info(f"Subdomain enumeration requested for: {request.domain}")
        start_time = datetime.now()

        # Import enumerator
        from subdomain_enum import SubdomainEnumerator

        enumerator = SubdomainEnumerator()
        results = await enumerator.enumerate(
            domain=request.domain,
            sources=request.sources,
            brute_force=request.brute_force,
            wordlist=request.wordlist
        )

        duration = (datetime.now() - start_time).total_seconds()

        # Format results
        subdomains = []
        for result in results:
            subdomains.append({
                'subdomain': result.subdomain,
                'ip_addresses': result.ip_addresses,
                'cname': result.cname,
                'source': result.source,
                'is_wildcard': result.is_wildcard
            })

        return SubdomainResponse(
            success=True,
            domain=request.domain,
            total_found=len(subdomains),
            duration_seconds=round(duration, 2),
            subdomains=subdomains
        )

    except Exception as e:
        logger.error(f"Subdomain enumeration error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/subdomains/{domain}")
async def get_subdomains_quick(
    domain: str,
    token: str = Depends(JWTBearer())
):
    """
    Quick subdomain lookup for a domain.

    Performs fast passive enumeration without brute forcing.
    """
    try:
        logger.info(f"Quick subdomain lookup for: {domain}")
        start_time = datetime.now()

        from subdomain_enum import SubdomainEnumerator

        enumerator = SubdomainEnumerator()
        results = await enumerator.enumerate(
            domain=domain,
            sources=['crtsh', 'hackertarget'],
            brute_force=False
        )

        duration = (datetime.now() - start_time).total_seconds()

        return {
            "success": True,
            "domain": domain,
            "total_found": len(results),
            "duration_seconds": round(duration, 2),
            "subdomains": [r.subdomain for r in results]
        }

    except Exception as e:
        logger.error(f"Quick subdomain lookup error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# PORT SCANNING ENDPOINTS
# ============================================================================

@router.post("/ports", response_model=PortScanResponse)
async def scan_ports(
    request: PortScanRequest,
    token: str = Depends(JWTBearer()),
    rate_limit: None = Depends(rate_limiter)
):
    """
    Scan ports on a target host.

    Performs TCP connect scanning with optional service detection.

    Available presets:
    - **quick**: Top 11 most common ports
    - **common**: Standard 50+ ports
    - **web**: Web server ports (80, 443, 8080, etc.)
    - **database**: Database ports (MySQL, PostgreSQL, MongoDB, etc.)
    - **full**: Top 1024 ports
    """
    try:
        logger.info(f"Port scan requested for: {request.target}")
        start_time = datetime.now()

        from port_scanner import PortScanner

        scanner = PortScanner(service_detection=request.service_detection)
        results = await scanner.scan(
            target=request.target,
            ports=request.ports,
            preset=request.preset
        )

        duration = (datetime.now() - start_time).total_seconds()

        ports = []
        for result in results:
            ports.append(scanner.to_dict(result))

        return PortScanResponse(
            success=True,
            target=request.target,
            total_open=len(ports),
            duration_seconds=round(duration, 2),
            ports=ports
        )

    except Exception as e:
        logger.error(f"Port scan error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/ports/{target}")
async def quick_port_scan(
    target: str,
    preset: str = 'quick',
    token: str = Depends(JWTBearer())
):
    """
    Quick port scan of a target.

    Performs a fast scan using the specified preset.
    """
    try:
        logger.info(f"Quick port scan for: {target}")
        start_time = datetime.now()

        from port_scanner import PortScanner

        scanner = PortScanner()
        results = await scanner.scan(target=target, preset=preset)

        duration = (datetime.now() - start_time).total_seconds()

        return {
            "success": True,
            "target": target,
            "preset": preset,
            "total_open": len(results),
            "duration_seconds": round(duration, 2),
            "ports": [
                {
                    "port": r.port,
                    "service": r.service,
                    "version": r.version
                }
                for r in results
            ]
        }

    except Exception as e:
        logger.error(f"Quick port scan error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# TECHNOLOGY DETECTION ENDPOINTS
# ============================================================================

@router.post("/technologies")
async def detect_technologies(
    request: TechDetectionRequest,
    token: str = Depends(JWTBearer()),
    rate_limit: None = Depends(rate_limiter)
):
    """
    Detect technologies used on a target.

    Fingerprints web technologies including:
    - Web servers (nginx, Apache, IIS)
    - Frameworks (React, Angular, Vue, Django, Rails)
    - CMS (WordPress, Drupal, Joomla)
    - E-commerce (Shopify, Magento)
    """
    try:
        logger.info(f"Technology detection requested for: {request.target}")

        manager = get_bbot_manager()

        # Create a quick scan focused on technology detection
        scan = manager.create_scan(
            name=f"Tech detection: {request.target}",
            targets=[request.target],
            modules=['httpx', 'wappalyzer']
        )

        await manager.run_scan_async(scan.scan_id)

        technologies = scan.results.get('technologies', {}).get(request.target, [])

        return {
            "success": True,
            "target": request.target,
            "total_detected": len(technologies),
            "technologies": technologies
        }

    except Exception as e:
        logger.error(f"Technology detection error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/technologies/{domain}")
async def quick_tech_detection(
    domain: str,
    token: str = Depends(JWTBearer())
):
    """
    Quick technology detection for a domain.
    """
    try:
        logger.info(f"Quick tech detection for: {domain}")

        manager = get_bbot_manager()

        scan = manager.create_scan(
            name=f"Quick tech: {domain}",
            targets=[domain],
            modules=['wappalyzer']
        )

        await manager.run_scan_async(scan.scan_id)

        technologies = scan.results.get('technologies', {}).get(domain, [])

        return {
            "success": True,
            "domain": domain,
            "technologies": technologies
        }

    except Exception as e:
        logger.error(f"Quick tech detection error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# VULNERABILITY SCANNING ENDPOINTS
# ============================================================================

@router.post("/vulnerabilities")
async def scan_vulnerabilities(
    target: str,
    background_tasks: BackgroundTasks,
    token: str = Depends(JWTBearer()),
    rate_limit: None = Depends(rate_limiter)
):
    """
    Scan target for common vulnerabilities.

    Performs security checks including:
    - Missing security headers
    - SSL/TLS misconfigurations
    - Information disclosure
    - Known vulnerabilities (requires nuclei)

    Note: This is a longer-running scan. Use background task for production.
    """
    try:
        logger.info(f"Vulnerability scan requested for: {target}")

        manager = get_bbot_manager()

        # Create aggressive scan for vulnerability detection
        scan = manager.create_scan(
            name=f"Vulnerability scan: {target}",
            targets=[target],
            preset='aggressive'
        )

        # Run in background
        background_tasks.add_task(run_scan_background, manager, scan.scan_id)

        return {
            "success": True,
            "scan_id": scan.scan_id,
            "message": "Vulnerability scan started in background",
            "check_status_at": f"/api/v1/recon/scan/{scan.scan_id}"
        }

    except Exception as e:
        logger.error(f"Vulnerability scan error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# FULL RECONNAISSANCE ENDPOINT
# ============================================================================

@router.post("/full")
async def full_reconnaissance(
    domain: str,
    background_tasks: BackgroundTasks,
    token: str = Depends(JWTBearer()),
    rate_limit: None = Depends(rate_limiter)
):
    """
    Perform full reconnaissance on a domain.

    Combines all reconnaissance techniques:
    - Subdomain enumeration
    - Port scanning
    - Technology detection
    - Vulnerability scanning

    Returns a scan ID to track progress.
    """
    try:
        logger.info(f"Full reconnaissance requested for: {domain}")

        manager = get_bbot_manager()

        # Create comprehensive scan
        scan = manager.create_scan(
            name=f"Full recon: {domain}",
            targets=[domain],
            preset='standard'
        )

        # Run in background
        background_tasks.add_task(run_scan_background, manager, scan.scan_id)

        return {
            "success": True,
            "scan_id": scan.scan_id,
            "domain": domain,
            "message": "Full reconnaissance started",
            "preset": "standard",
            "check_status_at": f"/api/v1/recon/scan/{scan.scan_id}"
        }

    except Exception as e:
        logger.error(f"Full reconnaissance error: {e}")
        raise HTTPException(status_code=500, detail=str(e))
