"""
FastAPI Orchestration Layer for Red Team Operations

Provides unified API for all red team capabilities.
"""

from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Dict, List, Optional, Any
from datetime import datetime
import sys
import os

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from auth_audit.authorization import AuthorizationManager, AuthorizationLevel
from auth_audit.audit_logger import AuditLogger, AuditEventType, AuditSeverity
from auth_audit.legal_disclaimer import LegalDisclaimer
from auth_audit.scope_limiter import ScopeLimiter

from c2_frameworks.c2_orchestrator import C2Orchestrator
from reconnaissance.bbot.bbot_manager import BBOTManager
from bugtrace_ai.network_analyzer import NetworkTrafficAnalyzer
from bugtrace_ai.webapp_analyzer import WebAppSecurityAnalyzer
from exploitation.metasploit_integration import MetasploitManager
from scanning.network_scanner import NetworkScanner
from webapp_testing.web_scanner import WebApplicationScanner
from phishing.gophish_integration import GophishManager
from reporting.report_generator import ReportGenerator, Finding


app = FastAPI(
    title="Apollo Red Team Orchestration API",
    description="AUTHORIZED USE ONLY - Law Enforcement and Authorized Penetration Testing",
    version="1.0.0"
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # Frontend
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize managers
auth_manager = AuthorizationManager()
audit_logger = AuditLogger()
c2_orchestrator = C2Orchestrator()
bbot_manager = BBOTManager()
metasploit = MetasploitManager()
network_scanner = NetworkScanner()
report_generator = ReportGenerator()


# Pydantic models
class AuthorizationRequest(BaseModel):
    operation_type: str
    target_scope: List[str]
    authorized_by: str
    duration_hours: int = 24


class ScanRequest(BaseModel):
    target: str
    scan_type: str = "default"
    ports: Optional[str] = None


class BBOTScanRequest(BaseModel):
    name: str
    targets: List[str]
    modules: Optional[List[str]] = None


class FindingRequest(BaseModel):
    title: str
    severity: str
    description: str
    affected_systems: List[str]
    evidence: Dict
    remediation: str
    cvss_score: Optional[float] = None


# Dependency for authentication
async def verify_api_key(x_api_key: str = Header(...)) -> str:
    """Verify API key"""
    # In production: validate against database
    if not x_api_key:
        raise HTTPException(status_code=401, detail="API key required")
    return x_api_key


@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "name": "Apollo Red Team API",
        "version": "1.0.0",
        "status": "operational",
        "warning": "AUTHORIZED USE ONLY"
    }


@app.get("/disclaimer")
async def get_disclaimer():
    """Get legal disclaimer"""
    return {
        "disclaimer": LegalDisclaimer.display_disclaimer(),
        "acknowledgment_required": True
    }


# Authorization endpoints
@app.post("/authorization/create")
async def create_authorization(
    request: AuthorizationRequest,
    api_key: str = Depends(verify_api_key)
):
    """Create new authorization"""
    try:
        operation_type = AuthorizationLevel(request.operation_type)

        auth = auth_manager.create_authorization(
            operation_type=operation_type,
            target_scope=request.target_scope,
            authorized_by=request.authorized_by,
            duration_hours=request.duration_hours
        )

        audit_logger.log_event(
            event_type=AuditEventType.AUTHORIZATION_CREATED,
            operator=request.authorized_by,
            details=auth.to_dict()
        )

        return {
            "success": True,
            "authorization": auth.to_dict()
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/authorization/list")
async def list_authorizations(api_key: str = Depends(verify_api_key)):
    """List active authorizations"""
    authorizations = auth_manager.list_active_authorizations()
    return {
        "authorizations": [auth.to_dict() for auth in authorizations]
    }


# C2 Framework endpoints
@app.post("/c2/operation/create")
async def create_c2_operation(
    name: str,
    description: str,
    api_key: str = Depends(verify_api_key)
):
    """Create C2 operation"""
    operation_id = c2_orchestrator.create_operation(name, description)
    return {"operation_id": operation_id}


@app.get("/c2/sessions")
async def get_c2_sessions(api_key: str = Depends(verify_api_key)):
    """Get all C2 sessions"""
    return c2_orchestrator.get_all_sessions()


@app.get("/c2/stats")
async def get_c2_stats(api_key: str = Depends(verify_api_key)):
    """Get C2 statistics"""
    return c2_orchestrator.get_combined_stats()


# Reconnaissance endpoints
@app.post("/recon/bbot/scan")
async def create_bbot_scan(
    request: BBOTScanRequest,
    api_key: str = Depends(verify_api_key)
):
    """Create BBOT reconnaissance scan"""
    scan = bbot_manager.create_scan(
        name=request.name,
        targets=request.targets,
        modules=request.modules
    )

    audit_logger.log_event(
        event_type=AuditEventType.OPERATION_STARTED,
        operator="api_user",
        details={"scan_id": scan.scan_id, "targets": request.targets}
    )

    return {"scan_id": scan.scan_id, "status": "created"}


@app.get("/recon/bbot/scan/{scan_id}")
async def get_bbot_scan(scan_id: str, api_key: str = Depends(verify_api_key)):
    """Get BBOT scan results"""
    scan = bbot_manager.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan.to_dict()


# Network scanning endpoints
@app.post("/scan/nmap")
async def nmap_scan(
    request: ScanRequest,
    api_key: str = Depends(verify_api_key)
):
    """Execute Nmap scan"""
    result = network_scanner.nmap_scan(
        target=request.target,
        scan_type=request.scan_type,
        ports=request.ports
    )

    audit_logger.log_event(
        event_type=AuditEventType.TARGET_SCANNED,
        operator="api_user",
        target=request.target,
        details={"scan_type": request.scan_type}
    )

    return result


@app.post("/scan/masscan")
async def masscan_scan(
    target: str,
    ports: str = "1-65535",
    rate: int = 1000,
    api_key: str = Depends(verify_api_key)
):
    """Execute Masscan"""
    result = network_scanner.masscan_scan(target, ports, rate)
    return result


# Reporting endpoints
@app.post("/report/finding")
async def add_finding(
    request: FindingRequest,
    api_key: str = Depends(verify_api_key)
):
    """Add finding to report"""
    finding = Finding(
        title=request.title,
        severity=request.severity,
        description=request.description,
        affected_systems=request.affected_systems,
        evidence=request.evidence,
        remediation=request.remediation,
        cvss_score=request.cvss_score
    )

    report_generator.add_finding(finding)

    audit_logger.log_event(
        event_type=AuditEventType.FINDING_IDENTIFIED,
        operator="api_user",
        severity=AuditSeverity.WARNING,
        details=finding.to_dict()
    )

    return {"success": True, "finding": finding.to_dict()}


@app.get("/report/generate/{format}")
async def generate_report(
    format: str,
    api_key: str = Depends(verify_api_key)
):
    """Generate report in specified format"""
    filename = f"redteam_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.{format}"

    if format == "json":
        path = report_generator.export_json(filename)
    elif format == "markdown" or format == "md":
        path = report_generator.export_markdown(filename)
    elif format == "html":
        path = report_generator.export_html(filename)
    else:
        raise HTTPException(status_code=400, detail="Invalid format")

    return {"success": True, "report_path": path}


# Audit endpoints
@app.get("/audit/events")
async def query_audit_events(
    operation_id: Optional[str] = None,
    target: Optional[str] = None,
    api_key: str = Depends(verify_api_key)
):
    """Query audit events"""
    events = audit_logger.query_events(
        operation_id=operation_id,
        target=target
    )
    return {
        "events": [e.to_dict() for e in events],
        "count": len(events)
    }


@app.get("/audit/verify")
async def verify_audit_integrity(api_key: str = Depends(verify_api_key)):
    """Verify audit log integrity"""
    valid, errors = audit_logger.verify_log_integrity()
    return {
        "valid": valid,
        "errors": errors
    }


# Health check
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "components": {
            "auth_manager": "operational",
            "audit_logger": "operational",
            "c2_orchestrator": "operational"
        }
    }


if __name__ == "__main__":
    import uvicorn

    print(LegalDisclaimer.display_disclaimer())
    print("\n[!] Starting Apollo Red Team API Server...")
    print("[!] AUTHORIZED USE ONLY")

    uvicorn.run(app, host="0.0.0.0", port=8000)
