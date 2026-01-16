#!/usr/bin/env python3
"""
Dark Web Monitoring API Endpoints
FastAPI router for dark web and breach checking services

Endpoints:
- POST /api/v1/darkweb/search - Search dark web
- POST /api/v1/breach/check - Check for breaches
- GET /api/v1/breach/results/{query} - Get breach results
- POST /api/v1/paste/monitor - Monitor paste sites
- GET /api/v1/darkweb/status - Get monitoring status
"""

import asyncio
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any
from fastapi import APIRouter, HTTPException, BackgroundTasks, Query, Depends
from pydantic import BaseModel, Field, EmailStr, validator
import logging
import hashlib
import os

# Import our dark web monitoring modules
from .ahmia_search import AhmiaSearch, DarkWebSearchResult
from .breach_checker import BreachChecker, BreachCheckResult
from .paste_monitor_enhanced import PasteMonitorEnhanced, PasteRecord, PasteSeverity
from .tor_proxy_enhanced import TorProxyEnhanced
from .timescale_storage import DarkWebStorage

logger = logging.getLogger(__name__)

# Create router
router = APIRouter(prefix="/api/v1", tags=["darkweb", "breach"])


# ============== Request/Response Models ==============

class DarkWebSearchRequest(BaseModel):
    """Request model for dark web search"""
    query: str = Field(..., min_length=2, max_length=500, description="Search query")
    engines: Optional[List[str]] = Field(
        default=["ahmia"],
        description="Search engines to use"
    )
    max_results: int = Field(default=50, ge=1, le=200, description="Maximum results")
    safe_search: bool = Field(default=True, description="Enable safe search filtering")
    include_monitoring: bool = Field(
        default=False,
        description="Add query to keyword monitoring"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "query": "cryptocurrency fraud",
                "engines": ["ahmia"],
                "max_results": 50,
                "safe_search": True
            }
        }


class DarkWebSearchResponse(BaseModel):
    """Response model for dark web search"""
    status: str
    query: str
    total_results: int
    engines_used: List[str]
    results: List[Dict[str, Any]]
    search_time_ms: float
    cached: bool = False


class BreachCheckRequest(BaseModel):
    """Request model for breach checking"""
    query: str = Field(..., description="Email, username, domain, or phone to check")
    query_type: str = Field(
        default="auto",
        description="Type of query: email, username, domain, phone, password, or auto"
    )
    sources: Optional[List[str]] = Field(
        default=None,
        description="Sources to check: hibp, dehashed, leakcheck (None = all available)"
    )
    include_credentials: bool = Field(
        default=False,
        description="Include credential details (requires authorization)"
    )

    @validator('query_type')
    def validate_query_type(cls, v):
        valid_types = ['email', 'username', 'domain', 'phone', 'password', 'auto']
        if v not in valid_types:
            raise ValueError(f"query_type must be one of: {valid_types}")
        return v

    class Config:
        json_schema_extra = {
            "example": {
                "query": "test@example.com",
                "query_type": "email",
                "include_credentials": False
            }
        }


class BreachCheckResponse(BaseModel):
    """Response model for breach checking"""
    status: str
    query: str
    query_type: str
    breaches_found: int
    pastes_found: int
    severity: str
    breaches: List[Dict[str, Any]]
    credentials_count: int
    sources_checked: List[str]
    checked_at: str


class PasswordCheckRequest(BaseModel):
    """Request model for password breach checking"""
    password: str = Field(..., min_length=1, description="Password to check")

    class Config:
        json_schema_extra = {
            "example": {
                "password": "MySecurePassword123"
            }
        }


class PasswordCheckResponse(BaseModel):
    """Response model for password check"""
    compromised: bool
    exposure_count: int
    sha1_prefix: str
    message: str


class PasteMonitorRequest(BaseModel):
    """Request model for paste monitoring"""
    keywords: List[str] = Field(..., min_items=1, max_items=50)
    sites: Optional[List[str]] = Field(
        default=None,
        description="Sites to monitor (None = all supported)"
    )
    duration_seconds: Optional[int] = Field(
        default=None,
        ge=60,
        le=86400,
        description="Monitoring duration in seconds"
    )
    min_severity: str = Field(
        default="LOW",
        description="Minimum severity to alert on"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "keywords": ["database dump", "credentials", "api key"],
                "sites": ["pastebin", "github_gist"],
                "duration_seconds": 3600,
                "min_severity": "MEDIUM"
            }
        }


class PasteMonitorResponse(BaseModel):
    """Response model for paste monitoring"""
    status: str
    monitoring_id: str
    keywords: List[str]
    sites: List[str]
    pastes_found: int
    results: List[Dict[str, Any]]


class MonitoringStatusResponse(BaseModel):
    """Response model for monitoring status"""
    tor_status: Dict[str, Any]
    search_stats: Dict[str, Any]
    breach_stats: Dict[str, Any]
    paste_stats: Dict[str, Any]
    active_monitors: int


class BatchBreachCheckRequest(BaseModel):
    """Request model for batch breach checking"""
    queries: List[str] = Field(..., min_items=1, max_items=100)
    query_type: str = Field(default="email")

    class Config:
        json_schema_extra = {
            "example": {
                "queries": ["user1@example.com", "user2@example.com"],
                "query_type": "email"
            }
        }


# ============== Service Instances ==============

# Initialize services (configured via environment variables)
def get_ahmia_search() -> AhmiaSearch:
    """Get Ahmia search instance"""
    darksearch_key = os.getenv("DARKSEARCH_API_KEY")
    return AhmiaSearch(
        darksearch_api_key=darksearch_key,
        cache_duration=3600,
        rate_limit_delay=2.0
    )


def get_breach_checker() -> BreachChecker:
    """Get breach checker instance"""
    return BreachChecker(
        hibp_api_key=os.getenv("HIBP_API_KEY"),
        dehashed_api_key=os.getenv("DEHASHED_API_KEY"),
        dehashed_email=os.getenv("DEHASHED_EMAIL"),
        leakcheck_api_key=os.getenv("LEAKCHECK_API_KEY")
    )


def get_paste_monitor() -> PasteMonitorEnhanced:
    """Get paste monitor instance"""
    return PasteMonitorEnhanced(
        pastebin_api_key=os.getenv("PASTEBIN_API_KEY"),
        github_token=os.getenv("GITHUB_TOKEN")
    )


def get_tor_proxy() -> TorProxyEnhanced:
    """Get Tor proxy instance"""
    return TorProxyEnhanced(
        socks_port=int(os.getenv("TOR_SOCKS_PORT", "9050")),
        control_port=int(os.getenv("TOR_CONTROL_PORT", "9051")),
        auto_rotate_interval=600
    )


def get_storage() -> DarkWebStorage:
    """Get TimescaleDB storage instance"""
    return DarkWebStorage(
        host=os.getenv("TIMESCALE_HOST", "localhost"),
        port=int(os.getenv("TIMESCALE_PORT", "5432")),
        database=os.getenv("TIMESCALE_DB", "apollo_darkweb"),
        user=os.getenv("TIMESCALE_USER", "apollo"),
        password=os.getenv("TIMESCALE_PASSWORD", "")
    )


# ============== Dark Web Search Endpoints ==============

@router.post("/darkweb/search", response_model=DarkWebSearchResponse)
async def search_dark_web(
    request: DarkWebSearchRequest,
    background_tasks: BackgroundTasks,
    search: AhmiaSearch = Depends(get_ahmia_search),
    storage: DarkWebStorage = Depends(get_storage)
):
    """
    Search dark web using clearnet search engines

    This endpoint searches dark web content through Ahmia.fi and optionally
    other search engines. It does NOT require Tor connectivity as it uses
    clearnet APIs to search indexed onion content.

    **Available engines:**
    - ahmia: Ahmia.fi (default, Tor Project affiliated)
    - darksearch: DarkSearch.io (requires API key)

    **Rate limits:**
    - 10 requests per minute per IP
    - 100 requests per hour per API key
    """
    start_time = datetime.utcnow()

    try:
        # Perform search
        results = await search.search(
            query=request.query,
            engines=request.engines,
            max_results=request.max_results,
            safe_search=request.safe_search
        )

        # Convert results to dict
        results_list = [r.to_dict() for r in results]

        # Calculate search time
        search_time = (datetime.utcnow() - start_time).total_seconds() * 1000

        # Store results in background
        background_tasks.add_task(
            storage.store_search_results,
            query=request.query,
            results=results_list
        )

        # Add to monitoring if requested
        if request.include_monitoring:
            background_tasks.add_task(
                search.add_keyword_monitor,
                keyword=request.query,
                check_interval=1800,  # 30 minutes
                engines=request.engines
            )

        return DarkWebSearchResponse(
            status="success",
            query=request.query,
            total_results=len(results_list),
            engines_used=list(search.stats['engines_used']),
            results=results_list,
            search_time_ms=search_time,
            cached=False
        )

    except Exception as e:
        logger.error(f"Dark web search error: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Search failed: {str(e)}"
        )


@router.get("/darkweb/status", response_model=MonitoringStatusResponse)
async def get_monitoring_status(
    search: AhmiaSearch = Depends(get_ahmia_search),
    breach: BreachChecker = Depends(get_breach_checker),
    paste: PasteMonitorEnhanced = Depends(get_paste_monitor),
    tor: TorProxyEnhanced = Depends(get_tor_proxy)
):
    """
    Get current monitoring system status

    Returns status information for all monitoring components including:
    - Tor proxy health and circuit information
    - Search engine statistics
    - Breach checker statistics
    - Paste monitor statistics
    """
    return MonitoringStatusResponse(
        tor_status=tor.get_health_status() if tor.running else {"running": False},
        search_stats=search.get_statistics(),
        breach_stats=breach.get_statistics(),
        paste_stats=paste.get_statistics(),
        active_monitors=len(search.monitored_keywords) + len(paste.monitoring_rules)
    )


# ============== Breach Check Endpoints ==============

@router.post("/breach/check", response_model=BreachCheckResponse)
async def check_breach(
    request: BreachCheckRequest,
    background_tasks: BackgroundTasks,
    checker: BreachChecker = Depends(get_breach_checker),
    storage: DarkWebStorage = Depends(get_storage)
):
    """
    Check email, username, domain, or phone for breaches

    This endpoint checks the provided identifier against multiple breach databases:
    - **HaveIBeenPwned (HIBP)**: Requires API key for email/domain lookups
    - **DeHashed**: Requires API credentials
    - **LeakCheck**: Requires API key

    **Query types:**
    - email: Check email address
    - username: Check username
    - domain: Check domain for breached accounts
    - phone: Check phone number
    - password: Check if password has been exposed (k-anonymity)
    - auto: Automatically detect query type

    **Note:** Credential details are only returned if `include_credentials=true`
    and proper authorization is provided.
    """
    try:
        # Auto-detect query type
        query_type = request.query_type
        if query_type == "auto":
            query_type = _detect_query_type(request.query)

        # Perform appropriate check
        if query_type == "email":
            result = await checker.check_email(
                request.query,
                include_unverified=True,
                check_pastes=True
            )
        elif query_type == "domain":
            result = await checker.check_domain(request.query)
        elif query_type == "username":
            result = await checker.check_username(request.query)
        elif query_type == "password":
            # Password check is handled separately
            pwd_result = await checker.check_password(request.query)
            return BreachCheckResponse(
                status="success",
                query="***REDACTED***",  # Never return the password
                query_type="password",
                breaches_found=pwd_result.get('exposure_count', 0),
                pastes_found=0,
                severity="critical" if pwd_result.get('compromised') else "none",
                breaches=[{
                    'name': 'HIBP Passwords',
                    'exposure_count': pwd_result.get('exposure_count', 0),
                    'compromised': pwd_result.get('compromised')
                }],
                credentials_count=0,
                sources_checked=['hibp_passwords'],
                checked_at=datetime.utcnow().isoformat()
            )
        else:
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported query type: {query_type}"
            )

        # Store results in background
        background_tasks.add_task(
            storage.store_breach_result,
            query=request.query,
            query_type=query_type,
            result=result.to_dict()
        )

        # Build response
        breaches_list = [b.to_dict() for b in result.breaches]

        return BreachCheckResponse(
            status="success",
            query=_mask_query(request.query, query_type),
            query_type=query_type,
            breaches_found=result.breaches_found,
            pastes_found=result.pastes_found,
            severity=result.severity,
            breaches=breaches_list,
            credentials_count=len(result.credentials),
            sources_checked=result.sources_checked,
            checked_at=result.checked_at.isoformat()
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Breach check error: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Breach check failed: {str(e)}"
        )


@router.post("/breach/check/password", response_model=PasswordCheckResponse)
async def check_password_breach(
    request: PasswordCheckRequest,
    checker: BreachChecker = Depends(get_breach_checker)
):
    """
    Check if a password has been exposed in data breaches

    Uses the HIBP Pwned Passwords API with k-anonymity model:
    - Only the first 5 characters of the SHA-1 hash are sent
    - Your full password is NEVER transmitted
    - This is a privacy-preserving way to check password exposure

    **No API key required** for this endpoint.
    """
    try:
        result = await checker.check_password(
            request.password,
            use_k_anonymity=True
        )

        sha1_hash = result.get('sha1_hash', '')

        return PasswordCheckResponse(
            compromised=result.get('compromised', False),
            exposure_count=result.get('exposure_count', 0) or 0,
            sha1_prefix=sha1_hash[:5] if sha1_hash else '',
            message=result.get('message', 'Check completed')
        )

    except Exception as e:
        logger.error(f"Password check error: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Password check failed: {str(e)}"
        )


@router.get("/breach/results/{query}")
async def get_breach_results(
    query: str,
    query_type: str = Query(default="email"),
    storage: DarkWebStorage = Depends(get_storage)
):
    """
    Get cached breach results for a query

    Retrieves previously stored breach check results from the database.
    Results are cached for 24 hours.

    **Parameters:**
    - query: The identifier to look up
    - query_type: Type of query (email, username, domain)
    """
    try:
        results = await storage.get_breach_results(
            query=query,
            query_type=query_type
        )

        if not results:
            raise HTTPException(
                status_code=404,
                detail="No results found for query"
            )

        return {
            "status": "success",
            "query": _mask_query(query, query_type),
            "results": results,
            "cached": True
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get breach results error: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to retrieve results: {str(e)}"
        )


@router.post("/breach/batch")
async def check_breach_batch(
    request: BatchBreachCheckRequest,
    background_tasks: BackgroundTasks,
    checker: BreachChecker = Depends(get_breach_checker),
    storage: DarkWebStorage = Depends(get_storage)
):
    """
    Check multiple identifiers for breaches in batch

    Checks up to 100 identifiers against breach databases.
    Results are returned in a dictionary keyed by the query.

    **Rate limits apply:** Batch requests may take longer due to
    rate limiting on upstream APIs.
    """
    try:
        results = await checker.check_multiple(
            queries=request.queries,
            query_type=request.query_type
        )

        # Store results in background
        for query, result in results.items():
            background_tasks.add_task(
                storage.store_breach_result,
                query=query,
                query_type=request.query_type,
                result=result.to_dict()
            )

        # Format response
        formatted = {}
        for query, result in results.items():
            formatted[_mask_query(query, request.query_type)] = {
                'breaches_found': result.breaches_found,
                'severity': result.severity,
                'sources_checked': result.sources_checked
            }

        return {
            "status": "success",
            "total_queries": len(request.queries),
            "results": formatted
        }

    except Exception as e:
        logger.error(f"Batch breach check error: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Batch check failed: {str(e)}"
        )


# ============== Paste Monitoring Endpoints ==============

@router.post("/paste/monitor", response_model=PasteMonitorResponse)
async def monitor_paste_sites(
    request: PasteMonitorRequest,
    background_tasks: BackgroundTasks,
    monitor: PasteMonitorEnhanced = Depends(get_paste_monitor),
    storage: DarkWebStorage = Depends(get_storage)
):
    """
    Monitor paste sites for specific keywords

    Scans paste sites for content matching the provided keywords.
    Supports both one-time scans and continuous monitoring.

    **Supported sites:**
    - pastebin: Requires Pro API key
    - github_gist: Uses GitHub API (token optional)
    - rentry, dpaste, ghostbin, hastebin: Public sites

    **Severity levels:**
    - INFO: General matches
    - LOW: Some sensitive data
    - MEDIUM: Credentials or PII detected
    - HIGH: Large credential dumps or API keys
    - CRITICAL: Credit cards, SSNs, or private keys
    """
    try:
        # Parse severity
        try:
            min_severity = PasteSeverity[request.min_severity.upper()]
        except KeyError:
            min_severity = PasteSeverity.LOW

        # Add monitoring rules
        rule_id = monitor.add_monitoring_rule(
            name=f"api_monitor_{datetime.utcnow().timestamp()}",
            keywords=request.keywords,
            min_severity=min_severity,
            sites=request.sites
        )

        # Perform initial scan
        sites = request.sites or list(monitor.PASTE_SITES.keys())
        results = await monitor.start_monitoring(
            keywords=request.keywords,
            sites=sites,
            interval=60,
            duration=min(request.duration_seconds or 60, 300)  # Max 5 min for API
        )

        # Store results in background
        for paste in results:
            background_tasks.add_task(
                storage.store_paste_result,
                paste=paste.to_dict()
            )

        return PasteMonitorResponse(
            status="success",
            monitoring_id=rule_id,
            keywords=request.keywords,
            sites=sites,
            pastes_found=len(results),
            results=[p.to_dict() for p in results[:50]]  # Limit response size
        )

    except Exception as e:
        logger.error(f"Paste monitor error: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Paste monitoring failed: {str(e)}"
        )


@router.get("/paste/alerts")
async def get_paste_alerts(
    severity: Optional[str] = None,
    limit: int = Query(default=100, ge=1, le=500),
    monitor: PasteMonitorEnhanced = Depends(get_paste_monitor)
):
    """
    Get paste monitoring alerts

    Returns alerts generated by paste monitoring rules.
    Can be filtered by severity level.
    """
    try:
        alerts = monitor.get_alerts(limit=limit)

        if severity:
            alerts = [
                a for a in alerts
                if a.get('paste', {}).get('severity', '').upper() == severity.upper()
            ]

        return {
            "status": "success",
            "total_alerts": len(alerts),
            "alerts": alerts
        }

    except Exception as e:
        logger.error(f"Get paste alerts error: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get alerts: {str(e)}"
        )


@router.get("/paste/stats")
async def get_paste_stats(
    monitor: PasteMonitorEnhanced = Depends(get_paste_monitor)
):
    """
    Get paste monitoring statistics

    Returns aggregated statistics from paste site monitoring.
    """
    return {
        "status": "success",
        "statistics": monitor.get_statistics()
    }


# ============== Tor Proxy Endpoints ==============

@router.post("/tor/rotate")
async def rotate_tor_circuit(
    tor: TorProxyEnhanced = Depends(get_tor_proxy)
):
    """
    Rotate Tor circuit for new exit node

    Requests a new Tor circuit, changing the exit node IP.
    Useful for avoiding rate limits or obtaining new identity.

    **Note:** Circuit rotation has a cooldown of 10 seconds.
    """
    if not tor.running:
        raise HTTPException(
            status_code=503,
            detail="Tor proxy is not running"
        )

    try:
        success = await tor.rotate_circuit()

        if success:
            circuit_info = tor.get_circuit_info()
            return {
                "status": "success",
                "message": "Circuit rotated successfully",
                "circuit": circuit_info
            }
        else:
            raise HTTPException(
                status_code=500,
                detail="Circuit rotation failed"
            )

    except Exception as e:
        logger.error(f"Circuit rotation error: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Circuit rotation failed: {str(e)}"
        )


@router.get("/tor/status")
async def get_tor_status(
    tor: TorProxyEnhanced = Depends(get_tor_proxy)
):
    """
    Get Tor proxy status and health information

    Returns detailed status including:
    - Connection status
    - Current exit IP
    - Circuit information
    - Health metrics
    """
    return {
        "status": "success",
        "health": tor.get_health_status(),
        "circuit": tor.get_circuit_info(),
        "proxy_url": tor.get_proxy_url()
    }


# ============== Helper Functions ==============

def _detect_query_type(query: str) -> str:
    """Auto-detect query type"""
    import re

    # Email pattern
    if re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', query):
        return 'email'

    # Domain pattern (no @ symbol, has dots)
    if '.' in query and '@' not in query and not query.startswith('+'):
        return 'domain'

    # Phone pattern
    if re.match(r'^[\+]?[(]?[0-9]{3}[)]?[-\s\.]?[0-9]{3}[-\s\.]?[0-9]{4,6}$', query):
        return 'phone'

    # Default to username
    return 'username'


def _mask_query(query: str, query_type: str) -> str:
    """Mask sensitive parts of query for logging/response"""
    if query_type == 'email':
        parts = query.split('@')
        if len(parts) == 2:
            username = parts[0]
            domain = parts[1]
            if len(username) > 2:
                masked = username[:2] + '*' * (len(username) - 2)
            else:
                masked = '*' * len(username)
            return f"{masked}@{domain}"
    elif query_type == 'password':
        return '***REDACTED***'

    return query


# ============== Main Application Integration ==============

def include_router(app):
    """Include dark web router in main FastAPI app"""
    app.include_router(router)


# Example standalone usage
if __name__ == "__main__":
    import uvicorn
    from fastapi import FastAPI

    app = FastAPI(
        title="Apollo Dark Web Monitoring API",
        description="Dark web search, breach checking, and paste monitoring services",
        version="1.0.0"
    )

    include_router(app)

    uvicorn.run(app, host="0.0.0.0", port=8080)
