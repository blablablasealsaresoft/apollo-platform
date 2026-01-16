"""
Pydantic Response Models
All response schemas for API endpoints
"""

from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime


class BaseResponse(BaseModel):
    """Base response model with success indicator."""
    success: bool = Field(..., description="Request success status")
    timestamp: Optional[datetime] = Field(None, description="Response timestamp")
    request_id: Optional[str] = Field(None, description="Unique request identifier")


class ErrorResponse(BaseResponse):
    """Error response model."""
    success: bool = Field(False, description="Always False for errors")
    error: Dict[str, Any] = Field(..., description="Error details")


# OSINT Response Models
class UsernameSearchResponse(BaseResponse):
    """Response for username search."""
    username: str
    total_platforms_checked: int
    platforms_found: int
    search_duration_seconds: float
    results: List[Dict[str, Any]]


class EmailIntelResponse(BaseResponse):
    """Response for email intelligence."""
    email: str
    valid: bool
    deliverable: bool
    disposable: bool
    breaches: Optional[Dict[str, Any]] = None
    social_accounts: List[Dict[str, Any]]
    reputation: Dict[str, Any]


class PhoneIntelResponse(BaseResponse):
    """Response for phone intelligence."""
    phone_number: str
    valid: bool
    country: str
    carrier: str
    line_type: str
    location: Dict[str, Any]
    reputation: Dict[str, Any]


class DomainScanResponse(BaseResponse):
    """Response for domain scan."""
    domain: str
    scan_id: str
    summary: Dict[str, int]
    subdomains: List[Dict[str, str]]
    technologies: List[Dict[str, str]]
    dns_records: Dict[str, List[str]]


# Blockchain Response Models
class WalletInfoResponse(BaseResponse):
    """Response for wallet information."""
    address: str
    blockchain: str
    balance: str
    balance_usd: float
    transaction_count: int
    risk_score: float
    labels: List[str]


class TransactionTraceResponse(BaseResponse):
    """Response for transaction tracing."""
    start_address: str
    blockchain: str
    total_nodes: int
    total_edges: int
    destination_addresses: List[Dict[str, Any]]


# Fusion Response Models
class IntelligenceFusionResponse(BaseResponse):
    """Response for intelligence fusion."""
    report_id: str
    target: str
    target_type: str
    sources_used: List[str]
    confidence_score: float
    risk_assessment: Dict[str, Any]
    entity_count: int
    link_count: int


# Generic List Response
class ListResponse(BaseResponse):
    """Generic list response."""
    total: int
    items: List[Dict[str, Any]]


# Health Check Response
class HealthCheckResponse(BaseResponse):
    """Health check response."""
    status: str
    services: Dict[str, str]
    uptime_seconds: Optional[float] = None
