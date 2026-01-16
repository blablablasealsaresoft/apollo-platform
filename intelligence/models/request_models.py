"""
Pydantic Request Models
All request schemas for API endpoints
"""

from pydantic import BaseModel, Field, EmailStr, validator
from typing import List, Optional, Dict, Any
from datetime import datetime


# OSINT Request Models
class UsernameSearchRequest(BaseModel):
    username: str = Field(..., description="Username to search", min_length=1, max_length=100)
    platforms: Optional[List[str]] = Field(None, description="Specific platforms to search")
    timeout: Optional[int] = Field(30, description="Timeout per platform in seconds")
    check_availability: bool = Field(False, description="Check if username is available")


class EmailIntelRequest(BaseModel):
    email: EmailStr = Field(..., description="Email address to investigate")
    check_breaches: bool = Field(True, description="Check breach databases")
    verify_smtp: bool = Field(False, description="Verify via SMTP")


class PhoneIntelRequest(BaseModel):
    phone_number: str = Field(..., description="Phone number in international format")
    carrier_lookup: bool = Field(True, description="Perform carrier lookup")
    location_lookup: bool = Field(True, description="Perform location lookup")


class DomainScanRequest(BaseModel):
    domain: str = Field(..., description="Domain to scan")
    scan_types: Optional[List[str]] = Field(
        ["subdomain", "port", "tech"],
        description="Types of scans to perform"
    )
    max_depth: int = Field(3, description="Maximum subdomain enumeration depth")


class ImageSearchRequest(BaseModel):
    image_url: Optional[str] = Field(None, description="URL of image to search")
    image_data: Optional[str] = Field(None, description="Base64 encoded image data")
    engines: List[str] = Field(["google", "tineye", "yandex"], description="Search engines to use")
    extract_metadata: bool = Field(True, description="Extract EXIF metadata")


class PublicRecordsRequest(BaseModel):
    first_name: Optional[str] = Field(None, description="First name")
    last_name: Optional[str] = Field(None, description="Last name")
    location: Optional[str] = Field(None, description="City, state, or ZIP code")
    age_range: Optional[tuple[int, int]] = Field(None, description="Age range (min, max)")
    record_types: List[str] = Field(["all"], description="Types of records to search")


# Blockchain Request Models
class WalletInfoRequest(BaseModel):
    address: str = Field(..., description="Wallet address")
    blockchain: str = Field("bitcoin", description="Blockchain network")
    include_transactions: bool = Field(False, description="Include recent transactions")


class TransactionTraceRequest(BaseModel):
    address: str = Field(..., description="Starting address")
    blockchain: str = Field("bitcoin", description="Blockchain network")
    max_hops: int = Field(5, description="Maximum hops to trace", ge=1, le=10)
    min_amount: Optional[float] = Field(None, description="Minimum transaction amount")


# SOCMINT Request Models
class ProfileAggregateRequest(BaseModel):
    username: str = Field(..., description="Username to aggregate")
    platforms: Optional[List[str]] = Field(None, description="Platforms to check")
    deep_scan: bool = Field(False, description="Perform deep profile analysis")


class NetworkAnalysisRequest(BaseModel):
    username: str = Field(..., description="Target username")
    platform: str = Field(..., description="Social media platform")
    depth: int = Field(2, description="Network depth to analyze", ge=1, le=5)
    min_connections: int = Field(10, description="Minimum connections threshold")


# GEOINT Request Models
class GeolocationRequest(BaseModel):
    identifier: str = Field(..., description="IP, phone, or address to geolocate")
    identifier_type: str = Field(..., description="Type: ip, phone, or address")


class ReverseGeocodeRequest(BaseModel):
    latitude: float = Field(..., description="Latitude", ge=-90, le=90)
    longitude: float = Field(..., description="Longitude", ge=-180, le=180)
    include_timezone: bool = Field(True, description="Include timezone information")


# Fusion Request Models
class IntelligenceFusionRequest(BaseModel):
    target: str = Field(..., description="Target identifier")
    target_type: str = Field("person", description="Type: person, organization, address, etc.")
    sources: Optional[List[str]] = Field(None, description="Intelligence sources to use")
    analysis_depth: str = Field("standard", description="Depth: quick, standard, comprehensive")


# Breach Request Models
class BreachSearchRequest(BaseModel):
    query: str = Field(..., description="Email, username, or domain to search")
    query_type: str = Field("email", description="Type: email, username, domain")
    include_passwords: bool = Field(False, description="Include password hashes if available")


# Dark Web Request Models
class DarkWebMonitorRequest(BaseModel):
    keywords: List[str] = Field(..., description="Keywords to monitor")
    sources: List[str] = Field(["marketplace", "forum", "paste"], description="Sources to monitor")
    alert_threshold: str = Field("any", description="Alert threshold: any, multiple, high_confidence")


# Batch Request Models
class BatchUsernameSearchRequest(BaseModel):
    usernames: List[str] = Field(..., description="List of usernames", min_items=1, max_items=100)
    platforms: Optional[List[str]] = Field(None, description="Platforms to search")


class BatchEmailSearchRequest(BaseModel):
    emails: List[str] = Field(..., description="List of emails", min_items=1, max_items=50)
    check_breaches: bool = Field(True, description="Check breach databases")
