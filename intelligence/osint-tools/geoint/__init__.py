"""
GEOINT - Geolocation Intelligence System
Comprehensive geolocation intelligence gathering for OSINT operations
"""

from .geoint_engine import GEOINT, GEOINTResult
from .ip_geolocation import IPGeolocation
from .phone_geolocation import PhoneGeolocation
from .photo_geolocation import PhotoGeolocation
from .address_intelligence import AddressIntelligence
from .whois_intelligence import WhoisIntelligence
from .dns_intelligence import DNSIntelligence
from .wifi_geolocation import WiFiGeolocation
from .geofencing import Geofencing, GeofenceZone, GeofenceEvent

__version__ = "1.0.0"
__author__ = "GEOINT Team"
__all__ = [
    'GEOINT',
    'GEOINTResult',
    'IPGeolocation',
    'PhoneGeolocation',
    'PhotoGeolocation',
    'AddressIntelligence',
    'WhoisIntelligence',
    'DNSIntelligence',
    'WiFiGeolocation',
    'Geofencing',
    'GeofenceZone',
    'GeofenceEvent'
]
