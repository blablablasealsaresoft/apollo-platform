"""
Transportation Tracking Module
Apollo Platform - GEOINT Engine

Real-time GPS tracking, geofencing, and movement analysis
using tracker-fob integration.
"""

from .tracker_fob import (
    TrackerFob,
    TrackerDevice,
    LocationUpdate,
    Geofence,
    GeofenceAlert,
    MovementPattern,
    DeviceStatus,
    AlertPriority,
    GeofenceEventType,
    create_tracker
)

from .timescale_location_store import (
    TimescaleLocationStore,
    LocationRecord,
    GeofenceRecord,
    AlertRecord,
    create_location_store
)

from .surveillance_integration import (
    SurveillanceIntegration,
    SurveillanceCamera,
    SurveillanceCorrelation,
    create_surveillance_integration
)

__all__ = [
    # Tracker-Fob
    'TrackerFob',
    'TrackerDevice',
    'LocationUpdate',
    'Geofence',
    'GeofenceAlert',
    'MovementPattern',
    'DeviceStatus',
    'AlertPriority',
    'GeofenceEventType',
    'create_tracker',

    # TimescaleDB Store
    'TimescaleLocationStore',
    'LocationRecord',
    'GeofenceRecord',
    'AlertRecord',
    'create_location_store',

    # Surveillance Integration
    'SurveillanceIntegration',
    'SurveillanceCamera',
    'SurveillanceCorrelation',
    'create_surveillance_integration',
]

__version__ = '1.0.0'
