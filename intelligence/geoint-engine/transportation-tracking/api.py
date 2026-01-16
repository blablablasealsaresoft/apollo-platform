"""
Geolocation Tracking API - FastAPI Endpoints
Apollo Platform - GEOINT Transportation Tracking

Provides REST API endpoints for location tracking, geofencing,
and movement analysis.
"""

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Query, Depends, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field, validator
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from enum import Enum
import asyncio
import json
import logging
import uuid

# Local imports
from tracker_fob import TrackerFob, LocationUpdate, TrackerDevice, Geofence, GeofenceAlert
from timescale_location_store import TimescaleLocationStore, LocationRecord, GeofenceRecord, AlertRecord

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="Apollo GEOINT Tracking API",
    description="Real-time GPS tracking, geofencing, and movement analysis API",
    version="1.0.0",
    docs_url="/api/geoint/docs",
    redoc_url="/api/geoint/redoc"
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize services
tracker = TrackerFob()
location_store: Optional[TimescaleLocationStore] = None

# WebSocket connection manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, List[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, channel: str):
        await websocket.accept()
        if channel not in self.active_connections:
            self.active_connections[channel] = []
        self.active_connections[channel].append(websocket)
        logger.info(f"WebSocket connected to channel: {channel}")

    def disconnect(self, websocket: WebSocket, channel: str):
        if channel in self.active_connections:
            self.active_connections[channel].remove(websocket)

    async def broadcast(self, channel: str, message: dict):
        if channel in self.active_connections:
            for connection in self.active_connections[channel]:
                try:
                    await connection.send_json(message)
                except:
                    pass

    async def broadcast_all(self, message: dict):
        for channel, connections in self.active_connections.items():
            for connection in connections:
                try:
                    await connection.send_json(message)
                except:
                    pass


ws_manager = ConnectionManager()


# ==================== Pydantic Models ====================

class DevicePriority(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EventType(str, Enum):
    ENTRY = "entry"
    EXIT = "exit"
    LOITERING = "loitering"
    PROXIMITY = "proximity"


class RegisterDeviceRequest(BaseModel):
    device_name: str = Field(..., min_length=1, max_length=255)
    target_description: str = Field(..., min_length=1)
    case_id: str = Field(..., min_length=1)
    authorization: str = Field(..., min_length=1, description="Warrant or legal authorization")
    warrant_expiration: Optional[str] = None
    authorized_by: Optional[str] = None
    update_interval: int = Field(default=30, ge=5, le=3600)
    metadata: Optional[Dict[str, Any]] = None


class DeviceResponse(BaseModel):
    device_id: str
    device_name: str
    target_description: str
    case_id: str
    status: str
    created_at: str
    last_update: Optional[str]
    battery_level: int


class LocationUpdateRequest(BaseModel):
    latitude: float = Field(..., ge=-90, le=90)
    longitude: float = Field(..., ge=-180, le=180)
    altitude: float = Field(default=0)
    speed: float = Field(default=0, ge=0)
    heading: float = Field(default=0, ge=0, le=360)
    accuracy: float = Field(default=10, ge=0)
    battery_level: int = Field(default=100, ge=0, le=100)
    signal_strength: int = Field(default=100, ge=0, le=100)
    metadata: Optional[Dict[str, Any]] = None


class LocationResponse(BaseModel):
    device_id: str
    latitude: float
    longitude: float
    altitude: float
    speed: float
    heading: float
    accuracy: float
    battery_level: int
    signal_strength: int
    timestamp: str


class CreateGeofenceRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    latitude: float = Field(..., ge=-90, le=90)
    longitude: float = Field(..., ge=-180, le=180)
    radius_meters: float = Field(..., gt=0, le=100000)
    alert_on: List[EventType] = Field(default=[EventType.ENTRY, EventType.EXIT])
    priority: DevicePriority = Field(default=DevicePriority.MEDIUM)
    case_id: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class GeofenceResponse(BaseModel):
    geofence_id: str
    name: str
    center_latitude: float
    center_longitude: float
    radius_meters: float
    priority: str
    active: bool
    created_at: str


class AlertResponse(BaseModel):
    alert_id: str
    geofence_id: str
    geofence_name: str
    device_id: str
    event_type: str
    latitude: float
    longitude: float
    priority: str
    timestamp: str
    acknowledged: bool


class MovementPatternResponse(BaseModel):
    pattern_id: str
    device_id: str
    analysis_period: str
    frequent_locations: List[Dict]
    home_location: Optional[Dict]
    work_location: Optional[Dict]
    average_daily_distance_km: float
    confidence_score: float


class ColocationRequest(BaseModel):
    device_ids: List[str] = Field(..., min_items=2)
    distance_threshold_meters: float = Field(default=100, gt=0)
    duration_threshold_seconds: int = Field(default=300, gt=0)
    timeframe_hours: int = Field(default=24, gt=0, le=720)


# ==================== Startup/Shutdown ====================

@app.on_event("startup")
async def startup():
    global location_store
    location_store = TimescaleLocationStore()
    try:
        await location_store.connect()
        await location_store.initialize_schema()
        logger.info("Location store connected and initialized")
    except Exception as e:
        logger.warning(f"Could not connect to TimescaleDB: {e}")
        location_store = None

    # Register alert callback for WebSocket broadcasting
    def alert_callback(alert: GeofenceAlert):
        asyncio.create_task(ws_manager.broadcast(
            f"alerts:{alert.device_id}",
            {
                "type": "geofence_alert",
                "alert_id": alert.alert_id,
                "geofence_id": alert.geofence_id,
                "event_type": alert.event_type.value,
                "priority": alert.priority.value,
                "timestamp": alert.timestamp
            }
        ))

    tracker.on_geofence_alert(alert_callback)


@app.on_event("shutdown")
async def shutdown():
    if location_store:
        await location_store.disconnect()


# ==================== Device Endpoints ====================

@app.post("/api/geoint/devices", response_model=DeviceResponse, tags=["Devices"])
async def register_device(request: RegisterDeviceRequest):
    """
    Register a new tracking device

    Requires legal authorization (warrant number) for tracking.
    """
    device_id = tracker.register_device(
        device_name=request.device_name,
        target_description=request.target_description,
        case_id=request.case_id,
        authorization=request.authorization,
        warrant_expiration=request.warrant_expiration,
        authorized_by=request.authorized_by,
        update_interval=request.update_interval,
        metadata=request.metadata
    )

    device = tracker.get_device(device_id)

    # Store in database
    if location_store:
        await location_store.register_device({
            'device_id': device_id,
            'device_name': request.device_name,
            'target_description': request.target_description,
            'case_id': request.case_id,
            'authorization': request.authorization,
            'warrant_expiration': request.warrant_expiration,
            'authorized_by': request.authorized_by,
            'metadata': request.metadata or {}
        })

    return DeviceResponse(
        device_id=device.device_id,
        device_name=device.device_name,
        target_description=device.target_description,
        case_id=device.case_id,
        status=device.status.value,
        created_at=device.created_at,
        last_update=device.last_update,
        battery_level=device.battery_level
    )


@app.get("/api/geoint/devices", response_model=List[DeviceResponse], tags=["Devices"])
async def list_devices(case_id: Optional[str] = Query(None)):
    """List all tracking devices, optionally filtered by case"""
    devices = tracker.get_all_devices(case_id=case_id)

    return [
        DeviceResponse(
            device_id=d.device_id,
            device_name=d.device_name,
            target_description=d.target_description,
            case_id=d.case_id,
            status=d.status.value,
            created_at=d.created_at,
            last_update=d.last_update,
            battery_level=d.battery_level
        )
        for d in devices
    ]


@app.get("/api/geoint/devices/{device_id}", response_model=DeviceResponse, tags=["Devices"])
async def get_device(device_id: str):
    """Get device details by ID"""
    device = tracker.get_device(device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    return DeviceResponse(
        device_id=device.device_id,
        device_name=device.device_name,
        target_description=device.target_description,
        case_id=device.case_id,
        status=device.status.value,
        created_at=device.created_at,
        last_update=device.last_update,
        battery_level=device.battery_level
    )


@app.delete("/api/geoint/devices/{device_id}", tags=["Devices"])
async def deactivate_device(device_id: str, reason: str = Query(default="Manual deactivation")):
    """Deactivate a tracking device"""
    success = tracker.deactivate_device(device_id, reason)
    if not success:
        raise HTTPException(status_code=404, detail="Device not found")

    if location_store:
        await location_store.update_device_status(device_id, "inactive")

    return {"message": "Device deactivated", "device_id": device_id}


# ==================== Location Endpoints ====================

@app.post("/api/geoint/devices/{device_id}/location", response_model=LocationResponse, tags=["Location"])
async def update_location(device_id: str, request: LocationUpdateRequest, background_tasks: BackgroundTasks):
    """
    Update device location

    This endpoint receives GPS coordinates from the tracking device
    and checks for geofence violations.
    """
    try:
        location = tracker.update_location(
            device_id=device_id,
            latitude=request.latitude,
            longitude=request.longitude,
            altitude=request.altitude,
            speed=request.speed,
            heading=request.heading,
            accuracy=request.accuracy,
            battery_level=request.battery_level,
            signal_strength=request.signal_strength,
            metadata=request.metadata
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

    # Store in database (background task)
    if location_store:
        background_tasks.add_task(
            store_location_async,
            device_id, request, tracker.get_device(device_id).case_id
        )

    # Broadcast to WebSocket subscribers
    background_tasks.add_task(
        ws_manager.broadcast,
        f"location:{device_id}",
        {
            "type": "location_update",
            "device_id": device_id,
            "latitude": request.latitude,
            "longitude": request.longitude,
            "speed": request.speed,
            "heading": request.heading,
            "timestamp": location.timestamp
        }
    )

    return LocationResponse(
        device_id=location.device_id,
        latitude=location.latitude,
        longitude=location.longitude,
        altitude=location.altitude,
        speed=location.speed,
        heading=location.heading,
        accuracy=location.accuracy,
        battery_level=location.battery_level,
        signal_strength=location.signal_strength,
        timestamp=location.timestamp
    )


async def store_location_async(device_id: str, request: LocationUpdateRequest, case_id: str):
    """Background task to store location in database"""
    if location_store:
        record = LocationRecord(
            device_id=device_id,
            latitude=request.latitude,
            longitude=request.longitude,
            altitude=request.altitude,
            speed=request.speed,
            heading=request.heading,
            accuracy=request.accuracy,
            battery_level=request.battery_level,
            signal_strength=request.signal_strength,
            case_id=case_id,
            metadata=request.metadata or {}
        )
        await location_store.insert_location(record)


@app.get("/api/geoint/devices/{device_id}/location", response_model=LocationResponse, tags=["Location"])
async def get_current_location(device_id: str):
    """Get current location of a device"""
    location = tracker.get_current_location(device_id)
    if not location:
        raise HTTPException(status_code=404, detail="No location data available")

    return LocationResponse(
        device_id=location.device_id,
        latitude=location.latitude,
        longitude=location.longitude,
        altitude=location.altitude,
        speed=location.speed,
        heading=location.heading,
        accuracy=location.accuracy,
        battery_level=location.battery_level,
        signal_strength=location.signal_strength,
        timestamp=location.timestamp
    )


@app.get("/api/geoint/devices/{device_id}/history", response_model=List[LocationResponse], tags=["Location"])
async def get_location_history(
    device_id: str,
    start_date: Optional[str] = Query(None, description="ISO format date"),
    end_date: Optional[str] = Query(None, description="ISO format date"),
    limit: int = Query(default=100, ge=1, le=10000)
):
    """Get location history for a device"""
    # Try database first
    if location_store:
        try:
            start_dt = datetime.fromisoformat(start_date) if start_date else None
            end_dt = datetime.fromisoformat(end_date) if end_date else None

            history = await location_store.get_location_history(
                device_id=device_id,
                start_time=start_dt,
                end_time=end_dt,
                limit=limit
            )

            return [
                LocationResponse(
                    device_id=h['device_id'],
                    latitude=h['latitude'],
                    longitude=h['longitude'],
                    altitude=h['altitude'],
                    speed=h['speed'],
                    heading=h['heading'],
                    accuracy=h['accuracy'],
                    battery_level=h['battery_level'],
                    signal_strength=h['signal_strength'],
                    timestamp=h['time'].isoformat()
                )
                for h in history
            ]
        except Exception as e:
            logger.error(f"Database query failed: {e}")

    # Fallback to in-memory
    history = tracker.get_location_history(
        device_id=device_id,
        start_date=start_date,
        end_date=end_date,
        limit=limit
    )

    return [
        LocationResponse(
            device_id=h.device_id,
            latitude=h.latitude,
            longitude=h.longitude,
            altitude=h.altitude,
            speed=h.speed,
            heading=h.heading,
            accuracy=h.accuracy,
            battery_level=h.battery_level,
            signal_strength=h.signal_strength,
            timestamp=h.timestamp
        )
        for h in history
    ]


# ==================== Geofence Endpoints ====================

@app.post("/api/geoint/geofences", response_model=GeofenceResponse, tags=["Geofences"])
async def create_geofence(request: CreateGeofenceRequest):
    """
    Create a new geofence zone

    Geofences trigger alerts when tracked devices enter, exit, or loiter
    within the defined area.
    """
    geofence_id = tracker.create_geofence(
        name=request.name,
        latitude=request.latitude,
        longitude=request.longitude,
        radius_meters=request.radius_meters,
        alert_on=[e.value for e in request.alert_on],
        priority=request.priority.value,
        case_id=request.case_id,
        metadata=request.metadata
    )

    geofence = tracker.get_geofence(geofence_id)

    # Store in database
    if location_store:
        record = GeofenceRecord(
            geofence_id=geofence_id,
            name=request.name,
            center_latitude=request.latitude,
            center_longitude=request.longitude,
            radius_meters=request.radius_meters,
            case_id=request.case_id,
            priority=request.priority.value,
            metadata=request.metadata or {}
        )
        await location_store.create_geofence(record)

    return GeofenceResponse(
        geofence_id=geofence.geofence_id,
        name=geofence.name,
        center_latitude=geofence.center_latitude,
        center_longitude=geofence.center_longitude,
        radius_meters=geofence.radius_meters,
        priority=geofence.priority.value,
        active=geofence.active,
        created_at=geofence.created_at
    )


@app.get("/api/geoint/geofences", response_model=List[GeofenceResponse], tags=["Geofences"])
async def list_geofences(case_id: Optional[str] = Query(None)):
    """List all geofences, optionally filtered by case"""
    geofences = tracker.get_all_geofences(case_id=case_id)

    return [
        GeofenceResponse(
            geofence_id=g.geofence_id,
            name=g.name,
            center_latitude=g.center_latitude,
            center_longitude=g.center_longitude,
            radius_meters=g.radius_meters,
            priority=g.priority.value,
            active=g.active,
            created_at=g.created_at
        )
        for g in geofences
    ]


@app.get("/api/geoint/geofences/{geofence_id}", response_model=GeofenceResponse, tags=["Geofences"])
async def get_geofence(geofence_id: str):
    """Get geofence details by ID"""
    geofence = tracker.get_geofence(geofence_id)
    if not geofence:
        raise HTTPException(status_code=404, detail="Geofence not found")

    return GeofenceResponse(
        geofence_id=geofence.geofence_id,
        name=geofence.name,
        center_latitude=geofence.center_latitude,
        center_longitude=geofence.center_longitude,
        radius_meters=geofence.radius_meters,
        priority=geofence.priority.value,
        active=geofence.active,
        created_at=geofence.created_at
    )


@app.put("/api/geoint/geofences/{geofence_id}", tags=["Geofences"])
async def update_geofence(
    geofence_id: str,
    name: Optional[str] = None,
    radius_meters: Optional[float] = None,
    priority: Optional[DevicePriority] = None,
    active: Optional[bool] = None
):
    """Update geofence properties"""
    updates = {}
    if name:
        updates['name'] = name
    if radius_meters:
        updates['radius_meters'] = radius_meters
    if priority:
        updates['priority'] = priority.value
    if active is not None:
        updates['active'] = active

    success = tracker.update_geofence(geofence_id, **updates)
    if not success:
        raise HTTPException(status_code=404, detail="Geofence not found")

    if location_store:
        await location_store.update_geofence(geofence_id, updates)

    return {"message": "Geofence updated", "geofence_id": geofence_id}


@app.delete("/api/geoint/geofences/{geofence_id}", tags=["Geofences"])
async def delete_geofence(geofence_id: str):
    """Delete a geofence"""
    success = tracker.delete_geofence(geofence_id)
    if not success:
        raise HTTPException(status_code=404, detail="Geofence not found")

    if location_store:
        await location_store.delete_geofence(geofence_id)

    return {"message": "Geofence deleted", "geofence_id": geofence_id}


@app.post("/api/geoint/geofences/{geofence_id}/assign/{device_id}", tags=["Geofences"])
async def assign_geofence_to_device(geofence_id: str, device_id: str):
    """Assign a geofence to monitor for a specific device"""
    success = tracker.assign_geofence_to_device(device_id, geofence_id)
    if not success:
        raise HTTPException(status_code=404, detail="Device or geofence not found")

    return {"message": "Geofence assigned to device", "geofence_id": geofence_id, "device_id": device_id}


# ==================== Alert Endpoints ====================

@app.get("/api/geoint/alerts", response_model=List[AlertResponse], tags=["Alerts"])
async def list_alerts(
    device_id: Optional[str] = Query(None),
    geofence_id: Optional[str] = Query(None),
    acknowledged: Optional[bool] = Query(None),
    limit: int = Query(default=100, ge=1, le=1000)
):
    """
    List geofence alerts

    Returns alerts triggered by geofence violations.
    """
    # Try database first
    if location_store:
        try:
            alerts = await location_store.get_alerts(
                device_id=device_id,
                geofence_id=geofence_id,
                acknowledged=acknowledged,
                limit=limit
            )

            return [
                AlertResponse(
                    alert_id=a['alert_id'],
                    geofence_id=a['geofence_id'],
                    geofence_name="",  # Would need join
                    device_id=a['device_id'],
                    event_type=a['event_type'],
                    latitude=a['latitude'],
                    longitude=a['longitude'],
                    priority=a['priority'],
                    timestamp=a['time'].isoformat(),
                    acknowledged=a['acknowledged']
                )
                for a in alerts
            ]
        except Exception as e:
            logger.error(f"Database query failed: {e}")

    # Fallback to in-memory
    alerts = tracker.get_alerts(
        device_id=device_id,
        geofence_id=geofence_id,
        acknowledged=acknowledged,
        limit=limit
    )

    return [
        AlertResponse(
            alert_id=a.alert_id,
            geofence_id=a.geofence_id,
            geofence_name=a.geofence_name,
            device_id=a.device_id,
            event_type=a.event_type.value,
            latitude=a.location.latitude,
            longitude=a.location.longitude,
            priority=a.priority.value,
            timestamp=a.timestamp,
            acknowledged=a.acknowledged
        )
        for a in alerts
    ]


@app.post("/api/geoint/alerts/{alert_id}/acknowledge", tags=["Alerts"])
async def acknowledge_alert(alert_id: str):
    """Acknowledge an alert"""
    success = tracker.acknowledge_alert(alert_id)
    if not success:
        raise HTTPException(status_code=404, detail="Alert not found")

    if location_store:
        await location_store.acknowledge_alert(alert_id)

    return {"message": "Alert acknowledged", "alert_id": alert_id}


@app.get("/api/geoint/alerts/unacknowledged/count", tags=["Alerts"])
async def get_unacknowledged_count(device_id: Optional[str] = Query(None)):
    """Get count of unacknowledged alerts"""
    if location_store:
        count = await location_store.get_unacknowledged_alerts_count(device_id)
        return {"count": count}

    alerts = tracker.get_alerts(device_id=device_id, acknowledged=False)
    return {"count": len(alerts)}


# ==================== Analysis Endpoints ====================

@app.get("/api/geoint/devices/{device_id}/patterns", response_model=MovementPatternResponse, tags=["Analysis"])
async def analyze_movement_patterns(
    device_id: str,
    days: int = Query(default=30, ge=1, le=365)
):
    """
    Analyze movement patterns for a device

    Uses historical location data to identify patterns, frequent locations,
    and predict future movements.
    """
    pattern = tracker.analyze_movement_patterns(device_id, days=days)

    # Store pattern in database
    if location_store:
        await location_store.save_movement_pattern({
            'pattern_id': pattern.pattern_id,
            'device_id': pattern.device_id,
            'analysis_period': pattern.analysis_period,
            'frequent_locations': pattern.frequent_locations,
            'travel_patterns': pattern.travel_patterns,
            'home_location': pattern.home_location,
            'work_location': pattern.work_location,
            'suspicious_activities': pattern.suspicious_activities,
            'predicted_locations': pattern.predicted_locations,
            'average_daily_distance_km': pattern.average_daily_distance_km,
            'confidence_score': pattern.confidence_score
        })

    return MovementPatternResponse(
        pattern_id=pattern.pattern_id,
        device_id=pattern.device_id,
        analysis_period=pattern.analysis_period,
        frequent_locations=pattern.frequent_locations,
        home_location=pattern.home_location,
        work_location=pattern.work_location,
        average_daily_distance_km=pattern.average_daily_distance_km,
        confidence_score=pattern.confidence_score
    )


@app.post("/api/geoint/analysis/colocation", tags=["Analysis"])
async def detect_colocation(request: ColocationRequest):
    """
    Detect co-location events between multiple devices

    Identifies when multiple tracked devices are in close proximity,
    potentially indicating meetings or coordinated activity.
    """
    colocations = tracker.detect_colocation(
        device_ids=request.device_ids,
        distance_threshold=request.distance_threshold_meters,
        duration_threshold=request.duration_threshold_seconds,
        timeframe_hours=request.timeframe_hours
    )

    return {
        "colocations": colocations,
        "total_events": len(colocations),
        "analysis_timeframe_hours": request.timeframe_hours
    }


@app.get("/api/geoint/devices/{device_id}/statistics", tags=["Analysis"])
async def get_movement_statistics(
    device_id: str,
    start_date: str = Query(..., description="ISO format date"),
    end_date: str = Query(..., description="ISO format date")
):
    """Get movement statistics for a device"""
    if not location_store:
        raise HTTPException(status_code=503, detail="Database not available")

    start_dt = datetime.fromisoformat(start_date)
    end_dt = datetime.fromisoformat(end_date)

    stats = await location_store.get_movement_statistics(device_id, start_dt, end_dt)
    return stats


@app.get("/api/geoint/devices/{device_id}/frequent-locations", tags=["Analysis"])
async def get_frequent_locations(
    device_id: str,
    start_date: str = Query(..., description="ISO format date"),
    end_date: str = Query(..., description="ISO format date"),
    min_visits: int = Query(default=5, ge=1)
):
    """Get frequently visited locations for a device"""
    if not location_store:
        raise HTTPException(status_code=503, detail="Database not available")

    start_dt = datetime.fromisoformat(start_date)
    end_dt = datetime.fromisoformat(end_date)

    locations = await location_store.get_frequent_locations(
        device_id, start_dt, end_dt, min_count=min_visits
    )
    return {"frequent_locations": locations}


# ==================== WebSocket Endpoints ====================

@app.websocket("/ws/geoint/location/{device_id}")
async def websocket_location_stream(websocket: WebSocket, device_id: str):
    """
    WebSocket endpoint for real-time location updates

    Subscribe to receive location updates for a specific device.
    """
    await ws_manager.connect(websocket, f"location:{device_id}")
    try:
        while True:
            # Keep connection alive
            data = await websocket.receive_text()
            # Handle any commands from client
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket, f"location:{device_id}")


@app.websocket("/ws/geoint/alerts/{device_id}")
async def websocket_alert_stream(websocket: WebSocket, device_id: str):
    """
    WebSocket endpoint for real-time geofence alerts

    Subscribe to receive alerts for a specific device.
    """
    await ws_manager.connect(websocket, f"alerts:{device_id}")
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket, f"alerts:{device_id}")


@app.websocket("/ws/geoint/case/{case_id}")
async def websocket_case_stream(websocket: WebSocket, case_id: str):
    """
    WebSocket endpoint for all updates related to a case

    Subscribe to receive all location and alert updates for devices
    associated with a specific case.
    """
    await ws_manager.connect(websocket, f"case:{case_id}")
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket, f"case:{case_id}")


# ==================== Export Endpoints ====================

@app.get("/api/geoint/devices/{device_id}/export", tags=["Export"])
async def export_tracking_data(
    device_id: str,
    format: str = Query(default="json", regex="^(json|kml)$"),
    start_date: Optional[str] = Query(None),
    end_date: Optional[str] = Query(None)
):
    """
    Export tracking data for a device

    Supports JSON and KML formats for use in mapping applications.
    """
    history = tracker.get_location_history(
        device_id=device_id,
        start_date=start_date,
        end_date=end_date,
        limit=10000
    )

    if format == "json":
        data = {
            "device_id": device_id,
            "locations": [
                {
                    "latitude": h.latitude,
                    "longitude": h.longitude,
                    "altitude": h.altitude,
                    "speed": h.speed,
                    "heading": h.heading,
                    "timestamp": h.timestamp
                }
                for h in history
            ],
            "exported_at": datetime.now().isoformat()
        }
        return data

    elif format == "kml":
        kml = generate_kml(device_id, history)
        return StreamingResponse(
            iter([kml]),
            media_type="application/vnd.google-earth.kml+xml",
            headers={"Content-Disposition": f"attachment; filename={device_id}.kml"}
        )


def generate_kml(device_id: str, history: List[LocationUpdate]) -> str:
    """Generate KML from location history"""
    coordinates = '\n'.join([
        f"          {loc.longitude},{loc.latitude},{loc.altitude}"
        for loc in history
    ])

    placemarks = ''
    for loc in history[::max(1, len(history)//20)]:  # Sample points
        placemarks += f'''
    <Placemark>
      <name>{loc.timestamp}</name>
      <Point>
        <coordinates>{loc.longitude},{loc.latitude},{loc.altitude}</coordinates>
      </Point>
    </Placemark>'''

    return f'''<?xml version="1.0" encoding="UTF-8"?>
<kml xmlns="http://www.opengis.net/kml/2.2">
  <Document>
    <name>Tracking Data - {device_id}</name>
    <Style id="trackStyle">
      <LineStyle>
        <color>ff0000ff</color>
        <width>2</width>
      </LineStyle>
    </Style>
    <Placemark>
      <name>Movement Track</name>
      <styleUrl>#trackStyle</styleUrl>
      <LineString>
        <coordinates>
{coordinates}
        </coordinates>
      </LineString>
    </Placemark>
{placemarks}
  </Document>
</kml>'''


# ==================== Health Endpoints ====================

@app.get("/api/geoint/health", tags=["Health"])
async def health_check():
    """Health check endpoint"""
    db_status = "connected" if location_store and location_store._pool else "disconnected"

    return {
        "status": "healthy",
        "database": db_status,
        "active_devices": len(tracker.devices),
        "active_geofences": len(tracker.geofences),
        "pending_alerts": len([a for a in tracker.alerts if not a.acknowledged])
    }


# Run with: uvicorn api:app --host 0.0.0.0 --port 8000 --reload
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
