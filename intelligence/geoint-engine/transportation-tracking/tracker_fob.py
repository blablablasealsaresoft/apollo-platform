"""
Tracker-Fob Integration - Real-Time GPS Tracking Engine
Apollo Platform - GEOINT Transportation Tracking

Implements real-time location tracking, geofencing, and movement pattern analysis
for criminal investigations using the tracker-fob integration model.
"""

import asyncio
import json
import logging
import uuid
from datetime import datetime, timedelta
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any, Callable, AsyncIterator
from enum import Enum
import math
import hashlib
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class DeviceStatus(Enum):
    """Tracker device status"""
    ACTIVE = "active"
    INACTIVE = "inactive"
    OFFLINE = "offline"
    LOW_BATTERY = "low_battery"
    MAINTENANCE = "maintenance"


class AlertPriority(Enum):
    """Alert priority levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    EMERGENCY = "emergency"


class GeofenceEventType(Enum):
    """Geofence event types"""
    ENTRY = "entry"
    EXIT = "exit"
    LOITERING = "loitering"
    PROXIMITY = "proximity"


@dataclass
class LocationUpdate:
    """Real-time location update from tracker"""
    device_id: str
    latitude: float
    longitude: float
    altitude: float = 0.0
    speed: float = 0.0  # km/h
    heading: float = 0.0  # degrees
    accuracy: float = 10.0  # meters
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    battery_level: int = 100
    signal_strength: int = 100
    metadata: Dict = field(default_factory=dict)

    @property
    def coordinates(self) -> tuple:
        return (self.latitude, self.longitude)


@dataclass
class TrackerDevice:
    """GPS Tracking Device"""
    device_id: str
    device_name: str
    target_description: str
    case_id: str
    authorization: str  # Warrant or legal authorization
    status: DeviceStatus = DeviceStatus.ACTIVE
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    last_update: Optional[str] = None
    last_location: Optional[LocationUpdate] = None
    update_interval: int = 30  # seconds
    battery_level: int = 100
    metadata: Dict = field(default_factory=dict)

    # Legal compliance
    warrant_expiration: Optional[str] = None
    authorized_by: Optional[str] = None

    # Tracking configuration
    geofence_ids: List[str] = field(default_factory=list)
    alert_contacts: List[str] = field(default_factory=list)


@dataclass
class Geofence:
    """Geofence zone definition"""
    geofence_id: str
    name: str
    center_latitude: float
    center_longitude: float
    radius_meters: float
    alert_on: List[GeofenceEventType] = field(default_factory=lambda: [GeofenceEventType.ENTRY])
    priority: AlertPriority = AlertPriority.MEDIUM
    case_id: Optional[str] = None
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    active: bool = True
    metadata: Dict = field(default_factory=dict)


@dataclass
class GeofenceAlert:
    """Geofence violation alert"""
    alert_id: str
    geofence_id: str
    geofence_name: str
    device_id: str
    event_type: GeofenceEventType
    location: LocationUpdate
    priority: AlertPriority
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    acknowledged: bool = False
    metadata: Dict = field(default_factory=dict)


@dataclass
class MovementPattern:
    """Analyzed movement pattern"""
    pattern_id: str
    device_id: str
    analysis_period: str
    frequent_locations: List[Dict] = field(default_factory=list)
    travel_patterns: List[Dict] = field(default_factory=list)
    average_daily_distance_km: float = 0.0
    home_location: Optional[Dict] = None
    work_location: Optional[Dict] = None
    suspicious_activities: List[Dict] = field(default_factory=list)
    predicted_locations: List[Dict] = field(default_factory=list)
    confidence_score: float = 0.0


class TrackerFob:
    """
    Main Tracker-Fob Integration Class

    Provides real-time GPS tracking, geofencing, and movement analysis
    for criminal investigations.
    """

    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize TrackerFob system

        Args:
            config: Configuration dictionary
        """
        self.config = config or self._default_config()

        # Storage
        self.devices: Dict[str, TrackerDevice] = {}
        self.geofences: Dict[str, Geofence] = {}
        self.location_history: Dict[str, List[LocationUpdate]] = {}
        self.alerts: List[GeofenceAlert] = []

        # Callbacks
        self.location_callbacks: List[Callable] = []
        self.alert_callbacks: List[Callable] = []

        # State
        self._active_streams: Dict[str, bool] = {}

        logger.info("TrackerFob system initialized")

    def _default_config(self) -> Dict:
        """Return default configuration"""
        return {
            'default_update_interval': 30,
            'high_priority_interval': 10,
            'battery_saver_interval': 300,
            'accuracy_threshold': 10,
            'max_history_per_device': 10000,
            'geofence_check_interval': 5,
            'loitering_threshold_minutes': 10,
            'alert_retention_days': 90,
            'storage_path': './tracker_data'
        }

    # ==================== Device Management ====================

    def register_device(self,
                       device_name: str,
                       target_description: str,
                       case_id: str,
                       authorization: str,
                       warrant_expiration: Optional[str] = None,
                       authorized_by: Optional[str] = None,
                       update_interval: int = 30,
                       metadata: Optional[Dict] = None) -> str:
        """
        Register a new tracking device

        Args:
            device_name: Name/identifier for the device
            target_description: Description of what's being tracked
            case_id: Associated case ID
            authorization: Legal authorization (warrant number)
            warrant_expiration: When authorization expires
            authorized_by: Who authorized the tracking
            update_interval: Location update interval in seconds
            metadata: Additional metadata

        Returns:
            Device ID
        """
        device_id = f"TRACKER_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8].upper()}"

        device = TrackerDevice(
            device_id=device_id,
            device_name=device_name,
            target_description=target_description,
            case_id=case_id,
            authorization=authorization,
            warrant_expiration=warrant_expiration,
            authorized_by=authorized_by,
            update_interval=update_interval,
            metadata=metadata or {}
        )

        self.devices[device_id] = device
        self.location_history[device_id] = []

        logger.info(f"Registered new tracking device: {device_id} - {device_name}")
        self._log_audit_event('device_registered', device_id, {
            'case_id': case_id,
            'authorization': authorization
        })

        return device_id

    def deactivate_device(self, device_id: str, reason: str = "Manual deactivation") -> bool:
        """Deactivate a tracking device"""
        if device_id not in self.devices:
            return False

        self.devices[device_id].status = DeviceStatus.INACTIVE
        self._active_streams[device_id] = False

        logger.info(f"Deactivated device {device_id}: {reason}")
        self._log_audit_event('device_deactivated', device_id, {'reason': reason})

        return True

    def get_device(self, device_id: str) -> Optional[TrackerDevice]:
        """Get device by ID"""
        return self.devices.get(device_id)

    def get_all_devices(self, case_id: Optional[str] = None) -> List[TrackerDevice]:
        """Get all devices, optionally filtered by case"""
        devices = list(self.devices.values())
        if case_id:
            devices = [d for d in devices if d.case_id == case_id]
        return devices

    # ==================== Location Tracking ====================

    def update_location(self, device_id: str,
                       latitude: float,
                       longitude: float,
                       altitude: float = 0.0,
                       speed: float = 0.0,
                       heading: float = 0.0,
                       accuracy: float = 10.0,
                       battery_level: int = 100,
                       signal_strength: int = 100,
                       metadata: Optional[Dict] = None) -> LocationUpdate:
        """
        Update device location

        Args:
            device_id: Device ID
            latitude: Latitude coordinate
            longitude: Longitude coordinate
            altitude: Altitude in meters
            speed: Speed in km/h
            heading: Heading in degrees
            accuracy: Location accuracy in meters
            battery_level: Battery percentage
            signal_strength: Signal strength percentage
            metadata: Additional data

        Returns:
            LocationUpdate object
        """
        if device_id not in self.devices:
            raise ValueError(f"Device not found: {device_id}")

        location = LocationUpdate(
            device_id=device_id,
            latitude=latitude,
            longitude=longitude,
            altitude=altitude,
            speed=speed,
            heading=heading,
            accuracy=accuracy,
            battery_level=battery_level,
            signal_strength=signal_strength,
            metadata=metadata or {}
        )

        # Update device
        device = self.devices[device_id]
        device.last_update = location.timestamp
        device.last_location = location
        device.battery_level = battery_level

        # Check battery level
        if battery_level < 20:
            device.status = DeviceStatus.LOW_BATTERY

        # Add to history
        self.location_history[device_id].append(location)

        # Limit history size
        max_history = self.config['max_history_per_device']
        if len(self.location_history[device_id]) > max_history:
            self.location_history[device_id] = self.location_history[device_id][-max_history:]

        # Check geofences
        geofence_alerts = self._check_geofences(device_id, location)

        # Notify callbacks
        for callback in self.location_callbacks:
            try:
                callback(location)
            except Exception as e:
                logger.error(f"Location callback error: {e}")

        # Process alerts
        for alert in geofence_alerts:
            self._process_alert(alert)

        return location

    def get_current_location(self, device_id: str) -> Optional[LocationUpdate]:
        """Get current location of a device"""
        device = self.devices.get(device_id)
        if device:
            return device.last_location
        return None

    def get_location_history(self,
                            device_id: str,
                            start_date: Optional[str] = None,
                            end_date: Optional[str] = None,
                            limit: int = 1000) -> List[LocationUpdate]:
        """
        Get location history for a device

        Args:
            device_id: Device ID
            start_date: Start date filter (ISO format)
            end_date: End date filter (ISO format)
            limit: Maximum records to return

        Returns:
            List of LocationUpdate objects
        """
        if device_id not in self.location_history:
            return []

        history = self.location_history[device_id]

        # Apply date filters
        if start_date:
            start_dt = datetime.fromisoformat(start_date)
            history = [h for h in history if datetime.fromisoformat(h.timestamp) >= start_dt]

        if end_date:
            end_dt = datetime.fromisoformat(end_date)
            history = [h for h in history if datetime.fromisoformat(h.timestamp) <= end_dt]

        return history[-limit:]

    async def stream_location(self,
                             device_id: str,
                             update_interval: Optional[int] = None) -> AsyncIterator[LocationUpdate]:
        """
        Stream real-time location updates

        Args:
            device_id: Device ID to stream
            update_interval: Override default update interval

        Yields:
            LocationUpdate objects
        """
        if device_id not in self.devices:
            raise ValueError(f"Device not found: {device_id}")

        device = self.devices[device_id]
        interval = update_interval or device.update_interval

        self._active_streams[device_id] = True
        logger.info(f"Started location stream for device {device_id}")

        while self._active_streams.get(device_id, False):
            if device.last_location:
                yield device.last_location
            await asyncio.sleep(interval)

        logger.info(f"Stopped location stream for device {device_id}")

    def stop_stream(self, device_id: str):
        """Stop streaming for a device"""
        self._active_streams[device_id] = False

    # ==================== Geofence Management ====================

    def create_geofence(self,
                       name: str,
                       latitude: float,
                       longitude: float,
                       radius_meters: float,
                       alert_on: Optional[List[str]] = None,
                       priority: str = "medium",
                       case_id: Optional[str] = None,
                       metadata: Optional[Dict] = None) -> str:
        """
        Create a geofence zone

        Args:
            name: Geofence name
            latitude: Center latitude
            longitude: Center longitude
            radius_meters: Radius in meters
            alert_on: List of event types to alert on
            priority: Alert priority level
            case_id: Associated case ID
            metadata: Additional data

        Returns:
            Geofence ID
        """
        geofence_id = f"GEOFENCE_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8].upper()}"

        # Parse event types
        event_types = []
        if alert_on:
            for event in alert_on:
                try:
                    event_types.append(GeofenceEventType(event.lower()))
                except ValueError:
                    logger.warning(f"Unknown event type: {event}")
        else:
            event_types = [GeofenceEventType.ENTRY, GeofenceEventType.EXIT]

        # Parse priority
        try:
            alert_priority = AlertPriority(priority.lower())
        except ValueError:
            alert_priority = AlertPriority.MEDIUM

        geofence = Geofence(
            geofence_id=geofence_id,
            name=name,
            center_latitude=latitude,
            center_longitude=longitude,
            radius_meters=radius_meters,
            alert_on=event_types,
            priority=alert_priority,
            case_id=case_id,
            metadata=metadata or {}
        )

        self.geofences[geofence_id] = geofence

        logger.info(f"Created geofence: {geofence_id} - {name}")
        return geofence_id

    def delete_geofence(self, geofence_id: str) -> bool:
        """Delete a geofence"""
        if geofence_id in self.geofences:
            del self.geofences[geofence_id]
            logger.info(f"Deleted geofence: {geofence_id}")
            return True
        return False

    def update_geofence(self, geofence_id: str, **kwargs) -> bool:
        """Update geofence properties"""
        if geofence_id not in self.geofences:
            return False

        geofence = self.geofences[geofence_id]

        for key, value in kwargs.items():
            if hasattr(geofence, key):
                setattr(geofence, key, value)

        return True

    def get_geofence(self, geofence_id: str) -> Optional[Geofence]:
        """Get geofence by ID"""
        return self.geofences.get(geofence_id)

    def get_all_geofences(self, case_id: Optional[str] = None) -> List[Geofence]:
        """Get all geofences, optionally filtered by case"""
        geofences = list(self.geofences.values())
        if case_id:
            geofences = [g for g in geofences if g.case_id == case_id]
        return geofences

    def assign_geofence_to_device(self, device_id: str, geofence_id: str) -> bool:
        """Assign a geofence to monitor for a device"""
        if device_id not in self.devices:
            return False
        if geofence_id not in self.geofences:
            return False

        device = self.devices[device_id]
        if geofence_id not in device.geofence_ids:
            device.geofence_ids.append(geofence_id)

        return True

    def _check_geofences(self, device_id: str, location: LocationUpdate) -> List[GeofenceAlert]:
        """Check if location violates any geofences"""
        alerts = []
        device = self.devices.get(device_id)

        if not device:
            return alerts

        # Get previous location
        history = self.location_history.get(device_id, [])
        previous_location = history[-2] if len(history) >= 2 else None

        # Check all geofences assigned to device (or all if none assigned)
        geofence_ids = device.geofence_ids or list(self.geofences.keys())

        for geofence_id in geofence_ids:
            geofence = self.geofences.get(geofence_id)
            if not geofence or not geofence.active:
                continue

            # Calculate distance from geofence center
            distance = self._calculate_distance(
                location.latitude, location.longitude,
                geofence.center_latitude, geofence.center_longitude
            )

            currently_inside = distance <= geofence.radius_meters

            # Check previous position if available
            previously_inside = False
            if previous_location:
                prev_distance = self._calculate_distance(
                    previous_location.latitude, previous_location.longitude,
                    geofence.center_latitude, geofence.center_longitude
                )
                previously_inside = prev_distance <= geofence.radius_meters

            # Check for entry
            if currently_inside and not previously_inside:
                if GeofenceEventType.ENTRY in geofence.alert_on:
                    alert = self._create_alert(
                        geofence, device_id, GeofenceEventType.ENTRY, location
                    )
                    alerts.append(alert)

            # Check for exit
            elif not currently_inside and previously_inside:
                if GeofenceEventType.EXIT in geofence.alert_on:
                    alert = self._create_alert(
                        geofence, device_id, GeofenceEventType.EXIT, location
                    )
                    alerts.append(alert)

            # Check for loitering
            if currently_inside and GeofenceEventType.LOITERING in geofence.alert_on:
                loitering = self._check_loitering(device_id, geofence)
                if loitering:
                    alert = self._create_alert(
                        geofence, device_id, GeofenceEventType.LOITERING, location
                    )
                    alerts.append(alert)

        return alerts

    def _check_loitering(self, device_id: str, geofence: Geofence) -> bool:
        """Check if device has been loitering in geofence"""
        threshold = self.config['loitering_threshold_minutes']
        history = self.location_history.get(device_id, [])

        if not history:
            return False

        # Check recent history for continuous presence
        cutoff_time = datetime.now() - timedelta(minutes=threshold)
        recent_in_zone = 0
        total_recent = 0

        for loc in reversed(history):
            loc_time = datetime.fromisoformat(loc.timestamp)
            if loc_time < cutoff_time:
                break

            total_recent += 1
            distance = self._calculate_distance(
                loc.latitude, loc.longitude,
                geofence.center_latitude, geofence.center_longitude
            )
            if distance <= geofence.radius_meters:
                recent_in_zone += 1

        # If mostly in zone for threshold period
        if total_recent > 0 and (recent_in_zone / total_recent) > 0.8:
            return True

        return False

    def _create_alert(self,
                     geofence: Geofence,
                     device_id: str,
                     event_type: GeofenceEventType,
                     location: LocationUpdate) -> GeofenceAlert:
        """Create a geofence alert"""
        alert_id = f"ALERT_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8].upper()}"

        alert = GeofenceAlert(
            alert_id=alert_id,
            geofence_id=geofence.geofence_id,
            geofence_name=geofence.name,
            device_id=device_id,
            event_type=event_type,
            location=location,
            priority=geofence.priority,
            metadata={
                'case_id': geofence.case_id,
                'device_name': self.devices.get(device_id, {}).device_name if device_id in self.devices else None
            }
        )

        self.alerts.append(alert)
        logger.warning(f"Geofence alert: {event_type.value} - {geofence.name} - Device {device_id}")

        return alert

    def _process_alert(self, alert: GeofenceAlert):
        """Process and dispatch alert"""
        for callback in self.alert_callbacks:
            try:
                callback(alert)
            except Exception as e:
                logger.error(f"Alert callback error: {e}")

        # Log for audit
        self._log_audit_event('geofence_alert', alert.device_id, {
            'alert_id': alert.alert_id,
            'geofence_id': alert.geofence_id,
            'event_type': alert.event_type.value,
            'priority': alert.priority.value
        })

    def get_alerts(self,
                   device_id: Optional[str] = None,
                   geofence_id: Optional[str] = None,
                   acknowledged: Optional[bool] = None,
                   limit: int = 100) -> List[GeofenceAlert]:
        """Get alerts with optional filters"""
        alerts = self.alerts

        if device_id:
            alerts = [a for a in alerts if a.device_id == device_id]
        if geofence_id:
            alerts = [a for a in alerts if a.geofence_id == geofence_id]
        if acknowledged is not None:
            alerts = [a for a in alerts if a.acknowledged == acknowledged]

        return list(reversed(alerts))[:limit]

    def acknowledge_alert(self, alert_id: str) -> bool:
        """Acknowledge an alert"""
        for alert in self.alerts:
            if alert.alert_id == alert_id:
                alert.acknowledged = True
                return True
        return False

    # ==================== Movement Analysis ====================

    def analyze_movement_patterns(self,
                                  device_id: str,
                                  days: int = 30) -> MovementPattern:
        """
        Analyze movement patterns for a device

        Args:
            device_id: Device ID to analyze
            days: Number of days to analyze

        Returns:
            MovementPattern analysis
        """
        pattern_id = f"PATTERN_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{device_id}"

        pattern = MovementPattern(
            pattern_id=pattern_id,
            device_id=device_id,
            analysis_period=f"Last {days} days"
        )

        history = self.location_history.get(device_id, [])
        if not history:
            return pattern

        # Filter to analysis period
        cutoff = datetime.now() - timedelta(days=days)
        filtered_history = [
            h for h in history
            if datetime.fromisoformat(h.timestamp) >= cutoff
        ]

        if not filtered_history:
            return pattern

        # Calculate total distance
        total_distance = 0
        for i in range(1, len(filtered_history)):
            distance = self._calculate_distance(
                filtered_history[i-1].latitude, filtered_history[i-1].longitude,
                filtered_history[i].latitude, filtered_history[i].longitude
            )
            total_distance += distance

        pattern.average_daily_distance_km = (total_distance / 1000) / days

        # Find frequent locations using clustering
        pattern.frequent_locations = self._find_frequent_locations(filtered_history)

        # Identify home/work
        if pattern.frequent_locations:
            # Most frequent overnight = home
            pattern.home_location = self._identify_home(filtered_history)
            # Most frequent during work hours = work
            pattern.work_location = self._identify_work(filtered_history)

        # Analyze travel patterns
        pattern.travel_patterns = self._analyze_travel_patterns(filtered_history)

        # Detect suspicious activities
        pattern.suspicious_activities = self._detect_suspicious_activities(filtered_history)

        # Predict future locations
        pattern.predicted_locations = self._predict_locations(filtered_history)

        # Calculate confidence
        pattern.confidence_score = self._calculate_pattern_confidence(pattern)

        return pattern

    def _find_frequent_locations(self, history: List[LocationUpdate]) -> List[Dict]:
        """Find frequently visited locations using simple clustering"""
        if not history:
            return []

        # Grid-based clustering
        grid_size = 0.001  # ~100m grid
        location_counts = {}

        for loc in history:
            grid_key = (
                round(loc.latitude / grid_size) * grid_size,
                round(loc.longitude / grid_size) * grid_size
            )

            if grid_key not in location_counts:
                location_counts[grid_key] = {
                    'latitude': grid_key[0],
                    'longitude': grid_key[1],
                    'count': 0,
                    'timestamps': []
                }

            location_counts[grid_key]['count'] += 1
            location_counts[grid_key]['timestamps'].append(loc.timestamp)

        # Sort by frequency
        frequent = sorted(
            location_counts.values(),
            key=lambda x: x['count'],
            reverse=True
        )[:10]  # Top 10

        # Add time analysis
        for loc in frequent:
            timestamps = [datetime.fromisoformat(ts) for ts in loc['timestamps']]
            hours = [ts.hour for ts in timestamps]
            loc['most_common_hour'] = max(set(hours), key=hours.count) if hours else None
            loc['visit_count'] = loc['count']
            del loc['timestamps']

        return frequent

    def _identify_home(self, history: List[LocationUpdate]) -> Optional[Dict]:
        """Identify home location (most frequent overnight location)"""
        overnight_locations = {}

        for loc in history:
            hour = datetime.fromisoformat(loc.timestamp).hour
            if hour < 6 or hour > 22:  # Overnight hours
                grid_key = (
                    round(loc.latitude, 3),
                    round(loc.longitude, 3)
                )
                overnight_locations[grid_key] = overnight_locations.get(grid_key, 0) + 1

        if not overnight_locations:
            return None

        most_frequent = max(overnight_locations.items(), key=lambda x: x[1])
        return {
            'latitude': most_frequent[0][0],
            'longitude': most_frequent[0][1],
            'confidence': min(most_frequent[1] / len(history) * 10, 1.0),
            'label': 'Probable Home Location'
        }

    def _identify_work(self, history: List[LocationUpdate]) -> Optional[Dict]:
        """Identify work location (most frequent during work hours)"""
        work_locations = {}

        for loc in history:
            hour = datetime.fromisoformat(loc.timestamp).hour
            weekday = datetime.fromisoformat(loc.timestamp).weekday()

            if weekday < 5 and 9 <= hour <= 17:  # Weekday work hours
                grid_key = (
                    round(loc.latitude, 3),
                    round(loc.longitude, 3)
                )
                work_locations[grid_key] = work_locations.get(grid_key, 0) + 1

        if not work_locations:
            return None

        most_frequent = max(work_locations.items(), key=lambda x: x[1])
        return {
            'latitude': most_frequent[0][0],
            'longitude': most_frequent[0][1],
            'confidence': min(most_frequent[1] / len(history) * 10, 1.0),
            'label': 'Probable Work Location'
        }

    def _analyze_travel_patterns(self, history: List[LocationUpdate]) -> List[Dict]:
        """Analyze regular travel patterns"""
        patterns = []

        # Group by day of week and hour
        day_hour_routes = {}

        for i in range(1, len(history)):
            prev = history[i-1]
            curr = history[i]

            prev_time = datetime.fromisoformat(prev.timestamp)
            curr_time = datetime.fromisoformat(curr.timestamp)

            # Skip if too much time between points
            if (curr_time - prev_time).total_seconds() > 3600:
                continue

            day_of_week = curr_time.strftime('%A')
            hour = curr_time.hour

            key = (day_of_week, hour)
            if key not in day_hour_routes:
                day_hour_routes[key] = []

            day_hour_routes[key].append({
                'from': (prev.latitude, prev.longitude),
                'to': (curr.latitude, curr.longitude),
                'speed': curr.speed
            })

        # Find consistent patterns
        for (day, hour), routes in day_hour_routes.items():
            if len(routes) >= 3:  # At least 3 occurrences
                avg_speed = sum(r['speed'] for r in routes) / len(routes)
                patterns.append({
                    'day_of_week': day,
                    'hour': hour,
                    'occurrences': len(routes),
                    'average_speed_kmh': avg_speed,
                    'pattern_type': 'regular_travel'
                })

        return patterns

    def _detect_suspicious_activities(self, history: List[LocationUpdate]) -> List[Dict]:
        """Detect potentially suspicious movement patterns"""
        suspicious = []

        for i in range(1, len(history)):
            prev = history[i-1]
            curr = history[i]

            prev_time = datetime.fromisoformat(prev.timestamp)
            curr_time = datetime.fromisoformat(curr.timestamp)
            time_diff = (curr_time - prev_time).total_seconds()

            if time_diff <= 0:
                continue

            # Calculate implied speed
            distance = self._calculate_distance(
                prev.latitude, prev.longitude,
                curr.latitude, curr.longitude
            )
            implied_speed = (distance / 1000) / (time_diff / 3600)  # km/h

            # Unusually fast movement
            if implied_speed > 200:  # Faster than typical highway
                suspicious.append({
                    'type': 'impossible_speed',
                    'timestamp': curr.timestamp,
                    'details': f"Implied speed: {implied_speed:.1f} km/h",
                    'location': {'lat': curr.latitude, 'lon': curr.longitude}
                })

            # Circling behavior (counter-surveillance)
            if i > 4:
                recent = history[i-4:i+1]
                if self._detect_circling(recent):
                    suspicious.append({
                        'type': 'circling_behavior',
                        'timestamp': curr.timestamp,
                        'details': 'Possible counter-surveillance detected',
                        'location': {'lat': curr.latitude, 'lon': curr.longitude}
                    })

        return suspicious

    def _detect_circling(self, locations: List[LocationUpdate]) -> bool:
        """Detect if target is circling (possible counter-surveillance)"""
        if len(locations) < 4:
            return False

        # Check if returned close to starting point
        start = locations[0]
        end = locations[-1]

        distance_traveled = sum(
            self._calculate_distance(
                locations[i].latitude, locations[i].longitude,
                locations[i+1].latitude, locations[i+1].longitude
            )
            for i in range(len(locations)-1)
        )

        direct_distance = self._calculate_distance(
            start.latitude, start.longitude,
            end.latitude, end.longitude
        )

        # If traveled much more than direct distance and ended up close to start
        if distance_traveled > 1000 and direct_distance < 200:
            return True

        return False

    def _predict_locations(self, history: List[LocationUpdate]) -> List[Dict]:
        """Predict future locations based on patterns"""
        predictions = []

        # Use frequent locations and time patterns
        frequent = self._find_frequent_locations(history)

        current_hour = datetime.now().hour
        current_day = datetime.now().strftime('%A')

        for loc in frequent[:3]:
            if loc.get('most_common_hour'):
                time_diff = abs(loc['most_common_hour'] - current_hour)
                confidence = max(0.3, 1.0 - (time_diff / 24))

                predictions.append({
                    'latitude': loc['latitude'],
                    'longitude': loc['longitude'],
                    'predicted_time': f"{loc['most_common_hour']}:00",
                    'confidence': confidence,
                    'reasoning': f"Historical pattern: frequently visited at {loc['most_common_hour']}:00"
                })

        return predictions

    def _calculate_pattern_confidence(self, pattern: MovementPattern) -> float:
        """Calculate confidence score for pattern analysis"""
        score = 0.0

        if pattern.frequent_locations:
            score += 0.2
        if pattern.home_location:
            score += 0.2
        if pattern.work_location:
            score += 0.2
        if pattern.travel_patterns:
            score += 0.2
        if pattern.predicted_locations:
            score += 0.2

        return min(score, 1.0)

    # ==================== Co-location Detection ====================

    def detect_colocation(self,
                         device_ids: List[str],
                         distance_threshold: float = 100,
                         duration_threshold: int = 300,
                         timeframe_hours: int = 24) -> List[Dict]:
        """
        Detect when multiple devices are co-located

        Args:
            device_ids: List of device IDs to check
            distance_threshold: Distance in meters to consider co-located
            duration_threshold: Duration in seconds for significant meeting
            timeframe_hours: How far back to look

        Returns:
            List of co-location events
        """
        colocations = []
        cutoff = datetime.now() - timedelta(hours=timeframe_hours)

        # Get all histories
        histories = {}
        for device_id in device_ids:
            history = self.location_history.get(device_id, [])
            histories[device_id] = [
                h for h in history
                if datetime.fromisoformat(h.timestamp) >= cutoff
            ]

        # Check each pair
        for i, device_a in enumerate(device_ids):
            for device_b in device_ids[i+1:]:
                meetings = self._find_meetings(
                    histories[device_a],
                    histories[device_b],
                    device_a,
                    device_b,
                    distance_threshold,
                    duration_threshold
                )
                colocations.extend(meetings)

        return colocations

    def _find_meetings(self,
                      history_a: List[LocationUpdate],
                      history_b: List[LocationUpdate],
                      device_a: str,
                      device_b: str,
                      distance_threshold: float,
                      duration_threshold: int) -> List[Dict]:
        """Find meetings between two devices"""
        meetings = []

        # Simple time-based comparison
        for loc_a in history_a:
            time_a = datetime.fromisoformat(loc_a.timestamp)

            for loc_b in history_b:
                time_b = datetime.fromisoformat(loc_b.timestamp)

                # Within 2 minutes of each other
                if abs((time_a - time_b).total_seconds()) < 120:
                    distance = self._calculate_distance(
                        loc_a.latitude, loc_a.longitude,
                        loc_b.latitude, loc_b.longitude
                    )

                    if distance <= distance_threshold:
                        meetings.append({
                            'device_a': device_a,
                            'device_b': device_b,
                            'timestamp': loc_a.timestamp,
                            'location': {
                                'latitude': (loc_a.latitude + loc_b.latitude) / 2,
                                'longitude': (loc_a.longitude + loc_b.longitude) / 2
                            },
                            'distance_meters': distance,
                            'significance': 'potential_meeting'
                        })
                        break

        return meetings

    # ==================== Utility Functions ====================

    def _calculate_distance(self, lat1: float, lon1: float,
                           lat2: float, lon2: float) -> float:
        """
        Calculate distance between two points in meters (Haversine formula)
        """
        R = 6371000  # Earth radius in meters

        lat1_rad = math.radians(lat1)
        lat2_rad = math.radians(lat2)
        delta_lat = math.radians(lat2 - lat1)
        delta_lon = math.radians(lon2 - lon1)

        a = (math.sin(delta_lat / 2) ** 2 +
             math.cos(lat1_rad) * math.cos(lat2_rad) *
             math.sin(delta_lon / 2) ** 2)

        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))

        return R * c

    def _log_audit_event(self, event_type: str, device_id: str, details: Dict):
        """Log an audit event for compliance"""
        event = {
            'timestamp': datetime.now().isoformat(),
            'event_type': event_type,
            'device_id': device_id,
            'details': details,
            'event_hash': hashlib.sha256(
                f"{datetime.now().isoformat()}{event_type}{device_id}".encode()
            ).hexdigest()
        }

        logger.info(f"AUDIT: {event_type} - {device_id}")

        # In production, this would write to secure audit log
        audit_path = Path(self.config['storage_path']) / 'audit.log'
        audit_path.parent.mkdir(parents=True, exist_ok=True)

        with open(audit_path, 'a') as f:
            f.write(json.dumps(event) + '\n')

    # ==================== Callbacks ====================

    def on_location_update(self, callback: Callable):
        """Register callback for location updates"""
        self.location_callbacks.append(callback)

    def on_geofence_alert(self, callback: Callable):
        """Register callback for geofence alerts"""
        self.alert_callbacks.append(callback)

    # ==================== Export ====================

    def export_tracking_data(self, device_id: str, output_path: str,
                            format: str = 'json'):
        """Export tracking data for a device"""
        history = self.location_history.get(device_id, [])
        device = self.devices.get(device_id)

        data = {
            'device': asdict(device) if device else None,
            'location_history': [asdict(loc) for loc in history],
            'exported_at': datetime.now().isoformat()
        }

        if format == 'json':
            with open(output_path, 'w') as f:
                json.dump(data, f, indent=2, default=str)

        elif format == 'kml':
            self._export_to_kml(history, device_id, output_path)

        logger.info(f"Exported tracking data for {device_id} to {output_path}")

    def _export_to_kml(self, history: List[LocationUpdate],
                      device_id: str, output_path: str):
        """Export location history to KML format"""
        kml_template = '''<?xml version="1.0" encoding="UTF-8"?>
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

        coordinates = '\n'.join([
            f"          {loc.longitude},{loc.latitude},{loc.altitude}"
            for loc in history
        ])

        placemarks = ''
        for loc in history[::10]:  # Every 10th point
            placemarks += f'''
    <Placemark>
      <name>{loc.timestamp}</name>
      <Point>
        <coordinates>{loc.longitude},{loc.latitude},{loc.altitude}</coordinates>
      </Point>
    </Placemark>'''

        kml = kml_template.format(
            device_id=device_id,
            coordinates=coordinates,
            placemarks=placemarks
        )

        with open(output_path, 'w') as f:
            f.write(kml)


# ==================== Convenience Functions ====================

def create_tracker(config: Optional[Dict] = None) -> TrackerFob:
    """Create a new TrackerFob instance"""
    return TrackerFob(config)


if __name__ == "__main__":
    # Example usage
    tracker = TrackerFob()

    # Register device
    device_id = tracker.register_device(
        device_name="Vehicle-Tracker-001",
        target_description="Suspect Vehicle - Honda Accord",
        case_id="CASE-2026-001",
        authorization="WARRANT-2026-001",
        warrant_expiration="2026-02-15T00:00:00"
    )

    print(f"Registered device: {device_id}")

    # Create geofence
    geofence_id = tracker.create_geofence(
        name="Victim Home Protection Zone",
        latitude=40.7589,
        longitude=-73.9851,
        radius_meters=500,
        alert_on=['entry', 'loitering'],
        priority='high',
        case_id="CASE-2026-001"
    )

    print(f"Created geofence: {geofence_id}")

    # Update location
    location = tracker.update_location(
        device_id=device_id,
        latitude=40.7614,
        longitude=-73.9776,
        speed=45.0,
        heading=180.0
    )

    print(f"Location updated: {location.coordinates}")
