"""
Geofencing Module
Create and monitor geographic zones
"""

import logging
from typing import Dict, Optional, List, Tuple
import json
from datetime import datetime
from pathlib import Path
import math
from dataclasses import dataclass, asdict


@dataclass
class GeofenceZone:
    """Geofence zone definition"""
    zone_id: str
    name: str
    latitude: float
    longitude: float
    radius_meters: float
    created_at: str
    active: bool = True
    alert_on_entry: bool = True
    alert_on_exit: bool = True
    metadata: Dict = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


@dataclass
class GeofenceEvent:
    """Geofence crossing event"""
    event_id: str
    zone_id: str
    event_type: str  # entry, exit
    latitude: float
    longitude: float
    timestamp: str
    distance_from_center: float
    metadata: Dict = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


class Geofencing:
    """Geofence Creation and Monitoring"""

    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize Geofencing module

        Args:
            config: Configuration dictionary
        """
        self.logger = logging.getLogger(__name__)
        self.config = config or {}

        # Storage
        self.zones: Dict[str, GeofenceZone] = {}
        self.events: List[GeofenceEvent] = []
        self.tracking_history: Dict[str, List[Tuple[float, float, str]]] = {}

        # Configuration
        self.storage_path = self.config.get('storage_path', './geofences.json')
        self.max_events = self.config.get('max_events', 10000)

        # Load existing zones
        self._load_zones()

    def create_zone(self, name: str, latitude: float, longitude: float,
                   radius_meters: float, **kwargs) -> str:
        """
        Create a new geofence zone

        Args:
            name: Zone name
            latitude: Center latitude
            longitude: Center longitude
            radius_meters: Radius in meters
            **kwargs: Additional metadata

        Returns:
            Zone ID
        """
        zone_id = f"ZONE_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{len(self.zones)}"

        zone = GeofenceZone(
            zone_id=zone_id,
            name=name,
            latitude=latitude,
            longitude=longitude,
            radius_meters=radius_meters,
            created_at=datetime.now().isoformat(),
            alert_on_entry=kwargs.get('alert_on_entry', True),
            alert_on_exit=kwargs.get('alert_on_exit', True),
            metadata=kwargs.get('metadata', {})
        )

        self.zones[zone_id] = zone
        self._save_zones()

        self.logger.info(f"Created geofence zone: {zone_id} - {name}")
        return zone_id

    def delete_zone(self, zone_id: str) -> bool:
        """Delete a geofence zone"""
        if zone_id in self.zones:
            del self.zones[zone_id]
            self._save_zones()
            self.logger.info(f"Deleted geofence zone: {zone_id}")
            return True
        return False

    def update_zone(self, zone_id: str, **kwargs) -> bool:
        """Update geofence zone properties"""
        if zone_id not in self.zones:
            return False

        zone = self.zones[zone_id]

        if 'name' in kwargs:
            zone.name = kwargs['name']
        if 'latitude' in kwargs:
            zone.latitude = kwargs['latitude']
        if 'longitude' in kwargs:
            zone.longitude = kwargs['longitude']
        if 'radius_meters' in kwargs:
            zone.radius_meters = kwargs['radius_meters']
        if 'active' in kwargs:
            zone.active = kwargs['active']
        if 'alert_on_entry' in kwargs:
            zone.alert_on_entry = kwargs['alert_on_entry']
        if 'alert_on_exit' in kwargs:
            zone.alert_on_exit = kwargs['alert_on_exit']

        self._save_zones()
        return True

    def check_point(self, zone_id: str, latitude: float, longitude: float) -> Dict:
        """
        Check if a point is within a geofence

        Args:
            zone_id: Geofence zone ID
            latitude: Point latitude
            longitude: Point longitude

        Returns:
            Check result dictionary
        """
        if zone_id not in self.zones:
            return {'error': 'Zone not found'}

        zone = self.zones[zone_id]

        distance = self._calculate_distance(
            zone.latitude, zone.longitude,
            latitude, longitude
        )

        inside = distance <= zone.radius_meters
        distance_km = distance / 1000

        result = {
            'zone_id': zone_id,
            'zone_name': zone.name,
            'inside': inside,
            'distance_from_center_meters': distance,
            'distance_from_center_km': distance_km,
            'latitude': latitude,
            'longitude': longitude,
            'checked_at': datetime.now().isoformat()
        }

        if inside:
            result['position'] = 'inside'
        else:
            result['position'] = 'outside'
            result['distance_from_boundary'] = distance - zone.radius_meters

        return result

    def track_movement(self, tracking_id: str, latitude: float, longitude: float,
                      check_zones: Optional[List[str]] = None) -> Dict:
        """
        Track movement and check for geofence crossings

        Args:
            tracking_id: Unique tracking ID
            latitude: Current latitude
            longitude: Current longitude
            check_zones: List of zone IDs to check (None = all active zones)

        Returns:
            Movement tracking result with any triggered events
        """
        timestamp = datetime.now().isoformat()
        current_position = (latitude, longitude, timestamp)

        # Initialize tracking history if needed
        if tracking_id not in self.tracking_history:
            self.tracking_history[tracking_id] = []

        # Get previous position
        history = self.tracking_history[tracking_id]
        previous_position = history[-1] if history else None

        # Add current position to history
        history.append(current_position)

        # Limit history size
        if len(history) > 1000:
            history.pop(0)

        result = {
            'tracking_id': tracking_id,
            'current_position': {
                'latitude': latitude,
                'longitude': longitude,
                'timestamp': timestamp
            },
            'events': [],
            'current_zones': []
        }

        # Determine which zones to check
        zones_to_check = check_zones or list(self.zones.keys())

        for zone_id in zones_to_check:
            if zone_id not in self.zones:
                continue

            zone = self.zones[zone_id]
            if not zone.active:
                continue

            # Check current position
            current_check = self.check_point(zone_id, latitude, longitude)
            currently_inside = current_check['inside']

            if currently_inside:
                result['current_zones'].append({
                    'zone_id': zone_id,
                    'zone_name': zone.name
                })

            # Check for entry/exit events
            if previous_position:
                prev_lat, prev_lon, prev_time = previous_position
                prev_check = self.check_point(zone_id, prev_lat, prev_lon)
                previously_inside = prev_check['inside']

                # Entry event
                if currently_inside and not previously_inside and zone.alert_on_entry:
                    event = self._create_event(
                        zone_id, 'entry', latitude, longitude,
                        current_check['distance_from_center_meters'],
                        {'tracking_id': tracking_id}
                    )
                    result['events'].append(asdict(event))

                # Exit event
                elif not currently_inside and previously_inside and zone.alert_on_exit:
                    event = self._create_event(
                        zone_id, 'exit', latitude, longitude,
                        current_check['distance_from_center_meters'],
                        {'tracking_id': tracking_id}
                    )
                    result['events'].append(asdict(event))

        return result

    def _create_event(self, zone_id: str, event_type: str,
                     latitude: float, longitude: float,
                     distance: float, metadata: Dict) -> GeofenceEvent:
        """Create a geofence event"""
        event_id = f"EVENT_{datetime.now().strftime('%Y%m%d_%H%M%S%f')}"

        event = GeofenceEvent(
            event_id=event_id,
            zone_id=zone_id,
            event_type=event_type,
            latitude=latitude,
            longitude=longitude,
            timestamp=datetime.now().isoformat(),
            distance_from_center=distance,
            metadata=metadata
        )

        self.events.append(event)

        # Limit events list
        if len(self.events) > self.max_events:
            self.events.pop(0)

        self.logger.info(f"Geofence event: {event_type} - Zone {zone_id}")

        return event

    def get_events(self, zone_id: Optional[str] = None,
                   event_type: Optional[str] = None,
                   limit: int = 100) -> List[Dict]:
        """
        Get geofence events

        Args:
            zone_id: Filter by zone ID
            event_type: Filter by event type (entry, exit)
            limit: Maximum events to return

        Returns:
            List of events
        """
        filtered_events = self.events

        if zone_id:
            filtered_events = [e for e in filtered_events if e.zone_id == zone_id]

        if event_type:
            filtered_events = [e for e in filtered_events if e.event_type == event_type]

        # Return most recent events
        filtered_events = list(reversed(filtered_events))[:limit]

        return [asdict(e) for e in filtered_events]

    def get_tracking_history(self, tracking_id: str, limit: int = 100) -> List[Dict]:
        """Get movement tracking history"""
        if tracking_id not in self.tracking_history:
            return []

        history = self.tracking_history[tracking_id][-limit:]

        return [
            {
                'latitude': lat,
                'longitude': lon,
                'timestamp': ts
            }
            for lat, lon, ts in history
        ]

    def analyze_movement_pattern(self, tracking_id: str) -> Dict:
        """
        Analyze movement patterns

        Args:
            tracking_id: Tracking ID to analyze

        Returns:
            Movement pattern analysis
        """
        if tracking_id not in self.tracking_history:
            return {'error': 'No tracking history found'}

        history = self.tracking_history[tracking_id]

        if len(history) < 2:
            return {'error': 'Insufficient data for analysis'}

        analysis = {
            'tracking_id': tracking_id,
            'total_points': len(history),
            'total_distance_km': 0,
            'start_time': history[0][2],
            'end_time': history[-1][2],
            'bounding_box': None,
            'frequent_zones': [],
            'average_speed_kmh': 0
        }

        # Calculate total distance
        total_distance = 0
        for i in range(1, len(history)):
            lat1, lon1, _ = history[i-1]
            lat2, lon2, _ = history[i]
            distance = self._calculate_distance(lat1, lon1, lat2, lon2)
            total_distance += distance

        analysis['total_distance_km'] = total_distance / 1000

        # Calculate bounding box
        lats = [h[0] for h in history]
        lons = [h[1] for h in history]
        analysis['bounding_box'] = {
            'north': max(lats),
            'south': min(lats),
            'east': max(lons),
            'west': min(lons)
        }

        # Calculate average speed
        try:
            start_dt = datetime.fromisoformat(history[0][2])
            end_dt = datetime.fromisoformat(history[-1][2])
            duration_hours = (end_dt - start_dt).total_seconds() / 3600

            if duration_hours > 0:
                analysis['average_speed_kmh'] = analysis['total_distance_km'] / duration_hours
        except Exception as e:
            self.logger.error(f"Speed calculation error: {e}")

        # Find frequent zones
        zone_visits = {}
        for lat, lon, _ in history:
            for zone_id, zone in self.zones.items():
                check = self.check_point(zone_id, lat, lon)
                if check['inside']:
                    zone_visits[zone_id] = zone_visits.get(zone_id, 0) + 1

        analysis['frequent_zones'] = [
            {'zone_id': zid, 'zone_name': self.zones[zid].name, 'visits': count}
            for zid, count in sorted(zone_visits.items(), key=lambda x: x[1], reverse=True)
        ]

        return analysis

    def _calculate_distance(self, lat1: float, lon1: float,
                          lat2: float, lon2: float) -> float:
        """
        Calculate distance between two points in meters (Haversine formula)

        Args:
            lat1, lon1: First point coordinates
            lat2, lon2: Second point coordinates

        Returns:
            Distance in meters
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

    def create_polygon_zone(self, name: str, coordinates: List[Tuple[float, float]], **kwargs) -> str:
        """
        Create a polygon geofence (future enhancement)

        Args:
            name: Zone name
            coordinates: List of (lat, lon) tuples defining polygon
            **kwargs: Additional metadata

        Returns:
            Zone ID
        """
        # For now, create a circular zone based on polygon centroid
        if not coordinates:
            raise ValueError("Coordinates required")

        # Calculate centroid
        avg_lat = sum(c[0] for c in coordinates) / len(coordinates)
        avg_lon = sum(c[1] for c in coordinates) / len(coordinates)

        # Calculate approximate radius (max distance from centroid)
        max_radius = 0
        for lat, lon in coordinates:
            distance = self._calculate_distance(avg_lat, avg_lon, lat, lon)
            max_radius = max(max_radius, distance)

        return self.create_zone(name, avg_lat, avg_lon, max_radius, **kwargs)

    def get_all_zones(self) -> List[Dict]:
        """Get all geofence zones"""
        return [asdict(zone) for zone in self.zones.values()]

    def get_zone(self, zone_id: str) -> Optional[Dict]:
        """Get specific zone details"""
        if zone_id in self.zones:
            return asdict(self.zones[zone_id])
        return None

    def _save_zones(self):
        """Save zones to disk"""
        try:
            data = {
                'zones': [asdict(zone) for zone in self.zones.values()],
                'updated_at': datetime.now().isoformat()
            }

            with open(self.storage_path, 'w') as f:
                json.dump(data, f, indent=2)

        except Exception as e:
            self.logger.error(f"Failed to save zones: {e}")

    def _load_zones(self):
        """Load zones from disk"""
        try:
            if Path(self.storage_path).exists():
                with open(self.storage_path, 'r') as f:
                    data = json.load(f)

                for zone_data in data.get('zones', []):
                    zone = GeofenceZone(**zone_data)
                    self.zones[zone.zone_id] = zone

                self.logger.info(f"Loaded {len(self.zones)} geofence zones")

        except Exception as e:
            self.logger.error(f"Failed to load zones: {e}")

    def export_zones_kml(self, output_path: str):
        """Export geofence zones to KML format"""
        kml_template = """<?xml version="1.0" encoding="UTF-8"?>
<kml xmlns="http://www.opengis.net/kml/2.2">
  <Document>
    <name>Geofence Zones</name>
    {placemarks}
  </Document>
</kml>"""

        placemark_template = """
    <Placemark>
      <name>{name}</name>
      <description>Zone ID: {zone_id}, Radius: {radius}m</description>
      <Point>
        <coordinates>{lon},{lat},0</coordinates>
      </Point>
    </Placemark>"""

        placemarks = []
        for zone in self.zones.values():
            placemarks.append(placemark_template.format(
                name=zone.name,
                zone_id=zone.zone_id,
                radius=zone.radius_meters,
                lat=zone.latitude,
                lon=zone.longitude
            ))

        kml = kml_template.format(placemarks=''.join(placemarks))

        with open(output_path, 'w') as f:
            f.write(kml)


if __name__ == "__main__":
    # Example usage
    geofence = Geofencing()

    # Create zones
    home_zone = geofence.create_zone(
        "Home",
        latitude=37.7749,
        longitude=-122.4194,
        radius_meters=100
    )

    office_zone = geofence.create_zone(
        "Office",
        latitude=37.3861,
        longitude=-122.0839,
        radius_meters=200
    )

    # Track movement
    result = geofence.track_movement(
        tracking_id="SUBJECT_001",
        latitude=37.7749,
        longitude=-122.4194
    )

    print(json.dumps(result, indent=2))

    # Get all zones
    zones = geofence.get_all_zones()
    print(f"Total zones: {len(zones)}")
