"""
Surveillance Network Integration - Connect Tracker-Fob to GEOINT Systems
Apollo Platform - GEOINT Transportation Tracking

Integrates real-time GPS tracking with the surveillance network for
comprehensive location intelligence.
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field, asdict
import math
import sys
import os

# Add parent paths for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tracker_fob import TrackerFob, LocationUpdate, GeofenceAlert

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class SurveillanceCamera:
    """Surveillance camera information"""
    camera_id: str
    name: str
    latitude: float
    longitude: float
    camera_type: str  # traffic, security, public, private
    status: str = "active"
    coverage_radius_meters: float = 100.0
    owner: str = ""
    feed_url: Optional[str] = None
    metadata: Dict = field(default_factory=dict)


@dataclass
class SurveillanceCorrelation:
    """Correlation between tracker location and surveillance"""
    correlation_id: str
    device_id: str
    location: Dict
    timestamp: str
    nearby_cameras: List[SurveillanceCamera] = field(default_factory=list)
    camera_footage_requests: List[str] = field(default_factory=list)
    facial_recognition_enabled: bool = False
    vehicle_recognition_enabled: bool = False
    confidence_score: float = 0.0


class SurveillanceIntegration:
    """
    Integrates GPS tracking with surveillance network

    Provides:
    - Correlation with nearby cameras
    - Automatic footage requests
    - Facial/vehicle recognition triggers
    - Geographic camera discovery
    """

    def __init__(self, tracker: TrackerFob, config: Optional[Dict] = None):
        """
        Initialize surveillance integration

        Args:
            tracker: TrackerFob instance
            config: Configuration options
        """
        self.tracker = tracker
        self.config = config or self._default_config()

        # Camera registry
        self.cameras: Dict[str, SurveillanceCamera] = {}

        # Correlations
        self.correlations: List[SurveillanceCorrelation] = []

        # Register callbacks
        self.tracker.on_location_update(self._handle_location_update)
        self.tracker.on_geofence_alert(self._handle_geofence_alert)

        # External callbacks
        self.correlation_callbacks: List[Callable] = []
        self.footage_request_callbacks: List[Callable] = []

        logger.info("SurveillanceIntegration initialized")

    def _default_config(self) -> Dict:
        """Default configuration"""
        return {
            'camera_search_radius_meters': 2000,
            'auto_request_footage': True,
            'footage_duration_before_seconds': 300,
            'footage_duration_after_seconds': 300,
            'enable_facial_recognition': True,
            'enable_vehicle_recognition': True,
            'min_correlation_confidence': 0.7,
            'camera_api_url': None,
            'storage_path': './surveillance_data'
        }

    # ==================== Camera Registry ====================

    def register_camera(self,
                       camera_id: str,
                       name: str,
                       latitude: float,
                       longitude: float,
                       camera_type: str,
                       coverage_radius: float = 100.0,
                       owner: str = "",
                       feed_url: Optional[str] = None,
                       metadata: Optional[Dict] = None) -> str:
        """
        Register a surveillance camera

        Args:
            camera_id: Unique camera identifier
            name: Camera name/description
            latitude: Camera latitude
            longitude: Camera longitude
            camera_type: Type of camera (traffic, security, public, private)
            coverage_radius: Coverage radius in meters
            owner: Camera owner/operator
            feed_url: URL for camera feed
            metadata: Additional metadata

        Returns:
            Camera ID
        """
        camera = SurveillanceCamera(
            camera_id=camera_id,
            name=name,
            latitude=latitude,
            longitude=longitude,
            camera_type=camera_type,
            coverage_radius_meters=coverage_radius,
            owner=owner,
            feed_url=feed_url,
            metadata=metadata or {}
        )

        self.cameras[camera_id] = camera
        logger.info(f"Registered camera: {camera_id} - {name}")

        return camera_id

    def register_cameras_bulk(self, cameras: List[Dict]) -> int:
        """Register multiple cameras at once"""
        count = 0
        for cam in cameras:
            try:
                self.register_camera(**cam)
                count += 1
            except Exception as e:
                logger.error(f"Failed to register camera: {e}")

        return count

    def get_camera(self, camera_id: str) -> Optional[SurveillanceCamera]:
        """Get camera by ID"""
        return self.cameras.get(camera_id)

    def get_all_cameras(self, camera_type: Optional[str] = None) -> List[SurveillanceCamera]:
        """Get all cameras, optionally filtered by type"""
        cameras = list(self.cameras.values())
        if camera_type:
            cameras = [c for c in cameras if c.camera_type == camera_type]
        return cameras

    # ==================== Camera Discovery ====================

    def find_nearby_cameras(self,
                           latitude: float,
                           longitude: float,
                           radius_meters: Optional[float] = None,
                           camera_types: Optional[List[str]] = None) -> List[SurveillanceCamera]:
        """
        Find cameras near a location

        Args:
            latitude: Search center latitude
            longitude: Search center longitude
            radius_meters: Search radius (default from config)
            camera_types: Filter by camera types

        Returns:
            List of nearby cameras sorted by distance
        """
        radius = radius_meters or self.config['camera_search_radius_meters']

        nearby = []
        for camera in self.cameras.values():
            if camera.status != "active":
                continue

            if camera_types and camera.camera_type not in camera_types:
                continue

            distance = self._calculate_distance(
                latitude, longitude,
                camera.latitude, camera.longitude
            )

            if distance <= radius:
                nearby.append((camera, distance))

        # Sort by distance
        nearby.sort(key=lambda x: x[1])

        return [cam for cam, _ in nearby]

    def find_cameras_along_route(self,
                                 route_points: List[Dict],
                                 buffer_meters: float = 500) -> List[Dict]:
        """
        Find cameras along a route

        Args:
            route_points: List of {latitude, longitude} points
            buffer_meters: Buffer distance from route

        Returns:
            List of cameras with distance info
        """
        cameras_found = {}

        for point in route_points:
            nearby = self.find_nearby_cameras(
                point['latitude'],
                point['longitude'],
                radius_meters=buffer_meters
            )

            for camera in nearby:
                if camera.camera_id not in cameras_found:
                    distance = self._calculate_distance(
                        point['latitude'], point['longitude'],
                        camera.latitude, camera.longitude
                    )
                    cameras_found[camera.camera_id] = {
                        'camera': asdict(camera),
                        'closest_distance': distance,
                        'route_point_index': route_points.index(point)
                    }

        return list(cameras_found.values())

    # ==================== Correlation ====================

    def _handle_location_update(self, location: LocationUpdate):
        """Handle location update from tracker"""
        # Find nearby cameras
        nearby_cameras = self.find_nearby_cameras(
            location.latitude,
            location.longitude
        )

        if not nearby_cameras:
            return

        # Create correlation
        correlation = SurveillanceCorrelation(
            correlation_id=f"CORR_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{location.device_id}",
            device_id=location.device_id,
            location={
                'latitude': location.latitude,
                'longitude': location.longitude,
                'speed': location.speed,
                'heading': location.heading
            },
            timestamp=location.timestamp,
            nearby_cameras=nearby_cameras[:10],  # Top 10 closest
            facial_recognition_enabled=self.config['enable_facial_recognition'],
            vehicle_recognition_enabled=self.config['enable_vehicle_recognition']
        )

        # Calculate confidence
        correlation.confidence_score = self._calculate_correlation_confidence(
            location, nearby_cameras
        )

        self.correlations.append(correlation)

        # Auto-request footage if enabled
        if self.config['auto_request_footage'] and nearby_cameras:
            correlation.camera_footage_requests = self._request_footage(
                nearby_cameras[:3],  # Top 3 closest cameras
                location.timestamp
            )

        # Notify callbacks
        for callback in self.correlation_callbacks:
            try:
                callback(correlation)
            except Exception as e:
                logger.error(f"Correlation callback error: {e}")

        logger.info(f"Created correlation {correlation.correlation_id} with {len(nearby_cameras)} cameras")

    def _handle_geofence_alert(self, alert: GeofenceAlert):
        """Handle geofence alert - may trigger additional surveillance"""
        logger.info(f"Geofence alert for surveillance: {alert.event_type.value} - {alert.device_id}")

        # Find cameras near alert location
        cameras = self.find_nearby_cameras(
            alert.location.latitude,
            alert.location.longitude,
            radius_meters=1000  # Expanded radius for alerts
        )

        if cameras and self.config['auto_request_footage']:
            # Request footage from all nearby cameras
            self._request_footage(
                cameras[:5],  # Top 5 cameras
                alert.timestamp,
                priority='high',
                reason=f"Geofence {alert.event_type.value}: {alert.geofence_name}"
            )

    def _calculate_correlation_confidence(self,
                                         location: LocationUpdate,
                                         cameras: List[SurveillanceCamera]) -> float:
        """Calculate confidence score for correlation"""
        if not cameras:
            return 0.0

        score = 0.0

        # Factor 1: Number of cameras (more = higher confidence)
        camera_score = min(len(cameras) / 5, 1.0) * 0.3
        score += camera_score

        # Factor 2: Camera coverage (at least one camera within coverage)
        for camera in cameras:
            distance = self._calculate_distance(
                location.latitude, location.longitude,
                camera.latitude, camera.longitude
            )
            if distance <= camera.coverage_radius_meters:
                score += 0.3
                break

        # Factor 3: Location accuracy
        if location.accuracy <= 10:
            score += 0.2
        elif location.accuracy <= 50:
            score += 0.1

        # Factor 4: Camera quality (traffic and security cameras preferred)
        high_quality = sum(1 for c in cameras if c.camera_type in ['traffic', 'security'])
        if high_quality > 0:
            score += min(high_quality / 3, 1.0) * 0.2

        return min(score, 1.0)

    # ==================== Footage Requests ====================

    def _request_footage(self,
                        cameras: List[SurveillanceCamera],
                        timestamp: str,
                        priority: str = 'normal',
                        reason: str = "Tracking correlation") -> List[str]:
        """
        Request footage from cameras

        Args:
            cameras: List of cameras to request from
            timestamp: Center timestamp for footage
            priority: Request priority
            reason: Reason for request

        Returns:
            List of request IDs
        """
        request_ids = []

        try:
            center_time = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        except:
            center_time = datetime.now()

        for camera in cameras:
            request_id = f"FOOTAGE_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{camera.camera_id}"

            request = {
                'request_id': request_id,
                'camera_id': camera.camera_id,
                'camera_name': camera.name,
                'start_time': (center_time - timedelta(
                    seconds=self.config['footage_duration_before_seconds']
                )).isoformat(),
                'end_time': (center_time + timedelta(
                    seconds=self.config['footage_duration_after_seconds']
                )).isoformat(),
                'priority': priority,
                'reason': reason,
                'requested_at': datetime.now().isoformat()
            }

            request_ids.append(request_id)

            # Notify callbacks
            for callback in self.footage_request_callbacks:
                try:
                    callback(request)
                except Exception as e:
                    logger.error(f"Footage request callback error: {e}")

            logger.info(f"Requested footage from {camera.name}: {request_id}")

        return request_ids

    def request_footage_manually(self,
                                camera_id: str,
                                start_time: str,
                                end_time: str,
                                priority: str = 'normal',
                                reason: str = "Manual request") -> Optional[str]:
        """Manually request footage from a specific camera"""
        camera = self.cameras.get(camera_id)
        if not camera:
            return None

        # Create a temporary center time for the request
        center_time = datetime.now().isoformat()

        requests = self._request_footage(
            [camera], center_time, priority, reason
        )

        return requests[0] if requests else None

    # ==================== Analysis ====================

    def analyze_camera_coverage(self,
                               geofence_id: str) -> Dict:
        """
        Analyze camera coverage for a geofence

        Args:
            geofence_id: Geofence to analyze

        Returns:
            Coverage analysis
        """
        geofence = self.tracker.get_geofence(geofence_id)
        if not geofence:
            return {'error': 'Geofence not found'}

        # Find cameras covering the geofence
        covering_cameras = []

        for camera in self.cameras.values():
            distance = self._calculate_distance(
                geofence.center_latitude, geofence.center_longitude,
                camera.latitude, camera.longitude
            )

            # Camera can see the geofence if it's within geofence radius + camera coverage
            if distance <= (geofence.radius_meters + camera.coverage_radius_meters):
                covering_cameras.append({
                    'camera': asdict(camera),
                    'distance_to_center': distance,
                    'coverage_overlap': True
                })

        # Calculate coverage score
        coverage_score = 0.0
        if covering_cameras:
            # More cameras = better coverage
            coverage_score = min(len(covering_cameras) / 5, 0.5)

            # Camera types matter
            traffic_cams = sum(1 for c in covering_cameras if c['camera']['camera_type'] == 'traffic')
            security_cams = sum(1 for c in covering_cameras if c['camera']['camera_type'] == 'security')

            if traffic_cams >= 2:
                coverage_score += 0.25
            if security_cams >= 1:
                coverage_score += 0.25

        return {
            'geofence_id': geofence_id,
            'geofence_name': geofence.name,
            'cameras_covering': len(covering_cameras),
            'coverage_score': coverage_score,
            'cameras': covering_cameras,
            'recommendations': self._generate_coverage_recommendations(covering_cameras)
        }

    def _generate_coverage_recommendations(self,
                                          cameras: List[Dict]) -> List[str]:
        """Generate recommendations for improving coverage"""
        recommendations = []

        if len(cameras) == 0:
            recommendations.append("No cameras cover this area. Consider adding surveillance.")
        elif len(cameras) < 3:
            recommendations.append("Limited camera coverage. Consider adding more cameras.")

        traffic_count = sum(1 for c in cameras if c['camera']['camera_type'] == 'traffic')
        if traffic_count == 0:
            recommendations.append("No traffic cameras in area. Traffic cams provide good vehicle tracking.")

        security_count = sum(1 for c in cameras if c['camera']['camera_type'] == 'security')
        if security_count == 0:
            recommendations.append("No security cameras in area. Security cams provide facial recognition capability.")

        return recommendations

    def get_correlations(self,
                        device_id: Optional[str] = None,
                        min_confidence: Optional[float] = None,
                        limit: int = 100) -> List[SurveillanceCorrelation]:
        """Get correlations with optional filters"""
        correlations = self.correlations

        if device_id:
            correlations = [c for c in correlations if c.device_id == device_id]

        if min_confidence:
            correlations = [c for c in correlations if c.confidence_score >= min_confidence]

        return list(reversed(correlations))[:limit]

    # ==================== Integration with Facial Recognition ====================

    def trigger_facial_recognition(self,
                                  correlation_id: str,
                                  target_image_path: Optional[str] = None) -> Dict:
        """
        Trigger facial recognition for a correlation

        Args:
            correlation_id: Correlation to process
            target_image_path: Optional target image to match

        Returns:
            Facial recognition request details
        """
        correlation = next(
            (c for c in self.correlations if c.correlation_id == correlation_id),
            None
        )

        if not correlation:
            return {'error': 'Correlation not found'}

        request = {
            'correlation_id': correlation_id,
            'device_id': correlation.device_id,
            'timestamp': correlation.timestamp,
            'cameras': [c.camera_id for c in correlation.nearby_cameras],
            'target_image': target_image_path,
            'requested_at': datetime.now().isoformat(),
            'status': 'pending'
        }

        logger.info(f"Triggered facial recognition for correlation {correlation_id}")

        return request

    def trigger_vehicle_recognition(self,
                                   correlation_id: str,
                                   license_plate: Optional[str] = None,
                                   vehicle_description: Optional[str] = None) -> Dict:
        """
        Trigger vehicle recognition for a correlation

        Args:
            correlation_id: Correlation to process
            license_plate: Optional license plate to match
            vehicle_description: Optional vehicle description

        Returns:
            Vehicle recognition request details
        """
        correlation = next(
            (c for c in self.correlations if c.correlation_id == correlation_id),
            None
        )

        if not correlation:
            return {'error': 'Correlation not found'}

        request = {
            'correlation_id': correlation_id,
            'device_id': correlation.device_id,
            'timestamp': correlation.timestamp,
            'cameras': [c.camera_id for c in correlation.nearby_cameras],
            'license_plate': license_plate,
            'vehicle_description': vehicle_description,
            'requested_at': datetime.now().isoformat(),
            'status': 'pending'
        }

        logger.info(f"Triggered vehicle recognition for correlation {correlation_id}")

        return request

    # ==================== Utility ====================

    def _calculate_distance(self, lat1: float, lon1: float,
                           lat2: float, lon2: float) -> float:
        """Calculate distance in meters between two points"""
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

    # ==================== Callbacks ====================

    def on_correlation(self, callback: Callable):
        """Register callback for surveillance correlations"""
        self.correlation_callbacks.append(callback)

    def on_footage_request(self, callback: Callable):
        """Register callback for footage requests"""
        self.footage_request_callbacks.append(callback)


# ==================== Factory Function ====================

def create_surveillance_integration(tracker: TrackerFob,
                                   config: Optional[Dict] = None) -> SurveillanceIntegration:
    """Create a SurveillanceIntegration instance"""
    return SurveillanceIntegration(tracker, config)


# ==================== Example Usage ====================

if __name__ == "__main__":
    # Create tracker and integration
    tracker = TrackerFob()
    integration = SurveillanceIntegration(tracker)

    # Register some cameras
    cameras = [
        {
            'camera_id': 'CAM-001',
            'name': 'Times Square North',
            'latitude': 40.7580,
            'longitude': -73.9855,
            'camera_type': 'traffic',
            'coverage_radius': 150
        },
        {
            'camera_id': 'CAM-002',
            'name': 'Times Square South',
            'latitude': 40.7570,
            'longitude': -73.9860,
            'camera_type': 'security',
            'coverage_radius': 100
        },
        {
            'camera_id': 'CAM-003',
            'name': 'Broadway & 42nd',
            'latitude': 40.7565,
            'longitude': -73.9870,
            'camera_type': 'traffic',
            'coverage_radius': 200
        }
    ]

    integration.register_cameras_bulk(cameras)

    # Register a device and geofence
    device_id = tracker.register_device(
        device_name="Test Tracker",
        target_description="Test Vehicle",
        case_id="TEST-001",
        authorization="TEST-WARRANT"
    )

    geofence_id = tracker.create_geofence(
        name="Times Square Area",
        latitude=40.7575,
        longitude=-73.9860,
        radius_meters=500,
        case_id="TEST-001"
    )

    # Update location (triggers correlation)
    location = tracker.update_location(
        device_id=device_id,
        latitude=40.7578,
        longitude=-73.9858,
        speed=10.0
    )

    print(f"\nLocation update triggered surveillance correlation")

    # Check correlations
    correlations = integration.get_correlations(device_id=device_id)
    print(f"Correlations found: {len(correlations)}")

    if correlations:
        latest = correlations[0]
        print(f"Latest correlation: {latest.correlation_id}")
        print(f"Nearby cameras: {len(latest.nearby_cameras)}")
        print(f"Confidence: {latest.confidence_score:.2f}")

    # Analyze coverage
    coverage = integration.analyze_camera_coverage(geofence_id)
    print(f"\nCoverage analysis for {coverage.get('geofence_name', 'Unknown')}:")
    print(f"Cameras covering: {coverage.get('cameras_covering', 0)}")
    print(f"Coverage score: {coverage.get('coverage_score', 0):.2f}")
