"""
Insecam Integration - Live Camera Access and Analysis
Access and analyze unsecured cameras from Insecam directory
"""

import json
import logging
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
from dataclasses import dataclass, asdict
from collections import defaultdict
import hashlib
import base64

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class Camera:
    """Camera information"""
    camera_id: str
    url: str
    country: str
    city: Optional[str] = None
    manufacturer: Optional[str] = None
    model: Optional[str] = None
    resolution: Optional[str] = None
    fps: Optional[int] = None
    stream_type: str = "MJPEG"
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    timezone: Optional[str] = None
    category: Optional[str] = None
    tags: List[str] = None
    screenshot_url: Optional[str] = None
    is_online: bool = True
    last_seen: Optional[str] = None
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.tags is None:
            self.tags = []
        if self.metadata is None:
            self.metadata = {}
        if self.last_seen is None:
            self.last_seen = datetime.utcnow().isoformat()


@dataclass
class CameraFeed:
    """Camera feed recording"""
    camera_id: str
    start_time: str
    end_time: Optional[str] = None
    duration_seconds: float = 0.0
    frame_count: int = 0
    file_path: Optional[str] = None
    file_size_mb: float = 0.0
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


class InsecamIntegration:
    """
    Insecam Camera Integration
    Access and analyze unsecured cameras
    """

    def __init__(self):
        """Initialize Insecam integration"""
        self.cameras = []
        self.recordings = []

        # Camera categories
        self.categories = [
            'traffic',
            'city',
            'building',
            'parking',
            'street',
            'shop',
            'office',
            'warehouse',
            'residential',
            'public',
            'beach',
            'mountain',
            'airport',
            'station',
        ]

        # Manufacturer database
        self.manufacturers = {
            'axis': 'AXIS Communications',
            'hikvision': 'Hikvision',
            'dahua': 'Dahua',
            'foscam': 'Foscam',
            'panasonic': 'Panasonic',
            'sony': 'Sony',
            'vivotek': 'Vivotek',
            'mobotix': 'Mobotix',
            'geovision': 'GeoVision',
            'samsung': 'Samsung',
        }

    def search_cameras(
        self,
        country: Optional[str] = None,
        city: Optional[str] = None,
        category: Optional[str] = None,
        manufacturer: Optional[str] = None,
        max_results: int = 100
    ) -> List[Camera]:
        """
        Search for cameras by criteria

        Args:
            country: Filter by country (e.g., 'US', 'CN', 'RU')
            city: Filter by city
            category: Filter by category
            manufacturer: Filter by manufacturer
            max_results: Maximum results to return

        Returns:
            List of cameras
        """
        logger.info(f"Searching cameras: country={country}, city={city}, category={category}")

        cameras = self._search_insecam(
            country=country,
            city=city,
            category=category,
            manufacturer=manufacturer,
            max_results=max_results
        )

        self.cameras.extend(cameras)
        logger.info(f"Found {len(cameras)} cameras")

        return cameras

    def get_camera_by_location(
        self,
        latitude: float,
        longitude: float,
        radius_km: float = 10.0,
        max_results: int = 50
    ) -> List[Camera]:
        """
        Get cameras near a location

        Args:
            latitude: Latitude coordinate
            longitude: Longitude coordinate
            radius_km: Search radius in kilometers
            max_results: Maximum results

        Returns:
            List of cameras within radius
        """
        logger.info(f"Searching cameras near ({latitude}, {longitude}) within {radius_km}km")

        # Simulated geographic search
        cameras = []

        for i in range(min(max_results, 30)):
            # Generate cameras within radius
            lat_offset = (i % 10 - 5) * (radius_km / 111.0)  # Rough conversion
            lon_offset = (i % 7 - 3) * (radius_km / 111.0)

            camera = Camera(
                camera_id=f"cam_{hashlib.md5(f'{latitude}{longitude}{i}'.encode()).hexdigest()[:8]}",
                url=f"http://example.com/camera{i}",
                country=self._get_country_from_coords(latitude, longitude),
                city=self._get_city_from_coords(latitude, longitude),
                latitude=latitude + lat_offset,
                longitude=longitude + lon_offset,
                manufacturer=list(self.manufacturers.values())[i % len(self.manufacturers)],
                category=self.categories[i % len(self.categories)],
                resolution="1920x1080" if i % 2 == 0 else "1280x720",
                fps=30 if i % 3 == 0 else 15,
                tags=['outdoor'] if i % 2 == 0 else ['indoor'],
                screenshot_url=f"http://example.com/screenshot{i}.jpg",
            )

            cameras.append(camera)

        self.cameras.extend(cameras)
        logger.info(f"Found {len(cameras)} cameras near location")

        return cameras

    def get_cameras_by_country(
        self,
        country: str,
        max_results: int = 100
    ) -> List[Camera]:
        """
        Get all cameras in a country

        Args:
            country: Country code (e.g., 'US', 'RU')
            max_results: Maximum results

        Returns:
            List of cameras in country
        """
        logger.info(f"Getting cameras in {country}")

        return self.search_cameras(country=country, max_results=max_results)

    def get_cameras_by_category(
        self,
        category: str,
        country: Optional[str] = None,
        max_results: int = 100
    ) -> List[Camera]:
        """
        Get cameras by category

        Args:
            category: Camera category (traffic, city, etc.)
            country: Optional country filter
            max_results: Maximum results

        Returns:
            List of cameras in category
        """
        logger.info(f"Getting {category} cameras")

        if category not in self.categories:
            logger.warning(f"Unknown category: {category}")

        return self.search_cameras(category=category, country=country, max_results=max_results)

    def access_camera_feed(
        self,
        camera: Camera,
        timeout: int = 30
    ) -> Dict[str, Any]:
        """
        Access live camera feed

        Args:
            camera: Camera to access
            timeout: Connection timeout in seconds

        Returns:
            Feed information dictionary
        """
        logger.info(f"Accessing camera feed: {camera.camera_id}")

        # Simulated feed access
        feed_info = {
            'camera_id': camera.camera_id,
            'status': 'online' if camera.is_online else 'offline',
            'url': camera.url,
            'stream_type': camera.stream_type,
            'resolution': camera.resolution,
            'fps': camera.fps,
            'accessible': True,
            'authentication_required': False,
            'accessed_at': datetime.utcnow().isoformat(),
        }

        logger.info(f"Camera feed accessed successfully")
        return feed_info

    def record_camera_feed(
        self,
        camera: Camera,
        duration_seconds: int = 60,
        output_path: Optional[str] = None
    ) -> CameraFeed:
        """
        Record camera feed

        Args:
            camera: Camera to record
            duration_seconds: Recording duration in seconds
            output_path: Output file path

        Returns:
            Camera feed recording information
        """
        logger.info(f"Recording camera {camera.camera_id} for {duration_seconds}s")

        # Generate output path if not provided
        if not output_path:
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            output_path = f"recording_{camera.camera_id}_{timestamp}.mp4"

        # Simulated recording
        estimated_fps = camera.fps or 15
        frame_count = duration_seconds * estimated_fps
        file_size_mb = (frame_count * 50000) / (1024 * 1024)  # Rough estimate

        recording = CameraFeed(
            camera_id=camera.camera_id,
            start_time=datetime.utcnow().isoformat(),
            end_time=(datetime.utcnow()).isoformat(),
            duration_seconds=duration_seconds,
            frame_count=frame_count,
            file_path=output_path,
            file_size_mb=round(file_size_mb, 2),
            metadata={
                'resolution': camera.resolution,
                'fps': camera.fps,
                'location': f"{camera.city}, {camera.country}",
            }
        )

        self.recordings.append(recording)
        logger.info(f"Recording saved to {output_path} ({file_size_mb:.2f} MB)")

        return recording

    def take_screenshot(
        self,
        camera: Camera,
        output_path: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Take screenshot from camera

        Args:
            camera: Camera to capture
            output_path: Output file path

        Returns:
            Screenshot information
        """
        logger.info(f"Taking screenshot from camera {camera.camera_id}")

        if not output_path:
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            output_path = f"screenshot_{camera.camera_id}_{timestamp}.jpg"

        # Simulated screenshot
        screenshot_info = {
            'camera_id': camera.camera_id,
            'file_path': output_path,
            'resolution': camera.resolution,
            'timestamp': datetime.utcnow().isoformat(),
            'file_size_kb': 250.5,
            'location': f"{camera.city}, {camera.country}",
        }

        logger.info(f"Screenshot saved to {output_path}")
        return screenshot_info

    def get_camera_metadata(self, camera: Camera) -> Dict[str, Any]:
        """
        Get detailed camera metadata

        Args:
            camera: Camera to analyze

        Returns:
            Detailed metadata dictionary
        """
        metadata = {
            'camera_id': camera.camera_id,
            'url': camera.url,
            'manufacturer': camera.manufacturer,
            'model': camera.model,
            'location': {
                'country': camera.country,
                'city': camera.city,
                'coordinates': {
                    'latitude': camera.latitude,
                    'longitude': camera.longitude,
                },
                'timezone': camera.timezone,
            },
            'technical': {
                'resolution': camera.resolution,
                'fps': camera.fps,
                'stream_type': camera.stream_type,
            },
            'classification': {
                'category': camera.category,
                'tags': camera.tags,
            },
            'status': {
                'is_online': camera.is_online,
                'last_seen': camera.last_seen,
            },
        }

        return metadata

    def _search_insecam(
        self,
        country: Optional[str] = None,
        city: Optional[str] = None,
        category: Optional[str] = None,
        manufacturer: Optional[str] = None,
        max_results: int = 100
    ) -> List[Camera]:
        """Internal: Search Insecam (simulated)"""

        cameras = []

        # Country-specific data
        country_cities = {
            'US': ['New York', 'Los Angeles', 'Chicago', 'Houston', 'Phoenix'],
            'CN': ['Beijing', 'Shanghai', 'Shenzhen', 'Guangzhou', 'Chengdu'],
            'RU': ['Moscow', 'St. Petersburg', 'Novosibirsk', 'Yekaterinburg', 'Kazan'],
            'JP': ['Tokyo', 'Osaka', 'Yokohama', 'Nagoya', 'Sapporo'],
            'GB': ['London', 'Manchester', 'Birmingham', 'Leeds', 'Glasgow'],
        }

        countries = [country] if country else ['US', 'CN', 'RU', 'JP', 'GB']
        selected_country = countries[0]
        cities = country_cities.get(selected_country, ['City1', 'City2', 'City3'])

        for i in range(min(max_results, 50)):
            cam_country = selected_country
            cam_city = city if city else cities[i % len(cities)]
            cam_category = category if category else self.categories[i % len(self.categories)]

            # Generate camera
            camera = Camera(
                camera_id=f"insecam_{hashlib.md5(f'{cam_country}{cam_city}{i}'.encode()).hexdigest()[:10]}",
                url=f"http://{203 + i % 50}.{i % 256}.{(i * 7) % 256}.{(i * 13) % 256}/video.mjpg",
                country=cam_country,
                city=cam_city,
                manufacturer=manufacturer if manufacturer else list(self.manufacturers.values())[i % len(self.manufacturers)],
                model=f"Model-{i % 10}",
                resolution=["1920x1080", "1280x720", "640x480"][i % 3],
                fps=[30, 25, 15][i % 3],
                stream_type=["MJPEG", "H.264", "RTSP"][i % 3],
                latitude=self._get_latitude(cam_country, cam_city, i),
                longitude=self._get_longitude(cam_country, cam_city, i),
                timezone=self._get_timezone(cam_country),
                category=cam_category,
                tags=self._generate_tags(cam_category),
                screenshot_url=f"http://example.com/insecam/screenshot_{i}.jpg",
                is_online=(i % 10 != 0),  # 90% online
            )

            cameras.append(camera)

        return cameras

    def _get_country_from_coords(self, lat: float, lon: float) -> str:
        """Get country from coordinates (simplified)"""
        if 25 <= lat <= 50 and -125 <= lon <= -65:
            return "US"
        elif 15 <= lat <= 55 and 70 <= lon <= 140:
            return "CN"
        elif 40 <= lat <= 70 and 20 <= lon <= 180:
            return "RU"
        elif 25 <= lat <= 50 and 125 <= lon <= 150:
            return "JP"
        else:
            return "XX"

    def _get_city_from_coords(self, lat: float, lon: float) -> str:
        """Get city from coordinates (simplified)"""
        country = self._get_country_from_coords(lat, lon)
        cities = {
            'US': 'New York',
            'CN': 'Beijing',
            'RU': 'Moscow',
            'JP': 'Tokyo',
        }
        return cities.get(country, 'Unknown')

    def _get_latitude(self, country: str, city: str, index: int) -> float:
        """Get latitude for country/city"""
        base_coords = {
            'US': 40.7128,
            'CN': 39.9042,
            'RU': 55.7558,
            'JP': 35.6762,
            'GB': 51.5074,
        }
        return base_coords.get(country, 0.0) + (index % 10 - 5) * 0.1

    def _get_longitude(self, country: str, city: str, index: int) -> float:
        """Get longitude for country/city"""
        base_coords = {
            'US': -74.0060,
            'CN': 116.4074,
            'RU': 37.6173,
            'JP': 139.6503,
            'GB': -0.1278,
        }
        return base_coords.get(country, 0.0) + (index % 8 - 4) * 0.1

    def _get_timezone(self, country: str) -> str:
        """Get timezone for country"""
        timezones = {
            'US': 'America/New_York',
            'CN': 'Asia/Shanghai',
            'RU': 'Europe/Moscow',
            'JP': 'Asia/Tokyo',
            'GB': 'Europe/London',
        }
        return timezones.get(country, 'UTC')

    def _generate_tags(self, category: str) -> List[str]:
        """Generate tags for category"""
        base_tags = [category]

        category_tags = {
            'traffic': ['road', 'highway', 'intersection'],
            'city': ['urban', 'downtown', 'street'],
            'parking': ['vehicles', 'lot', 'garage'],
            'beach': ['coastal', 'ocean', 'outdoor'],
            'shop': ['retail', 'indoor', 'commercial'],
        }

        if category in category_tags:
            base_tags.extend(category_tags[category][:2])

        return base_tags

    def get_statistics(self) -> Dict[str, Any]:
        """Get statistics about discovered cameras"""

        stats = {
            'total_cameras': len(self.cameras),
            'by_country': defaultdict(int),
            'by_category': defaultdict(int),
            'by_manufacturer': defaultdict(int),
            'online_cameras': len([c for c in self.cameras if c.is_online]),
            'total_recordings': len(self.recordings),
        }

        for camera in self.cameras:
            stats['by_country'][camera.country] += 1
            if camera.category:
                stats['by_category'][camera.category] += 1
            if camera.manufacturer:
                stats['by_manufacturer'][camera.manufacturer] += 1

        stats['by_country'] = dict(stats['by_country'])
        stats['by_category'] = dict(stats['by_category'])
        stats['by_manufacturer'] = dict(stats['by_manufacturer'])

        return stats

    def export_cameras(self, output_file: str = "insecam_cameras.json") -> Dict:
        """Export camera data to JSON"""

        export_data = {
            'exported_at': datetime.utcnow().isoformat(),
            'total_cameras': len(self.cameras),
            'statistics': self.get_statistics(),
            'cameras': [asdict(c) for c in self.cameras],
        }

        try:
            with open(output_file, 'w') as f:
                json.dump(export_data, f, indent=2)
            logger.info(f"Cameras exported to {output_file}")
        except Exception as e:
            logger.error(f"Error exporting cameras: {e}")

        return export_data

    def export_kml(self, output_file: str = "cameras.kml") -> str:
        """
        Export cameras as KML for Google Earth

        Args:
            output_file: Output KML file path

        Returns:
            KML content
        """
        logger.info(f"Exporting cameras to KML: {output_file}")

        kml_header = """<?xml version="1.0" encoding="UTF-8"?>
<kml xmlns="http://www.opengis.net/kml/2.2">
<Document>
    <name>Insecam Cameras</name>
    <description>Camera locations from Insecam</description>
"""

        kml_footer = """</Document>
</kml>"""

        placemarks = []
        for camera in self.cameras:
            if camera.latitude and camera.longitude:
                placemark = f"""    <Placemark>
        <name>{camera.camera_id}</name>
        <description>
            Manufacturer: {camera.manufacturer}
            Category: {camera.category}
            City: {camera.city}, {camera.country}
            URL: {camera.url}
        </description>
        <Point>
            <coordinates>{camera.longitude},{camera.latitude},0</coordinates>
        </Point>
    </Placemark>
"""
                placemarks.append(placemark)

        kml_content = kml_header + '\n'.join(placemarks) + kml_footer

        try:
            with open(output_file, 'w') as f:
                f.write(kml_content)
            logger.info(f"KML exported to {output_file}")
        except Exception as e:
            logger.error(f"Error exporting KML: {e}")

        return kml_content


def main():
    """Example usage"""
    print("Insecam Camera Integration")
    print("=" * 50)

    # Initialize
    insecam = InsecamIntegration()

    # Search cameras by country
    print("\n[*] Searching cameras in the US...")
    cameras = insecam.search_cameras(country="US", max_results=10)
    print(f"[+] Found {len(cameras)} cameras")

    # Show sample cameras
    for cam in cameras[:3]:
        print(f"\n  Camera: {cam.camera_id}")
        print(f"  Location: {cam.city}, {cam.country}")
        print(f"  Manufacturer: {cam.manufacturer}")
        print(f"  Category: {cam.category}")
        print(f"  Resolution: {cam.resolution}")
        print(f"  Status: {'Online' if cam.is_online else 'Offline'}")

    # Search by location
    print("\n[*] Searching cameras near New York...")
    nearby = insecam.get_camera_by_location(40.7128, -74.0060, radius_km=5, max_results=5)
    print(f"[+] Found {len(nearby)} nearby cameras")

    # Search by category
    print("\n[*] Searching traffic cameras...")
    traffic_cams = insecam.get_cameras_by_category('traffic', max_results=5)
    print(f"[+] Found {len(traffic_cams)} traffic cameras")

    # Access camera feed
    if cameras:
        print(f"\n[*] Accessing camera feed: {cameras[0].camera_id}")
        feed_info = insecam.access_camera_feed(cameras[0])
        print(f"[+] Feed status: {feed_info['status']}")
        print(f"  Resolution: {feed_info['resolution']}")
        print(f"  FPS: {feed_info['fps']}")

    # Record camera
    if cameras:
        print(f"\n[*] Recording camera for 30 seconds...")
        recording = insecam.record_camera_feed(cameras[0], duration_seconds=30)
        print(f"[+] Recording saved: {recording.file_path}")
        print(f"  Duration: {recording.duration_seconds}s")
        print(f"  Frames: {recording.frame_count}")
        print(f"  Size: {recording.file_size_mb} MB")

    # Get statistics
    print("\n[*] Camera statistics:")
    stats = insecam.get_statistics()
    print(f"  Total cameras: {stats['total_cameras']}")
    print(f"  Online: {stats['online_cameras']}")
    print(f"  Countries: {len(stats['by_country'])}")
    print(f"  Categories: {len(stats['by_category'])}")

    # Export data
    print("\n[*] Exporting camera data...")
    insecam.export_cameras()
    insecam.export_kml()
    print("[+] Export completed")


if __name__ == "__main__":
    main()
