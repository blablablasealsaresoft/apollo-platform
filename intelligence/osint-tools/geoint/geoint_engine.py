"""
GEOINT Engine - Comprehensive Geolocation Intelligence System
Main orchestration engine for geolocation intelligence gathering
"""

import json
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
from dataclasses import dataclass, asdict
import concurrent.futures
from pathlib import Path

from ip_geolocation import IPGeolocation
from phone_geolocation import PhoneGeolocation
from photo_geolocation import PhotoGeolocation
from address_intelligence import AddressIntelligence
from whois_intelligence import WhoisIntelligence
from dns_intelligence import DNSIntelligence
from wifi_geolocation import WiFiGeolocation
from geofencing import Geofencing


@dataclass
class GEOINTResult:
    """GEOINT analysis result"""
    target_id: str
    timestamp: str
    ip_data: Optional[Dict] = None
    phone_data: Optional[Dict] = None
    photo_data: Optional[Dict] = None
    address_data: Optional[Dict] = None
    whois_data: Optional[Dict] = None
    dns_data: Optional[Dict] = None
    wifi_data: Optional[Dict] = None
    correlations: List[Dict] = None
    confidence_score: float = 0.0
    locations: List[Dict] = None

    def __post_init__(self):
        if self.correlations is None:
            self.correlations = []
        if self.locations is None:
            self.locations = []


class GEOINT:
    """Main GEOINT Engine for comprehensive geolocation intelligence"""

    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize GEOINT engine

        Args:
            config_path: Path to configuration file
        """
        self.logger = logging.getLogger(__name__)
        self._setup_logging()

        # Load configuration
        self.config = self._load_config(config_path)

        # Initialize sub-modules
        self.ip_geo = IPGeolocation(self.config.get('ip_config', {}))
        self.phone_geo = PhoneGeolocation(self.config.get('phone_config', {}))
        self.photo_geo = PhotoGeolocation(self.config.get('photo_config', {}))
        self.address_intel = AddressIntelligence(self.config.get('address_config', {}))
        self.whois_intel = WhoisIntelligence(self.config.get('whois_config', {}))
        self.dns_intel = DNSIntelligence(self.config.get('dns_config', {}))
        self.wifi_geo = WiFiGeolocation(self.config.get('wifi_config', {}))
        self.geofencing = Geofencing(self.config.get('geofence_config', {}))

        self.logger.info("GEOINT Engine initialized successfully")

    def _setup_logging(self):
        """Setup logging configuration"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('geoint.log'),
                logging.StreamHandler()
            ]
        )

    def _load_config(self, config_path: Optional[str]) -> Dict:
        """Load configuration from file or use defaults"""
        if config_path and Path(config_path).exists():
            with open(config_path, 'r') as f:
                return json.load(f)
        return self._default_config()

    def _default_config(self) -> Dict:
        """Return default configuration"""
        return {
            'max_workers': 5,
            'timeout': 30,
            'enable_caching': True,
            'cache_ttl': 3600,
            'confidence_threshold': 0.7,
            'correlation_enabled': True
        }

    def locate_target(self,
                     target_id: Optional[str] = None,
                     ip: Optional[str] = None,
                     phone: Optional[str] = None,
                     photo: Optional[str] = None,
                     address: Optional[str] = None,
                     domain: Optional[str] = None,
                     bssid: Optional[str] = None,
                     **kwargs) -> GEOINTResult:
        """
        Comprehensive target location analysis

        Args:
            target_id: Unique identifier for target
            ip: IP address to geolocate
            phone: Phone number to analyze
            photo: Path to photo for EXIF analysis
            address: Physical address
            domain: Domain name for WHOIS/DNS
            bssid: WiFi BSSID
            **kwargs: Additional parameters

        Returns:
            GEOINTResult object with comprehensive data
        """
        if not target_id:
            target_id = f"TARGET_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        self.logger.info(f"Starting GEOINT analysis for {target_id}")

        result = GEOINTResult(
            target_id=target_id,
            timestamp=datetime.now().isoformat()
        )

        # Parallel data gathering
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.config['max_workers']) as executor:
            futures = {}

            if ip:
                futures['ip'] = executor.submit(self._analyze_ip, ip)
            if phone:
                futures['phone'] = executor.submit(self._analyze_phone, phone)
            if photo:
                futures['photo'] = executor.submit(self._analyze_photo, photo)
            if address:
                futures['address'] = executor.submit(self._analyze_address, address)
            if domain:
                futures['whois'] = executor.submit(self._analyze_whois, domain)
                futures['dns'] = executor.submit(self._analyze_dns, domain)
            if bssid:
                futures['wifi'] = executor.submit(self._analyze_wifi, bssid)

            # Collect results
            for key, future in futures.items():
                try:
                    data = future.result(timeout=self.config['timeout'])
                    setattr(result, f"{key}_data", data)
                except Exception as e:
                    self.logger.error(f"Error in {key} analysis: {e}")

        # Perform correlation analysis
        if self.config['correlation_enabled']:
            result.correlations = self._correlate_data(result)
            result.locations = self._extract_locations(result)
            result.confidence_score = self._calculate_confidence(result)

        self.logger.info(f"GEOINT analysis complete for {target_id}")
        return result

    def _analyze_ip(self, ip: str) -> Dict:
        """Analyze IP address"""
        try:
            return self.ip_geo.geolocate(ip)
        except Exception as e:
            self.logger.error(f"IP analysis failed: {e}")
            return {}

    def _analyze_phone(self, phone: str) -> Dict:
        """Analyze phone number"""
        try:
            return self.phone_geo.geolocate(phone)
        except Exception as e:
            self.logger.error(f"Phone analysis failed: {e}")
            return {}

    def _analyze_photo(self, photo_path: str) -> Dict:
        """Analyze photo for location data"""
        try:
            return self.photo_geo.extract_location(photo_path)
        except Exception as e:
            self.logger.error(f"Photo analysis failed: {e}")
            return {}

    def _analyze_address(self, address: str) -> Dict:
        """Analyze physical address"""
        try:
            return self.address_intel.analyze(address)
        except Exception as e:
            self.logger.error(f"Address analysis failed: {e}")
            return {}

    def _analyze_whois(self, domain: str) -> Dict:
        """Analyze WHOIS data"""
        try:
            return self.whois_intel.lookup(domain)
        except Exception as e:
            self.logger.error(f"WHOIS analysis failed: {e}")
            return {}

    def _analyze_dns(self, domain: str) -> Dict:
        """Analyze DNS records"""
        try:
            return self.dns_intel.analyze(domain)
        except Exception as e:
            self.logger.error(f"DNS analysis failed: {e}")
            return {}

    def _analyze_wifi(self, bssid: str) -> Dict:
        """Analyze WiFi BSSID"""
        try:
            return self.wifi_geo.locate(bssid)
        except Exception as e:
            self.logger.error(f"WiFi analysis failed: {e}")
            return {}

    def _correlate_data(self, result: GEOINTResult) -> List[Dict]:
        """Correlate data from different sources"""
        correlations = []

        # Extract all location data
        locations = []

        if result.ip_data and 'location' in result.ip_data:
            locations.append({
                'source': 'ip',
                'lat': result.ip_data['location'].get('latitude'),
                'lon': result.ip_data['location'].get('longitude'),
                'city': result.ip_data['location'].get('city'),
                'country': result.ip_data['location'].get('country')
            })

        if result.phone_data and 'location' in result.phone_data:
            locations.append({
                'source': 'phone',
                'country': result.phone_data['location'].get('country'),
                'region': result.phone_data['location'].get('region')
            })

        if result.photo_data and 'gps' in result.photo_data:
            locations.append({
                'source': 'photo',
                'lat': result.photo_data['gps'].get('latitude'),
                'lon': result.photo_data['gps'].get('longitude')
            })

        if result.address_data and 'coordinates' in result.address_data:
            locations.append({
                'source': 'address',
                'lat': result.address_data['coordinates'].get('latitude'),
                'lon': result.address_data['coordinates'].get('longitude')
            })

        if result.wifi_data and 'location' in result.wifi_data:
            locations.append({
                'source': 'wifi',
                'lat': result.wifi_data['location'].get('latitude'),
                'lon': result.wifi_data['location'].get('longitude')
            })

        # Find correlations
        for i, loc1 in enumerate(locations):
            for loc2 in locations[i+1:]:
                correlation = self._compare_locations(loc1, loc2)
                if correlation:
                    correlations.append(correlation)

        return correlations

    def _compare_locations(self, loc1: Dict, loc2: Dict) -> Optional[Dict]:
        """Compare two locations for correlation"""
        correlation = {
            'sources': [loc1['source'], loc2['source']],
            'match_type': None,
            'confidence': 0.0,
            'details': {}
        }

        # Check country match
        if loc1.get('country') and loc2.get('country'):
            if loc1['country'] == loc2['country']:
                correlation['match_type'] = 'country'
                correlation['confidence'] = 0.6
                correlation['details']['country'] = loc1['country']

        # Check coordinate proximity
        if all(k in loc1 for k in ['lat', 'lon']) and all(k in loc2 for k in ['lat', 'lon']):
            distance = self._calculate_distance(
                loc1['lat'], loc1['lon'],
                loc2['lat'], loc2['lon']
            )
            if distance < 100:  # Within 100km
                correlation['match_type'] = 'proximity'
                correlation['confidence'] = 0.9
                correlation['details']['distance_km'] = round(distance, 2)

        return correlation if correlation['match_type'] else None

    def _calculate_distance(self, lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        """Calculate distance between two coordinates (Haversine formula)"""
        from math import radians, sin, cos, sqrt, atan2

        R = 6371  # Earth radius in km

        lat1, lon1, lat2, lon2 = map(radians, [lat1, lon1, lat2, lon2])
        dlat = lat2 - lat1
        dlon = lon2 - lon1

        a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
        c = 2 * atan2(sqrt(a), sqrt(1-a))

        return R * c

    def _extract_locations(self, result: GEOINTResult) -> List[Dict]:
        """Extract all unique locations from result"""
        locations = []
        seen = set()

        for data_type in ['ip_data', 'phone_data', 'photo_data', 'address_data', 'wifi_data']:
            data = getattr(result, data_type)
            if data:
                loc = self._extract_location_from_data(data, data_type)
                if loc:
                    loc_key = f"{loc.get('lat')},{loc.get('lon')}"
                    if loc_key not in seen:
                        locations.append(loc)
                        seen.add(loc_key)

        return locations

    def _extract_location_from_data(self, data: Dict, source: str) -> Optional[Dict]:
        """Extract location from data dictionary"""
        location = {'source': source.replace('_data', '')}

        if 'location' in data:
            location.update(data['location'])
        elif 'gps' in data:
            location.update(data['gps'])
        elif 'coordinates' in data:
            location.update(data['coordinates'])
        else:
            return None

        return location if location.get('latitude') or location.get('country') else None

    def _calculate_confidence(self, result: GEOINTResult) -> float:
        """Calculate overall confidence score"""
        scores = []

        # Count data sources
        sources = sum([
            bool(result.ip_data),
            bool(result.phone_data),
            bool(result.photo_data),
            bool(result.address_data),
            bool(result.whois_data),
            bool(result.dns_data),
            bool(result.wifi_data)
        ])

        # Base score on number of sources
        base_score = min(sources * 0.15, 0.7)
        scores.append(base_score)

        # Add correlation bonus
        if result.correlations:
            correlation_score = min(len(result.correlations) * 0.1, 0.3)
            scores.append(correlation_score)

        return min(sum(scores), 1.0)

    def create_geofence(self, name: str, latitude: float, longitude: float,
                       radius_meters: float, **kwargs) -> str:
        """
        Create a geofence zone

        Args:
            name: Geofence name
            latitude: Center latitude
            longitude: Center longitude
            radius_meters: Radius in meters

        Returns:
            Geofence ID
        """
        return self.geofencing.create_zone(name, latitude, longitude, radius_meters, **kwargs)

    def check_geofence(self, geofence_id: str, latitude: float, longitude: float) -> Dict:
        """Check if coordinates are within geofence"""
        return self.geofencing.check_point(geofence_id, latitude, longitude)

    def export_result(self, result: GEOINTResult, output_path: str, format: str = 'json'):
        """
        Export GEOINT result to file

        Args:
            result: GEOINTResult object
            output_path: Output file path
            format: Output format (json, csv, kml)
        """
        if format == 'json':
            with open(output_path, 'w') as f:
                json.dump(asdict(result), f, indent=2)
        elif format == 'kml':
            self._export_kml(result, output_path)
        elif format == 'csv':
            self._export_csv(result, output_path)
        else:
            raise ValueError(f"Unsupported format: {format}")

        self.logger.info(f"Result exported to {output_path}")

    def _export_kml(self, result: GEOINTResult, output_path: str):
        """Export locations to KML format"""
        kml_template = """<?xml version="1.0" encoding="UTF-8"?>
<kml xmlns="http://www.opengis.net/kml/2.2">
  <Document>
    <name>{target_id}</name>
    {placemarks}
  </Document>
</kml>"""

        placemark_template = """
    <Placemark>
      <name>{source}</name>
      <Point>
        <coordinates>{lon},{lat},0</coordinates>
      </Point>
    </Placemark>"""

        placemarks = []
        for loc in result.locations:
            if 'latitude' in loc and 'longitude' in loc:
                placemarks.append(placemark_template.format(
                    source=loc.get('source', 'Unknown'),
                    lat=loc['latitude'],
                    lon=loc['longitude']
                ))

        kml = kml_template.format(
            target_id=result.target_id,
            placemarks=''.join(placemarks)
        )

        with open(output_path, 'w') as f:
            f.write(kml)

    def _export_csv(self, result: GEOINTResult, output_path: str):
        """Export locations to CSV format"""
        import csv

        with open(output_path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Source', 'Latitude', 'Longitude', 'City', 'Country'])

            for loc in result.locations:
                writer.writerow([
                    loc.get('source', ''),
                    loc.get('latitude', ''),
                    loc.get('longitude', ''),
                    loc.get('city', ''),
                    loc.get('country', '')
                ])

    def batch_analyze(self, targets: List[Dict], output_dir: str = './results') -> List[GEOINTResult]:
        """
        Batch analyze multiple targets

        Args:
            targets: List of target dictionaries
            output_dir: Directory to save results

        Returns:
            List of GEOINTResult objects
        """
        results = []
        Path(output_dir).mkdir(parents=True, exist_ok=True)

        for target in targets:
            try:
                result = self.locate_target(**target)
                results.append(result)

                # Auto-export
                output_file = Path(output_dir) / f"{result.target_id}.json"
                self.export_result(result, str(output_file))

            except Exception as e:
                self.logger.error(f"Batch analysis failed for {target}: {e}")

        return results


if __name__ == "__main__":
    # Example usage
    geoint = GEOINT()

    # Single target analysis
    result = geoint.locate_target(
        target_id="SUSPECT_001",
        ip="8.8.8.8",
        phone="+1-555-0123",
        photo="suspect_photo.jpg"
    )

    print(f"Analysis complete: {result.target_id}")
    print(f"Confidence: {result.confidence_score:.2f}")
    print(f"Locations found: {len(result.locations)}")

    # Export results
    geoint.export_result(result, "suspect_001.json", format='json')
    geoint.export_result(result, "suspect_001.kml", format='kml')
