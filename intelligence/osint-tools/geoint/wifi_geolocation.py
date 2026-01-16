"""
WiFi Geolocation Module
WiFi access point intelligence and geolocation
"""

import logging
import requests
from typing import Dict, Optional, List
import json
from datetime import datetime


class WiFiGeolocation:
    """WiFi Access Point Geolocation and Intelligence"""

    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize WiFi Geolocation module

        Args:
            config: Configuration dictionary
        """
        self.logger = logging.getLogger(__name__)
        self.config = config or {}

        # API keys
        self.wigle_key = self.config.get('wigle_key')
        self.wigle_token = self.config.get('wigle_token')
        self.google_key = self.config.get('google_geolocation_key')
        self.mozilla_key = self.config.get('mozilla_location_key')

        # Cache
        self.cache = {}

    def locate(self, bssid: str, ssid: Optional[str] = None) -> Dict:
        """
        Locate WiFi access point

        Args:
            bssid: BSSID (MAC address) of access point
            ssid: Optional SSID name

        Returns:
            Dictionary with WiFi location intelligence
        """
        # Normalize BSSID
        bssid = self._normalize_bssid(bssid)

        # Check cache
        if bssid in self.cache:
            return self.cache[bssid]

        result = {
            'bssid': bssid,
            'ssid': ssid,
            'timestamp': datetime.now().isoformat(),
            'location': {},
            'network_info': {},
            'observations': [],
            'confidence': 0.0
        }

        try:
            # Query WiGLE database
            if self.wigle_key:
                wigle_data = self._query_wigle(bssid)
                if wigle_data:
                    result['location'] = wigle_data.get('location', {})
                    result['network_info'] = wigle_data.get('network_info', {})
                    result['observations'] = wigle_data.get('observations', [])
                    result['confidence'] = 0.85

            # Query Google Geolocation API
            if self.google_key and not result['location']:
                google_data = self._query_google(bssid, ssid)
                if google_data:
                    result['location'] = google_data.get('location', {})
                    result['confidence'] = google_data.get('accuracy', 0) / 1000  # Convert to confidence

            # Query Mozilla Location Service
            if self.mozilla_key and not result['location']:
                mozilla_data = self._query_mozilla(bssid, ssid)
                if mozilla_data:
                    result['location'] = mozilla_data.get('location', {})
                    result['confidence'] = mozilla_data.get('accuracy', 0) / 1000

            # Enrich with additional data
            if result['location']:
                result['location']['reverse_geocode'] = self._reverse_geocode(
                    result['location'].get('latitude'),
                    result['location'].get('longitude')
                )

        except Exception as e:
            self.logger.error(f"WiFi location lookup error: {e}")
            result['error'] = str(e)

        # Cache result
        self.cache[bssid] = result

        return result

    def _normalize_bssid(self, bssid: str) -> str:
        """Normalize BSSID to standard format (XX:XX:XX:XX:XX:XX)"""
        # Remove common separators
        bssid = bssid.replace('-', ':').replace('.', ':').upper()

        # Ensure proper format
        parts = bssid.split(':')
        if len(parts) == 6:
            return ':'.join(parts)

        # Handle no separators
        if len(bssid) == 12:
            return ':'.join([bssid[i:i+2] for i in range(0, 12, 2)])

        return bssid

    def _query_wigle(self, bssid: str) -> Dict:
        """
        Query WiGLE database for BSSID

        WiGLE is the largest WiFi network database
        """
        try:
            url = "https://api.wigle.net/api/v2/network/search"
            auth = (self.wigle_key, self.wigle_token)
            params = {
                'netid': bssid,
                'first': 0,
                'freenet': 'false',
                'paynet': 'false'
            }

            response = requests.get(url, auth=auth, params=params, timeout=30)
            response.raise_for_status()
            data = response.json()

            if data.get('success') and data.get('results'):
                result = data['results'][0]

                return {
                    'location': {
                        'latitude': result.get('trilat'),
                        'longitude': result.get('trilong'),
                        'country': result.get('country'),
                        'region': result.get('region'),
                        'city': result.get('city'),
                        'postal_code': result.get('postalcode')
                    },
                    'network_info': {
                        'ssid': result.get('ssid'),
                        'encryption': result.get('encryption'),
                        'channel': result.get('channel'),
                        'signal_quality': result.get('qos'),
                        'last_update': result.get('lastupdt'),
                        'first_seen': result.get('firsttime')
                    },
                    'observations': [{
                        'date': result.get('lastupdt'),
                        'latitude': result.get('trilat'),
                        'longitude': result.get('trilong')
                    }]
                }

        except Exception as e:
            self.logger.error(f"WiGLE query error: {e}")

        return {}

    def _query_google(self, bssid: str, ssid: Optional[str] = None) -> Dict:
        """Query Google Geolocation API"""
        try:
            url = f"https://www.googleapis.com/geolocation/v1/geolocate?key={self.google_key}"

            payload = {
                'considerIp': False,
                'wifiAccessPoints': [
                    {
                        'macAddress': bssid
                    }
                ]
            }

            if ssid:
                payload['wifiAccessPoints'][0]['ssid'] = ssid

            response = requests.post(url, json=payload, timeout=30)
            response.raise_for_status()
            data = response.json()

            return {
                'location': {
                    'latitude': data.get('location', {}).get('lat'),
                    'longitude': data.get('location', {}).get('lng')
                },
                'accuracy': data.get('accuracy')
            }

        except Exception as e:
            self.logger.error(f"Google Geolocation query error: {e}")

        return {}

    def _query_mozilla(self, bssid: str, ssid: Optional[str] = None) -> Dict:
        """Query Mozilla Location Service"""
        try:
            url = "https://location.services.mozilla.com/v1/geolocate"
            params = {'key': self.mozilla_key} if self.mozilla_key else {}

            payload = {
                'wifiAccessPoints': [
                    {
                        'macAddress': bssid
                    }
                ]
            }

            if ssid:
                payload['wifiAccessPoints'][0]['ssid'] = ssid

            response = requests.post(url, params=params, json=payload, timeout=30)
            response.raise_for_status()
            data = response.json()

            return {
                'location': {
                    'latitude': data.get('location', {}).get('lat'),
                    'longitude': data.get('location', {}).get('lng')
                },
                'accuracy': data.get('accuracy')
            }

        except Exception as e:
            self.logger.error(f"Mozilla Location Service query error: {e}")

        return {}

    def _reverse_geocode(self, latitude: Optional[float], longitude: Optional[float]) -> Optional[str]:
        """Reverse geocode coordinates to address"""
        if not latitude or not longitude:
            return None

        try:
            url = "https://nominatim.openstreetmap.org/reverse"
            params = {
                'lat': latitude,
                'lon': longitude,
                'format': 'json',
                'addressdetails': 1
            }
            headers = {'User-Agent': 'GEOINT-WiFiAnalyzer/1.0'}

            response = requests.get(url, params=params, headers=headers, timeout=10)
            response.raise_for_status()
            data = response.json()

            return data.get('display_name')

        except Exception as e:
            self.logger.error(f"Reverse geocoding error: {e}")
            return None

    def search_by_location(self, latitude: float, longitude: float, radius_km: float = 1.0) -> List[Dict]:
        """
        Search for WiFi networks near a location

        Args:
            latitude: Latitude
            longitude: Longitude
            radius_km: Search radius in kilometers

        Returns:
            List of nearby WiFi networks
        """
        networks = []

        try:
            if self.wigle_key:
                url = "https://api.wigle.net/api/v2/network/search"
                auth = (self.wigle_key, self.wigle_token)
                params = {
                    'latrange1': latitude - (radius_km / 111),  # Approximate conversion
                    'latrange2': latitude + (radius_km / 111),
                    'longrange1': longitude - (radius_km / 111),
                    'longrange2': longitude + (radius_km / 111),
                    'variance': 0.01
                }

                response = requests.get(url, auth=auth, params=params, timeout=30)
                response.raise_for_status()
                data = response.json()

                for result in data.get('results', []):
                    networks.append({
                        'bssid': result.get('netid'),
                        'ssid': result.get('ssid'),
                        'latitude': result.get('trilat'),
                        'longitude': result.get('trilong'),
                        'encryption': result.get('encryption'),
                        'channel': result.get('channel'),
                        'last_seen': result.get('lastupdt')
                    })

        except Exception as e:
            self.logger.error(f"WiFi location search error: {e}")

        return networks

    def search_by_ssid(self, ssid: str, limit: int = 100) -> List[Dict]:
        """
        Search for networks by SSID name

        Args:
            ssid: SSID to search for
            limit: Maximum results

        Returns:
            List of networks matching SSID
        """
        networks = []

        try:
            if self.wigle_key:
                url = "https://api.wigle.net/api/v2/network/search"
                auth = (self.wigle_key, self.wigle_token)
                params = {
                    'ssid': ssid,
                    'first': 0,
                    'resultsPerPage': limit
                }

                response = requests.get(url, auth=auth, params=params, timeout=30)
                response.raise_for_status()
                data = response.json()

                for result in data.get('results', []):
                    networks.append({
                        'bssid': result.get('netid'),
                        'ssid': result.get('ssid'),
                        'latitude': result.get('trilat'),
                        'longitude': result.get('trilong'),
                        'encryption': result.get('encryption'),
                        'channel': result.get('channel'),
                        'country': result.get('country'),
                        'region': result.get('region'),
                        'city': result.get('city'),
                        'last_seen': result.get('lastupdt')
                    })

        except Exception as e:
            self.logger.error(f"SSID search error: {e}")

        return networks

    def identify_network_owner(self, bssid: str) -> Dict:
        """
        Identify network owner from BSSID

        Uses OUI (Organizationally Unique Identifier) lookup
        """
        result = {
            'bssid': bssid,
            'vendor': None,
            'company': None,
            'address': None
        }

        try:
            # Extract OUI (first 3 octets)
            oui = bssid.replace(':', '').replace('-', '').upper()[:6]

            # Query MAC vendors database
            url = f"https://api.macvendors.com/{bssid}"
            headers = {'User-Agent': 'GEOINT-WiFiAnalyzer/1.0'}

            response = requests.get(url, headers=headers, timeout=10)

            if response.status_code == 200:
                vendor = response.text.strip()
                result['vendor'] = vendor
                result['company'] = vendor

        except Exception as e:
            self.logger.error(f"Network owner identification error: {e}")

        return result

    def analyze_network_security(self, bssid: str) -> Dict:
        """
        Analyze WiFi network security

        Args:
            bssid: BSSID to analyze

        Returns:
            Security analysis
        """
        security = {
            'bssid': bssid,
            'encryption_type': None,
            'security_level': 'unknown',
            'vulnerabilities': [],
            'recommendations': []
        }

        try:
            # Get network info
            network_info = self.locate(bssid)

            encryption = network_info.get('network_info', {}).get('encryption', '').lower()

            if encryption:
                security['encryption_type'] = encryption

                # Analyze security level
                if 'wpa3' in encryption:
                    security['security_level'] = 'high'
                elif 'wpa2' in encryption:
                    security['security_level'] = 'medium'
                    security['recommendations'].append('Consider upgrading to WPA3')
                elif 'wpa' in encryption:
                    security['security_level'] = 'low'
                    security['vulnerabilities'].append('WPA is vulnerable to attacks')
                    security['recommendations'].append('Upgrade to WPA2 or WPA3')
                elif 'wep' in encryption:
                    security['security_level'] = 'critical'
                    security['vulnerabilities'].append('WEP is easily crackable')
                    security['recommendations'].append('Immediately upgrade to WPA2/WPA3')
                elif 'open' in encryption or not encryption:
                    security['security_level'] = 'critical'
                    security['vulnerabilities'].append('No encryption')
                    security['recommendations'].append('Enable WPA2/WPA3 encryption')

        except Exception as e:
            self.logger.error(f"Network security analysis error: {e}")

        return security

    def track_access_point(self, bssid: str, duration_days: int = 30) -> Dict:
        """
        Track access point movements over time

        Args:
            bssid: BSSID to track
            duration_days: Tracking duration in days

        Returns:
            Tracking history
        """
        tracking = {
            'bssid': bssid,
            'locations': [],
            'movement_detected': False,
            'average_location': None
        }

        try:
            # This would query historical location data
            # Simplified implementation using WiGLE
            if self.wigle_key:
                network_data = self._query_wigle(bssid)

                if network_data.get('observations'):
                    tracking['locations'] = network_data['observations']

                    # Check for movement
                    if len(tracking['locations']) > 1:
                        lats = [loc['latitude'] for loc in tracking['locations']]
                        lons = [loc['longitude'] for loc in tracking['locations']]

                        # Simple movement detection (variance in position)
                        import statistics
                        if len(lats) > 1:
                            lat_var = statistics.variance(lats)
                            lon_var = statistics.variance(lons)

                            if lat_var > 0.001 or lon_var > 0.001:
                                tracking['movement_detected'] = True

                        # Calculate average location
                        tracking['average_location'] = {
                            'latitude': statistics.mean(lats),
                            'longitude': statistics.mean(lons)
                        }

        except Exception as e:
            self.logger.error(f"Access point tracking error: {e}")

        return tracking

    def batch_locate(self, bssids: List[str]) -> List[Dict]:
        """Batch locate multiple WiFi access points"""
        results = []
        for bssid in bssids:
            try:
                result = self.locate(bssid)
                results.append(result)
            except Exception as e:
                self.logger.error(f"Batch location failed for {bssid}: {e}")
                results.append({'bssid': bssid, 'error': str(e)})
        return results


if __name__ == "__main__":
    # Example usage
    wifi_geo = WiFiGeolocation({
        'wigle_key': 'your_key_here',
        'wigle_token': 'your_token_here'
    })

    # Locate access point
    result = wifi_geo.locate("00:11:22:33:44:55", ssid="TestNetwork")
    print(json.dumps(result, indent=2))

    # Search by location
    nearby = wifi_geo.search_by_location(37.7749, -122.4194, radius_km=0.5)
    print(f"Found {len(nearby)} networks nearby")

    # Security analysis
    security = wifi_geo.analyze_network_security("00:11:22:33:44:55")
    print(json.dumps(security, indent=2))
