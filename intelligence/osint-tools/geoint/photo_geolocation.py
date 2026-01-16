"""
Photo Geolocation Module
Extract location data from photos using EXIF, AI, and image analysis
"""

import logging
import requests
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
from typing import Dict, Optional, List, Tuple
import json
from datetime import datetime
from pathlib import Path
import math


class PhotoGeolocation:
    """Photo Geolocation and Image Intelligence"""

    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize Photo Geolocation module

        Args:
            config: Configuration dictionary
        """
        self.logger = logging.getLogger(__name__)
        self.config = config or {}

        # API keys
        self.geospy_key = self.config.get('geospy_key')
        self.google_vision_key = self.config.get('google_vision_key')

        # Cache
        self.cache = {}

    def extract_location(self, image_path: str) -> Dict:
        """
        Extract location data from photo

        Args:
            image_path: Path to image file

        Returns:
            Dictionary with location intelligence
        """
        if not Path(image_path).exists():
            return {'error': 'Image file not found'}

        result = {
            'image_path': image_path,
            'timestamp': datetime.now().isoformat(),
            'exif': {},
            'gps': {},
            'datetime': {},
            'camera': {},
            'landmarks': [],
            'estimated_location': {},
            'confidence': 0.0
        }

        try:
            # Extract EXIF data
            exif_data = self._extract_exif(image_path)
            result['exif'] = exif_data

            # Extract GPS coordinates
            gps_data = self._extract_gps(exif_data)
            if gps_data:
                result['gps'] = gps_data
                result['confidence'] = 0.95  # GPS is highly accurate

            # Extract datetime
            datetime_data = self._extract_datetime(exif_data)
            result['datetime'] = datetime_data

            # Extract camera info
            camera_data = self._extract_camera_info(exif_data)
            result['camera'] = camera_data

            # If no GPS, try AI-based geolocation
            if not gps_data:
                # GeoSpy AI
                if self.geospy_key:
                    geospy_result = self._geospy_analyze(image_path)
                    if geospy_result:
                        result['estimated_location'] = geospy_result
                        result['confidence'] = geospy_result.get('confidence', 0.5)

                # Google Vision API for landmark detection
                if self.google_vision_key:
                    landmarks = self._detect_landmarks(image_path)
                    result['landmarks'] = landmarks
                    if landmarks:
                        result['confidence'] = max(result['confidence'], 0.7)

            # Sun position analysis (if datetime available)
            if datetime_data.get('datetime_original'):
                sun_analysis = self._analyze_sun_position(image_path, datetime_data['datetime_original'])
                result['sun_analysis'] = sun_analysis

            # Shadow analysis
            shadow_data = self._analyze_shadows(image_path)
            result['shadow_analysis'] = shadow_data

        except Exception as e:
            self.logger.error(f"Photo location extraction error: {e}")
            result['error'] = str(e)

        return result

    def _extract_exif(self, image_path: str) -> Dict:
        """Extract all EXIF data from image"""
        try:
            image = Image.open(image_path)
            exif_data = {}

            exif = image.getexif()
            if exif:
                for tag_id, value in exif.items():
                    tag = TAGS.get(tag_id, tag_id)
                    exif_data[tag] = value

            return exif_data
        except Exception as e:
            self.logger.error(f"EXIF extraction error: {e}")
            return {}

    def _extract_gps(self, exif_data: Dict) -> Dict:
        """Extract GPS coordinates from EXIF data"""
        try:
            gps_info = exif_data.get('GPSInfo', {})
            if not gps_info:
                return {}

            gps_data = {}
            for key, value in gps_info.items():
                tag = GPSTAGS.get(key, key)
                gps_data[tag] = value

            # Convert to decimal degrees
            lat = self._convert_to_degrees(gps_data.get('GPSLatitude'))
            lon = self._convert_to_degrees(gps_data.get('GPSLongitude'))

            if lat and lon:
                # Adjust for hemisphere
                if gps_data.get('GPSLatitudeRef') == 'S':
                    lat = -lat
                if gps_data.get('GPSLongitudeRef') == 'W':
                    lon = -lon

                result = {
                    'latitude': lat,
                    'longitude': lon,
                    'altitude': gps_data.get('GPSAltitude'),
                    'altitude_ref': gps_data.get('GPSAltitudeRef'),
                    'timestamp': gps_data.get('GPSTimeStamp'),
                    'datestamp': gps_data.get('GPSDateStamp'),
                    'speed': gps_data.get('GPSSpeed'),
                    'direction': gps_data.get('GPSImgDirection')
                }

                # Reverse geocode
                location_name = self._reverse_geocode(lat, lon)
                if location_name:
                    result['location_name'] = location_name

                return result
        except Exception as e:
            self.logger.error(f"GPS extraction error: {e}")

        return {}

    def _convert_to_degrees(self, value) -> Optional[float]:
        """Convert GPS coordinates to decimal degrees"""
        try:
            if not value:
                return None

            d, m, s = value
            return float(d) + float(m) / 60.0 + float(s) / 3600.0
        except Exception:
            return None

    def _reverse_geocode(self, lat: float, lon: float) -> Optional[str]:
        """Reverse geocode coordinates to location name"""
        try:
            url = f"https://nominatim.openstreetmap.org/reverse"
            params = {
                'lat': lat,
                'lon': lon,
                'format': 'json',
                'addressdetails': 1
            }
            headers = {'User-Agent': 'GEOINT-PhotoAnalyzer/1.0'}

            response = requests.get(url, params=params, headers=headers, timeout=10)
            response.raise_for_status()
            data = response.json()

            return data.get('display_name')
        except Exception as e:
            self.logger.error(f"Reverse geocoding error: {e}")
            return None

    def _extract_datetime(self, exif_data: Dict) -> Dict:
        """Extract datetime information from EXIF"""
        return {
            'datetime_original': exif_data.get('DateTimeOriginal'),
            'datetime_digitized': exif_data.get('DateTimeDigitized'),
            'datetime': exif_data.get('DateTime'),
            'subsec_time': exif_data.get('SubSecTime'),
            'offset_time': exif_data.get('OffsetTime'),
            'offset_time_original': exif_data.get('OffsetTimeOriginal')
        }

    def _extract_camera_info(self, exif_data: Dict) -> Dict:
        """Extract camera and settings information"""
        return {
            'make': exif_data.get('Make'),
            'model': exif_data.get('Model'),
            'software': exif_data.get('Software'),
            'focal_length': exif_data.get('FocalLength'),
            'f_number': exif_data.get('FNumber'),
            'exposure_time': exif_data.get('ExposureTime'),
            'iso': exif_data.get('ISOSpeedRatings'),
            'flash': exif_data.get('Flash'),
            'orientation': exif_data.get('Orientation'),
            'white_balance': exif_data.get('WhiteBalance')
        }

    def _geospy_analyze(self, image_path: str) -> Dict:
        """
        Analyze image using GeoSpy AI for location estimation

        Note: GeoSpy uses deep learning to estimate location from image content
        """
        try:
            # This is a placeholder for GeoSpy API integration
            # Actual implementation would require GeoSpy API access
            url = "https://api.geospy.ai/v1/analyze"
            headers = {'Authorization': f'Bearer {self.geospy_key}'}

            with open(image_path, 'rb') as f:
                files = {'image': f}
                response = requests.post(url, headers=headers, files=files, timeout=30)
                response.raise_for_status()
                data = response.json()

            return {
                'latitude': data.get('latitude'),
                'longitude': data.get('longitude'),
                'country': data.get('country'),
                'city': data.get('city'),
                'confidence': data.get('confidence'),
                'region': data.get('region'),
                'details': data.get('details')
            }
        except Exception as e:
            self.logger.error(f"GeoSpy analysis error: {e}")
            return {}

    def _detect_landmarks(self, image_path: str) -> List[Dict]:
        """Detect landmarks in image using Google Vision API"""
        try:
            url = f"https://vision.googleapis.com/v1/images:annotate?key={self.google_vision_key}"

            with open(image_path, 'rb') as f:
                image_content = f.read()

            import base64
            encoded_image = base64.b64encode(image_content).decode('utf-8')

            payload = {
                'requests': [{
                    'image': {'content': encoded_image},
                    'features': [{'type': 'LANDMARK_DETECTION', 'maxResults': 10}]
                }]
            }

            response = requests.post(url, json=payload, timeout=30)
            response.raise_for_status()
            data = response.json()

            landmarks = []
            for annotation in data.get('responses', [{}])[0].get('landmarkAnnotations', []):
                landmark = {
                    'name': annotation.get('description'),
                    'confidence': annotation.get('score'),
                    'latitude': annotation.get('locations', [{}])[0].get('latLng', {}).get('latitude'),
                    'longitude': annotation.get('locations', [{}])[0].get('latLng', {}).get('longitude')
                }
                landmarks.append(landmark)

            return landmarks
        except Exception as e:
            self.logger.error(f"Landmark detection error: {e}")
            return []

    def _analyze_sun_position(self, image_path: str, datetime_str: str) -> Dict:
        """
        Analyze sun position in image to estimate location

        This is a simplified version. Full implementation would require:
        - Shadow angle analysis
        - Sun position calculation
        - Image brightness analysis
        """
        try:
            # Parse datetime
            from datetime import datetime
            dt = datetime.strptime(datetime_str, '%Y:%m:%d %H:%M:%S')

            # This is a placeholder for actual sun position analysis
            # Would use libraries like pysolar or ephem
            return {
                'datetime': dt.isoformat(),
                'estimated_latitude_range': None,
                'estimated_longitude_range': None,
                'confidence': 0.3,
                'notes': 'Sun position analysis requires shadow angle measurement'
            }
        except Exception as e:
            self.logger.error(f"Sun position analysis error: {e}")
            return {}

    def _analyze_shadows(self, image_path: str) -> Dict:
        """
        Analyze shadows in image for direction and time estimation

        Shadow analysis can help estimate:
        - Time of day
        - Direction (N/S/E/W)
        - Latitude (shadow length)
        """
        try:
            from PIL import ImageStat, ImageEnhance

            image = Image.open(image_path)

            # Convert to grayscale for analysis
            gray = image.convert('L')

            # Calculate image statistics
            stat = ImageStat.Stat(gray)

            return {
                'average_brightness': stat.mean[0],
                'brightness_stddev': stat.stddev[0],
                'has_shadows': stat.stddev[0] > 50,  # High contrast suggests shadows
                'shadow_confidence': min(stat.stddev[0] / 100, 1.0)
            }
        except Exception as e:
            self.logger.error(f"Shadow analysis error: {e}")
            return {}

    def analyze_metadata(self, image_path: str) -> Dict:
        """
        Extract all metadata from image including hidden data

        Args:
            image_path: Path to image file

        Returns:
            Complete metadata dictionary
        """
        metadata = {
            'exif': {},
            'iptc': {},
            'xmp': {},
            'comments': []
        }

        try:
            # EXIF
            metadata['exif'] = self._extract_exif(image_path)

            # IPTC and XMP would require additional libraries like iptcinfo3
            # Placeholder for full implementation

        except Exception as e:
            self.logger.error(f"Metadata extraction error: {e}")

        return metadata

    def estimate_location_from_content(self, image_path: str) -> Dict:
        """
        Estimate location from image content (buildings, signs, vegetation, etc.)

        This would use computer vision to identify:
        - Architecture style
        - Street signs
        - Language on signs
        - Vegetation type
        - Vehicle types and license plates
        """
        result = {
            'confidence': 0.0,
            'indicators': []
        }

        try:
            # This would integrate with computer vision models
            # Placeholder for actual implementation

            # Text detection (signs, license plates)
            if self.google_vision_key:
                text_data = self._detect_text(image_path)
                if text_data:
                    result['indicators'].append({
                        'type': 'text',
                        'data': text_data,
                        'confidence': 0.6
                    })
        except Exception as e:
            self.logger.error(f"Content analysis error: {e}")

        return result

    def _detect_text(self, image_path: str) -> List[str]:
        """Detect text in image using OCR"""
        try:
            url = f"https://vision.googleapis.com/v1/images:annotate?key={self.google_vision_key}"

            with open(image_path, 'rb') as f:
                image_content = f.read()

            import base64
            encoded_image = base64.b64encode(image_content).decode('utf-8')

            payload = {
                'requests': [{
                    'image': {'content': encoded_image},
                    'features': [{'type': 'TEXT_DETECTION'}]
                }]
            }

            response = requests.post(url, json=payload, timeout=30)
            response.raise_for_status()
            data = response.json()

            texts = []
            for annotation in data.get('responses', [{}])[0].get('textAnnotations', []):
                texts.append(annotation.get('description'))

            return texts
        except Exception as e:
            self.logger.error(f"Text detection error: {e}")
            return []

    def batch_analyze(self, image_paths: List[str]) -> List[Dict]:
        """Batch analyze multiple images"""
        results = []
        for image_path in image_paths:
            try:
                result = self.extract_location(image_path)
                results.append(result)
            except Exception as e:
                self.logger.error(f"Batch analysis failed for {image_path}: {e}")
                results.append({'image_path': image_path, 'error': str(e)})
        return results


if __name__ == "__main__":
    # Example usage
    photo_geo = PhotoGeolocation({
        'geospy_key': 'your_key_here',
        'google_vision_key': 'your_key_here'
    })

    # Analyze single photo
    result = photo_geo.extract_location("suspect_photo.jpg")
    print(json.dumps(result, indent=2))
