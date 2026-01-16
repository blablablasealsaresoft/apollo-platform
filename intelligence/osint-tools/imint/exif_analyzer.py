"""
EXIF Analyzer - Extract and Analyze Image Metadata
GPS coordinates, camera info, timestamps, software detection
"""

import os
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
from pathlib import Path


class EXIFAnalyzer:
    """
    Comprehensive EXIF metadata extraction and analysis
    """

    def __init__(self, config: Optional[Dict] = None):
        """Initialize EXIF analyzer"""
        self.config = config or {}
        self.logger = logging.getLogger('EXIFAnalyzer')

        # Initialize EXIF libraries
        self._initialize_libraries()

        self.logger.info("EXIF Analyzer initialized")

    def _initialize_libraries(self):
        """Initialize EXIF extraction libraries"""
        try:
            from PIL import Image
            from PIL.ExifTags import TAGS, GPSTAGS
            self.Image = Image
            self.TAGS = TAGS
            self.GPSTAGS = GPSTAGS
            self.has_pil = True
            self.logger.info("PIL/Pillow loaded")
        except ImportError:
            self.has_pil = False
            self.logger.warning("PIL/Pillow not available")

        try:
            import exifread
            self.exifread = exifread
            self.has_exifread = True
            self.logger.info("exifread loaded")
        except ImportError:
            self.has_exifread = False
            self.logger.warning("exifread not available")

    def extract_exif(self, image_path: str) -> Dict[str, Any]:
        """
        Extract all EXIF metadata from image

        Args:
            image_path: Path to image file

        Returns:
            Complete EXIF metadata
        """
        self.logger.info(f"Extracting EXIF from: {image_path}")

        exif_data = {
            'file_path': image_path,
            'file_name': os.path.basename(image_path),
            'has_exif': False,
            'camera': {},
            'gps': {},
            'datetime': {},
            'software': {},
            'all_tags': {}
        }

        # Try PIL/Pillow first
        if self.has_pil:
            pil_data = self._extract_with_pil(image_path)
            if pil_data:
                exif_data.update(pil_data)
                exif_data['has_exif'] = True

        # Try exifread for more detailed data
        elif self.has_exifread:
            exifread_data = self._extract_with_exifread(image_path)
            if exifread_data:
                exif_data.update(exifread_data)
                exif_data['has_exif'] = True

        # Analyze and enhance data
        if exif_data['has_exif']:
            exif_data['analysis'] = self._analyze_exif(exif_data)

        return exif_data

    def _extract_with_pil(self, image_path: str) -> Optional[Dict[str, Any]]:
        """Extract EXIF using PIL/Pillow"""
        try:
            image = self.Image.open(image_path)
            exif_raw = image._getexif()

            if not exif_raw:
                return None

            exif_data = {
                'camera': {},
                'gps': {},
                'datetime': {},
                'software': {},
                'all_tags': {}
            }

            # Process all EXIF tags
            for tag_id, value in exif_raw.items():
                tag_name = self.TAGS.get(tag_id, tag_id)
                exif_data['all_tags'][tag_name] = str(value)

                # Camera information
                if tag_name in ['Make', 'Model', 'LensModel', 'LensMake']:
                    exif_data['camera'][tag_name.lower()] = str(value)

                # DateTime information
                elif tag_name in ['DateTime', 'DateTimeOriginal', 'DateTimeDigitized']:
                    exif_data['datetime'][tag_name.lower()] = str(value)

                # Software information
                elif tag_name in ['Software', 'ProcessingSoftware']:
                    exif_data['software'][tag_name.lower()] = str(value)

                # GPS information
                elif tag_name == 'GPSInfo':
                    gps_data = {}
                    for gps_tag_id, gps_value in value.items():
                        gps_tag_name = self.GPSTAGS.get(gps_tag_id, gps_tag_id)
                        gps_data[gps_tag_name] = gps_value

                    exif_data['gps'] = self._parse_gps_data(gps_data)

            # Additional camera details
            if 'FNumber' in exif_data['all_tags']:
                exif_data['camera']['aperture'] = exif_data['all_tags']['FNumber']
            if 'ExposureTime' in exif_data['all_tags']:
                exif_data['camera']['shutter_speed'] = exif_data['all_tags']['ExposureTime']
            if 'ISOSpeedRatings' in exif_data['all_tags']:
                exif_data['camera']['iso'] = exif_data['all_tags']['ISOSpeedRatings']
            if 'FocalLength' in exif_data['all_tags']:
                exif_data['camera']['focal_length'] = exif_data['all_tags']['FocalLength']

            return exif_data

        except Exception as e:
            self.logger.error(f"PIL EXIF extraction error: {str(e)}")
            return None

    def _extract_with_exifread(self, image_path: str) -> Optional[Dict[str, Any]]:
        """Extract EXIF using exifread"""
        try:
            with open(image_path, 'rb') as f:
                tags = self.exifread.process_file(f, details=True)

            if not tags:
                return None

            exif_data = {
                'camera': {},
                'gps': {},
                'datetime': {},
                'software': {},
                'all_tags': {}
            }

            # Process tags
            for tag, value in tags.items():
                tag_str = str(tag)
                value_str = str(value)
                exif_data['all_tags'][tag_str] = value_str

                # Camera info
                if 'Image Make' in tag_str:
                    exif_data['camera']['make'] = value_str
                elif 'Image Model' in tag_str:
                    exif_data['camera']['model'] = value_str
                elif 'EXIF LensModel' in tag_str:
                    exif_data['camera']['lens'] = value_str

                # DateTime
                elif 'DateTime' in tag_str:
                    key = tag_str.split()[-1].lower()
                    exif_data['datetime'][key] = value_str

                # Software
                elif 'Software' in tag_str:
                    exif_data['software']['software'] = value_str

                # GPS
                elif tag_str.startswith('GPS'):
                    exif_data['gps'][tag_str] = value_str

            # Parse GPS coordinates
            if exif_data['gps']:
                exif_data['gps'] = self._parse_gps_from_exifread(exif_data['gps'])

            return exif_data

        except Exception as e:
            self.logger.error(f"exifread extraction error: {str(e)}")
            return None

    def _parse_gps_data(self, gps_data: Dict) -> Dict[str, Any]:
        """Parse GPS data from PIL format"""
        parsed_gps = {}

        try:
            # Get latitude
            if 'GPSLatitude' in gps_data and 'GPSLatitudeRef' in gps_data:
                lat = gps_data['GPSLatitude']
                lat_ref = gps_data['GPSLatitudeRef']
                latitude = self._convert_to_degrees(lat)
                if lat_ref == 'S':
                    latitude = -latitude
                parsed_gps['latitude'] = latitude

            # Get longitude
            if 'GPSLongitude' in gps_data and 'GPSLongitudeRef' in gps_data:
                lon = gps_data['GPSLongitude']
                lon_ref = gps_data['GPSLongitudeRef']
                longitude = self._convert_to_degrees(lon)
                if lon_ref == 'W':
                    longitude = -longitude
                parsed_gps['longitude'] = longitude

            # Get altitude
            if 'GPSAltitude' in gps_data:
                altitude = float(gps_data['GPSAltitude'])
                parsed_gps['altitude'] = altitude

            # Get timestamp
            if 'GPSTimeStamp' in gps_data and 'GPSDateStamp' in gps_data:
                time_stamp = gps_data['GPSTimeStamp']
                date_stamp = gps_data['GPSDateStamp']
                parsed_gps['timestamp'] = f"{date_stamp} {time_stamp[0]}:{time_stamp[1]}:{time_stamp[2]}"

        except Exception as e:
            self.logger.error(f"GPS parsing error: {str(e)}")

        return parsed_gps

    def _parse_gps_from_exifread(self, gps_tags: Dict) -> Dict[str, Any]:
        """Parse GPS data from exifread format"""
        parsed_gps = {}

        try:
            # This would need proper parsing of exifread GPS format
            # Simplified version here
            if 'GPS GPSLatitude' in gps_tags:
                parsed_gps['latitude_raw'] = gps_tags['GPS GPSLatitude']
            if 'GPS GPSLongitude' in gps_tags:
                parsed_gps['longitude_raw'] = gps_tags['GPS GPSLongitude']
            if 'GPS GPSAltitude' in gps_tags:
                parsed_gps['altitude'] = gps_tags['GPS GPSAltitude']

        except Exception as e:
            self.logger.error(f"GPS parsing error: {str(e)}")

        return parsed_gps

    def _convert_to_degrees(self, value):
        """Convert GPS coordinates to degrees"""
        d = float(value[0])
        m = float(value[1])
        s = float(value[2])
        return d + (m / 60.0) + (s / 3600.0)

    def _analyze_exif(self, exif_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze EXIF data for intelligence"""
        analysis = {
            'has_location': bool(exif_data['gps']),
            'has_camera_info': bool(exif_data['camera']),
            'has_datetime': bool(exif_data['datetime']),
            'has_software': bool(exif_data['software']),
            'intelligence': []
        }

        # Location intelligence
        if exif_data['gps']:
            lat = exif_data['gps'].get('latitude')
            lon = exif_data['gps'].get('longitude')
            if lat and lon:
                analysis['intelligence'].append({
                    'type': 'location',
                    'priority': 'high',
                    'data': f"GPS coordinates: {lat}, {lon}",
                    'google_maps_url': f"https://www.google.com/maps?q={lat},{lon}"
                })

        # Camera intelligence
        if exif_data['camera']:
            make = exif_data['camera'].get('make', '')
            model = exif_data['camera'].get('model', '')
            if make or model:
                analysis['intelligence'].append({
                    'type': 'camera',
                    'priority': 'medium',
                    'data': f"Camera: {make} {model}"
                })

        # Timestamp intelligence
        if exif_data['datetime']:
            for key, value in exif_data['datetime'].items():
                analysis['intelligence'].append({
                    'type': 'timestamp',
                    'priority': 'medium',
                    'data': f"{key}: {value}"
                })

        # Software intelligence
        if exif_data['software']:
            for key, value in exif_data['software'].items():
                analysis['intelligence'].append({
                    'type': 'software',
                    'priority': 'low',
                    'data': f"Edited with: {value}"
                })

        return analysis

    def extract_gps_coordinates(self, image_path: str) -> Optional[Dict[str, float]]:
        """
        Extract only GPS coordinates from image

        Args:
            image_path: Path to image

        Returns:
            GPS coordinates or None
        """
        exif_data = self.extract_exif(image_path)

        if exif_data['gps']:
            lat = exif_data['gps'].get('latitude')
            lon = exif_data['gps'].get('longitude')

            if lat and lon:
                return {
                    'latitude': lat,
                    'longitude': lon,
                    'altitude': exif_data['gps'].get('altitude')
                }

        return None

    def strip_exif(self, image_path: str, output_path: str):
        """
        Remove all EXIF data from image

        Args:
            image_path: Input image path
            output_path: Output image path
        """
        self.logger.info(f"Stripping EXIF from: {image_path}")

        if not self.has_pil:
            raise Exception("PIL/Pillow required for EXIF stripping")

        try:
            image = self.Image.open(image_path)

            # Create image without EXIF
            data = list(image.getdata())
            image_without_exif = self.Image.new(image.mode, image.size)
            image_without_exif.putdata(data)

            # Save without EXIF
            image_without_exif.save(output_path)

            self.logger.info(f"EXIF stripped. Saved to: {output_path}")

        except Exception as e:
            self.logger.error(f"EXIF stripping error: {str(e)}")
            raise

    def batch_extract_exif(self, image_dir: str) -> List[Dict[str, Any]]:
        """
        Extract EXIF from all images in directory

        Args:
            image_dir: Directory containing images

        Returns:
            List of EXIF data for all images
        """
        self.logger.info(f"Batch extracting EXIF from: {image_dir}")

        results = []

        # Find all images
        image_files = []
        for ext in ['.jpg', '.jpeg', '.png', '.tiff', '.bmp']:
            image_files.extend(Path(image_dir).glob(f"**/*{ext}"))

        for image_file in image_files:
            try:
                exif_data = self.extract_exif(str(image_file))
                results.append(exif_data)
            except Exception as e:
                self.logger.error(f"Error processing {image_file}: {str(e)}")

        self.logger.info(f"Extracted EXIF from {len(results)} images")

        return results


if __name__ == "__main__":
    print("EXIF Analyzer - Image Metadata Extraction")
    print("=" * 60)

    analyzer = EXIFAnalyzer()

    print("\nCapabilities:")
    print("  - Extract all EXIF metadata")
    print("  - GPS coordinate extraction")
    print("  - Camera information")
    print("  - Timestamp analysis")
    print("  - Software detection")
    print("  - EXIF stripping")
    print("\nUsage:")
    print("  exif_data = analyzer.extract_exif('photo.jpg')")
    print("  gps = analyzer.extract_gps_coordinates('photo.jpg')")
    print("  analyzer.strip_exif('photo.jpg', 'photo_no_exif.jpg')")
