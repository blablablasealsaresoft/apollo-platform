"""
IMINT Engine - Main Image and Video Intelligence System
Comprehensive IMINT capabilities for OSINT operations
"""

import os
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any
from pathlib import Path
import hashlib

from reverse_image_search import ReverseImageSearch
from face_recognition import FaceRecognition
from exif_analyzer import EXIFAnalyzer
from object_detector import ObjectDetector
from video_analyzer import VideoAnalyzer
from image_forensics import ImageForensics
from pimeyes_integration import PimEyesIntegration


class IMINT:
    """
    Main IMINT Engine for comprehensive image and video intelligence
    """

    def __init__(self, config: Optional[Dict] = None):
        """Initialize IMINT engine with all modules"""
        self.config = config or {}
        self.setup_logging()

        # Initialize all IMINT modules
        self.reverse_search = ReverseImageSearch(self.config.get('reverse_search', {}))
        self.face_recognition = FaceRecognition(self.config.get('face_recognition', {}))
        self.exif_analyzer = EXIFAnalyzer(self.config.get('exif', {}))
        self.object_detector = ObjectDetector(self.config.get('object_detection', {}))
        self.video_analyzer = VideoAnalyzer(self.config.get('video', {}))
        self.image_forensics = ImageForensics(self.config.get('forensics', {}))
        self.pimeyes = PimEyesIntegration(self.config.get('pimeyes', {}))

        self.logger.info("IMINT Engine initialized with all modules")

    def setup_logging(self):
        """Setup logging configuration"""
        log_level = self.config.get('log_level', 'INFO')
        logging.basicConfig(
            level=getattr(logging, log_level),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger('IMINT')

    def analyze_image(self, image_path: str, operations: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Comprehensive image analysis

        Args:
            image_path: Path to image file
            operations: List of operations to perform (None = all)

        Returns:
            Complete IMINT analysis results
        """
        self.logger.info(f"Starting comprehensive analysis of: {image_path}")

        if not os.path.exists(image_path):
            raise FileNotFoundError(f"Image not found: {image_path}")

        # Default to all operations if not specified
        if operations is None:
            operations = [
                'hash', 'exif', 'reverse_search', 'face_recognition',
                'object_detection', 'forensics', 'pimeyes'
            ]

        results = {
            'image_path': image_path,
            'timestamp': datetime.now().isoformat(),
            'file_info': self._get_file_info(image_path),
            'analysis': {}
        }

        # File hash
        if 'hash' in operations:
            results['analysis']['hashes'] = self._calculate_hashes(image_path)

        # EXIF metadata
        if 'exif' in operations:
            self.logger.info("Extracting EXIF metadata...")
            results['analysis']['exif'] = self.exif_analyzer.extract_exif(image_path)

        # Reverse image search
        if 'reverse_search' in operations:
            self.logger.info("Performing reverse image search...")
            results['analysis']['reverse_search'] = self.reverse_search.search_all_engines(image_path)

        # Face recognition
        if 'face_recognition' in operations:
            self.logger.info("Analyzing faces...")
            results['analysis']['faces'] = self.face_recognition.analyze_image(image_path)

        # Object detection
        if 'object_detection' in operations:
            self.logger.info("Detecting objects...")
            results['analysis']['objects'] = self.object_detector.detect_objects(image_path)

        # Image forensics
        if 'forensics' in operations:
            self.logger.info("Performing forensic analysis...")
            results['analysis']['forensics'] = self.image_forensics.analyze_image(image_path)

        # PimEyes face search
        if 'pimeyes' in operations and results['analysis'].get('faces', {}).get('faces_detected', 0) > 0:
            self.logger.info("Searching faces with PimEyes...")
            results['analysis']['pimeyes'] = self.pimeyes.search_faces(image_path)

        # Generate intelligence summary
        results['intelligence_summary'] = self._generate_intelligence_summary(results)

        self.logger.info("Analysis complete")
        return results

    def analyze_video(self, video_path: str, operations: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Comprehensive video analysis

        Args:
            video_path: Path to video file
            operations: List of operations to perform

        Returns:
            Complete video IMINT analysis
        """
        self.logger.info(f"Starting video analysis of: {video_path}")

        if not os.path.exists(video_path):
            raise FileNotFoundError(f"Video not found: {video_path}")

        results = {
            'video_path': video_path,
            'timestamp': datetime.now().isoformat(),
            'file_info': self._get_file_info(video_path),
            'analysis': {}
        }

        # Basic video analysis
        results['analysis']['video_metadata'] = self.video_analyzer.extract_metadata(video_path)

        # Extract key frames
        self.logger.info("Extracting key frames...")
        frames = self.video_analyzer.extract_key_frames(video_path)
        results['analysis']['key_frames'] = []

        # Analyze each key frame
        for i, frame_path in enumerate(frames):
            self.logger.info(f"Analyzing frame {i+1}/{len(frames)}...")
            frame_analysis = self.analyze_image(frame_path, operations)
            results['analysis']['key_frames'].append({
                'frame_number': i,
                'frame_path': frame_path,
                'analysis': frame_analysis
            })

        # Scene detection
        results['analysis']['scenes'] = self.video_analyzer.detect_scenes(video_path)

        # Audio extraction and analysis
        if self.config.get('extract_audio', True):
            results['analysis']['audio'] = self.video_analyzer.extract_audio(video_path)

        results['intelligence_summary'] = self._generate_video_intelligence_summary(results)

        self.logger.info("Video analysis complete")
        return results

    def analyze_youtube_video(self, video_url: str) -> Dict[str, Any]:
        """
        Analyze YouTube video with metadata and content analysis

        Args:
            video_url: YouTube video URL

        Returns:
            YouTube video intelligence
        """
        self.logger.info(f"Analyzing YouTube video: {video_url}")

        # Download and analyze
        results = self.video_analyzer.analyze_youtube_video(video_url)

        return results

    def batch_analyze_images(self, image_paths: List[str], operations: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """
        Batch analyze multiple images

        Args:
            image_paths: List of image paths
            operations: Operations to perform on each image

        Returns:
            List of analysis results
        """
        self.logger.info(f"Starting batch analysis of {len(image_paths)} images")

        results = []
        for i, image_path in enumerate(image_paths):
            self.logger.info(f"Processing image {i+1}/{len(image_paths)}: {image_path}")
            try:
                result = self.analyze_image(image_path, operations)
                results.append(result)
            except Exception as e:
                self.logger.error(f"Error analyzing {image_path}: {str(e)}")
                results.append({
                    'image_path': image_path,
                    'error': str(e),
                    'timestamp': datetime.now().isoformat()
                })

        return results

    def compare_faces(self, image1_path: str, image2_path: str) -> Dict[str, Any]:
        """
        Compare faces in two images

        Args:
            image1_path: First image path
            image2_path: Second image path

        Returns:
            Face comparison results
        """
        self.logger.info(f"Comparing faces: {image1_path} vs {image2_path}")

        results = self.face_recognition.compare_faces(image1_path, image2_path)

        return results

    def search_face_in_database(self, face_image_path: str, database_path: str) -> List[Dict[str, Any]]:
        """
        Search for a face in a database of images

        Args:
            face_image_path: Path to face image
            database_path: Path to image database directory

        Returns:
            List of matches with similarity scores
        """
        self.logger.info(f"Searching face in database: {database_path}")

        matches = self.face_recognition.search_database(face_image_path, database_path)

        return matches

    def monitor_face_online(self, face_image_path: str, alert_callback: Optional[callable] = None) -> Dict[str, Any]:
        """
        Monitor a face across the internet using PimEyes

        Args:
            face_image_path: Path to face image
            alert_callback: Function to call when new images found

        Returns:
            Monitoring results
        """
        self.logger.info(f"Setting up face monitoring for: {face_image_path}")

        results = self.pimeyes.monitor_face(face_image_path, alert_callback)

        return results

    def extract_location_from_image(self, image_path: str) -> Optional[Dict[str, Any]]:
        """
        Extract GPS location from image EXIF data

        Args:
            image_path: Path to image

        Returns:
            Location data if available
        """
        exif_data = self.exif_analyzer.extract_exif(image_path)

        if 'gps' in exif_data and exif_data['gps']:
            location = {
                'latitude': exif_data['gps'].get('latitude'),
                'longitude': exif_data['gps'].get('longitude'),
                'altitude': exif_data['gps'].get('altitude'),
                'timestamp': exif_data['gps'].get('timestamp'),
                'google_maps_url': self._generate_maps_url(
                    exif_data['gps'].get('latitude'),
                    exif_data['gps'].get('longitude')
                )
            }
            return location

        return None

    def detect_manipulation(self, image_path: str) -> Dict[str, Any]:
        """
        Detect if image has been manipulated

        Args:
            image_path: Path to image

        Returns:
            Manipulation detection results
        """
        self.logger.info(f"Analyzing image for manipulation: {image_path}")

        results = self.image_forensics.detect_manipulation(image_path)

        return results

    def _get_file_info(self, file_path: str) -> Dict[str, Any]:
        """Get basic file information"""
        file_stat = os.stat(file_path)
        return {
            'filename': os.path.basename(file_path),
            'size_bytes': file_stat.st_size,
            'size_mb': round(file_stat.st_size / (1024 * 1024), 2),
            'created': datetime.fromtimestamp(file_stat.st_ctime).isoformat(),
            'modified': datetime.fromtimestamp(file_stat.st_mtime).isoformat()
        }

    def _calculate_hashes(self, file_path: str) -> Dict[str, str]:
        """Calculate file hashes"""
        hashes = {}

        with open(file_path, 'rb') as f:
            data = f.read()
            hashes['md5'] = hashlib.md5(data).hexdigest()
            hashes['sha1'] = hashlib.sha1(data).hexdigest()
            hashes['sha256'] = hashlib.sha256(data).hexdigest()

        return hashes

    def _generate_maps_url(self, latitude: float, longitude: float) -> str:
        """Generate Google Maps URL from coordinates"""
        if latitude and longitude:
            return f"https://www.google.com/maps?q={latitude},{longitude}"
        return ""

    def _generate_intelligence_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate intelligence summary from analysis results"""
        summary = {
            'key_findings': [],
            'threat_level': 'low',
            'actionable_intelligence': []
        }

        analysis = results.get('analysis', {})

        # EXIF findings
        if 'exif' in analysis and analysis['exif'].get('gps'):
            gps = analysis['exif']['gps']
            summary['key_findings'].append(f"GPS coordinates found: {gps.get('latitude')}, {gps.get('longitude')}")
            summary['actionable_intelligence'].append({
                'type': 'location',
                'data': gps,
                'priority': 'high'
            })

        # Face findings
        if 'faces' in analysis:
            face_count = analysis['faces'].get('faces_detected', 0)
            if face_count > 0:
                summary['key_findings'].append(f"{face_count} face(s) detected")
                for face in analysis['faces'].get('faces', []):
                    if face.get('emotions'):
                        dominant_emotion = max(face['emotions'].items(), key=lambda x: x[1])
                        summary['key_findings'].append(f"Dominant emotion: {dominant_emotion[0]} ({dominant_emotion[1]:.1f}%)")

        # Object findings
        if 'objects' in analysis:
            objects = analysis['objects'].get('detected_objects', [])
            if objects:
                summary['key_findings'].append(f"{len(objects)} object(s) detected")
                # Highlight weapons, vehicles, etc.
                threat_objects = [obj for obj in objects if obj.get('category') in ['weapon', 'vehicle', 'person']]
                if threat_objects:
                    summary['threat_level'] = 'medium'

        # Forensics findings
        if 'forensics' in analysis:
            if analysis['forensics'].get('manipulation_detected'):
                summary['key_findings'].append("Image manipulation detected")
                summary['threat_level'] = 'high'
                summary['actionable_intelligence'].append({
                    'type': 'manipulation',
                    'data': analysis['forensics'],
                    'priority': 'critical'
                })

        # Reverse search findings
        if 'reverse_search' in analysis:
            total_results = sum(len(engine.get('results', [])) for engine in analysis['reverse_search'].values())
            if total_results > 0:
                summary['key_findings'].append(f"{total_results} reverse image search results found")

        return summary

    def _generate_video_intelligence_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate intelligence summary for video analysis"""
        summary = {
            'key_findings': [],
            'total_frames_analyzed': len(results['analysis'].get('key_frames', [])),
            'scenes_detected': len(results['analysis'].get('scenes', [])),
            'actionable_intelligence': []
        }

        # Aggregate findings from all frames
        all_faces = []
        all_objects = []
        all_locations = []

        for frame in results['analysis'].get('key_frames', []):
            frame_analysis = frame.get('analysis', {}).get('analysis', {})

            if 'faces' in frame_analysis:
                all_faces.extend(frame_analysis['faces'].get('faces', []))

            if 'objects' in frame_analysis:
                all_objects.extend(frame_analysis['objects'].get('detected_objects', []))

            if 'exif' in frame_analysis and frame_analysis['exif'].get('gps'):
                all_locations.append(frame_analysis['exif']['gps'])

        if all_faces:
            summary['key_findings'].append(f"Total faces detected: {len(all_faces)}")

        if all_objects:
            summary['key_findings'].append(f"Total objects detected: {len(all_objects)}")

        if all_locations:
            summary['key_findings'].append(f"GPS locations found in {len(all_locations)} frame(s)")
            summary['actionable_intelligence'].append({
                'type': 'locations',
                'data': all_locations,
                'priority': 'high'
            })

        return summary

    def export_results(self, results: Dict[str, Any], output_path: str, format: str = 'json'):
        """
        Export analysis results to file

        Args:
            results: Analysis results
            output_path: Output file path
            format: Output format (json, html, pdf)
        """
        self.logger.info(f"Exporting results to {output_path} in {format} format")

        if format == 'json':
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)

        elif format == 'html':
            html_content = self._generate_html_report(results)
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)

        elif format == 'pdf':
            # Generate HTML first, then convert to PDF
            html_content = self._generate_html_report(results)
            # PDF conversion would require additional library
            self.logger.warning("PDF export requires additional dependencies")

        self.logger.info(f"Results exported to {output_path}")

    def _generate_html_report(self, results: Dict[str, Any]) -> str:
        """Generate HTML report from results"""
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>IMINT Analysis Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                h1 {{ color: #333; }}
                .section {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; }}
                .finding {{ background: #f0f0f0; padding: 10px; margin: 5px 0; }}
                .critical {{ background: #ffcccc; }}
                .high {{ background: #ffe6cc; }}
            </style>
        </head>
        <body>
            <h1>IMINT Analysis Report</h1>
            <div class="section">
                <h2>File Information</h2>
                <p><strong>File:</strong> {results.get('image_path', results.get('video_path', 'N/A'))}</p>
                <p><strong>Timestamp:</strong> {results.get('timestamp')}</p>
            </div>
            <div class="section">
                <h2>Intelligence Summary</h2>
                {self._format_summary_html(results.get('intelligence_summary', {}))}
            </div>
            <div class="section">
                <h2>Detailed Analysis</h2>
                <pre>{json.dumps(results.get('analysis', {}), indent=2)}</pre>
            </div>
        </body>
        </html>
        """
        return html

    def _format_summary_html(self, summary: Dict[str, Any]) -> str:
        """Format intelligence summary as HTML"""
        html = f"<p><strong>Threat Level:</strong> {summary.get('threat_level', 'unknown').upper()}</p>"
        html += "<h3>Key Findings:</h3><ul>"
        for finding in summary.get('key_findings', []):
            html += f"<li>{finding}</li>"
        html += "</ul>"
        return html


if __name__ == "__main__":
    # Example usage
    print("IMINT Engine - Image and Video Intelligence System")
    print("=" * 60)

    # Initialize engine
    config = {
        'log_level': 'INFO',
        'reverse_search': {
            'engines': ['google', 'tineye', 'yandex', 'bing']
        },
        'face_recognition': {
            'enable_age_gender': True,
            'enable_emotions': True
        },
        'object_detection': {
            'confidence_threshold': 0.5
        }
    }

    imint = IMINT(config)

    print("\nIMINT Engine initialized and ready for operations")
    print("\nExample usage:")
    print("  results = imint.analyze_image('suspect_photo.jpg')")
    print("  results = imint.analyze_video('surveillance_video.mp4')")
    print("  results = imint.analyze_youtube_video('https://youtube.com/watch?v=...')")
    print("  location = imint.extract_location_from_image('photo.jpg')")
    print("  matches = imint.search_face_in_database('face.jpg', 'database/')")
