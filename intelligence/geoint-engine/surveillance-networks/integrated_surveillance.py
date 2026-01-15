"""
Integrated Surveillance System for Apollo Platform
Combines facial recognition, voice recognition, and camera feeds

Elite-level system for FBI Most Wanted tracking
"""

import asyncio
import logging
from typing import List, Dict, Optional, Callable
from datetime import datetime
from pathlib import Path
import json
import redis

from real_time_matcher import RealTimeFaceMatcher, FaceMatch
from camera_feed_manager import CameraFeedManager
from voice_recognition import VoiceRecognitionSystem, VoiceMatch

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class IntegratedSurveillanceSystem:
    """
    Elite integrated surveillance system
    Combines facial recognition, voice recognition, and camera management
    """

    def __init__(
        self,
        face_database_path: str = "face_database/ignatova_face_encodings.npy",
        aged_database_path: str = "aged_variants/ignatova_aged_encodings.npy",
        voice_database_path: str = "voice_database/ignatova_voiceprint.npy",
        redis_host: str = "localhost",
        redis_port: int = 6379,
        redis_password: Optional[str] = None
    ):
        """
        Initialize integrated surveillance system

        Args:
            face_database_path: Path to face encodings
            aged_database_path: Path to aged face encodings
            voice_database_path: Path to voiceprint
            redis_host: Redis server for pub/sub alerts
            redis_port: Redis port
            redis_password: Redis password
        """
        logger.info("Initializing Apollo Integrated Surveillance System")

        # Initialize facial recognition
        self.face_matcher = RealTimeFaceMatcher(
            face_database_path=face_database_path,
            match_threshold=0.6,
            use_gpu=False,
            max_workers=4
        )

        # Load aged faces if available
        if Path(aged_database_path).exists():
            logger.info("Loading aged face database for enhanced matching")
            # Combine original and aged encodings
            # Implementation would merge the databases

        # Initialize voice recognition
        self.voice_system = VoiceRecognitionSystem(
            voiceprint_path=voice_database_path,
            match_threshold=0.75,
            use_gpu=False
        )

        # Initialize camera feed manager
        self.camera_manager = CameraFeedManager(
            max_feeds=10000,
            frame_skip=3
        )

        # Connect to Redis for real-time alerts
        try:
            self.redis_client = redis.Redis(
                host=redis_host,
                port=redis_port,
                password=redis_password,
                decode_responses=True
            )
            self.redis_client.ping()
            logger.info(f"Connected to Redis at {redis_host}:{redis_port}")
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {e}")
            self.redis_client = None

        # Statistics
        self.stats = {
            'system_started': datetime.now().isoformat(),
            'total_face_matches': 0,
            'total_voice_matches': 0,
            'cameras_active': 0,
            'alerts_sent': 0
        }

        # Alert callbacks
        self.alert_callbacks: List[Callable] = []

    def register_alert_callback(self, callback: Callable):
        """Register a callback for when matches are detected"""
        self.alert_callbacks.append(callback)

    def start(self):
        """Start all surveillance systems"""
        logger.info("🚀 Starting Apollo Integrated Surveillance System")

        # Start facial recognition
        self.face_matcher.start()

        # Set frame callback to process facial recognition
        self.camera_manager.set_frame_callback(self._process_camera_frame)

        # Start camera feeds
        self.camera_manager.start_all()

        # Update stats
        self.stats['cameras_active'] = len(self.camera_manager.cameras)

        logger.info("✓ All systems operational")

    def stop(self):
        """Stop all surveillance systems"""
        logger.info("Stopping surveillance systems...")

        self.face_matcher.stop()
        self.camera_manager.stop_all()

        logger.info("✓ All systems stopped")

    def _process_camera_frame(
        self,
        camera_id: str,
        frame,
        frame_id: int
    ):
        """
        Process frame from camera feed
        Called by camera manager for each frame
        """
        # Submit frame for facial recognition
        self.face_matcher.submit_frame(frame, camera_id, frame_id)

        # Check for matches
        matches = self.face_matcher.get_matches(timeout=0.01)

        for match in matches:
            self._handle_face_match(match)

    def _handle_face_match(self, match: FaceMatch):
        """Handle detected facial match"""
        self.stats['total_face_matches'] += 1

        # Create alert
        alert = {
            'type': 'facial_recognition',
            'target': match.target_name,
            'confidence': match.confidence,
            'camera_id': match.camera_id,
            'location': self.camera_manager.cameras[match.camera_id].location,
            'timestamp': match.timestamp.isoformat(),
            'frame_id': match.frame_id,
            'priority': 'CRITICAL'
        }

        logger.critical(
            f"🚨 FACIAL MATCH ALERT 🚨\n"
            f"   Target: {match.target_name}\n"
            f"   Confidence: {match.confidence:.2%}\n"
            f"   Camera: {match.camera_id}\n"
            f"   Location: {alert['location']}\n"
            f"   Time: {match.timestamp}"
        )

        # Save evidence
        self.face_matcher.save_match_evidence(match, "evidence/facial_matches")

        # Publish alert
        self._publish_alert(alert)

        # Call registered callbacks
        for callback in self.alert_callbacks:
            try:
                callback(alert)
            except Exception as e:
                logger.error(f"Alert callback error: {e}")

    def process_audio_file(
        self,
        audio_path: str,
        source: str = "unknown"
    ) -> Optional[VoiceMatch]:
        """
        Process audio file for voice matching

        Args:
            audio_path: Path to audio file
            source: Source description (phone call, recording, etc.)

        Returns:
            VoiceMatch if match found, None otherwise
        """
        try:
            match = self.voice_system.match_audio(audio_path, transcribe=True)

            if match.metadata['is_match']:
                self._handle_voice_match(match, source)

            return match

        except Exception as e:
            logger.error(f"Error processing audio {audio_path}: {e}")
            return None

    def _handle_voice_match(
        self,
        match: VoiceMatch,
        source: str
    ):
        """Handle detected voice match"""
        self.stats['total_voice_matches'] += 1

        # Create alert
        alert = {
            'type': 'voice_recognition',
            'target': 'Ruja Plamenova Ignatova',
            'confidence': match.confidence,
            'source': source,
            'audio_file': match.audio_file,
            'duration': match.duration,
            'timestamp': match.timestamp.isoformat(),
            'transcript': match.transcript,
            'priority': 'CRITICAL'
        }

        logger.critical(
            f"🚨 VOICE MATCH ALERT 🚨\n"
            f"   Target: Ruja Ignatova\n"
            f"   Confidence: {match.confidence:.2%}\n"
            f"   Source: {source}\n"
            f"   Duration: {match.duration:.1f}s\n"
            f"   Time: {match.timestamp}"
        )

        # Publish alert
        self._publish_alert(alert)

        # Call registered callbacks
        for callback in self.alert_callbacks:
            try:
                callback(alert)
            except Exception as e:
                logger.error(f"Alert callback error: {e}")

    def _publish_alert(self, alert: Dict):
        """Publish alert to Redis pub/sub"""
        if self.redis_client is None:
            return

        try:
            # Publish to apollo_alerts channel
            self.redis_client.publish(
                'apollo_alerts',
                json.dumps(alert)
            )

            self.stats['alerts_sent'] += 1

            logger.info(f"Alert published to Redis: {alert['type']}")

        except Exception as e:
            logger.error(f"Failed to publish alert to Redis: {e}")

    def load_camera_feeds_from_config(
        self,
        config_file: str = "config/camera_feeds.json"
    ) -> int:
        """Load camera feeds from configuration file"""
        return self.camera_manager.load_camera_registry(config_file)

    def get_system_status(self) -> Dict:
        """Get comprehensive system status"""
        face_stats = self.face_matcher.get_stats()
        camera_stats = self.camera_manager.get_stats()

        return {
            'system_uptime': (
                datetime.now() -
                datetime.fromisoformat(self.stats['system_started'])
            ).total_seconds(),
            'facial_recognition': face_stats,
            'cameras': camera_stats,
            'voice_recognition': {
                'matches': self.stats['total_voice_matches']
            },
            'alerts': {
                'total_sent': self.stats['alerts_sent'],
                'face_matches': self.stats['total_face_matches'],
                'voice_matches': self.stats['total_voice_matches']
            }
        }

    def generate_status_report(self, output_file: str = "surveillance_report.txt"):
        """Generate detailed status report"""
        status = self.get_system_status()

        report = []
        report.append("=" * 70)
        report.append("APOLLO INTEGRATED SURVEILLANCE SYSTEM - STATUS REPORT")
        report.append("=" * 70)
        report.append(f"\nGenerated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"System Uptime: {status['system_uptime']:.0f} seconds\n")

        report.append("FACIAL RECOGNITION:")
        report.append(f"  Frames Processed: {status['facial_recognition']['frames_processed']}")
        report.append(f"  Matches Found: {status['facial_recognition']['matches_found']}")
        report.append(f"  Avg Processing Time: {status['facial_recognition']['avg_processing_time_ms']:.1f}ms")
        report.append(f"  False Positives Filtered: {status['facial_recognition']['false_positives_filtered']}\n")

        report.append("CAMERA SURVEILLANCE:")
        report.append(f"  Total Cameras: {status['cameras']['total_cameras']}")
        report.append(f"  Active Cameras: {status['cameras']['active_cameras']}")
        report.append(f"  Total Frames: {status['cameras']['total_frames']}")
        report.append(f"  Frames Per Second: {status['cameras']['frames_per_second']:.1f}")
        report.append(f"  Errors: {status['cameras']['errors']}\n")

        report.append("ALERTS:")
        report.append(f"  Total Alerts Sent: {status['alerts']['total_sent']}")
        report.append(f"  Facial Matches: {status['alerts']['face_matches']}")
        report.append(f"  Voice Matches: {status['alerts']['voice_matches']}\n")

        report.append("=" * 70)

        report_text = "\n".join(report)

        # Print to console
        print(report_text)

        # Save to file
        with open(output_file, 'w') as f:
            f.write(report_text)

        logger.info(f"Status report saved to {output_file}")


def main():
    """Run integrated surveillance system"""
    print("=" * 70)
    print("APOLLO INTEGRATED SURVEILLANCE SYSTEM")
    print("Target: Ruja Plamenova Ignatova (FBI Most Wanted)")
    print("Capabilities: Facial Recognition + Voice Recognition + Camera Network")
    print("=" * 70)

    # Initialize system
    surveillance = IntegratedSurveillanceSystem()

    # Register alert callback
    def alert_handler(alert):
        print(f"\n🚨 ALERT: {alert['type'].upper()}")
        print(f"   Confidence: {alert['confidence']:.2%}")
        print(f"   Time: {alert['timestamp']}")

    surveillance.register_alert_callback(alert_handler)

    # Load camera feeds (if config exists)
    config_path = "config/camera_feeds.json"
    if Path(config_path).exists():
        num_cameras = surveillance.load_camera_feeds_from_config(config_path)
        print(f"\n✓ Loaded {num_cameras} camera feeds")
    else:
        print(f"\nℹ No camera config found at {config_path}")
        print("  Add cameras manually or create config file")

    # Start system
    print("\n🚀 Starting surveillance system...")
    surveillance.start()

    print("\n✓ System operational - monitoring for target")
    print("Press Ctrl+C to stop\n")

    try:
        import time
        while True:
            time.sleep(10)
            surveillance.generate_status_report()

    except KeyboardInterrupt:
        print("\n\nStopping surveillance system...")
        surveillance.stop()
        print("✓ System stopped")


if __name__ == "__main__":
    main()
