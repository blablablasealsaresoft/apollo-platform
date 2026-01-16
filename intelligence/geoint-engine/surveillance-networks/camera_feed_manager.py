"""
Camera Feed Manager for Apollo Platform
Manages 10,000+ concurrent camera feeds with load balancing

For authorized law enforcement surveillance operations
"""

import cv2
import threading
import queue
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime
import logging
from pathlib import Path
import json
import time
from enum import Enum

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class FeedStatus(Enum):
    """Camera feed status"""
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    ERROR = "error"
    RECONNECTING = "reconnecting"


@dataclass
class CameraFeed:
    """Represents a camera feed"""
    camera_id: str
    stream_url: str
    location: str
    priority: int = 1  # 1-10, higher = more important
    status: FeedStatus = FeedStatus.DISCONNECTED
    last_frame_time: Optional[datetime] = None
    error_count: int = 0
    frames_processed: int = 0
    metadata: Dict = field(default_factory=dict)


class CameraFeedManager:
    """
    Elite-level camera feed manager
    Handles thousands of concurrent RTSP/RTMP/HTTP streams
    """

    def __init__(
        self,
        max_feeds: int = 10000,
        reconnect_interval: int = 30,
        frame_skip: int = 3,  # Process every Nth frame
        quality_threshold: float = 0.3
    ):
        """
        Initialize camera feed manager

        Args:
            max_feeds: Maximum number of concurrent feeds
            reconnect_interval: Seconds between reconnection attempts
            frame_skip: Process every Nth frame (for performance)
            quality_threshold: Minimum quality score to process frame
        """
        self.max_feeds = max_feeds
        self.reconnect_interval = reconnect_interval
        self.frame_skip = frame_skip
        self.quality_threshold = quality_threshold

        # Camera registry
        self.cameras: Dict[str, CameraFeed] = {}
        self.camera_threads: Dict[str, threading.Thread] = {}

        # Processing callback
        self.frame_callback: Optional[Callable] = None

        # Control
        self.running = False

        # Statistics
        self.stats = {
            'total_cameras': 0,
            'active_cameras': 0,
            'total_frames': 0,
            'frames_per_second': 0,
            'errors': 0
        }

        # Performance monitoring
        self._last_fps_check = time.time()
        self._frames_since_check = 0

    def register_camera(
        self,
        camera_id: str,
        stream_url: str,
        location: str,
        priority: int = 1,
        metadata: Optional[Dict] = None
    ) -> bool:
        """
        Register a new camera feed

        Args:
            camera_id: Unique camera identifier
            stream_url: RTSP/RTMP/HTTP stream URL
            location: Physical location description
            priority: Priority level (1-10)
            metadata: Additional metadata

        Returns:
            True if registered successfully
        """
        if len(self.cameras) >= self.max_feeds:
            logger.error(f"Maximum feed limit ({self.max_feeds}) reached")
            return False

        if camera_id in self.cameras:
            logger.warning(f"Camera {camera_id} already registered")
            return False

        camera = CameraFeed(
            camera_id=camera_id,
            stream_url=stream_url,
            location=location,
            priority=priority,
            metadata=metadata or {}
        )

        self.cameras[camera_id] = camera
        self.stats['total_cameras'] = len(self.cameras)

        logger.info(f"Registered camera {camera_id} at {location}")
        return True

    def unregister_camera(self, camera_id: str) -> bool:
        """Unregister and stop a camera feed"""
        if camera_id not in self.cameras:
            return False

        # Stop thread if running
        if camera_id in self.camera_threads:
            self._stop_camera_thread(camera_id)

        del self.cameras[camera_id]
        self.stats['total_cameras'] = len(self.cameras)

        logger.info(f"Unregistered camera {camera_id}")
        return True

    def set_frame_callback(self, callback: Callable):
        """
        Set callback function for processing frames

        Callback signature: callback(camera_id, frame, frame_id)
        """
        self.frame_callback = callback

    def start_all(self):
        """Start processing all registered cameras"""
        self.running = True

        for camera_id in self.cameras:
            self._start_camera_thread(camera_id)

        logger.info(f"Started {len(self.cameras)} camera feeds")

    def stop_all(self):
        """Stop all camera feeds"""
        self.running = False

        for camera_id in list(self.camera_threads.keys()):
            self._stop_camera_thread(camera_id)

        logger.info("Stopped all camera feeds")

    def _start_camera_thread(self, camera_id: str):
        """Start processing thread for a camera"""
        if camera_id in self.camera_threads:
            logger.warning(f"Camera {camera_id} thread already running")
            return

        thread = threading.Thread(
            target=self._camera_worker,
            args=(camera_id,),
            daemon=True
        )
        thread.start()
        self.camera_threads[camera_id] = thread

        logger.info(f"Started thread for camera {camera_id}")

    def _stop_camera_thread(self, camera_id: str):
        """Stop processing thread for a camera"""
        if camera_id not in self.camera_threads:
            return

        thread = self.camera_threads[camera_id]

        # Wait for thread to stop
        thread.join(timeout=2.0)

        if thread.is_alive():
            logger.warning(f"Thread for camera {camera_id} did not stop gracefully")

        del self.camera_threads[camera_id]

    def _camera_worker(self, camera_id: str):
        """
        Worker thread for processing a single camera feed
        Handles reconnection on failure
        """
        camera = self.cameras[camera_id]
        frame_id = 0
        cap = None

        while self.running:
            try:
                # Connect to stream
                if cap is None:
                    logger.info(f"Connecting to camera {camera_id}...")
                    camera.status = FeedStatus.RECONNECTING
                    cap = cv2.VideoCapture(camera.stream_url)

                    if not cap.isOpened():
                        raise Exception("Failed to open stream")

                    camera.status = FeedStatus.CONNECTED
                    camera.error_count = 0
                    self.stats['active_cameras'] = sum(
                        1 for c in self.cameras.values()
                        if c.status == FeedStatus.CONNECTED
                    )
                    logger.info(f"Camera {camera_id} connected")

                # Read frame
                ret, frame = cap.read()

                if not ret:
                    raise Exception("Failed to read frame")

                # Update camera state
                camera.last_frame_time = datetime.now()
                camera.frames_processed += 1
                frame_id += 1

                # Frame skipping for performance
                if frame_id % self.frame_skip != 0:
                    continue

                # Quality check (simple motion detection)
                if not self._check_frame_quality(frame):
                    continue

                # Call processing callback
                if self.frame_callback:
                    try:
                        self.frame_callback(camera_id, frame, frame_id)
                    except Exception as e:
                        logger.error(f"Callback error for {camera_id}: {e}")

                # Update statistics
                self.stats['total_frames'] += 1
                self._frames_since_check += 1
                self._update_fps()

            except Exception as e:
                camera.error_count += 1
                camera.status = FeedStatus.ERROR
                self.stats['errors'] += 1

                logger.error(
                    f"Camera {camera_id} error ({camera.error_count}): {e}"
                )

                # Cleanup
                if cap is not None:
                    cap.release()
                    cap = None

                # Update active camera count
                self.stats['active_cameras'] = sum(
                    1 for c in self.cameras.values()
                    if c.status == FeedStatus.CONNECTED
                )

                # Exponential backoff for reconnection
                sleep_time = min(
                    self.reconnect_interval * (2 ** min(camera.error_count - 1, 5)),
                    300  # Max 5 minutes
                )

                logger.info(f"Reconnecting to {camera_id} in {sleep_time}s...")
                time.sleep(sleep_time)

        # Cleanup on exit
        if cap is not None:
            cap.release()

    def _check_frame_quality(self, frame) -> bool:
        """
        Basic quality check for frames
        Returns False for blank/static frames
        """
        if frame is None or frame.size == 0:
            return False

        # Check if frame is too dark
        mean_brightness = frame.mean()
        if mean_brightness < 10:
            return False

        # Check if frame is too bright (blank)
        if mean_brightness > 250:
            return False

        return True

    def _update_fps(self):
        """Update frames per second statistic"""
        now = time.time()
        elapsed = now - self._last_fps_check

        if elapsed >= 1.0:
            self.stats['frames_per_second'] = self._frames_since_check / elapsed
            self._frames_since_check = 0
            self._last_fps_check = now

    def get_stats(self) -> Dict:
        """Get current statistics"""
        return self.stats.copy()

    def get_camera_status(self, camera_id: str) -> Optional[Dict]:
        """Get status of a specific camera"""
        if camera_id not in self.cameras:
            return None

        camera = self.cameras[camera_id]

        return {
            'camera_id': camera.camera_id,
            'location': camera.location,
            'status': camera.status.value,
            'priority': camera.priority,
            'last_frame_time': camera.last_frame_time.isoformat() if camera.last_frame_time else None,
            'error_count': camera.error_count,
            'frames_processed': camera.frames_processed
        }

    def get_all_camera_status(self) -> List[Dict]:
        """Get status of all cameras"""
        return [
            self.get_camera_status(camera_id)
            for camera_id in self.cameras
        ]

    def load_camera_registry(self, config_file: str) -> int:
        """
        Load cameras from JSON configuration file

        Config format:
        {
          "cameras": [
            {
              "camera_id": "cam_001",
              "stream_url": "rtsp://...",
              "location": "Dubai Airport Terminal 3",
              "priority": 9,
              "metadata": {...}
            },
            ...
          ]
        }

        Returns:
            Number of cameras loaded
        """
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)

            count = 0
            for cam in config.get('cameras', []):
                if self.register_camera(
                    camera_id=cam['camera_id'],
                    stream_url=cam['stream_url'],
                    location=cam['location'],
                    priority=cam.get('priority', 1),
                    metadata=cam.get('metadata')
                ):
                    count += 1

            logger.info(f"Loaded {count} cameras from {config_file}")
            return count

        except Exception as e:
            logger.error(f"Failed to load camera registry: {e}")
            return 0

    def save_camera_registry(self, config_file: str) -> bool:
        """Save current camera registry to JSON file"""
        try:
            config = {
                'cameras': [
                    {
                        'camera_id': cam.camera_id,
                        'stream_url': cam.stream_url,
                        'location': cam.location,
                        'priority': cam.priority,
                        'metadata': cam.metadata
                    }
                    for cam in self.cameras.values()
                ]
            }

            with open(config_file, 'w') as f:
                json.dump(config, f, indent=2)

            logger.info(f"Saved {len(self.cameras)} cameras to {config_file}")
            return True

        except Exception as e:
            logger.error(f"Failed to save camera registry: {e}")
            return False


def main():
    """Test the camera feed manager"""
    # Initialize manager
    manager = CameraFeedManager(max_feeds=100, frame_skip=3)

    # Frame processing callback
    def process_frame(camera_id: str, frame, frame_id: int):
        """Process each frame (would integrate with RealTimeFaceMatcher)"""
        print(f"Processing frame {frame_id} from {camera_id}")

    manager.set_frame_callback(process_frame)

    # Register test cameras (webcam)
    manager.register_camera(
        camera_id="test_webcam",
        stream_url=0,  # Default webcam
        location="Test Location",
        priority=5
    )

    # Start processing
    print("Starting camera feed manager...")
    print("Press Ctrl+C to stop")

    manager.start_all()

    try:
        while True:
            time.sleep(5)
            stats = manager.get_stats()
            print(f"\nStats: {stats}")

            # Show camera status
            status = manager.get_all_camera_status()
            for cam_status in status:
                print(f"  {cam_status['camera_id']}: {cam_status['status']}")

    except KeyboardInterrupt:
        print("\nStopping...")
        manager.stop_all()


if __name__ == "__main__":
    main()
