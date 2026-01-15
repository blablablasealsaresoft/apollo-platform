"""
Real-Time Facial Recognition Matcher for Apollo Platform
Matches faces against target database in real-time from camera feeds

For authorized law enforcement use only - FBI Most Wanted tracking
"""

import cv2
import face_recognition
import numpy as np
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass
from datetime import datetime
import threading
import queue
import logging
from pathlib import Path
import json

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class FaceMatch:
    """Represents a facial recognition match"""
    target_name: str
    confidence: float
    location: Tuple[int, int, int, int]  # top, right, bottom, left
    timestamp: datetime
    frame_id: int
    camera_id: str
    frame: Optional[np.ndarray] = None


class RealTimeFaceMatcher:
    """
    Elite-level real-time facial recognition matcher
    Supports multiple camera feeds with GPU acceleration
    """

    def __init__(
        self,
        face_database_path: str = "face_database/ignatova_face_encodings.npy",
        metadata_path: str = "face_database/ignatova_face_metadata.json",
        match_threshold: float = 0.6,
        use_gpu: bool = False,
        max_workers: int = 4
    ):
        """
        Initialize the real-time matcher

        Args:
            face_database_path: Path to face encodings database
            metadata_path: Path to metadata JSON
            match_threshold: Distance threshold for matches (lower = stricter)
            use_gpu: Use GPU acceleration if available
            max_workers: Number of worker threads for processing
        """
        self.match_threshold = match_threshold
        self.use_gpu = use_gpu
        self.max_workers = max_workers

        # Load face database
        logger.info(f"Loading face database from {face_database_path}")
        self.known_encodings = np.load(face_database_path)

        with open(metadata_path, 'r') as f:
            self.metadata = json.load(f)

        logger.info(f"Loaded {len(self.known_encodings)} face encodings for Ignatova")

        # Processing queue
        self.frame_queue = queue.Queue(maxsize=100)
        self.result_queue = queue.Queue()

        # Worker threads
        self.workers = []
        self.running = False

        # Statistics
        self.stats = {
            'frames_processed': 0,
            'matches_found': 0,
            'false_positives_filtered': 0,
            'avg_processing_time_ms': 0
        }

    def start(self):
        """Start worker threads for processing"""
        self.running = True
        for i in range(self.max_workers):
            worker = threading.Thread(target=self._process_worker, daemon=True)
            worker.start()
            self.workers.append(worker)
        logger.info(f"Started {self.max_workers} worker threads")

    def stop(self):
        """Stop all worker threads"""
        self.running = False
        for worker in self.workers:
            worker.join(timeout=2.0)
        logger.info("Stopped all workers")

    def _process_worker(self):
        """Worker thread that processes frames from queue"""
        while self.running:
            try:
                # Get frame from queue with timeout
                frame_data = self.frame_queue.get(timeout=1.0)

                # Process frame
                matches = self._process_frame(
                    frame_data['frame'],
                    frame_data['camera_id'],
                    frame_data['frame_id']
                )

                # Put results in output queue
                for match in matches:
                    self.result_queue.put(match)

                self.frame_queue.task_done()

            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Worker error: {e}")

    def _process_frame(
        self,
        frame: np.ndarray,
        camera_id: str,
        frame_id: int
    ) -> List[FaceMatch]:
        """
        Process a single frame and return matches

        Args:
            frame: BGR image from camera
            camera_id: Unique camera identifier
            frame_id: Frame sequence number

        Returns:
            List of FaceMatch objects for matches above threshold
        """
        start_time = datetime.now()
        matches = []

        try:
            # Convert BGR to RGB
            rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)

            # Detect faces (use CNN model for better accuracy)
            face_locations = face_recognition.face_locations(
                rgb_frame,
                model='cnn' if self.use_gpu else 'hog',
                number_of_times_to_upsample=1
            )

            if not face_locations:
                return matches

            # Get encodings for detected faces
            face_encodings = face_recognition.face_encodings(
                rgb_frame,
                face_locations
            )

            # Compare each detected face against database
            for face_encoding, face_location in zip(face_encodings, face_locations):
                # Calculate distances to all known faces
                distances = face_recognition.face_distance(
                    self.known_encodings,
                    face_encoding
                )

                # Get best match
                best_match_idx = np.argmin(distances)
                best_distance = distances[best_match_idx]

                # Check if match is good enough
                if best_distance < self.match_threshold:
                    confidence = 1.0 - best_distance  # Convert distance to confidence

                    # Quality filter: reject low-quality faces
                    if self._assess_face_quality(rgb_frame, face_location) < 0.3:
                        self.stats['false_positives_filtered'] += 1
                        continue

                    match = FaceMatch(
                        target_name="Ruja Plamenova Ignatova",
                        confidence=confidence,
                        location=face_location,
                        timestamp=datetime.now(),
                        frame_id=frame_id,
                        camera_id=camera_id,
                        frame=frame.copy()  # Store frame for evidence
                    )

                    matches.append(match)
                    self.stats['matches_found'] += 1

                    logger.warning(
                        f"🎯 MATCH FOUND! Camera: {camera_id}, "
                        f"Confidence: {confidence:.2%}, Frame: {frame_id}"
                    )

            # Update statistics
            self.stats['frames_processed'] += 1
            processing_time = (datetime.now() - start_time).total_seconds() * 1000

            # Running average
            alpha = 0.1
            self.stats['avg_processing_time_ms'] = (
                alpha * processing_time +
                (1 - alpha) * self.stats['avg_processing_time_ms']
            )

        except Exception as e:
            logger.error(f"Frame processing error: {e}")

        return matches

    def _assess_face_quality(
        self,
        image: np.ndarray,
        face_location: Tuple[int, int, int, int]
    ) -> float:
        """
        Assess face quality to filter false positives

        Args:
            image: RGB image
            face_location: (top, right, bottom, left)

        Returns:
            Quality score 0.0-1.0
        """
        top, right, bottom, left = face_location
        face = image[top:bottom, left:right]

        if face.size == 0:
            return 0.0

        # Face size score
        face_area = (bottom - top) * (right - left)
        image_area = image.shape[0] * image.shape[1]
        size_score = min((face_area / image_area) * 10, 1.0)

        # Sharpness score (Laplacian variance)
        gray_face = cv2.cvtColor(face, cv2.COLOR_RGB2GRAY)
        laplacian = cv2.Laplacian(gray_face, cv2.CV_64F)
        sharpness_score = min(laplacian.var() / 1000, 1.0)

        # Brightness score
        brightness = np.mean(gray_face) / 255.0
        brightness_score = 1.0 - abs(brightness - 0.5) * 2  # Prefer mid-range

        # Combined score
        quality = (
            size_score * 0.5 +
            sharpness_score * 0.3 +
            brightness_score * 0.2
        )

        return quality

    def submit_frame(
        self,
        frame: np.ndarray,
        camera_id: str,
        frame_id: int
    ) -> bool:
        """
        Submit a frame for processing

        Args:
            frame: BGR image from camera
            camera_id: Unique camera identifier
            frame_id: Frame sequence number

        Returns:
            True if frame was queued, False if queue is full
        """
        try:
            self.frame_queue.put_nowait({
                'frame': frame,
                'camera_id': camera_id,
                'frame_id': frame_id
            })
            return True
        except queue.Full:
            logger.warning(f"Frame queue full, dropping frame {frame_id}")
            return False

    def get_matches(self, timeout: float = 0.1) -> List[FaceMatch]:
        """
        Get available matches from result queue

        Args:
            timeout: Maximum time to wait for matches

        Returns:
            List of FaceMatch objects
        """
        matches = []
        try:
            while True:
                match = self.result_queue.get(timeout=timeout)
                matches.append(match)
        except queue.Empty:
            pass

        return matches

    def get_stats(self) -> Dict:
        """Get processing statistics"""
        return self.stats.copy()

    def save_match_evidence(
        self,
        match: FaceMatch,
        output_dir: str = "matches"
    ) -> str:
        """
        Save match evidence (frame + metadata)

        Args:
            match: FaceMatch object
            output_dir: Directory to save evidence

        Returns:
            Path to saved evidence
        """
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        # Generate filename
        timestamp = match.timestamp.strftime("%Y%m%d_%H%M%S")
        filename = f"match_{match.camera_id}_{timestamp}_{match.frame_id}"

        # Draw box around face
        if match.frame is not None:
            top, right, bottom, left = match.location
            cv2.rectangle(
                match.frame,
                (left, top),
                (right, bottom),
                (0, 0, 255),  # Red box
                3
            )

            # Add label
            label = f"{match.target_name} ({match.confidence:.1%})"
            cv2.putText(
                match.frame,
                label,
                (left, top - 10),
                cv2.FONT_HERSHEY_SIMPLEX,
                0.75,
                (0, 0, 255),
                2
            )

            # Save image
            image_path = output_path / f"{filename}.jpg"
            cv2.imwrite(str(image_path), match.frame)

        # Save metadata
        metadata = {
            'target_name': match.target_name,
            'confidence': match.confidence,
            'location': match.location,
            'timestamp': match.timestamp.isoformat(),
            'frame_id': match.frame_id,
            'camera_id': match.camera_id
        }

        metadata_path = output_path / f"{filename}.json"
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)

        logger.info(f"Saved match evidence to {image_path}")
        return str(image_path)


def main():
    """Test the real-time matcher"""
    # Initialize matcher
    matcher = RealTimeFaceMatcher(
        match_threshold=0.6,
        use_gpu=False,
        max_workers=4
    )

    # Start processing
    matcher.start()

    # Test with webcam (camera_id = 0)
    cap = cv2.VideoCapture(0)
    frame_id = 0

    print("Starting real-time facial recognition...")
    print("Press 'q' to quit")

    try:
        while True:
            ret, frame = cap.read()
            if not ret:
                break

            # Submit frame for processing (process every 3rd frame for performance)
            if frame_id % 3 == 0:
                matcher.submit_frame(frame, "webcam_0", frame_id)

            # Check for matches
            matches = matcher.get_matches()
            for match in matches:
                print(f"\n🎯 TARGET DETECTED!")
                print(f"   Camera: {match.camera_id}")
                print(f"   Confidence: {match.confidence:.2%}")
                print(f"   Time: {match.timestamp}")

                # Save evidence
                matcher.save_match_evidence(match)

            # Display stats
            if frame_id % 100 == 0:
                stats = matcher.get_stats()
                print(f"\nStats: {stats}")

            # Show frame
            cv2.imshow('Apollo Surveillance', frame)

            if cv2.waitKey(1) & 0xFF == ord('q'):
                break

            frame_id += 1

    finally:
        cap.release()
        cv2.destroyAllWindows()
        matcher.stop()


if __name__ == "__main__":
    main()
