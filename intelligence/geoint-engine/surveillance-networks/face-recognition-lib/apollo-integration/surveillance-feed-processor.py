#!/usr/bin/env python3
"""
Surveillance Feed Processor - Process camera feeds for facial recognition
Apollo Platform - Real-Time Surveillance Module
"""

import face_recognition
import cv2
import pickle
import numpy as np
from typing import List, Dict
from datetime import datetime
import threading
import queue


class SurveillanceFeedProcessor:
    """
    Process live surveillance camera feeds with facial recognition
    for high-value target detection (Ignatova case)
    """
    
    def __init__(self, target_database: str, tolerance: float = 0.6):
        self.tolerance = tolerance
        self.processing_queue = queue.Queue()
        self.alert_queue = queue.Queue()
        
        # Load target database
        print(f"[*] Loading target database: {target_database}")
        with open(target_database, 'rb') as f:
            database = pickle.load(f)
        
        self.known_encodings = database['encodings']
        self.target_name = database['target_name']
        
        print(f"[*] Loaded: {self.target_name}")
        print(f"[*] Face encodings: {len(self.known_encodings)}")
    
    def process_camera_feed(self, camera_info: Dict):
        """
        Process single camera feed with facial recognition
        
        Args:
            camera_info: Camera configuration (URL, location, etc.)
        """
        camera_url = camera_info['url']
        camera_id = camera_info['id']
        camera_location = camera_info.get('location', 'Unknown')
        
        print(f"[*] Processing camera: {camera_id}")
        print(f"[*] Location: {camera_location}")
        print(f"[*] URL: {camera_url}")
        
        # Open video stream
        video_capture = cv2.VideoCapture(camera_url)
        
        if not video_capture.isOpened():
            print(f"[!] Failed to open camera: {camera_id}")
            return
        
        frame_count = 0
        process_every_n_frames = 30  # Process every 30th frame (1 per second at 30fps)
        
        while True:
            ret, frame = video_capture.read()
            
            if not ret:
                print(f"[!] Camera feed lost: {camera_id}")
                break
            
            frame_count += 1
            
            # Process only every Nth frame for performance
            if frame_count % process_every_n_frames != 0:
                continue
            
            # Resize frame for faster processing
            small_frame = cv2.resize(frame, (0, 0), fx=0.25, fy=0.25)
            rgb_small_frame = cv2.cvtColor(small_frame, cv2.COLOR_BGR2RGB)
            
            # Find faces
            face_locations = face_recognition.face_locations(rgb_small_frame)
            face_encodings = face_recognition.face_encodings(rgb_small_frame, face_locations)
            
            # Check each face
            for face_encoding, face_location in zip(face_encodings, face_locations):
                # Compare against target
                matches = face_recognition.compare_faces(
                    self.known_encodings,
                    face_encoding,
                    tolerance=self.tolerance
                )
                
                if True in matches:
                    # Calculate confidence
                    face_distances = face_recognition.face_distance(
                        self.known_encodings,
                        face_encoding
                    )
                    best_match_index = np.argmin(face_distances)
                    confidence = 1.0 - face_distances[best_match_index]
                    
                    if confidence >= 0.70:  # 70%+ confidence threshold
                        # MATCH FOUND!
                        match_info = {
                            'camera_id': camera_id,
                            'camera_location': camera_location,
                            'target_name': self.target_name,
                            'confidence': float(confidence),
                            'timestamp': datetime.now().isoformat(),
                            'frame_number': frame_count,
                            'face_location': face_location
                        }
                        
                        # Save frame
                        frame_filename = f"match_{camera_id}_{frame_count}_{confidence:.0%}.jpg"
                        cv2.imwrite(f"./matches/{frame_filename}", frame)
                        match_info['frame_saved'] = frame_filename
                        
                        print(f"\n[!] *** MATCH DETECTED ***")
                        print(f"    Camera: {camera_id} ({camera_location})")
                        print(f"    Target: {self.target_name}")
                        print(f"    Confidence: {confidence:.1%}")
                        print(f"    Frame saved: {frame_filename}")
                        
                        # CRITICAL ALERT
                        self._alert_match(match_info)
        
        video_capture.release()
    
    def process_multiple_cameras(self, cameras: List[Dict]):
        """
        Process multiple camera feeds simultaneously
        
        Args:
            cameras: List of camera configurations
        """
        print(f"[*] Processing {len(cameras)} camera feeds")
        
        threads = []
        
        # Start thread for each camera
        for camera in cameras:
            thread = threading.Thread(
                target=self.process_camera_feed,
                args=(camera,)
            )
            thread.daemon = True
            thread.start()
            threads.append(thread)
        
        # Wait for all threads
        for thread in threads:
            thread.join()
    
    def process_social_media_photos(self, photos: List[str]) -> List[Dict]:
        """
        Process social media photos for target identification
        
        Args:
            photos: List of photo URLs or paths
            
        Returns:
            List of matches found
        """
        print(f"[*] Processing {len(photos)} social media photos")
        
        matches = []
        
        for photo_path in photos:
            try:
                result = self.match_single_photo(photo_path)
                if result and result['matched']:
                    matches.append(result)
            except Exception as e:
                print(f"[!] Error processing {photo_path}: {e}")
        
        print(f"[*] Social media scan complete: {len(matches)} matches")
        
        return matches
    
    def _alert_match(self, match_info: Dict):
        """Send critical alert on facial recognition match"""
        try:
            from apollo.alerts import CriticalAlert
            
            alert = CriticalAlert()
            
            # Determine priority based on confidence
            if match_info['confidence'] >= 0.85:
                priority = 'CRITICAL'
                action = 'IMMEDIATE_DISPATCH'
                notify_channels = ['fbi', 'interpol', 'local-le', 'all-units']
            elif match_info['confidence'] >= 0.75:
                priority = 'HIGH'
                action = 'DEPLOY_SURVEILLANCE'
                notify_channels = ['fbi', 'case-officer', 'local-le']
            else:
                priority = 'MEDIUM'
                action = 'INVESTIGATE'
                notify_channels = ['case-officer']
            
            alert.send({
                'type': 'FACIAL_RECOGNITION_MATCH',
                'target': match_info['target_name'],
                'camera_id': match_info['camera_id'],
                'location': match_info['camera_location'],
                'confidence': match_info['confidence'],
                'timestamp': match_info['timestamp'],
                'frame_saved': match_info.get('frame_saved'),
                'priority': priority,
                'action': action,
                'notify': notify_channels
            })
            
            # Feed to Apollo intelligence
            from apollo.intelligence import IntelligenceFusion
            
            fusion = IntelligenceFusion()
            fusion.ingest({
                'source': 'facial-recognition',
                'type': 'biometric-match',
                'data': match_info,
                'timestamp': match_info['timestamp']
            })
            
        except Exception as e:
            print(f"[!] Alert system error: {e}")


if __name__ == "__main__":
    # Example: Monitor cameras for Ignatova
    processor = SurveillanceFeedProcessor(
        target_database="./databases/known-faces/ruja_ignatova_aged_7y_encodings.pkl",
        tolerance=0.6
    )
    
    # Example cameras in Dubai (high-probability location)
    dubai_cameras = [
        {
            'id': 'DUBAI-CAM-001',
            'location': 'Burj Al Arab Hotel, Dubai',
            'url': 'rtsp://camera1.dubai.ae/stream'
        },
        {
            'id': 'DUBAI-CAM-002',
            'location': 'Dubai Marina, Dubai',
            'url': 'rtsp://camera2.dubai.ae/stream'
        },
        {
            'id': 'DUBAI-CAM-003',
            'location': 'Dubai Mall, Dubai',
            'url': 'rtsp://camera3.dubai.ae/stream'
        }
    ]
    
    # Process all cameras simultaneously
    processor.process_multiple_cameras(dubai_cameras)
