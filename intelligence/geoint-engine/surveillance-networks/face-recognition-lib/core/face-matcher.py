#!/usr/bin/env python3
"""
Face Matcher - Compare faces against target database
Apollo Platform - Facial Recognition Module
"""

import face_recognition
import pickle
from typing import List, Dict, Optional
from pathlib import Path
import numpy as np


class FaceMatcher:
    """
    Match faces from surveillance/social media against target database
    """
    
    def __init__(self, tolerance: float = 0.6):
        self.tolerance = tolerance  # Lower = more strict
        self.known_encodings = []
        self.known_names = []
        
    def load_target_database(self, db_file: str):
        """Load target face encoding database"""
        print(f"[*] Loading database: {db_file}")
        
        with open(db_file, 'rb') as f:
            database = pickle.load(f)
        
        self.known_encodings = database['encodings']
        self.known_names = [database['target_name']] * len(database['encodings'])
        
        print(f"[*] Loaded {len(self.known_encodings)} face encodings")
    
    def match_single_photo(self, photo_path: str, return_confidence: bool = True) -> Optional[Dict]:
        """
        Match single photo against target database
        
        Args:
            photo_path: Path to photo to check
            return_confidence: Return confidence score
            
        Returns:
            Match result with confidence if match found
        """
        print(f"[*] Analyzing: {photo_path}")
        
        # Load image
        image = face_recognition.load_image_file(photo_path)
        
        # Find face encodings
        face_encodings = face_recognition.face_encodings(image)
        
        if not face_encodings:
            print(f"    ✗ No faces found")
            return None
        
        # Check each face in image
        for face_encoding in face_encodings:
            # Compare against known encodings
            matches = face_recognition.compare_faces(
                self.known_encodings,
                face_encoding,
                tolerance=self.tolerance
            )
            
            # Calculate face distances
            face_distances = face_recognition.face_distance(
                self.known_encodings,
                face_encoding
            )
            
            # Find best match
            if True in matches:
                best_match_index = np.argmin(face_distances)
                confidence = 1.0 - face_distances[best_match_index]
                
                result = {
                    'matched': True,
                    'target_name': self.known_names[best_match_index],
                    'confidence': float(confidence),
                    'distance': float(face_distances[best_match_index]),
                    'photo_path': photo_path
                }
                
                print(f"    ✓ MATCH FOUND: {result['target_name']} ({confidence:.1%} confidence)")
                
                # Alert if high confidence
                if confidence >= 0.70:
                    self._alert_match(result)
                
                return result
        
        print(f"    ✗ No match")
        return None
    
    def batch_match_directory(self, photo_dir: str, recursive: bool = True) -> List[Dict]:
        """
        Match all photos in directory against target database
        
        Args:
            photo_dir: Directory containing photos to check
            recursive: Search subdirectories
            
        Returns:
            List of all matches found
        """
        print(f"[*] Batch matching directory: {photo_dir}")
        
        matches = []
        pattern = "**/*.jpg" if recursive else "*.jpg"
        
        photo_count = 0
        for photo_path in Path(photo_dir).glob(pattern):
            photo_count += 1
            
            result = self.match_single_photo(str(photo_path))
            if result and result['matched']:
                matches.append(result)
        
        print(f"\n[*] Batch processing complete:")
        print(f"    Photos processed: {photo_count}")
        print(f"    Matches found: {len(matches)}")
        
        return matches
    
    def match_video_stream(self, video_source: str, frame_skip: int = 30):
        """
        Match faces in video stream (live or recorded)
        
        Args:
            video_source: Video file path or camera index
            frame_skip: Process every Nth frame (for performance)
        """
        import cv2
        
        print(f"[*] Processing video: {video_source}")
        
        video_capture = cv2.VideoCapture(video_source)
        frame_number = 0
        
        while True:
            ret, frame = video_capture.read()
            
            if not ret:
                break
            
            frame_number += 1
            
            # Skip frames for performance
            if frame_number % frame_skip != 0:
                continue
            
            # Convert BGR (OpenCV) to RGB (face_recognition)
            rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            
            # Find faces
            face_locations = face_recognition.face_locations(rgb_frame)
            face_encodings = face_recognition.face_encodings(rgb_frame, face_locations)
            
            # Check each face
            for (top, right, bottom, left), face_encoding in zip(face_locations, face_encodings):
                # Compare against known faces
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
                    
                    if confidence >= 0.70:
                        print(f"\n[!] MATCH in frame {frame_number}: {confidence:.1%} confidence")
                        
                        # Draw box on frame
                        cv2.rectangle(frame, (left, top), (right, bottom), (0, 0, 255), 2)
                        
                        # Alert
                        self._alert_video_match(frame_number, confidence, video_source)
            
            # Display frame (optional)
            # cv2.imshow('Video', frame)
            # if cv2.waitKey(1) & 0xFF == ord('q'):
            #     break
        
        video_capture.release()
        cv2.destroyAllWindows()
    
    def create_searchable_index(self, image_directory: str, index_name: str) -> str:
        """
        Create searchable index of all faces in a directory
        Useful for processing large surveillance archives
        
        Args:
            image_directory: Directory with images to index
            index_name: Name for the index
            
        Returns:
            Path to index file
        """
        print(f"[*] Creating searchable index: {index_name}")
        
        index = {
            'name': index_name,
            'encodings': [],
            'image_paths': [],
            'face_locations': [],
            'created': str(datetime.now())
        }
        
        # Process all images
        for image_path in Path(image_directory).rglob("*.jpg"):
            try:
                image = face_recognition.load_image_file(str(image_path))
                
                # Get all faces in image
                face_locations = face_recognition.face_locations(image)
                face_encodings = face_recognition.face_encodings(image, face_locations)
                
                # Add to index
                for encoding, location in zip(face_encodings, face_locations):
                    index['encodings'].append(encoding)
                    index['image_paths'].append(str(image_path))
                    index['face_locations'].append(location)
                
            except Exception as e:
                print(f"[!] Error processing {image_path}: {e}")
        
        # Save index
        index_file = self.database_path / f"{index_name}.pkl"
        with open(index_file, 'wb') as f:
            pickle.dump(index, f)
        
        print(f"[*] Index created: {index_file}")
        print(f"[*] Total faces indexed: {len(index['encodings'])}")
        
        return str(index_file)
    
    def _alert_match(self, result: Dict):
        """Alert on facial recognition match"""
        try:
            from apollo.alerts import CriticalAlert
            
            alert = CriticalAlert()
            alert.send({
                'type': 'FACIAL_RECOGNITION_MATCH',
                'target': result['target_name'],
                'confidence': result['confidence'],
                'photo': result['photo_path'],
                'distance': result['distance'],
                'priority': 'CRITICAL' if result['confidence'] >= 0.85 else 'HIGH',
                'notify': ['fbi', 'interpol', 'case-officer'],
                'action': 'IMMEDIATE_INVESTIGATION'
            })
        except Exception as e:
            print(f"[!] Alert error: {e}")
    
    def _alert_video_match(self, frame_number: int, confidence: float, video_source: str):
        """Alert on video stream match"""
        try:
            from apollo.alerts import CriticalAlert
            
            alert = CriticalAlert()
            alert.send({
                'type': 'VIDEO_FACIAL_MATCH',
                'frame': frame_number,
                'confidence': confidence,
                'source': video_source,
                'timestamp': datetime.now().isoformat(),
                'priority': 'CRITICAL',
                'notify': ['fbi', 'local-le'],
                'action': 'DISPATCH_UNITS'
            })
        except Exception as e:
            print(f"[!] Alert error: {e}")


if __name__ == "__main__":
    from datetime import datetime
    
    # Example: Create Ignatova database
    encoder = FaceEncodingDatabase()
    
    # Create database from known photos
    db_file = encoder.create_target_database(
        target_name="Ruja Ignatova",
        photo_dir="./photos/ignatova/"
    )
    
    print(f"\n[*] Database ready for matching")
    print(f"[*] Load with: matcher.load_target_database('{db_file}')")
