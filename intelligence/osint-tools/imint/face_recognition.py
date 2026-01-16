"""
Face Recognition - Comprehensive Face Intelligence
Detection, recognition, comparison, age/gender estimation, emotion detection
"""

import os
import logging
import numpy as np
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
import json


class FaceRecognition:
    """
    Comprehensive face intelligence system
    """

    def __init__(self, config: Optional[Dict] = None):
        """Initialize face recognition system"""
        self.config = config or {}
        self.logger = logging.getLogger('FaceRecognition')

        # Configuration
        self.enable_age_gender = self.config.get('enable_age_gender', True)
        self.enable_emotions = self.config.get('enable_emotions', True)
        self.face_detection_threshold = self.config.get('face_detection_threshold', 0.9)
        self.face_match_threshold = self.config.get('face_match_threshold', 0.6)

        # Initialize models
        self._initialize_models()

        self.logger.info("Face Recognition system initialized")

    def _initialize_models(self):
        """Initialize face detection and recognition models"""
        try:
            # Try to import face_recognition library
            import face_recognition
            self.face_recognition = face_recognition
            self.has_face_recognition = True
            self.logger.info("face_recognition library loaded")
        except ImportError:
            self.has_face_recognition = False
            self.logger.warning("face_recognition library not available")

        try:
            # Try to import DeepFace for age/gender/emotion
            from deepface import DeepFace
            self.deepface = DeepFace
            self.has_deepface = True
            self.logger.info("DeepFace library loaded")
        except ImportError:
            self.has_deepface = False
            self.logger.warning("DeepFace library not available")

        try:
            # Try to import cv2 for face detection
            import cv2
            self.cv2 = cv2
            self.has_cv2 = True

            # Load Haar Cascade for face detection
            cascade_path = cv2.data.haarcascades + 'haarcascade_frontalface_default.xml'
            self.face_cascade = cv2.CascadeClassifier(cascade_path)
            self.logger.info("OpenCV loaded")
        except ImportError:
            self.has_cv2 = False
            self.logger.warning("OpenCV not available")

    def analyze_image(self, image_path: str) -> Dict[str, Any]:
        """
        Comprehensive face analysis of an image

        Args:
            image_path: Path to image file

        Returns:
            Complete face analysis results
        """
        self.logger.info(f"Analyzing faces in: {image_path}")

        results = {
            'image_path': image_path,
            'faces_detected': 0,
            'faces': [],
            'analysis_methods': []
        }

        # Method 1: Use face_recognition library
        if self.has_face_recognition:
            results['analysis_methods'].append('face_recognition')
            fr_results = self._analyze_with_face_recognition(image_path)
            results['faces'].extend(fr_results)
            results['faces_detected'] = len(fr_results)

        # Method 2: Use OpenCV for detection
        elif self.has_cv2:
            results['analysis_methods'].append('opencv')
            cv_results = self._analyze_with_opencv(image_path)
            results['faces'].extend(cv_results)
            results['faces_detected'] = len(cv_results)

        # Add age, gender, emotion analysis
        if self.has_deepface and results['faces_detected'] > 0:
            results['analysis_methods'].append('deepface')
            for i, face in enumerate(results['faces']):
                try:
                    deepface_analysis = self._analyze_with_deepface(image_path, face)
                    results['faces'][i].update(deepface_analysis)
                except Exception as e:
                    self.logger.warning(f"DeepFace analysis failed for face {i}: {str(e)}")

        return results

    def _analyze_with_face_recognition(self, image_path: str) -> List[Dict[str, Any]]:
        """Analyze using face_recognition library"""
        import face_recognition

        faces = []

        try:
            # Load image
            image = face_recognition.load_image_file(image_path)

            # Find faces
            face_locations = face_recognition.face_locations(image, model="hog")
            face_encodings = face_recognition.face_encodings(image, face_locations)

            for i, (location, encoding) in enumerate(zip(face_locations, face_encodings)):
                top, right, bottom, left = location

                face_data = {
                    'face_id': i,
                    'location': {
                        'top': int(top),
                        'right': int(right),
                        'bottom': int(bottom),
                        'left': int(left),
                        'width': int(right - left),
                        'height': int(bottom - top)
                    },
                    'encoding': encoding.tolist(),
                    'confidence': 1.0  # face_recognition doesn't provide confidence
                }

                faces.append(face_data)

            self.logger.info(f"Detected {len(faces)} face(s) with face_recognition")

        except Exception as e:
            self.logger.error(f"face_recognition analysis error: {str(e)}")

        return faces

    def _analyze_with_opencv(self, image_path: str) -> List[Dict[str, Any]]:
        """Analyze using OpenCV"""
        import cv2

        faces = []

        try:
            # Read image
            image = cv2.imread(image_path)
            gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)

            # Detect faces
            detected_faces = self.face_cascade.detectMultiScale(
                gray,
                scaleFactor=1.1,
                minNeighbors=5,
                minSize=(30, 30)
            )

            for i, (x, y, w, h) in enumerate(detected_faces):
                face_data = {
                    'face_id': i,
                    'location': {
                        'left': int(x),
                        'top': int(y),
                        'width': int(w),
                        'height': int(h),
                        'right': int(x + w),
                        'bottom': int(y + h)
                    },
                    'encoding': None,
                    'confidence': 0.9  # OpenCV Haar doesn't provide confidence
                }

                faces.append(face_data)

            self.logger.info(f"Detected {len(faces)} face(s) with OpenCV")

        except Exception as e:
            self.logger.error(f"OpenCV analysis error: {str(e)}")

        return faces

    def _analyze_with_deepface(self, image_path: str, face_data: Dict) -> Dict[str, Any]:
        """Analyze face attributes with DeepFace"""
        analysis = {}

        try:
            # Analyze image
            result = self.deepface.analyze(
                img_path=image_path,
                actions=['age', 'gender', 'emotion', 'race'],
                enforce_detection=False
            )

            # DeepFace returns list of results for multiple faces
            if isinstance(result, list) and len(result) > 0:
                result = result[0]

            # Extract attributes
            if self.enable_age_gender:
                analysis['age'] = result.get('age')
                analysis['gender'] = result.get('dominant_gender')
                analysis['gender_confidence'] = result.get('gender', {})

            if self.enable_emotions:
                analysis['dominant_emotion'] = result.get('dominant_emotion')
                analysis['emotions'] = result.get('emotion', {})

            analysis['race'] = result.get('dominant_race')
            analysis['race_confidence'] = result.get('race', {})

        except Exception as e:
            self.logger.warning(f"DeepFace analysis error: {str(e)}")

        return analysis

    def compare_faces(self, image1_path: str, image2_path: str) -> Dict[str, Any]:
        """
        Compare faces in two images

        Args:
            image1_path: First image path
            image2_path: Second image path

        Returns:
            Comparison results with similarity score
        """
        self.logger.info(f"Comparing faces: {image1_path} vs {image2_path}")

        results = {
            'image1': image1_path,
            'image2': image2_path,
            'match': False,
            'distance': None,
            'similarity': None,
            'error': None
        }

        try:
            if self.has_face_recognition:
                import face_recognition

                # Load images
                image1 = face_recognition.load_image_file(image1_path)
                image2 = face_recognition.load_image_file(image2_path)

                # Get encodings
                encodings1 = face_recognition.face_encodings(image1)
                encodings2 = face_recognition.face_encodings(image2)

                if len(encodings1) == 0:
                    results['error'] = "No face found in first image"
                    return results

                if len(encodings2) == 0:
                    results['error'] = "No face found in second image"
                    return results

                # Compare first face in each image
                encoding1 = encodings1[0]
                encoding2 = encodings2[0]

                # Calculate distance
                distance = face_recognition.face_distance([encoding1], encoding2)[0]
                results['distance'] = float(distance)
                results['similarity'] = float(1 - distance)

                # Determine if match
                results['match'] = distance < self.face_match_threshold

                self.logger.info(f"Face comparison: distance={distance:.4f}, match={results['match']}")

            else:
                results['error'] = "face_recognition library not available"

        except Exception as e:
            self.logger.error(f"Face comparison error: {str(e)}")
            results['error'] = str(e)

        return results

    def search_database(self, face_image_path: str, database_path: str, top_k: int = 10) -> List[Dict[str, Any]]:
        """
        Search for a face in a database of images

        Args:
            face_image_path: Path to face image to search
            database_path: Path to directory of images
            top_k: Number of top matches to return

        Returns:
            List of matches sorted by similarity
        """
        self.logger.info(f"Searching face in database: {database_path}")

        matches = []

        if not self.has_face_recognition:
            self.logger.error("face_recognition library not available")
            return matches

        try:
            import face_recognition

            # Load search face
            search_image = face_recognition.load_image_file(face_image_path)
            search_encodings = face_recognition.face_encodings(search_image)

            if len(search_encodings) == 0:
                self.logger.error("No face found in search image")
                return matches

            search_encoding = search_encodings[0]

            # Search through database
            database_files = []
            for ext in ['.jpg', '.jpeg', '.png', '.bmp']:
                database_files.extend(Path(database_path).glob(f"**/*{ext}"))

            self.logger.info(f"Searching {len(database_files)} images...")

            for image_file in database_files:
                try:
                    # Load database image
                    db_image = face_recognition.load_image_file(str(image_file))
                    db_encodings = face_recognition.face_encodings(db_image)

                    if len(db_encodings) == 0:
                        continue

                    # Compare with each face in database image
                    for db_encoding in db_encodings:
                        distance = face_recognition.face_distance([search_encoding], db_encoding)[0]
                        similarity = 1 - distance

                        if similarity > self.face_match_threshold:
                            matches.append({
                                'image_path': str(image_file),
                                'distance': float(distance),
                                'similarity': float(similarity),
                                'match': True
                            })

                except Exception as e:
                    self.logger.debug(f"Error processing {image_file}: {str(e)}")
                    continue

            # Sort by similarity and return top_k
            matches.sort(key=lambda x: x['similarity'], reverse=True)
            matches = matches[:top_k]

            self.logger.info(f"Found {len(matches)} matches")

        except Exception as e:
            self.logger.error(f"Database search error: {str(e)}")

        return matches

    def extract_face(self, image_path: str, output_dir: str) -> List[str]:
        """
        Extract and save individual faces from image

        Args:
            image_path: Path to image
            output_dir: Directory to save extracted faces

        Returns:
            List of saved face image paths
        """
        self.logger.info(f"Extracting faces from: {image_path}")

        os.makedirs(output_dir, exist_ok=True)
        extracted_faces = []

        try:
            if self.has_cv2:
                import cv2

                # Read image
                image = cv2.imread(image_path)

                # Analyze to get face locations
                analysis = self.analyze_image(image_path)

                # Extract each face
                for i, face in enumerate(analysis['faces']):
                    loc = face['location']

                    # Crop face
                    face_img = image[loc['top']:loc['bottom'], loc['left']:loc['right']]

                    # Save face
                    face_filename = f"face_{i}_{Path(image_path).stem}.jpg"
                    face_path = os.path.join(output_dir, face_filename)
                    cv2.imwrite(face_path, face_img)

                    extracted_faces.append(face_path)
                    self.logger.info(f"Extracted face saved to: {face_path}")

        except Exception as e:
            self.logger.error(f"Face extraction error: {str(e)}")

        return extracted_faces

    def create_face_database(self, images_dir: str, output_file: str):
        """
        Create a face database from directory of images

        Args:
            images_dir: Directory containing images
            output_file: Output JSON file for database
        """
        self.logger.info(f"Creating face database from: {images_dir}")

        database = {
            'created': str(Path(images_dir)),
            'total_images': 0,
            'total_faces': 0,
            'faces': []
        }

        if not self.has_face_recognition:
            self.logger.error("face_recognition library not available")
            return

        import face_recognition

        # Process all images
        image_files = []
        for ext in ['.jpg', '.jpeg', '.png', '.bmp']:
            image_files.extend(Path(images_dir).glob(f"**/*{ext}"))

        database['total_images'] = len(image_files)

        for image_file in image_files:
            try:
                # Load and analyze
                image = face_recognition.load_image_file(str(image_file))
                locations = face_recognition.face_locations(image)
                encodings = face_recognition.face_encodings(image, locations)

                # Store each face
                for location, encoding in zip(locations, encodings):
                    database['faces'].append({
                        'image_path': str(image_file),
                        'location': {
                            'top': int(location[0]),
                            'right': int(location[1]),
                            'bottom': int(location[2]),
                            'left': int(location[3])
                        },
                        'encoding': encoding.tolist()
                    })
                    database['total_faces'] += 1

            except Exception as e:
                self.logger.debug(f"Error processing {image_file}: {str(e)}")
                continue

        # Save database
        with open(output_file, 'w') as f:
            json.dump(database, f, indent=2)

        self.logger.info(f"Database created: {database['total_faces']} faces from {database['total_images']} images")


if __name__ == "__main__":
    print("Face Recognition - Face Intelligence System")
    print("=" * 60)

    face_rec = FaceRecognition({
        'enable_age_gender': True,
        'enable_emotions': True
    })

    print("\nCapabilities:")
    print("  - Face detection and encoding")
    print("  - Face comparison and matching")
    print("  - Age and gender estimation")
    print("  - Emotion detection")
    print("  - Face database search")
    print("\nUsage:")
    print("  results = face_rec.analyze_image('photo.jpg')")
    print("  comparison = face_rec.compare_faces('face1.jpg', 'face2.jpg')")
    print("  matches = face_rec.search_database('suspect.jpg', 'database/')")
