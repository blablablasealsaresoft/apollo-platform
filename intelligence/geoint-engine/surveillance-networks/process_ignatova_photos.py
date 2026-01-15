#!/usr/bin/env python3
"""
Apollo Platform - Ignatova Photo Processing
Elite-level facial recognition system for processing Ruja Ignatova photos

This script processes all available photos of Ruja Ignatova to create a comprehensive
face database for real-time surveillance and matching. Optimized for FBI Most Wanted hunt.

Author: Agent 5 - Facial/Audio Recognition Lead
Level: Bill Gates / John McAfee Elite
"""

import os
import sys
import json
import hashlib
import numpy as np
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Tuple, Optional
import warnings
warnings.filterwarnings('ignore')

# Try to import required libraries
try:
    import face_recognition
    import cv2
    from PIL import Image
except ImportError as e:
    print(f"❌ Missing required library: {e}")
    print("\n📦 Install with:")
    print("pip install face-recognition opencv-python Pillow")
    sys.exit(1)

class IgnatovaFaceProcessor:
    """
    Elite facial recognition processor for Ruja Ignatova

    Features:
    - Multi-photo face encoding extraction
    - Quality assessment for each detection
    - Age-aware processing (photos from different years)
    - Robust handling of multiple faces in images
    - JSON database generation for rapid matching
    """

    def __init__(self, photos_dir: str, output_dir: str = None):
        self.photos_dir = Path(photos_dir)
        self.output_dir = Path(output_dir) if output_dir else Path("./face_database")
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Results storage
        self.face_encodings: List[np.ndarray] = []
        self.metadata: List[Dict] = []
        self.processing_log: List[str] = []

        print("=" * 80)
        print("🔍 APOLLO FACIAL RECOGNITION SYSTEM")
        print("=" * 80)
        print(f"📁 Photos Directory: {self.photos_dir}")
        print(f"💾 Output Directory: {self.output_dir}")
        print()

    def calculate_image_quality(self, image: np.ndarray, face_location: Tuple) -> float:
        """
        Calculate quality score for a face detection

        Factors:
        - Image resolution
        - Face size in image
        - Brightness/contrast
        - Sharpness

        Returns: Quality score 0.0-1.0
        """
        try:
            top, right, bottom, left = face_location
            face_width = right - left
            face_height = bottom - top

            # Face size score (larger = better)
            face_area = face_width * face_height
            image_area = image.shape[0] * image.shape[1]
            size_ratio = face_area / image_area
            size_score = min(size_ratio * 10, 1.0)  # Cap at 1.0

            # Extract face region
            face_region = image[top:bottom, left:right]

            # Brightness score
            if len(face_region.shape) == 3:
                gray_face = cv2.cvtColor(face_region, cv2.COLOR_BGR2GRAY)
            else:
                gray_face = face_region

            brightness = np.mean(gray_face) / 255.0
            brightness_score = 1.0 - abs(0.5 - brightness)  # Optimal at 0.5

            # Sharpness score (Laplacian variance)
            laplacian = cv2.Laplacian(gray_face, cv2.CV_64F)
            sharpness = laplacian.var()
            sharpness_score = min(sharpness / 1000, 1.0)  # Normalize

            # Combined quality score
            quality = (size_score * 0.5 + brightness_score * 0.3 + sharpness_score * 0.2)

            return round(quality, 4)

        except Exception as e:
            self.log(f"⚠️ Error calculating quality: {e}")
            return 0.5  # Default moderate quality

    def process_image(self, image_path: Path) -> int:
        """
        Process a single image and extract face encodings

        Returns: Number of faces detected
        """
        try:
            print(f"\n📷 Processing: {image_path.name}")

            # Load image
            image = face_recognition.load_image_file(str(image_path))

            # Get image info
            height, width = image.shape[:2]
            file_size = image_path.stat().st_size

            print(f"   📐 Size: {width}x{height} ({file_size / 1024:.1f} KB)")

            # Detect faces (use CNN model for better accuracy if available)
            try:
                face_locations = face_recognition.face_locations(image, model='cnn')
                model_used = 'CNN (GPU)'
            except:
                face_locations = face_recognition.face_locations(image, model='hog')
                model_used = 'HOG (CPU)'

            num_faces = len(face_locations)
            print(f"   👤 Faces detected: {num_faces} (using {model_used})")

            if num_faces == 0:
                self.log(f"⚠️ No faces detected in {image_path.name}")
                return 0

            # Process each detected face
            face_encodings = face_recognition.face_encodings(image, face_locations)

            for i, (face_location, face_encoding) in enumerate(zip(face_locations, face_encodings)):
                # Calculate quality
                quality = self.calculate_image_quality(image, face_location)

                # Get face dimensions
                top, right, bottom, left = face_location
                face_width = right - left
                face_height = bottom - top

                print(f"   ✓ Face #{i+1}: Quality={quality:.2f}, Size={face_width}x{face_height}")

                # Store encoding
                self.face_encodings.append(face_encoding)

                # Store metadata
                self.metadata.append({
                    'source_file': image_path.name,
                    'source_path': str(image_path),
                    'face_number': i + 1,
                    'face_location': {
                        'top': int(top),
                        'right': int(right),
                        'bottom': int(bottom),
                        'left': int(left)
                    },
                    'face_dimensions': {
                        'width': int(face_width),
                        'height': int(face_height)
                    },
                    'image_dimensions': {
                        'width': int(width),
                        'height': int(height)
                    },
                    'quality_score': float(quality),
                    'model_used': model_used,
                    'file_size_kb': round(file_size / 1024, 2),
                    'processed_at': datetime.utcnow().isoformat(),
                    'encoding_hash': hashlib.sha256(face_encoding.tobytes()).hexdigest()[:16]
                })

            return num_faces

        except Exception as e:
            self.log(f"❌ Error processing {image_path.name}: {e}")
            return 0

    def process_all_photos(self) -> Dict:
        """
        Process all photos in the directory

        Returns: Processing statistics
        """
        print("\n" + "=" * 80)
        print("🚀 STARTING PHOTO PROCESSING")
        print("=" * 80)

        # Find all image files
        image_extensions = {'.jpg', '.jpeg', '.png', '.webp', '.avif'}
        image_files = []

        for ext in image_extensions:
            image_files.extend(self.photos_dir.glob(f'*{ext}'))
            image_files.extend(self.photos_dir.glob(f'*{ext.upper()}'))

        image_files = sorted(set(image_files))  # Remove duplicates

        print(f"📸 Found {len(image_files)} image files")

        stats = {
            'total_files': len(image_files),
            'processed_files': 0,
            'failed_files': 0,
            'total_faces': 0,
            'start_time': datetime.utcnow().isoformat()
        }

        # Process each file
        for i, image_path in enumerate(image_files, 1):
            print(f"\n[{i}/{len(image_files)}]", end=' ')

            faces_found = self.process_image(image_path)

            if faces_found > 0:
                stats['processed_files'] += 1
                stats['total_faces'] += faces_found
            else:
                stats['failed_files'] += 1

        stats['end_time'] = datetime.utcnow().isoformat()

        return stats

    def save_database(self) -> str:
        """
        Save face database to disk

        Returns: Path to saved database
        """
        print("\n" + "=" * 80)
        print("💾 SAVING FACE DATABASE")
        print("=" * 80)

        # Save encodings as numpy array
        encodings_path = self.output_dir / "ignatova_face_encodings.npy"
        encodings_array = np.array(self.face_encodings)
        np.save(encodings_path, encodings_array)
        print(f"✓ Saved {len(self.face_encodings)} face encodings to: {encodings_path}")

        # Save metadata as JSON
        metadata_path = self.output_dir / "ignatova_face_metadata.json"
        database = {
            'target': {
                'name': 'Ruja Plamenova Ignatova',
                'aliases': ['CryptoQueen', 'Dr. Ruja', 'The Missing Cryptoqueen'],
                'date_of_birth': '1980-05-30',
                'nationality': 'Bulgaria',
                'status': 'FBI_MOST_WANTED',
                'last_seen': '2017-10-25',
                'reward': 250000,
                'current_age_estimate': 45,
                'years_missing': 8
            },
            'database_info': {
                'created_at': datetime.utcnow().isoformat(),
                'total_encodings': len(self.face_encodings),
                'source_photos': len(set(m['source_file'] for m in self.metadata)),
                'average_quality': round(np.mean([m['quality_score'] for m in self.metadata]), 4),
                'encodings_file': str(encodings_path.name),
                'version': '1.0.0'
            },
            'encodings': self.metadata,
            'processing_log': self.processing_log
        }

        with open(metadata_path, 'w') as f:
            json.dump(database, f, indent=2)
        print(f"✓ Saved metadata to: {metadata_path}")

        # Generate summary report
        report_path = self.output_dir / "processing_report.txt"
        self.generate_report(report_path, database)
        print(f"✓ Generated report: {report_path}")

        return str(self.output_dir)

    def generate_report(self, report_path: Path, database: Dict):
        """Generate human-readable processing report"""
        with open(report_path, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("APOLLO PLATFORM - IGNATOVA FACE DATABASE REPORT\n")
            f.write("=" * 80 + "\n\n")

            f.write("TARGET INFORMATION:\n")
            f.write("-" * 80 + "\n")
            target = database['target']
            f.write(f"Name: {target['name']}\n")
            f.write(f"Aliases: {', '.join(target['aliases'])}\n")
            f.write(f"DOB: {target['date_of_birth']} (Current age: ~{target['current_age_estimate']})\n")
            f.write(f"Status: {target['status']}\n")
            f.write(f"Reward: ${target['reward']:,}\n")
            f.write(f"Last Seen: {target['last_seen']} ({target['years_missing']} years ago)\n\n")

            f.write("DATABASE STATISTICS:\n")
            f.write("-" * 80 + "\n")
            info = database['database_info']
            f.write(f"Total Face Encodings: {info['total_encodings']}\n")
            f.write(f"Source Photos: {info['source_photos']}\n")
            f.write(f"Average Quality: {info['average_quality']:.2%}\n")
            f.write(f"Created: {info['created_at']}\n")
            f.write(f"Version: {info['version']}\n\n")

            f.write("QUALITY DISTRIBUTION:\n")
            f.write("-" * 80 + "\n")
            qualities = [m['quality_score'] for m in database['encodings']]
            f.write(f"Highest Quality: {max(qualities):.2%}\n")
            f.write(f"Lowest Quality: {min(qualities):.2%}\n")
            f.write(f"Median Quality: {np.median(qualities):.2%}\n")
            f.write(f"Encodings > 0.7 quality: {sum(1 for q in qualities if q > 0.7)}\n")
            f.write(f"Encodings > 0.5 quality: {sum(1 for q in qualities if q > 0.5)}\n\n")

            f.write("TOP 10 HIGHEST QUALITY ENCODINGS:\n")
            f.write("-" * 80 + "\n")
            sorted_encodings = sorted(database['encodings'], key=lambda x: x['quality_score'], reverse=True)[:10]
            for i, enc in enumerate(sorted_encodings, 1):
                f.write(f"{i}. {enc['source_file']} - Quality: {enc['quality_score']:.2%}\n")

            f.write("\n" + "=" * 80 + "\n")
            f.write("DATABASE READY FOR SURVEILLANCE DEPLOYMENT\n")
            f.write("=" * 80 + "\n")

    def log(self, message: str):
        """Add message to processing log"""
        timestamp = datetime.utcnow().isoformat()
        log_entry = f"[{timestamp}] {message}"
        self.processing_log.append(log_entry)
        print(log_entry)

def main():
    """Main execution function"""
    print("\n" + "=" * 80)
    print("🎯 APOLLO PLATFORM - IGNATOVA FACIAL RECOGNITION SYSTEM")
    print("=" * 80)
    print("Target: Ruja Plamenova Ignatova (CryptoQueen)")
    print("Status: FBI Most Wanted")
    print("Mission: Process photos and create face database for real-time surveillance")
    print("=" * 80 + "\n")

    # Configuration
    photos_dir = Path(__file__).parent.parent.parent.parent.parent / "Ruja" / "photos"
    output_dir = Path(__file__).parent / "ignatova_database"

    if not photos_dir.exists():
        print(f"❌ Error: Photos directory not found: {photos_dir}")
        print("\n💡 Please ensure Ruja photos are in the correct location.")
        sys.exit(1)

    # Initialize processor
    processor = IgnatovaFaceProcessor(photos_dir, output_dir)

    # Process all photos
    stats = processor.process_all_photos()

    # Save database
    if processor.face_encodings:
        db_path = processor.save_database()

        # Print final summary
        print("\n" + "=" * 80)
        print("✅ PROCESSING COMPLETE")
        print("=" * 80)
        print(f"📊 Total Files: {stats['total_files']}")
        print(f"✅ Successfully Processed: {stats['processed_files']}")
        print(f"❌ Failed: {stats['failed_files']}")
        print(f"👤 Total Face Encodings: {stats['total_faces']}")
        print(f"💾 Database Location: {db_path}")
        print("\n🎯 FACE DATABASE READY FOR SURVEILLANCE DEPLOYMENT!")
        print("=" * 80)

        return 0
    else:
        print("\n❌ No faces detected in any photos!")
        print("   Check photo quality and try again.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
