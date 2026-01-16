#!/usr/bin/env python3
"""
Process All Ruja Ignatova Photos - Create Comprehensive FR Database
Apollo Platform - Ignatova Hunt Implementation
"""

import face_recognition
import os
import pickle
from pathlib import Path
from PIL import Image
import cv2
import numpy as np

# Configuration
CASE_DIR = "intelligence/case-files/HVT-CRYPTO-2026-001"
PHOTOS_DIR = f"{CASE_DIR}/photos"
OUTPUT_DB = f"{CASE_DIR}/ruja-ignatova-master-fr-database.pkl"

def process_all_ruja_photos():
    """
    Process all 26+ Ruja photos for facial recognition
    """
    print("="*65)
    print("  RUJA IGNATOVA - PHOTO PROCESSING")
    print("  Processing 26+ photos for facial recognition")
    print("="*65)
    print()
    
    # Initialize database
    master_database = {
        'target_name': 'Ruja Ignatova',
        'case_id': 'HVT-CRYPTO-2026-001',
        'encodings': [],
        'photo_files': [],
        'quality_scores': [],
        'metadata': []
    }
    
    # Primary target photos (Ruja Ignatova)
    target_photos = [
        'ruja-exhibit.webp',
        'birthdaycelly.webp',
        'large.webp',
        'large (1).webp',
        'G8bk8NPWAAA8Vu0.jpg',
        'a9988b9c48767a807a593d93a6d290111f8ea464-1619x1080.avif',
        '_125676577_pic5.png.webp',
        '_125677778_pic6.png.webp',
        'Screenshot 2026-01-12 190403.jpg',
        'Screenshot 2026-01-12 192059.jpg',
        'ruja-ignatova-husband-bjorn-strehl-onecoin.webp'  # Extract Ruja only
    ]
    
    processed = 0
    skipped = 0
    
    for photo_file in target_photos:
        photo_path = os.path.join(PHOTOS_DIR, photo_file)
        
        if not os.path.exists(photo_path):
            print(f"  ✗ Not found: {photo_file}")
            skipped += 1
            continue
        
        try:
            print(f"  Processing: {photo_file}...")
            
            # Load image
            image = face_recognition.load_image_file(photo_path)
            
            # Find face locations
            face_locations = face_recognition.face_locations(image)
            
            if not face_locations:
                print(f"    ✗ No face detected")
                skipped += 1
                continue
            
            # Get face encodings
            face_encodings = face_recognition.face_encodings(image, face_locations)
            
            for idx, encoding in enumerate(face_encodings):
                # Calculate quality score
                quality = assess_photo_quality(image, face_locations[idx])
                
                master_database['encodings'].append(encoding)
                master_database['photo_files'].append(photo_file)
                master_database['quality_scores'].append(quality)
                master_database['metadata'].append({
                    'file': photo_file,
                    'face_index': idx,
                    'quality': quality,
                    'location': face_locations[idx]
                })
                
                processed += 1
                print(f"    ✓ Encoding created (quality: {quality:.2f})")
        
        except Exception as e:
            print(f"    ✗ Error: {e}")
            skipped += 1
    
    print()
    print(f"[*] Processing complete:")
    print(f"    Photos processed: {processed}")
    print(f"    Photos skipped: {skipped}")
    print(f"    Total encodings: {len(master_database['encodings'])}")
    
    # Save database
    with open(OUTPUT_DB, 'wb') as f:
        pickle.dump(master_database, f)
    
    print(f"\n[*] Master database saved: {OUTPUT_DB}")
    print(f"[*] Ready for variant generation and deployment")
    
    return master_database

def assess_photo_quality(image, face_location):
    """
    Assess photo quality for facial recognition
    Returns score 0.0-1.0
    """
    top, right, bottom, left = face_location
    
    # Extract face region
    face_image = image[top:bottom, left:right]
    
    # Calculate quality metrics
    height, width = face_image.shape[:2]
    size_score = min(1.0, (height * width) / (200 * 200))  # Prefer 200x200+
    
    # Brightness check
    gray = cv2.cvtColor(face_image, cv2.COLOR_RGB2GRAY)
    brightness = np.mean(gray) / 255.0
    brightness_score = 1.0 - abs(brightness - 0.5) * 2  # Prefer mid-range
    
    # Sharpness (Laplacian variance)
    laplacian = cv2.Laplacian(gray, cv2.CV_64F)
    sharpness_score = min(1.0, np.var(laplacian) / 1000)
    
    # Overall quality
    quality = (size_score * 0.4 + brightness_score * 0.3 + sharpness_score * 0.3)
    
    return quality

if __name__ == "__main__":
    master_db = process_all_ruja_photos()
    
    print("\n" + "="*65)
    print("  READY FOR NEXT STEPS:")
    print("  1. Extract video frames (add 50-100 more images)")
    print("  2. Generate appearance variants (150+)")
    print("  3. Deploy globally to all FR systems")
    print("="*65)
