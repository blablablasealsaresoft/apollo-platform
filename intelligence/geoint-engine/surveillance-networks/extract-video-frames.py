#!/usr/bin/env python3
"""
Extract Video Frames - Get additional Ignatova face images from video
Apollo Platform - Video Frame Extraction
"""

import face_recognition
import cv2
import pickle
import os
from pathlib import Path

# Configuration
CASE_DIR = "intelligence/case-files/HVT-CRYPTO-2026-001"
VIDEO_FILE = f"{CASE_DIR}/Videos/Ruja-Cut-V2.mp4"
OUTPUT_FRAMES_DIR = f"{CASE_DIR}/extracted_frames"
MASTER_DB = f"{CASE_DIR}/ruja-ignatova-master-fr-database.pkl"

def extract_video_frames():
    """
    Extract high-quality face frames from Ignatova video footage
    """
    print("="*65)
    print("  RUJA IGNATOVA - VIDEO FRAME EXTRACTION")
    print("  Extracting additional face images from video")
    print("="*65)
    print()
    
    if not os.path.exists(VIDEO_FILE):
        print(f"[!] Video not found: {VIDEO_FILE}")
        print("[*] Ensure Ruja-Cut-V2.mp4 is in Videos directory")
        return None
    
    # Create output directory
    Path(OUTPUT_FRAMES_DIR).mkdir(parents=True, exist_ok=True)
    
    # Load existing database
    if os.path.exists(MASTER_DB):
        with open(MASTER_DB, 'rb') as f:
            master_db = pickle.load(f)
        print(f"[*] Loaded existing database: {len(master_db['encodings'])} encodings")
    else:
        print("[!] Master database not found. Run process-all-ruja-photos.py first!")
        return None
    
    # Open video
    print(f"[*] Opening video: {VIDEO_FILE}")
    video = cv2.VideoCapture(VIDEO_FILE)
    
    if not video.isOpened():
        print("[!] Failed to open video")
        return None
    
    # Get video properties
    fps = video.get(cv2.CAP_PROP_FPS)
    frame_count = int(video.get(cv2.CAP_PROP_FRAME_COUNT))
    duration = frame_count / fps if fps > 0 else 0
    
    print(f"[*] Video properties:")
    print(f"    FPS: {fps}")
    print(f"    Total frames: {frame_count}")
    print(f"    Duration: {duration:.1f} seconds")
    print()
    
    # Process frames
    print("[*] Extracting frames with faces...")
    
    frame_number = 0
    frames_processed = 0
    faces_found = 0
    process_every_n = 30  # Process every 30th frame (~1 per second at 30fps)
    
    while True:
        ret, frame = video.read()
        
        if not ret:
            break
        
        frame_number += 1
        
        # Only process every Nth frame for speed
        if frame_number % process_every_n != 0:
            continue
        
        frames_processed += 1
        
        # Convert BGR to RGB
        rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        
        # Find faces
        face_locations = face_recognition.face_locations(rgb_frame)
        
        if not face_locations:
            continue
        
        # Get face encodings
        face_encodings = face_recognition.face_encodings(rgb_frame, face_locations)
        
        for idx, (encoding, location) in enumerate(zip(face_encodings, face_locations)):
            faces_found += 1
            
            # Save frame
            frame_filename = f"frame_{frame_number:06d}_face_{idx}.jpg"
            frame_path = os.path.join(OUTPUT_FRAMES_DIR, frame_filename)
            
            # Extract and save face crop
            top, right, bottom, left = location
            face_image = rgb_frame[top:bottom, left:right]
            cv2.imwrite(frame_path, cv2.cvtColor(face_image, cv2.COLOR_RGB2BGR))
            
            # Add to master database
            master_db['encodings'].append(encoding)
            master_db['photo_files'].append(frame_filename)
            master_db['quality_scores'].append(0.8)  # Video quality
            master_db['metadata'].append({
                'source': 'video',
                'file': frame_filename,
                'frame_number': frame_number,
                'timestamp': frame_number / fps
            })
        
        # Progress indicator
        if frames_processed % 30 == 0:
            print(f"    Processed {frames_processed} frames, found {faces_found} faces...")
    
    video.release()
    
    print()
    print(f"[*] Video processing complete:")
    print(f"    Total video frames: {frame_count}")
    print(f"    Frames analyzed: {frames_processed}")
    print(f"    Faces extracted: {faces_found}")
    print(f"    Face images saved: {OUTPUT_FRAMES_DIR}")
    
    # Update master database
    with open(MASTER_DB, 'wb') as f:
        pickle.dump(master_db, f)
    
    print(f"\n[*] Master database updated:")
    print(f"    Total encodings now: {len(master_db['encodings'])}")
    print(f"    Database file: {MASTER_DB}")
    
    return master_db

if __name__ == "__main__":
    result = extract_video_frames()
    
    if result:
        print("\n" + "="*65)
        print("  VIDEO FRAME EXTRACTION SUCCESSFUL")
        print("="*65)
        print(f"  Total face encodings: {len(result['encodings'])}")
        print(f"  Ready for variant generation and global deployment")
        print("="*65)
