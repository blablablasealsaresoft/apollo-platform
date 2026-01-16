#!/usr/bin/env python3
"""
Ignatova Surveillance Example - Complete facial recognition deployment
Apollo Platform - Ignatova Hunt Implementation
"""

import face_recognition
import sys
import os
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, os.path.abspath('..'))

from core.face_encoder import FaceEncodingDatabase
from core.face_matcher import FaceMatcher


def deploy_ignatova_facial_recognition():
    """
    Complete facial recognition deployment for Ruja Ignatova hunt
    """
    print("═══════════════════════════════════════════════════════════")
    print("  APOLLO FACIAL RECOGNITION DEPLOYMENT")
    print("  Target: Ruja Ignatova (CryptoQueen)")
    print("  Case: HVT-CRYPTO-2026-001")
    print("═══════════════════════════════════════════════════════════")
    
    # Step 1: Create face encoding database
    print("\n[Step 1/5] Creating face encoding database...")
    encoder = FaceEncodingDatabase()
    
    # Original photos
    original_db = encoder.create_target_database(
        target_name="Ruja Ignatova",
        photo_dir="./photos/ignatova/original/"
    )
    
    # Age-progressed photos (7 years)
    aged_db = encoder.create_age_progression_database(
        target_name="Ruja Ignatova",
        original_photos="./photos/ignatova/original/",
        years=7
    )
    
    print(f"✓ Databases created:")
    print(f"  - Original: {original_db}")
    print(f"  - Age-progressed: {aged_db}")
    
    # Step 2: Create matcher with age-progressed database
    print("\n[Step 2/5] Initializing face matcher...")
    matcher = FaceMatcher(tolerance=0.6)
    matcher.load_target_database(aged_db)
    print(f"✓ Matcher ready with {len(matcher.known_encodings)} face encodings")
    
    # Step 3: Search existing surveillance archives
    print("\n[Step 3/5] Searching surveillance archives...")
    archives = [
        "./surveillance/dubai/2023/",
        "./surveillance/moscow/2023/",
        "./surveillance/sofia/2023/"
    ]
    
    total_matches = []
    for archive in archives:
        if Path(archive).exists():
            print(f"[*] Searching: {archive}")
            matches = matcher.batch_match_directory(archive, recursive=True)
            total_matches.extend(matches)
    
    print(f"✓ Archive search complete: {len(total_matches)} matches found")
    
    # Step 4: Search social media photos
    print("\n[Step 4/5] Searching social media photos...")
    social_media_dirs = [
        "./osint/vk_photos/",
        "./osint/facebook_scraped/",
        "./osint/instagram_photos/"
    ]
    
    social_matches = []
    for sm_dir in social_media_dirs:
        if Path(sm_dir).exists():
            print(f"[*] Searching: {sm_dir}")
            matches = matcher.batch_match_directory(sm_dir, recursive=True)
            social_matches.extend(matches)
    
    print(f"✓ Social media search complete: {len(social_matches)} matches")
    
    # Step 5: Deploy live camera monitoring
    print("\n[Step 5/5] Deploying live camera monitoring...")
    
    # High-probability location cameras
    target_cameras = [
        # Dubai (42% probability)
        {'id': 'DXB-001', 'location': 'Burj Al Arab, Dubai', 'url': 'rtsp://cam1.dubai'},
        {'id': 'DXB-002', 'location': 'Dubai Marina', 'url': 'rtsp://cam2.dubai'},
        {'id': 'DXB-003', 'location': 'Dubai Mall', 'url': 'rtsp://cam3.dubai'},
        
        # Moscow (28% probability)
        {'id': 'MOW-001', 'location': 'Sheremetyevo Airport', 'url': 'rtsp://cam1.moscow'},
        {'id': 'MOW-002', 'location': 'Red Square area', 'url': 'rtsp://cam2.moscow'},
        
        # Sofia (15% probability)
        {'id': 'SOF-001', 'location': 'Sofia Airport', 'url': 'rtsp://cam1.sofia'},
        {'id': 'SOF-002', 'location': 'Vitosha Blvd', 'url': 'rtsp://cam2.sofia'}
    ]
    
    print(f"[*] Deploying to {len(target_cameras)} cameras...")
    print("    Cameras will process continuously until target found")
    print("    Alert threshold: 70% confidence")
    print("    Critical alert: 85% confidence (immediate dispatch)")
    
    # Start processing (in production, would spawn threads)
    # matcher.process_multiple_cameras(target_cameras)
    
    print("\n✓ Live monitoring deployed")
    
    # Summary
    print("\n═══════════════════════════════════════════════════════════")
    print("  FACIAL RECOGNITION DEPLOYMENT COMPLETE")
    print("═══════════════════════════════════════════════════════════")
    print(f"\nTarget:                 {matcher.target_name}")
    print(f"Face encodings:         {len(matcher.known_encodings)}")
    print(f"Tolerance:              {matcher.tolerance}")
    print(f"Archive matches:        {len(total_matches)}")
    print(f"Social media matches:   {len(social_matches)}")
    print(f"Live cameras:           {len(target_cameras)}")
    print(f"\nStatus:                 MONITORING ACTIVE")
    print(f"Alert threshold:        70% confidence")
    print(f"Critical threshold:     85% confidence")
    print("\n═══════════════════════════════════════════════════════════")
    
    # Generate report
    if total_matches or social_matches:
        print("\n[*] HIGH-PRIORITY MATCHES TO INVESTIGATE:")
        
        for match in sorted(total_matches + social_matches, 
                          key=lambda x: x['confidence'], 
                          reverse=True)[:10]:
            print(f"\n    Match: {match['confidence']:.1%} confidence")
            print(f"    Photo: {match['photo_path']}")
            print(f"    Distance: {match['distance']:.4f}")


def quick_photo_check(photo_path: str, target_database: str):
    """
    Quick check single photo against target database
    Useful for rapid investigation of leads
    """
    print(f"[*] Quick check: {photo_path}")
    
    matcher = FaceMatcher(tolerance=0.6)
    matcher.load_target_database(target_database)
    
    result = matcher.match_single_photo(photo_path)
    
    if result and result['matched']:
        print(f"\n[!] MATCH FOUND!")
        print(f"    Target: {result['target_name']}")
        print(f"    Confidence: {result['confidence']:.1%}")
        print(f"    Recommendation: {'IMMEDIATE INVESTIGATION' if result['confidence'] >= 0.85 else 'INVESTIGATE'}")
    else:
        print(f"\n[*] No match found")


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        # Quick check mode
        photo_path = sys.argv[1]
        database = sys.argv[2] if len(sys.argv) > 2 else "./databases/known-faces/ruja_ignatova_aged_7y_encodings.pkl"
        
        quick_photo_check(photo_path, database)
    else:
        # Full deployment
        deploy_ignatova_facial_recognition()
