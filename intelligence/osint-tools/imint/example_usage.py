"""
IMINT System - Example Usage
Demonstrates all capabilities of the IMINT system
"""

from imint_engine import IMINT
from reverse_image_search import ReverseImageSearch
from face_recognition import FaceRecognition
from pimeyes_integration import PimEyesIntegration
from exif_analyzer import EXIFAnalyzer
from object_detector import ObjectDetector
from video_analyzer import VideoAnalyzer
from image_forensics import ImageForensics


def example_comprehensive_image_analysis():
    """Example: Comprehensive image analysis"""
    print("=" * 80)
    print("EXAMPLE 1: Comprehensive Image Analysis")
    print("=" * 80)

    # Initialize IMINT engine
    config = {
        'log_level': 'INFO',
        'reverse_search': {
            'engines': ['google', 'tineye', 'yandex', 'bing']
        },
        'face_recognition': {
            'enable_age_gender': True,
            'enable_emotions': True
        }
    }

    imint = IMINT(config)

    # Analyze image
    image_path = 'suspect_photo.jpg'
    results = imint.analyze_image(image_path)

    print(f"\nAnalysis Results for: {results['image_path']}")
    print(f"Timestamp: {results['timestamp']}")
    print(f"\nIntelligence Summary:")
    for finding in results['intelligence_summary']['key_findings']:
        print(f"  - {finding}")

    # Export results
    imint.export_results(results, 'analysis_report.json', format='json')
    print("\nResults exported to: analysis_report.json")


def example_face_search_and_matching():
    """Example: Face search and matching"""
    print("\n" + "=" * 80)
    print("EXAMPLE 2: Face Search and Matching")
    print("=" * 80)

    face_rec = FaceRecognition({
        'enable_age_gender': True,
        'enable_emotions': True
    })

    # Analyze faces
    results = face_rec.analyze_image('group_photo.jpg')
    print(f"\nFaces detected: {results['faces_detected']}")

    for i, face in enumerate(results['faces']):
        print(f"\nFace {i + 1}:")
        print(f"  Age: {face.get('age', 'N/A')}")
        print(f"  Gender: {face.get('gender', 'N/A')}")
        print(f"  Emotion: {face.get('dominant_emotion', 'N/A')}")

    # Compare two faces
    comparison = face_rec.compare_faces('face1.jpg', 'face2.jpg')
    print(f"\nFace Comparison:")
    print(f"  Match: {comparison['match']}")
    print(f"  Similarity: {comparison.get('similarity', 0):.2%}")

    # Search in database
    matches = face_rec.search_database('suspect.jpg', 'database/', top_k=5)
    print(f"\nDatabase Search Results: {len(matches)} matches found")
    for match in matches[:3]:
        print(f"  - {match['image_path']}: {match['similarity']:.2%} similarity")


def example_reverse_image_search():
    """Example: Reverse image search"""
    print("\n" + "=" * 80)
    print("EXAMPLE 3: Reverse Image Search")
    print("=" * 80)

    searcher = ReverseImageSearch()

    # Search all engines
    results = searcher.search_all_engines('image.jpg')

    print(f"\nReverse Image Search Results:")
    print(f"  Engines searched: {results['summary']['engines_searched']}")
    print(f"  Total results: {results['summary']['total_results']}")
    print(f"  Unique domains: {len(results['summary']['unique_domains'])}")

    # Search by URL
    url_results = searcher.search_by_url('https://example.com/image.jpg')
    print(f"\nSearch URLs generated for:")
    for engine, url in url_results.items():
        print(f"  - {engine}: {url[:60]}...")


def example_exif_and_location():
    """Example: EXIF extraction and location intelligence"""
    print("\n" + "=" * 80)
    print("EXAMPLE 4: EXIF and Location Intelligence")
    print("=" * 80)

    analyzer = EXIFAnalyzer()

    # Extract EXIF
    exif_data = analyzer.extract_exif('photo.jpg')

    print(f"\nEXIF Data:")
    print(f"  Has EXIF: {exif_data['has_exif']}")

    if exif_data['camera']:
        print(f"  Camera: {exif_data['camera'].get('make')} {exif_data['camera'].get('model')}")

    if exif_data['gps']:
        gps = exif_data['gps']
        print(f"\nGPS Location:")
        print(f"  Latitude: {gps.get('latitude')}")
        print(f"  Longitude: {gps.get('longitude')}")
        print(f"  Google Maps: https://www.google.com/maps?q={gps.get('latitude')},{gps.get('longitude')}")

    # Extract GPS only
    coords = analyzer.extract_gps_coordinates('photo.jpg')
    if coords:
        print(f"\nExtracted Coordinates: {coords}")


def example_object_detection():
    """Example: Object detection"""
    print("\n" + "=" * 80)
    print("EXAMPLE 5: Object Detection")
    print("=" * 80)

    detector = ObjectDetector({
        'confidence_threshold': 0.5
    })

    # Detect objects
    results = detector.detect_objects('scene.jpg')

    print(f"\nObject Detection Results:")
    print(f"  Total objects: {results['total_objects']}")
    print(f"  Categories: {results['categories']}")

    print(f"\nDetected Objects:")
    for obj in results['detected_objects'][:5]:
        print(f"  - {obj['class']}: {obj['confidence']:.2%}")

    # Detect vehicles
    vehicles = detector.detect_vehicles('traffic.jpg')
    print(f"\nVehicles detected: {len(vehicles)}")

    # Detect weapons
    weapons = detector.detect_weapons('security_cam.jpg')
    if weapons:
        print(f"\n⚠️  WARNING: {len(weapons)} weapon(s) detected!")


def example_video_analysis():
    """Example: Video analysis"""
    print("\n" + "=" * 80)
    print("EXAMPLE 6: Video Analysis")
    print("=" * 80)

    analyzer = VideoAnalyzer({
        'frames_per_second': 1,
        'max_frames': 50
    })

    # Extract metadata
    metadata = analyzer.extract_metadata('surveillance.mp4')
    print(f"\nVideo Metadata:")
    print(f"  Duration: {metadata.get('duration_formatted', 'N/A')}")
    print(f"  Resolution: {metadata.get('resolution', 'N/A')}")
    print(f"  FPS: {metadata.get('fps', 'N/A')}")
    print(f"  Frame count: {metadata.get('frame_count', 'N/A')}")

    # Extract key frames
    frames = analyzer.extract_key_frames('surveillance.mp4', method='uniform')
    print(f"\nExtracted {len(frames)} key frames")

    # Detect scenes
    scenes = analyzer.detect_scenes('surveillance.mp4')
    print(f"\nDetected {len(scenes)} scene changes")

    # Extract audio
    audio_path = analyzer.extract_audio('surveillance.mp4', output_format='wav')
    if audio_path:
        print(f"\nAudio extracted to: {audio_path}")


def example_youtube_osint():
    """Example: YouTube video OSINT"""
    print("\n" + "=" * 80)
    print("EXAMPLE 7: YouTube Video OSINT")
    print("=" * 80)

    analyzer = VideoAnalyzer()

    # Analyze YouTube video
    video_url = 'https://youtube.com/watch?v=dQw4w9WgXcQ'
    results = analyzer.analyze_youtube_video(video_url)

    if results.get('metadata'):
        meta = results['metadata']
        print(f"\nYouTube Video Intelligence:")
        print(f"  Title: {meta.get('title')}")
        print(f"  Uploader: {meta.get('uploader')}")
        print(f"  Upload Date: {meta.get('upload_date')}")
        print(f"  View Count: {meta.get('view_count'):,}")
        print(f"  Duration: {meta.get('duration')} seconds")
        print(f"  Tags: {', '.join(meta.get('tags', [])[:5])}")


def example_image_forensics():
    """Example: Image forensics and manipulation detection"""
    print("\n" + "=" * 80)
    print("EXAMPLE 8: Image Forensics")
    print("=" * 80)

    forensics = ImageForensics({
        'ela_quality': 95
    })

    # Comprehensive forensic analysis
    results = forensics.analyze_image('suspect_image.jpg')

    print(f"\nForensic Analysis Results:")
    print(f"  Manipulation Detected: {results['manipulation_detected']}")
    print(f"  Manipulation Score: {results['manipulation_score']:.2%}")
    print(f"  Tests Performed: {', '.join(results['tests_performed'])}")

    if results['anomalies']:
        print(f"\n⚠️  Anomalies Detected:")
        for anomaly in results['anomalies']:
            print(f"  - {anomaly}")

    # Generate detailed report
    forensics.generate_forensics_report(results, 'forensics_report.txt')
    print(f"\nDetailed report saved to: forensics_report.txt")


def example_pimeyes_face_search():
    """Example: PimEyes face search"""
    print("\n" + "=" * 80)
    print("EXAMPLE 9: PimEyes Face Search")
    print("=" * 80)

    pimeyes = PimEyesIntegration({
        'api_key': 'YOUR_PIMEYES_API_KEY'
    })

    # Search face
    results = pimeyes.search_faces('face.jpg')

    print(f"\nPimEyes Search Results:")
    print(f"  Status: {results['status']}")
    print(f"  Total Matches: {results['total_matches']}")

    if results['results']:
        print(f"\nTop Matches:")
        for match in results['results'][:5]:
            print(f"  - {match.get('url')}")
            print(f"    Similarity: {match.get('similarity', 0):.2%}")

    # Setup monitoring
    def alert_callback(new_results):
        print(f"\n🔔 Alert: {len(new_results)} new matches found!")

    monitor = pimeyes.monitor_face('person_of_interest.jpg', alert_callback)
    print(f"\nMonitoring setup complete")
    print(f"  Initial matches: {monitor.get('initial_matches', 0)}")


def example_complete_investigation():
    """Example: Complete investigation workflow"""
    print("\n" + "=" * 80)
    print("EXAMPLE 10: Complete Investigation Workflow")
    print("=" * 80)

    print("\n📋 Investigation: Suspicious Social Media Profile")

    imint = IMINT({
        'face_recognition': {'enable_age_gender': True},
        'reverse_search': {'engines': ['google', 'tineye']}
    })

    image_path = 'profile_picture.jpg'

    # Step 1: Initial analysis
    print("\n[1/5] Performing comprehensive analysis...")
    results = imint.analyze_image(image_path)

    # Step 2: Extract location
    print("[2/5] Extracting location data...")
    location = imint.extract_location_from_image(image_path)
    if location:
        print(f"  ✓ Location found: {location['latitude']}, {location['longitude']}")
    else:
        print("  ✗ No location data available")

    # Step 3: Check for manipulation
    print("[3/5] Checking for image manipulation...")
    forensics = ImageForensics()
    forensic_results = forensics.analyze_image(image_path)
    if forensic_results['manipulation_detected']:
        print(f"  ⚠️  Manipulation detected! Score: {forensic_results['manipulation_score']:.2%}")
    else:
        print("  ✓ No manipulation detected")

    # Step 4: Reverse image search
    print("[4/5] Performing reverse image search...")
    searcher = ReverseImageSearch()
    reverse_results = searcher.search_all_engines(image_path)
    print(f"  ✓ Found {reverse_results['summary']['total_results']} results across {reverse_results['summary']['engines_searched']} engines")

    # Step 5: Face search
    print("[5/5] Searching for face matches...")
    pimeyes = PimEyesIntegration()
    face_results = pimeyes.search_faces(image_path)
    print(f"  ✓ Found {face_results['total_matches']} face matches")

    # Generate final report
    print("\n" + "=" * 80)
    print("INVESTIGATION SUMMARY")
    print("=" * 80)
    print(f"\nImage: {image_path}")
    print(f"\nKey Findings:")
    for finding in results['intelligence_summary']['key_findings']:
        print(f"  • {finding}")

    print(f"\nThreat Level: {results['intelligence_summary']['threat_level'].upper()}")

    # Export complete results
    imint.export_results(results, 'investigation_report.json', format='json')
    print(f"\n✅ Complete investigation report saved to: investigation_report.json")


def main():
    """Run all examples"""
    print("\n" + "=" * 80)
    print("IMINT SYSTEM - COMPREHENSIVE EXAMPLES")
    print("=" * 80)
    print("\nNote: These examples use placeholder file paths.")
    print("Replace with actual image/video paths to run.")
    print("\n" + "=" * 80)

    examples = [
        ("Comprehensive Image Analysis", example_comprehensive_image_analysis),
        ("Face Search and Matching", example_face_search_and_matching),
        ("Reverse Image Search", example_reverse_image_search),
        ("EXIF and Location Intelligence", example_exif_and_location),
        ("Object Detection", example_object_detection),
        ("Video Analysis", example_video_analysis),
        ("YouTube OSINT", example_youtube_osint),
        ("Image Forensics", example_image_forensics),
        ("PimEyes Face Search", example_pimeyes_face_search),
        ("Complete Investigation", example_complete_investigation)
    ]

    print("\nAvailable Examples:")
    for i, (name, _) in enumerate(examples, 1):
        print(f"  {i}. {name}")

    print("\nTo run a specific example, uncomment the corresponding line in main()")
    print("For production use, replace placeholder paths with actual files.\n")

    # Uncomment to run specific examples:
    # example_comprehensive_image_analysis()
    # example_face_search_and_matching()
    # example_reverse_image_search()
    # example_exif_and_location()
    # example_object_detection()
    # example_video_analysis()
    # example_youtube_osint()
    # example_image_forensics()
    # example_pimeyes_face_search()
    # example_complete_investigation()


if __name__ == "__main__":
    main()
