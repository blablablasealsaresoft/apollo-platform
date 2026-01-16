# IMINT - Image and Video Intelligence System

Comprehensive IMINT (Image Intelligence) system for OSINT operations, providing advanced image and video analysis capabilities.

## Overview

The IMINT system provides a complete suite of tools for analyzing images and videos to extract intelligence, detect manipulation, recognize faces, identify objects, and gather metadata.

## Components

### 1. IMINT Engine (`imint_engine.py`)
Main orchestration engine that coordinates all IMINT modules.

**Features:**
- Comprehensive image analysis
- Video analysis
- Batch processing
- Intelligence summary generation
- Multi-format export (JSON, HTML, PDF)

**Usage:**
```python
from imint_engine import IMINT

# Initialize
imint = IMINT(config={
    'log_level': 'INFO',
    'reverse_search': {'engines': ['google', 'tineye', 'yandex']},
    'face_recognition': {'enable_age_gender': True, 'enable_emotions': True}
})

# Analyze image
results = imint.analyze_image('suspect_photo.jpg')

# Extract location
location = imint.extract_location_from_image('photo.jpg')

# Compare faces
comparison = imint.compare_faces('face1.jpg', 'face2.jpg')

# Analyze video
video_results = imint.analyze_video('surveillance.mp4')

# YouTube analysis
yt_results = imint.analyze_youtube_video('https://youtube.com/watch?v=...')

# Export results
imint.export_results(results, 'report.json', format='json')
```

### 2. Reverse Image Search (`reverse_image_search.py`)
Multi-engine reverse image search across major platforms.

**Supported Engines:**
- Google Images
- TinEye
- Yandex Images
- Bing Visual Search
- Baidu Images

**Usage:**
```python
from reverse_image_search import ReverseImageSearch

searcher = ReverseImageSearch({
    'google_api_key': 'YOUR_KEY',
    'tineye_api_key': 'YOUR_KEY',
    'bing_api_key': 'YOUR_KEY'
})

# Search all engines
results = searcher.search_all_engines('image.jpg')

# Search by URL
results = searcher.search_by_url('https://example.com/image.jpg')

# Individual engine searches
google_results = searcher.search_google('image.jpg')
tineye_results = searcher.search_tineye('image.jpg')
```

### 3. Face Recognition (`face_recognition.py`)
Advanced face detection, recognition, and analysis.

**Features:**
- Face detection and encoding
- Face comparison and matching
- Age and gender estimation
- Emotion detection
- Face database search
- Face extraction

**Usage:**
```python
from face_recognition import FaceRecognition

face_rec = FaceRecognition({
    'enable_age_gender': True,
    'enable_emotions': True,
    'face_match_threshold': 0.6
})

# Analyze faces in image
results = face_rec.analyze_image('photo.jpg')

# Compare faces
comparison = face_rec.compare_faces('face1.jpg', 'face2.jpg')

# Search in database
matches = face_rec.search_database('suspect.jpg', 'database_dir/', top_k=10)

# Extract faces
faces = face_rec.extract_face('group_photo.jpg', 'output_dir/')

# Create face database
face_rec.create_face_database('images_dir/', 'face_db.json')
```

### 4. PimEyes Integration (`pimeyes_integration.py`)
Search and monitor faces across the internet using PimEyes.

**Features:**
- Face search across the web
- Face monitoring with alerts
- Batch face searching
- Credit management

**Usage:**
```python
from pimeyes_integration import PimEyesIntegration

pimeyes = PimEyesIntegration({
    'api_key': 'YOUR_PIMEYES_API_KEY'
})

# Search for faces
results = pimeyes.search_faces('face.jpg')

# Monitor face
def alert_callback(new_results):
    print(f"New matches found: {len(new_results)}")

monitor = pimeyes.monitor_face('suspect.jpg', alert_callback)

# Check for updates
updates = pimeyes.check_monitoring_updates(monitor)

# Batch search
batch_results = pimeyes.batch_search_faces(['face1.jpg', 'face2.jpg'])
```

### 5. EXIF Analyzer (`exif_analyzer.py`)
Extract and analyze image metadata.

**Features:**
- Complete EXIF extraction
- GPS coordinate extraction
- Camera information
- Timestamp analysis
- Software detection
- EXIF stripping

**Usage:**
```python
from exif_analyzer import EXIFAnalyzer

analyzer = EXIFAnalyzer()

# Extract all EXIF data
exif_data = analyzer.extract_exif('photo.jpg')

# Extract GPS coordinates only
gps = analyzer.extract_gps_coordinates('photo.jpg')
# Returns: {'latitude': 37.7749, 'longitude': -122.4194, 'altitude': 10}

# Strip EXIF (for privacy)
analyzer.strip_exif('photo.jpg', 'photo_no_exif.jpg')

# Batch extract
all_exif = analyzer.batch_extract_exif('photos_directory/')
```

### 6. Object Detector (`object_detector.py`)
Advanced object detection using YOLO and other models.

**Features:**
- YOLO object detection
- Vehicle detection
- Weapon detection
- Landmark identification
- Logo/brand recognition
- Image annotation

**Usage:**
```python
from object_detector import ObjectDetector

detector = ObjectDetector({
    'confidence_threshold': 0.5,
    'yolo_weights': 'yolov3.weights',
    'yolo_config': 'yolov3.cfg'
})

# Detect all objects
results = detector.detect_objects('image.jpg')

# Detect vehicles
vehicles = detector.detect_vehicles('traffic.jpg')

# Detect weapons
weapons = detector.detect_weapons('security_cam.jpg')

# Annotate image
detector.annotate_image('image.jpg', 'annotated.jpg', results)
```

### 7. Video Analyzer (`video_analyzer.py`)
Comprehensive video analysis and intelligence extraction.

**Features:**
- Video metadata extraction
- Key frame extraction
- Scene detection
- Audio extraction
- YouTube video OSINT
- Thumbnail generation

**Usage:**
```python
from video_analyzer import VideoAnalyzer

analyzer = VideoAnalyzer({
    'frames_per_second': 1,
    'max_frames': 100
})

# Extract metadata
metadata = analyzer.extract_metadata('video.mp4')

# Extract key frames
frames = analyzer.extract_key_frames('video.mp4', method='interval')

# Detect scenes
scenes = analyzer.detect_scenes('video.mp4', threshold=30.0)

# Extract audio
audio_path = analyzer.extract_audio('video.mp4', output_format='wav')

# Analyze YouTube video
yt_data = analyzer.analyze_youtube_video('https://youtube.com/watch?v=...')

# Create thumbnail
thumbnail = analyzer.create_video_thumbnail('video.mp4', timestamp=10.0)
```

### 8. Image Forensics (`image_forensics.py`)
Detect image manipulation and analyze authenticity.

**Features:**
- Error Level Analysis (ELA)
- JPEG ghost detection
- Noise analysis
- Clone detection
- Metadata consistency check
- Deepfake indicators

**Usage:**
```python
from image_forensics import ImageForensics

forensics = ImageForensics({
    'ela_quality': 95,
    'ela_scale': 10
})

# Comprehensive analysis
results = forensics.analyze_image('suspect_image.jpg')

# Error Level Analysis
ela = forensics.error_level_analysis('image.jpg')

# JPEG ghost analysis
ghost = forensics.jpeg_ghost_analysis('image.jpg')

# Noise analysis
noise = forensics.noise_analysis('image.jpg')

# Detect deepfakes
deepfake = forensics.detect_deepfake('face.jpg')

# Generate report
forensics.generate_forensics_report(results, 'forensics_report.txt')
```

## Installation

### Required Dependencies

```bash
# Core dependencies
pip install pillow numpy opencv-python

# Face recognition
pip install face_recognition deepface

# Deep learning (optional)
pip install tensorflow torch torchvision

# EXIF reading
pip install exifread

# Video processing
pip install ffmpeg-python

# YouTube
pip install yt-dlp
```

### System Requirements

**FFmpeg** (for video/audio processing):
- Windows: Download from https://ffmpeg.org/download.html
- Linux: `sudo apt install ffmpeg`
- Mac: `brew install ffmpeg`

**yt-dlp** (for YouTube):
```bash
pip install yt-dlp
```

**YOLO Weights** (for object detection):
- Download YOLOv3 weights: https://pjreddie.com/media/files/yolov3.weights
- Download config: https://github.com/pjreddie/darknet/blob/master/cfg/yolov3.cfg
- Download class names: https://github.com/pjreddie/darknet/blob/master/data/coco.names

## Configuration

### API Keys

Set environment variables or pass in config:

```bash
# Google Custom Search
export GOOGLE_API_KEY="your_key"
export GOOGLE_CX="your_cx"

# TinEye
export TINEYE_API_KEY="your_key"

# Bing
export BING_API_KEY="your_key"

# PimEyes
export PIMEYES_API_KEY="your_key"
```

### Config Example

```python
config = {
    'log_level': 'INFO',
    'reverse_search': {
        'engines': ['google', 'tineye', 'yandex', 'bing', 'baidu'],
        'google_api_key': 'YOUR_KEY',
        'tineye_api_key': 'YOUR_KEY',
        'bing_api_key': 'YOUR_KEY'
    },
    'face_recognition': {
        'enable_age_gender': True,
        'enable_emotions': True,
        'face_detection_threshold': 0.9,
        'face_match_threshold': 0.6
    },
    'object_detection': {
        'confidence_threshold': 0.5,
        'nms_threshold': 0.4,
        'yolo_weights': 'yolov3.weights',
        'yolo_config': 'yolov3.cfg',
        'yolo_names': 'coco.names'
    },
    'video': {
        'frames_per_second': 1,
        'max_frames': 100,
        'download_youtube_videos': False
    },
    'forensics': {
        'ela_quality': 95,
        'ela_scale': 10
    },
    'pimeyes': {
        'api_key': 'YOUR_KEY',
        'max_results': 100,
        'monitoring_interval': 3600
    }
}
```

## Use Cases

### 1. Suspect Identification
```python
# Analyze suspect photo
results = imint.analyze_image('suspect.jpg', operations=[
    'exif', 'face_recognition', 'reverse_search', 'pimeyes'
])

# Extract location from EXIF
location = imint.extract_location_from_image('suspect.jpg')

# Search face across internet
pimeyes_results = pimeyes.search_faces('suspect.jpg')
```

### 2. Image Verification
```python
# Check if image is manipulated
forensics_results = forensics.analyze_image('news_photo.jpg')

if forensics_results['manipulation_detected']:
    print("Image may be manipulated!")
    print(f"Manipulation score: {forensics_results['manipulation_score']}")
    print(f"Anomalies: {forensics_results['anomalies']}")
```

### 3. Surveillance Video Analysis
```python
# Analyze surveillance video
metadata = analyzer.extract_metadata('surveillance.mp4')
frames = analyzer.extract_key_frames('surveillance.mp4')
scenes = analyzer.detect_scenes('surveillance.mp4')

# Analyze each frame for faces and objects
for frame in frames:
    face_results = face_rec.analyze_image(frame)
    object_results = detector.detect_objects(frame)
```

### 4. Social Media Investigation
```python
# Download and analyze profile picture
profile_pic = 'profile.jpg'

# Reverse image search
reverse_results = searcher.search_all_engines(profile_pic)

# Face search
pimeyes_results = pimeyes.search_faces(profile_pic)

# Extract EXIF
exif = analyzer.extract_exif(profile_pic)
```

## Output Examples

### Image Analysis Result
```json
{
  "image_path": "suspect_photo.jpg",
  "timestamp": "2026-01-14T10:30:00",
  "file_info": {
    "filename": "suspect_photo.jpg",
    "size_mb": 2.5,
    "created": "2026-01-10T15:20:00"
  },
  "analysis": {
    "hashes": {
      "md5": "abc123...",
      "sha256": "def456..."
    },
    "exif": {
      "gps": {
        "latitude": 37.7749,
        "longitude": -122.4194
      },
      "camera": {
        "make": "Canon",
        "model": "EOS 5D"
      }
    },
    "faces": {
      "faces_detected": 1,
      "faces": [{
        "age": 35,
        "gender": "male",
        "emotions": {
          "neutral": 75.5,
          "happy": 15.2
        }
      }]
    },
    "objects": {
      "detected_objects": [
        {"class": "person", "confidence": 0.95},
        {"class": "car", "confidence": 0.87}
      ]
    }
  },
  "intelligence_summary": {
    "key_findings": [
      "GPS coordinates found: 37.7749, -122.4194",
      "1 face(s) detected",
      "2 object(s) detected"
    ],
    "threat_level": "low"
  }
}
```

## Best Practices

1. **Always verify API keys** before running searches
2. **Respect rate limits** for external APIs
3. **Store sensitive results securely**
4. **Strip EXIF** from images before sharing
5. **Use batch processing** for large datasets
6. **Monitor PimEyes credits** to avoid overages
7. **Verify forensic results** with multiple methods
8. **Keep YOLO weights updated** for better detection

## Legal and Ethical Considerations

- Only use on images you have legal right to analyze
- Respect privacy laws and regulations
- Obtain proper authorization for surveillance analysis
- Follow platform terms of service for reverse image searches
- Use face recognition responsibly and ethically
- Comply with data protection regulations (GDPR, etc.)

## Troubleshooting

### Face recognition not working
```bash
pip install cmake dlib
pip install face_recognition
```

### YOLO not detecting objects
- Ensure weights file is downloaded and path is correct
- Check confidence threshold (try lowering it)
- Verify OpenCV is properly installed

### Video analysis failing
- Install FFmpeg system-wide
- Check video codec compatibility
- Try converting video to MP4 format

### API errors
- Verify API keys are valid
- Check rate limits
- Ensure internet connectivity

## Performance Tips

1. **Use GPU** for faster object detection and face recognition
2. **Limit frame extraction** for long videos
3. **Batch process** multiple images in parallel
4. **Cache results** to avoid re-processing
5. **Use lower resolution** for initial analysis

## Future Enhancements

- [ ] Advanced deepfake detection with ML models
- [ ] Real-time video stream analysis
- [ ] Multi-face tracking across video frames
- [ ] License plate recognition
- [ ] Text extraction (OCR) from images
- [ ] Satellite imagery analysis
- [ ] 3D face reconstruction
- [ ] Gait analysis from video

## Support

For issues, questions, or contributions, refer to the main Apollo project documentation.

---

**IMINT System - Advanced Image and Video Intelligence for OSINT Operations**
