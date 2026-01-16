# Apollo Platform - Facial Recognition System

## Overview

The Apollo Facial Recognition System provides enterprise-grade face detection, encoding, matching, and real-time video processing capabilities. Built on the `face_recognition` library (based on dlib), this system enables:

- **Face Detection**: Identify and locate faces in images and video streams
- **Face Encoding**: Convert faces to 128-dimensional vectors for comparison
- **Face Matching**: Compare faces against a database with confidence scoring
- **Real-Time Processing**: Process live camera feeds with multi-threaded architecture
- **Age Progression**: Estimate how targets may have aged over time

## Architecture

```
facial_recognition_service.py
├── FaceDetection           # Data class for detected faces
├── FaceMatch               # Data class for match results
├── FaceEnrollment          # Data class for enrolled faces
├── FaceEncodingDatabase    # Persistent storage for encodings
├── FacialRecognitionService # Main service class
└── RealTimeVideoMatcher    # Video stream processing
```

## Installation

### Dependencies

```bash
# Install face_recognition (requires dlib)
pip install face-recognition

# Install OpenCV for video processing
pip install opencv-python

# Or install all dependencies
pip install -r requirements.txt
```

### System Requirements

- Python 3.8+
- CMake (for dlib compilation)
- Linux/macOS recommended (Windows requires additional setup)
- GPU optional but recommended for CNN model

## API Endpoints

### Search by Image
```http
POST /api/v1/facial/search
Content-Type: multipart/form-data

Parameters:
- image: File (required) - Image file to search
- threshold: float (0.6) - Match threshold (0.0-1.0, lower is stricter)
- maxResults: int (10) - Maximum matches to return

Response:
{
  "success": true,
  "data": {
    "faces_detected": 1,
    "matches": [
      {
        "id": "match-abc123",
        "targetId": "target-001",
        "confidence": 0.85,
        "matchedTarget": {
          "firstName": "John",
          "lastName": "Doe"
        }
      }
    ]
  }
}
```

### Compare Two Faces
```http
POST /api/v1/facial/compare
Content-Type: multipart/form-data

Parameters:
- image1: File (required) - First image
- image2: File (required) - Second image

Response:
{
  "success": true,
  "data": {
    "match": true,
    "confidence": 0.92,
    "distance": 0.08,
    "threshold": 0.6
  }
}
```

### Enroll Face
```http
POST /api/v1/facial/enroll
Content-Type: multipart/form-data

Parameters:
- image: File (required) - Face image to enroll
- targetId: string (required) - Unique target identifier
- targetName: string (optional) - Display name

Response:
{
  "success": true,
  "data": {
    "faceId": "face-xyz789",
    "targetId": "target-001",
    "qualityScore": 0.95
  }
}
```

### Get Matches
```http
GET /api/v1/facial/matches?targetId=optional-filter

Response:
{
  "success": true,
  "data": [
    {
      "id": "match-001",
      "targetId": "target-001",
      "confidence": 0.87,
      "timestamp": "2026-01-16T12:00:00Z",
      "verified": false
    }
  ]
}
```

### Get Face Database
```http
GET /api/v1/facial/database

Response:
{
  "success": true,
  "data": [
    {
      "id": "face-001",
      "targetId": "target-001",
      "name": "John Doe",
      "qualityScore": 0.95,
      "createdAt": "2026-01-15T10:00:00Z"
    }
  ]
}
```

### Verify Match
```http
PATCH /api/v1/facial/matches/{match_id}
Content-Type: application/json

Body:
{
  "verified": true,
  "notes": "Confirmed by analyst"
}
```

### Health Check
```http
GET /api/v1/facial/health

Response:
{
  "status": "healthy",
  "service": "facial_recognition",
  "enrolled_faces": 150,
  "total_matches": 42
}
```

## Usage Examples

### Python API

```python
from facial_recognition_service import get_facial_recognition_service

# Initialize service
service = get_facial_recognition_service(
    database_path="./face_database",
    match_threshold=0.6,
    use_cnn=False  # Set True for GPU acceleration
)

# Detect faces in an image
detections = service.detect_faces("photo.jpg")
for detection in detections:
    print(f"Face at {detection.location}, quality: {detection.confidence}")

# Enroll a face
result = service.enroll_face(
    target_id="suspect-001",
    target_name="John Doe",
    image="mugshot.jpg"
)
print(f"Enrolled face ID: {result['faceId']}")

# Search for matches
result = service.search_by_image("unknown_person.jpg")
for match in result['matches']:
    print(f"Match: {match['target_name']} ({match['confidence']:.1%})")

# Compare two faces
result = service.compare_faces("photo1.jpg", "photo2.jpg")
if result['match']:
    print(f"Same person! Confidence: {result['confidence']:.1%}")
```

### Real-Time Video Processing

```python
from facial_recognition_service import (
    get_facial_recognition_service,
    RealTimeVideoMatcher
)
import cv2

# Initialize services
facial_service = get_facial_recognition_service()
video_matcher = RealTimeVideoMatcher(facial_service, frame_skip=3)

# Start processing workers
video_matcher.start()

# Add camera feed
video_matcher.add_camera("lobby_cam_1", 0)  # 0 = webcam

# Process frames
cap = cv2.VideoCapture(0)
frame_id = 0

while True:
    ret, frame = cap.read()
    if not ret:
        break

    # Submit frame for processing
    video_matcher.submit_frame(frame, "lobby_cam_1", frame_id)

    # Check for matches
    matches = video_matcher.get_matches()
    for match in matches:
        print(f"ALERT: Match found! {match['target_name']}")

    frame_id += 1

# Cleanup
video_matcher.stop()
cap.release()
```

## Configuration

### Match Threshold

The match threshold controls how strict face matching is:

| Threshold | Behavior |
|-----------|----------|
| 0.4 | Very strict - minimal false positives |
| 0.6 | Balanced (default) |
| 0.8 | Lenient - may have false positives |

### Detection Models

| Model | Speed | Accuracy | GPU Required |
|-------|-------|----------|--------------|
| HOG | Fast | Good | No |
| CNN | Slow | Excellent | Recommended |

## Database Storage

Face encodings are stored in:
- `face_database/face_database.pkl` - Pickled enrollment data
- Encodings are 128-dimensional numpy arrays
- Metadata includes target info, quality scores, timestamps

## Performance

- HOG detection: ~0.1s per image (CPU)
- CNN detection: ~0.5s per image (CPU), ~0.05s (GPU)
- Matching: O(n) where n = enrolled faces
- Video: 10-30 FPS depending on resolution and model

## Security Considerations

1. **Access Control**: All endpoints require JWT authentication
2. **Data Privacy**: Face encodings cannot be reversed to images
3. **Audit Logging**: All operations are logged
4. **Rate Limiting**: 30 requests/minute per user

## Troubleshooting

### Installation Issues

```bash
# If dlib fails to compile
apt-get install cmake libopenblas-dev liblapack-dev

# macOS
brew install cmake

# Windows (use conda)
conda install -c conda-forge dlib
```

### No Face Detected

- Ensure image contains a clear face
- Try different detection model (CNN vs HOG)
- Check image resolution (minimum 100x100 pixels)
- Verify lighting conditions

### Low Confidence Matches

- Enroll multiple photos of the same person
- Use high-quality reference images
- Adjust match threshold based on use case

## Integration with Apollo Platform

The facial recognition system integrates with:

- **Intelligence Fusion Engine**: Correlate face matches with other intelligence
- **Alert System**: Trigger alerts on high-confidence matches
- **Evidence Management**: Store match evidence for investigations
- **Real-Time Dashboard**: Display live match notifications

## Author

Apollo Platform - Agent 4 (Facial Recognition Lead)

## License

Internal use only - Apollo Intelligence Platform
