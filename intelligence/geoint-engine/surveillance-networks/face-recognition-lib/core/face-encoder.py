# face_recognition Library Integration

## Overview

**face_recognition** is the world's simplest facial recognition API for Python, now integrated into Apollo's GEOINT surveillance system for enhanced facial recognition capabilities.

**Source**: [face_recognition](https://github.com/blablablasealsaresoft/face_recognition)  
**Type**: Python facial recognition library (based on dlib)  
**Status**: ✅ Integrated  
**Location**: `intelligence/geoint-engine/surveillance-networks/face-recognition-lib/`

---

## What is face_recognition?

The world's simplest facial recognition library that provides:
- **Face detection** - Find faces in images
- **Face encoding** - Convert faces to 128-d vectors
- **Face comparison** - Compare faces with high accuracy
- **Facial landmarks** - Identify eyes, nose, mouth, etc.
- **Command-line interface** - Easy batch processing
- **Python API** - Simple programmatic access

### Why It Matters for Apollo

**Benefits**:
- ✅ **Simple API** - Easy to integrate
- ✅ **High accuracy** - Based on state-of-the-art dlib models
- ✅ **Fast processing** - Can use GPU acceleration
- ✅ **Batch processing** - Process thousands of images
- ✅ **Local processing** - No API costs, privacy-preserving
- ✅ **Open source** - MIT licensed

**Perfect for**:
- Processing surveillance camera feeds
- Comparing suspect photos across databases
- Real-time facial recognition in video streams
- Batch processing of social media photos
- Creating face encoding databases

---

## Installation

### Add to Apollo Requirements

**File**: `intelligence/geoint-engine/requirements.txt`

```txt
# Face Recognition Library
face-recognition>=1.3.0
dlib>=19.24.0
cmake>=3.26.0
```

### Install

```bash
# Install face_recognition
pip install face-recognition

# Or with GPU support
pip install face-recognition[cuda]

# For Apollo
cd intelligence/geoint-engine
pip install -r requirements.txt
```

---

## Integration into Apollo

### Directory Structure

```
face-recognition-lib/
├── core/
│   ├── face-encoder.py          # Create face encodings
│   ├── face-matcher.py          # Match faces against database
│   ├── batch-processor.py       # Process large image sets
│   └── video-processor.py       # Real-time video analysis
├── databases/
│   ├── known-faces/             # Database of known faces
│   │   ├── ignatova-encodings.pkl
│   │   └── suspects-database.pkl
│   └── surveillance-cache/      # Cached surveillance results
├── apollo-integration/
│   ├── surveillance-feed.py     # Process camera feeds
│   ├── social-media-scan.py     # Scan social media photos
│   └── intelligence-fusion.py   # Feed to Apollo intelligence
├── examples/
│   ├── ignatova-search.py       # Ignatova-specific search
│   └── batch-surveillance.py    # Batch camera feed processing
└── README.md
```

---

## Core Implementation

### 1. Face Encoding Database

**File**: `core/face-encoder.py`

```python
#!/usr/bin/env python3
"""
Face Encoding Database - Create searchable face encodings
Apollo Platform - Facial Recognition Module
"""

import face_recognition
import pickle
import os
from typing import List, Dict
from pathlib import Path


class FaceEncodingDatabase:
    """
    Create and manage database of known face encodings
    for rapid comparison against surveillance feeds
    """
    
    def __init__(self, database_path: str = "databases/known-faces"):
        self.database_path = Path(database_path)
        self.database_path.mkdir(parents=True, exist_ok=True)
        
    def create_target_database(self, target_name: str, photo_dir: str) -> str:
        """
        Create face encoding database for target
        
        Args:
            target_name: Name of target (e.g., "Ruja Ignatova")
            photo_dir: Directory with target photos
            
        Returns:
            Path to encoding database file
        """
        print(f"[*] Creating face encodings for: {target_name}")
        
        encodings = []
        photos = []
        
        # Load all photos of target
        for image_file in Path(photo_dir).glob("*.jpg"):
            print(f"[*] Processing: {image_file.name}")
            
            # Load image
            image = face_recognition.load_image_file(str(image_file))
            
            # Get face encodings (may be multiple faces in photo)
            face_encodings = face_recognition.face_encodings(image)
            
            if face_encodings:
                # Use first face (assumes target is primary subject)
                encodings.append(face_encodings[0])
                photos.append(image_file.name)
                print(f"    ✓ Encoded: {image_file.name}")
            else:
                print(f"    ✗ No face found: {image_file.name}")
        
        # Save database
        database = {
            'target_name': target_name,
            'encodings': encodings,
            'photos': photos,
            'created': str(datetime.now())
        }
        
        db_file = self.database_path / f"{target_name.lower().replace(' ', '_')}_encodings.pkl"
        
        with open(db_file, 'wb') as f:
            pickle.dump(database, f)
        
        print(f"[*] Database created: {db_file}")
        print(f"[*] Total encodings: {len(encodings)}")
        
        return str(db_file)
    
    def create_age_progression_database(self, target_name: str, original_photos: str, years: int) -> str:
        """
        Create database with age-progressed face encodings
        
        Args:
            target_name: Target name
            original_photos: Original photo directory
            years: Years to age progress
            
        Returns:
            Path to age-progressed encoding database
        """
        print(f"[*] Creating age-progressed encodings (+{years} years)")
        
        # First, create encodings from originals
        original_db = self.create_target_database(target_name, original_photos)
        
        # Then use Apollo AI to generate age-progressed variants
        try:
            from apollo.ai import AppearanceVariantGenerator
            
            generator = AppearanceVariantGenerator()
            
            variants_dir = self.database_path / f"{target_name}_age_progressed"
            variants_dir.mkdir(exist_ok=True)
            
            # Generate age-progressed photos
            for image_file in Path(original_photos).glob("*.jpg"):
                aged_image = generator.age_progression(
                    str(image_file),
                    years=years
                )
                
                # Save aged image
                aged_file = variants_dir / f"{image_file.stem}_aged_{years}y.jpg"
                aged_image.save(aged_file)
            
            # Create encodings from aged photos
            aged_db = self.create_target_database(
                f"{target_name}_aged_{years}y",
                str(variants_dir)
            )
            
            return aged_db
            
        except Exception as e:
            print(f"[!] Age progression error: {e}")
            return original_db
    
    def load_database(self, db_file: str) -> Dict:
        """Load face encoding database"""
        with open(db_file, 'rb') as f:
            return pickle.load(f)


if __name__ == "__main__":
    # Example: Create Ignatova database
    encoder = FaceEncodingDatabase()
    
    # Create database from known photos
    db_file = encoder.create_target_database(
        target_name="Ruja Ignatova",
        photo_dir="./photos/ignatova/"
    )
    
    # Create age-progressed database (7 years)
    aged_db = encoder.create_age_progression_database(
        target_name="Ruja Ignatova",
        original_photos="./photos/ignatova/",
        years=7
    )
    
    print(f"\n[*] Databases ready for surveillance matching")
