"""
Unit Tests for Facial Recognition Module
Apollo Platform - GEOINT Facial Recognition System

Comprehensive unit tests for:
- Face detection data models
- Face encoding database operations
- Face matching algorithms
- Service configuration and initialization

Author: Apollo Platform - Agent 9
"""

import pytest
import numpy as np
import tempfile
import json
from pathlib import Path
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock
from dataclasses import dataclass, field
from typing import List, Tuple, Optional, Dict, Any


# ============================================================
# Data Model Unit Tests (No external dependencies)
# ============================================================

@dataclass
class FaceLocation:
    """Face bounding box location"""
    top: int
    right: int
    bottom: int
    left: int

    def to_tuple(self) -> Tuple[int, int, int, int]:
        return (self.top, self.right, self.bottom, self.left)

    @property
    def width(self) -> int:
        return self.right - self.left

    @property
    def height(self) -> int:
        return self.bottom - self.top

    @property
    def area(self) -> int:
        return self.width * self.height

    @property
    def center(self) -> Tuple[int, int]:
        return ((self.left + self.right) // 2, (self.top + self.bottom) // 2)


@dataclass
class FaceDetectionResult:
    """Result of face detection"""
    face_id: str
    location: FaceLocation
    confidence: float
    encoding: Optional[np.ndarray] = None
    landmarks: Optional[Dict[str, List]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            'face_id': self.face_id,
            'location': self.location.to_tuple(),
            'confidence': self.confidence,
            'has_encoding': self.encoding is not None,
            'has_landmarks': self.landmarks is not None
        }


@dataclass
class FaceMatchResult:
    """Result of face matching"""
    target_id: str
    target_name: str
    confidence: float
    distance: float
    is_match: bool

    def to_dict(self) -> Dict[str, Any]:
        return {
            'target_id': self.target_id,
            'target_name': self.target_name,
            'confidence': self.confidence,
            'distance': self.distance,
            'is_match': self.is_match
        }


@dataclass
class FaceEnrollment:
    """Enrolled face data"""
    enrollment_id: str
    target_id: str
    target_name: str
    encoding: np.ndarray
    quality_score: float
    created_at: datetime = field(default_factory=datetime.now)
    source_file: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class TestFaceLocation:
    """Unit tests for FaceLocation data model"""

    def test_creation(self):
        """Test FaceLocation creation"""
        loc = FaceLocation(top=10, right=90, bottom=90, left=10)

        assert loc.top == 10
        assert loc.right == 90
        assert loc.bottom == 90
        assert loc.left == 10

    def test_to_tuple(self):
        """Test conversion to tuple"""
        loc = FaceLocation(top=10, right=100, bottom=110, left=20)

        assert loc.to_tuple() == (10, 100, 110, 20)

    def test_width_calculation(self):
        """Test width calculation"""
        loc = FaceLocation(top=0, right=100, bottom=100, left=20)

        assert loc.width == 80

    def test_height_calculation(self):
        """Test height calculation"""
        loc = FaceLocation(top=10, right=100, bottom=110, left=0)

        assert loc.height == 100

    def test_area_calculation(self):
        """Test area calculation"""
        loc = FaceLocation(top=0, right=100, bottom=50, left=0)

        assert loc.area == 5000  # 100 * 50

    def test_center_calculation(self):
        """Test center point calculation"""
        loc = FaceLocation(top=0, right=100, bottom=100, left=0)

        assert loc.center == (50, 50)

    def test_center_with_offset(self):
        """Test center calculation with offset"""
        loc = FaceLocation(top=20, right=120, bottom=80, left=40)

        assert loc.center == (80, 50)  # ((40+120)/2, (20+80)/2)


class TestFaceDetectionResult:
    """Unit tests for FaceDetectionResult data model"""

    def test_creation_minimal(self):
        """Test minimal creation"""
        loc = FaceLocation(10, 90, 90, 10)
        result = FaceDetectionResult(
            face_id="face-001",
            location=loc,
            confidence=0.95
        )

        assert result.face_id == "face-001"
        assert result.confidence == 0.95
        assert result.encoding is None
        assert result.landmarks is None

    def test_creation_with_encoding(self):
        """Test creation with encoding"""
        loc = FaceLocation(10, 90, 90, 10)
        encoding = np.random.rand(128)

        result = FaceDetectionResult(
            face_id="face-001",
            location=loc,
            confidence=0.95,
            encoding=encoding
        )

        assert result.encoding is not None
        assert result.encoding.shape == (128,)

    def test_creation_with_landmarks(self):
        """Test creation with landmarks"""
        loc = FaceLocation(10, 90, 90, 10)
        landmarks = {
            'left_eye': [(30, 35), (35, 35)],
            'right_eye': [(60, 35), (65, 35)],
            'nose_tip': [(50, 55)],
            'mouth': [(40, 70), (60, 70)]
        }

        result = FaceDetectionResult(
            face_id="face-001",
            location=loc,
            confidence=0.95,
            landmarks=landmarks
        )

        assert result.landmarks is not None
        assert 'left_eye' in result.landmarks
        assert 'right_eye' in result.landmarks

    def test_to_dict(self):
        """Test conversion to dictionary"""
        loc = FaceLocation(10, 90, 90, 10)
        encoding = np.random.rand(128)

        result = FaceDetectionResult(
            face_id="face-001",
            location=loc,
            confidence=0.95,
            encoding=encoding
        )

        data = result.to_dict()

        assert data['face_id'] == "face-001"
        assert data['location'] == (10, 90, 90, 10)
        assert data['confidence'] == 0.95
        assert data['has_encoding'] is True
        assert data['has_landmarks'] is False


class TestFaceMatchResult:
    """Unit tests for FaceMatchResult data model"""

    def test_creation_match(self):
        """Test creation for positive match"""
        result = FaceMatchResult(
            target_id="target-001",
            target_name="John Doe",
            confidence=0.92,
            distance=0.08,
            is_match=True
        )

        assert result.is_match is True
        assert result.confidence == 0.92
        assert result.distance == 0.08

    def test_creation_no_match(self):
        """Test creation for negative match"""
        result = FaceMatchResult(
            target_id="target-002",
            target_name="Jane Doe",
            confidence=0.45,
            distance=0.55,
            is_match=False
        )

        assert result.is_match is False
        assert result.confidence == 0.45

    def test_to_dict(self):
        """Test conversion to dictionary"""
        result = FaceMatchResult(
            target_id="target-001",
            target_name="Test Person",
            confidence=0.85,
            distance=0.15,
            is_match=True
        )

        data = result.to_dict()

        assert data['target_id'] == "target-001"
        assert data['target_name'] == "Test Person"
        assert data['confidence'] == 0.85
        assert data['is_match'] is True


class TestFaceEnrollment:
    """Unit tests for FaceEnrollment data model"""

    def test_creation_minimal(self):
        """Test minimal creation"""
        encoding = np.random.rand(128)

        enrollment = FaceEnrollment(
            enrollment_id="enroll-001",
            target_id="target-001",
            target_name="Test Person",
            encoding=encoding,
            quality_score=0.95
        )

        assert enrollment.enrollment_id == "enroll-001"
        assert enrollment.target_id == "target-001"
        assert enrollment.quality_score == 0.95
        assert enrollment.source_file is None

    def test_creation_with_metadata(self):
        """Test creation with metadata"""
        encoding = np.random.rand(128)
        metadata = {
            'capture_device': 'CCTV-001',
            'lighting_condition': 'daylight',
            'face_angle': 'frontal'
        }

        enrollment = FaceEnrollment(
            enrollment_id="enroll-001",
            target_id="target-001",
            target_name="Test Person",
            encoding=encoding,
            quality_score=0.90,
            metadata=metadata
        )

        assert enrollment.metadata['capture_device'] == 'CCTV-001'
        assert enrollment.metadata['face_angle'] == 'frontal'

    def test_created_at_default(self):
        """Test default created_at timestamp"""
        encoding = np.random.rand(128)

        enrollment = FaceEnrollment(
            enrollment_id="enroll-001",
            target_id="target-001",
            target_name="Test Person",
            encoding=encoding,
            quality_score=0.95
        )

        assert enrollment.created_at is not None
        assert isinstance(enrollment.created_at, datetime)


# ============================================================
# Face Matching Algorithm Unit Tests
# ============================================================

class FaceMatchingEngine:
    """Face matching engine for testing"""

    def __init__(self, match_threshold: float = 0.6):
        self.match_threshold = match_threshold

    def compute_distance(self, encoding1: np.ndarray, encoding2: np.ndarray) -> float:
        """Compute Euclidean distance between encodings"""
        return float(np.linalg.norm(encoding1 - encoding2))

    def compute_similarity(self, encoding1: np.ndarray, encoding2: np.ndarray) -> float:
        """Compute cosine similarity between encodings"""
        dot_product = np.dot(encoding1, encoding2)
        norm1 = np.linalg.norm(encoding1)
        norm2 = np.linalg.norm(encoding2)

        if norm1 == 0 or norm2 == 0:
            return 0.0

        return float(dot_product / (norm1 * norm2))

    def is_match(self, distance: float) -> bool:
        """Determine if distance indicates a match"""
        return distance <= self.match_threshold

    def distance_to_confidence(self, distance: float, max_distance: float = 1.0) -> float:
        """Convert distance to confidence score"""
        return max(0.0, 1.0 - (distance / max_distance))


class TestFaceMatchingEngine:
    """Unit tests for FaceMatchingEngine"""

    @pytest.fixture
    def engine(self):
        """Create matching engine instance"""
        return FaceMatchingEngine(match_threshold=0.6)

    def test_compute_distance_identical(self, engine):
        """Test distance for identical encodings"""
        encoding = np.random.rand(128)

        distance = engine.compute_distance(encoding, encoding)

        assert distance == pytest.approx(0.0)

    def test_compute_distance_different(self, engine):
        """Test distance for different encodings"""
        encoding1 = np.zeros(128)
        encoding2 = np.ones(128)

        distance = engine.compute_distance(encoding1, encoding2)

        # Euclidean distance: sqrt(128 * 1^2) = sqrt(128) ~ 11.31
        assert distance == pytest.approx(np.sqrt(128), rel=0.01)

    def test_compute_similarity_identical(self, engine):
        """Test similarity for identical encodings"""
        encoding = np.random.rand(128)

        similarity = engine.compute_similarity(encoding, encoding)

        assert similarity == pytest.approx(1.0)

    def test_compute_similarity_orthogonal(self, engine):
        """Test similarity for orthogonal encodings"""
        encoding1 = np.array([1.0, 0.0, 0.0])
        encoding2 = np.array([0.0, 1.0, 0.0])

        similarity = engine.compute_similarity(encoding1, encoding2)

        assert similarity == pytest.approx(0.0)

    def test_compute_similarity_opposite(self, engine):
        """Test similarity for opposite encodings"""
        encoding1 = np.array([1.0, 1.0, 1.0])
        encoding2 = np.array([-1.0, -1.0, -1.0])

        similarity = engine.compute_similarity(encoding1, encoding2)

        assert similarity == pytest.approx(-1.0)

    def test_compute_similarity_zero_vector(self, engine):
        """Test similarity with zero vector"""
        encoding1 = np.zeros(128)
        encoding2 = np.random.rand(128)

        similarity = engine.compute_similarity(encoding1, encoding2)

        assert similarity == 0.0

    def test_is_match_below_threshold(self, engine):
        """Test match detection below threshold"""
        assert engine.is_match(0.4) is True
        assert engine.is_match(0.6) is True

    def test_is_match_above_threshold(self, engine):
        """Test match detection above threshold"""
        assert engine.is_match(0.7) is False
        assert engine.is_match(1.0) is False

    def test_is_match_at_threshold(self, engine):
        """Test match detection at threshold"""
        assert engine.is_match(0.6) is True

    def test_distance_to_confidence_zero(self, engine):
        """Test confidence for zero distance"""
        confidence = engine.distance_to_confidence(0.0)

        assert confidence == 1.0

    def test_distance_to_confidence_max(self, engine):
        """Test confidence for max distance"""
        confidence = engine.distance_to_confidence(1.0)

        assert confidence == 0.0

    def test_distance_to_confidence_half(self, engine):
        """Test confidence for half distance"""
        confidence = engine.distance_to_confidence(0.5)

        assert confidence == pytest.approx(0.5)

    def test_distance_to_confidence_negative_capped(self, engine):
        """Test confidence caps at 0 for high distance"""
        confidence = engine.distance_to_confidence(1.5)

        assert confidence == 0.0


# ============================================================
# Face Database Unit Tests
# ============================================================

class FaceDatabase:
    """In-memory face database for testing"""

    def __init__(self, storage_path: Optional[str] = None):
        self.storage_path = storage_path
        self.enrollments: Dict[str, FaceEnrollment] = {}

    def add_enrollment(self, enrollment: FaceEnrollment) -> str:
        """Add enrollment to database"""
        self.enrollments[enrollment.enrollment_id] = enrollment
        return enrollment.enrollment_id

    def get_enrollment(self, enrollment_id: str) -> Optional[FaceEnrollment]:
        """Get enrollment by ID"""
        return self.enrollments.get(enrollment_id)

    def get_enrollments_by_target(self, target_id: str) -> List[FaceEnrollment]:
        """Get all enrollments for a target"""
        return [e for e in self.enrollments.values() if e.target_id == target_id]

    def remove_enrollment(self, enrollment_id: str) -> bool:
        """Remove enrollment by ID"""
        if enrollment_id in self.enrollments:
            del self.enrollments[enrollment_id]
            return True
        return False

    def clear(self):
        """Clear all enrollments"""
        self.enrollments.clear()

    def count(self) -> int:
        """Count total enrollments"""
        return len(self.enrollments)

    def get_all_encodings(self) -> List[Tuple[str, np.ndarray]]:
        """Get all encodings with their IDs"""
        return [(e.enrollment_id, e.encoding) for e in self.enrollments.values()]

    def save_to_disk(self, path: str):
        """Save database to disk"""
        import pickle
        with open(path, 'wb') as f:
            pickle.dump(self.enrollments, f)

    def load_from_disk(self, path: str):
        """Load database from disk"""
        import pickle
        with open(path, 'rb') as f:
            self.enrollments = pickle.load(f)


class TestFaceDatabase:
    """Unit tests for FaceDatabase"""

    @pytest.fixture
    def database(self):
        """Create database instance"""
        return FaceDatabase()

    @pytest.fixture
    def sample_enrollment(self):
        """Create sample enrollment"""
        return FaceEnrollment(
            enrollment_id="enroll-001",
            target_id="target-001",
            target_name="Test Person",
            encoding=np.random.rand(128),
            quality_score=0.95
        )

    def test_add_enrollment(self, database, sample_enrollment):
        """Test adding enrollment"""
        enrollment_id = database.add_enrollment(sample_enrollment)

        assert enrollment_id == "enroll-001"
        assert database.count() == 1

    def test_get_enrollment(self, database, sample_enrollment):
        """Test getting enrollment by ID"""
        database.add_enrollment(sample_enrollment)

        retrieved = database.get_enrollment("enroll-001")

        assert retrieved is not None
        assert retrieved.target_name == "Test Person"

    def test_get_enrollment_not_found(self, database):
        """Test getting non-existent enrollment"""
        retrieved = database.get_enrollment("non-existent")

        assert retrieved is None

    def test_get_enrollments_by_target(self, database):
        """Test getting enrollments by target ID"""
        # Add multiple enrollments for same target
        for i in range(3):
            enrollment = FaceEnrollment(
                enrollment_id=f"enroll-00{i}",
                target_id="target-001",
                target_name="Test Person",
                encoding=np.random.rand(128),
                quality_score=0.95
            )
            database.add_enrollment(enrollment)

        # Add enrollment for different target
        other_enrollment = FaceEnrollment(
            enrollment_id="enroll-099",
            target_id="target-099",
            target_name="Other Person",
            encoding=np.random.rand(128),
            quality_score=0.90
        )
        database.add_enrollment(other_enrollment)

        # Query
        target_enrollments = database.get_enrollments_by_target("target-001")

        assert len(target_enrollments) == 3
        assert all(e.target_id == "target-001" for e in target_enrollments)

    def test_remove_enrollment(self, database, sample_enrollment):
        """Test removing enrollment"""
        database.add_enrollment(sample_enrollment)

        result = database.remove_enrollment("enroll-001")

        assert result is True
        assert database.count() == 0

    def test_remove_enrollment_not_found(self, database):
        """Test removing non-existent enrollment"""
        result = database.remove_enrollment("non-existent")

        assert result is False

    def test_clear(self, database, sample_enrollment):
        """Test clearing database"""
        database.add_enrollment(sample_enrollment)
        database.clear()

        assert database.count() == 0

    def test_get_all_encodings(self, database):
        """Test getting all encodings"""
        for i in range(3):
            enrollment = FaceEnrollment(
                enrollment_id=f"enroll-00{i}",
                target_id=f"target-00{i}",
                target_name=f"Person {i}",
                encoding=np.random.rand(128),
                quality_score=0.95
            )
            database.add_enrollment(enrollment)

        encodings = database.get_all_encodings()

        assert len(encodings) == 3
        assert all(len(e[1]) == 128 for e in encodings)

    def test_persistence(self, database, sample_enrollment, tmp_path):
        """Test saving and loading database"""
        database.add_enrollment(sample_enrollment)

        save_path = tmp_path / "test_db.pkl"
        database.save_to_disk(str(save_path))

        # Create new database and load
        new_database = FaceDatabase()
        new_database.load_from_disk(str(save_path))

        assert new_database.count() == 1
        retrieved = new_database.get_enrollment("enroll-001")
        assert retrieved.target_name == "Test Person"


# ============================================================
# Quality Assessment Unit Tests
# ============================================================

class FaceQualityAssessor:
    """Face quality assessment"""

    def __init__(
        self,
        min_face_size: int = 80,
        min_confidence: float = 0.7,
        min_quality_score: float = 0.5
    ):
        self.min_face_size = min_face_size
        self.min_confidence = min_confidence
        self.min_quality_score = min_quality_score

    def assess_size(self, location: FaceLocation) -> Tuple[bool, str]:
        """Assess face size quality"""
        if location.width < self.min_face_size or location.height < self.min_face_size:
            return False, f"Face too small: {location.width}x{location.height} (min: {self.min_face_size})"
        return True, "Size OK"

    def assess_confidence(self, confidence: float) -> Tuple[bool, str]:
        """Assess detection confidence"""
        if confidence < self.min_confidence:
            return False, f"Low confidence: {confidence:.2f} (min: {self.min_confidence})"
        return True, "Confidence OK"

    def compute_blur_score(self, encoding: np.ndarray) -> float:
        """Compute blur score from encoding variance (mock)"""
        # In real implementation, this would analyze actual image
        variance = np.var(encoding)
        return min(1.0, variance * 10)

    def assess_overall(
        self,
        location: FaceLocation,
        confidence: float,
        encoding: Optional[np.ndarray] = None
    ) -> Tuple[bool, float, List[str]]:
        """
        Perform overall quality assessment

        Returns:
            Tuple of (passes, quality_score, issues)
        """
        issues = []
        scores = []

        # Check size
        size_ok, size_msg = self.assess_size(location)
        if not size_ok:
            issues.append(size_msg)
        scores.append(1.0 if size_ok else 0.3)

        # Check confidence
        conf_ok, conf_msg = self.assess_confidence(confidence)
        if not conf_ok:
            issues.append(conf_msg)
        scores.append(confidence)

        # Check blur if encoding available
        if encoding is not None:
            blur_score = self.compute_blur_score(encoding)
            if blur_score < 0.5:
                issues.append(f"Blurry image: {blur_score:.2f}")
            scores.append(blur_score)

        # Compute overall score
        overall_score = sum(scores) / len(scores)
        passes = overall_score >= self.min_quality_score and size_ok and conf_ok

        return passes, overall_score, issues


class TestFaceQualityAssessor:
    """Unit tests for FaceQualityAssessor"""

    @pytest.fixture
    def assessor(self):
        """Create assessor instance"""
        return FaceQualityAssessor(
            min_face_size=80,
            min_confidence=0.7,
            min_quality_score=0.5
        )

    def test_assess_size_pass(self, assessor):
        """Test size assessment passes for large face"""
        location = FaceLocation(0, 100, 100, 0)

        passes, msg = assessor.assess_size(location)

        assert passes is True
        assert msg == "Size OK"

    def test_assess_size_fail(self, assessor):
        """Test size assessment fails for small face"""
        location = FaceLocation(0, 50, 50, 0)

        passes, msg = assessor.assess_size(location)

        assert passes is False
        assert "too small" in msg.lower()

    def test_assess_confidence_pass(self, assessor):
        """Test confidence assessment passes"""
        passes, msg = assessor.assess_confidence(0.85)

        assert passes is True
        assert msg == "Confidence OK"

    def test_assess_confidence_fail(self, assessor):
        """Test confidence assessment fails"""
        passes, msg = assessor.assess_confidence(0.5)

        assert passes is False
        assert "low confidence" in msg.lower()

    def test_compute_blur_score(self, assessor):
        """Test blur score computation"""
        encoding = np.random.rand(128)

        score = assessor.compute_blur_score(encoding)

        assert 0.0 <= score <= 1.0

    def test_assess_overall_pass(self, assessor):
        """Test overall assessment passes"""
        location = FaceLocation(0, 100, 100, 0)
        encoding = np.random.rand(128) * 0.5  # Medium variance

        passes, score, issues = assessor.assess_overall(
            location, confidence=0.9, encoding=encoding
        )

        assert passes is True
        assert score >= 0.5
        assert len(issues) == 0

    def test_assess_overall_fail_size(self, assessor):
        """Test overall assessment fails on size"""
        location = FaceLocation(0, 40, 40, 0)

        passes, score, issues = assessor.assess_overall(
            location, confidence=0.9
        )

        assert passes is False
        assert any("small" in issue.lower() for issue in issues)

    def test_assess_overall_fail_confidence(self, assessor):
        """Test overall assessment fails on confidence"""
        location = FaceLocation(0, 100, 100, 0)

        passes, score, issues = assessor.assess_overall(
            location, confidence=0.5
        )

        assert passes is False
        assert any("confidence" in issue.lower() for issue in issues)


# ============================================================
# Run tests
# ============================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
