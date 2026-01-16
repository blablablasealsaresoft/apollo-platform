"""
Test Suite for Facial Recognition Service
Apollo Platform - GEOINT Facial Recognition System

Tests for:
- Face detection
- Face encoding
- Face matching
- Database operations
- API endpoints

Author: Apollo Platform - Agent 4
"""

import pytest
import os
import sys
import json
import tempfile
import numpy as np
from pathlib import Path
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock

# Add paths for imports
sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "geoint-engine" / "surveillance-networks"))


class TestFacialRecognitionService:
    """Test the FacialRecognitionService class"""

    @pytest.fixture
    def mock_face_recognition(self):
        """Mock the face_recognition library"""
        with patch.dict('sys.modules', {'face_recognition': MagicMock()}):
            import face_recognition as fr
            # Setup mock returns
            fr.load_image_file = Mock(return_value=np.zeros((100, 100, 3), dtype=np.uint8))
            fr.face_locations = Mock(return_value=[(10, 90, 90, 10)])
            fr.face_encodings = Mock(return_value=[np.random.rand(128)])
            fr.face_distance = Mock(return_value=np.array([0.4]))
            fr.face_landmarks = Mock(return_value=[{'left_eye': [], 'right_eye': []}])
            yield fr

    @pytest.fixture
    def temp_database(self, tmp_path):
        """Create a temporary database directory"""
        db_path = tmp_path / "test_face_db"
        db_path.mkdir()
        return str(db_path)

    def test_service_initialization(self, mock_face_recognition, temp_database):
        """Test service initializes correctly"""
        try:
            from facial_recognition_service import FacialRecognitionService
            service = FacialRecognitionService(
                database_path=temp_database,
                match_threshold=0.6,
                use_cnn=False
            )
            assert service is not None
            assert service.match_threshold == 0.6
            assert service.detection_model == 'hog'
        except ImportError:
            pytest.skip("face_recognition library not available")

    def test_face_detection(self, mock_face_recognition, temp_database):
        """Test face detection returns correct format"""
        try:
            from facial_recognition_service import FacialRecognitionService
            service = FacialRecognitionService(database_path=temp_database)

            # Create test image
            test_image = np.zeros((100, 100, 3), dtype=np.uint8)

            detections = service.detect_faces(test_image)

            assert len(detections) == 1
            assert detections[0].location == (10, 90, 90, 10)
            assert detections[0].encoding is not None
        except ImportError:
            pytest.skip("face_recognition library not available")

    def test_face_enrollment(self, mock_face_recognition, temp_database):
        """Test face enrollment adds to database"""
        try:
            from facial_recognition_service import FacialRecognitionService
            service = FacialRecognitionService(database_path=temp_database)

            test_image = np.zeros((100, 100, 3), dtype=np.uint8)

            result = service.enroll_face(
                target_id="test-target-001",
                target_name="Test Person",
                image=test_image
            )

            assert result['success'] is True
            assert 'faceId' in result
            assert result['targetId'] == "test-target-001"

            # Verify in database
            assert len(service.database.enrollments) == 1
        except ImportError:
            pytest.skip("face_recognition library not available")

    def test_face_matching(self, mock_face_recognition, temp_database):
        """Test face matching against enrolled faces"""
        try:
            from facial_recognition_service import FacialRecognitionService
            service = FacialRecognitionService(database_path=temp_database)

            # Enroll a face first
            test_image = np.zeros((100, 100, 3), dtype=np.uint8)
            service.enroll_face(
                target_id="test-target-001",
                target_name="Test Person",
                image=test_image
            )

            # Search with another image
            result = service.search_by_image(test_image)

            assert result['success'] is True
            assert 'matches' in result
        except ImportError:
            pytest.skip("face_recognition library not available")

    def test_face_comparison(self, mock_face_recognition, temp_database):
        """Test comparing two faces"""
        try:
            from facial_recognition_service import FacialRecognitionService
            service = FacialRecognitionService(database_path=temp_database)

            image1 = np.zeros((100, 100, 3), dtype=np.uint8)
            image2 = np.zeros((100, 100, 3), dtype=np.uint8)

            result = service.compare_faces(image1, image2)

            assert 'match' in result
            assert 'confidence' in result
            assert 'distance' in result
        except ImportError:
            pytest.skip("face_recognition library not available")


class TestFaceEncodingDatabase:
    """Test the FaceEncodingDatabase class"""

    @pytest.fixture
    def temp_db_path(self, tmp_path):
        """Create temporary database path"""
        return str(tmp_path / "test_db")

    def test_database_creation(self, temp_db_path):
        """Test database creates directory"""
        try:
            from facial_recognition_service import FaceEncodingDatabase
            db = FaceEncodingDatabase(temp_db_path)
            assert Path(temp_db_path).exists()
        except ImportError:
            pytest.skip("Module not available")

    def test_enrollment_persistence(self, temp_db_path):
        """Test enrollments persist to disk"""
        try:
            from facial_recognition_service import FaceEncodingDatabase, FaceEnrollment

            db = FaceEncodingDatabase(temp_db_path)

            enrollment = FaceEnrollment(
                enrollment_id="test-001",
                target_id="target-001",
                target_name="Test Person",
                encoding=np.random.rand(128),
                quality_score=0.95
            )

            db.add_enrollment(enrollment)
            assert "test-001" in db.enrollments

            # Reload database
            db2 = FaceEncodingDatabase(temp_db_path)
            assert "test-001" in db2.enrollments
        except ImportError:
            pytest.skip("Module not available")


class TestFacialRecognitionRoutes:
    """Test the API routes for facial recognition"""

    @pytest.fixture
    def test_client(self):
        """Create FastAPI test client"""
        try:
            from fastapi.testclient import TestClient
            from routes.facial_routes import router
            from fastapi import FastAPI

            app = FastAPI()
            app.include_router(router, prefix="/api/v1/facial")

            return TestClient(app)
        except ImportError:
            pytest.skip("FastAPI not available")

    def test_health_endpoint(self, test_client):
        """Test health check endpoint"""
        response = test_client.get("/api/v1/facial/health")
        assert response.status_code in [200, 503]  # 503 if service unavailable

    def test_search_requires_auth(self, test_client):
        """Test search endpoint requires authentication"""
        response = test_client.post("/api/v1/facial/search")
        assert response.status_code == 403  # Forbidden without token

    def test_database_endpoint(self, test_client):
        """Test database endpoint"""
        response = test_client.get("/api/v1/facial/database")
        # Should return 403 without auth
        assert response.status_code == 403


class TestDataModels:
    """Test data models and serialization"""

    def test_face_detection_to_dict(self):
        """Test FaceDetection serialization"""
        try:
            from facial_recognition_service import FaceDetection

            detection = FaceDetection(
                face_id="test-123",
                location=(10, 90, 90, 10),
                confidence=0.95
            )

            data = detection.to_dict()

            assert data['face_id'] == "test-123"
            assert data['location'] == (10, 90, 90, 10)
            assert data['confidence'] == 0.95
        except ImportError:
            pytest.skip("Module not available")

    def test_face_match_to_dict(self):
        """Test FaceMatch serialization"""
        try:
            from facial_recognition_service import FaceMatch

            match = FaceMatch(
                match_id="match-123",
                target_id="target-001",
                target_name="Test Person",
                confidence=0.85,
                distance=0.15
            )

            data = match.to_dict()

            assert data['id'] == "match-123"
            assert data['targetId'] == "target-001"
            assert data['confidence'] == 0.85
            assert 'matchedTarget' in data
        except ImportError:
            pytest.skip("Module not available")


class TestAgeProgression:
    """Test age progression functionality"""

    def test_age_progression_import(self):
        """Test age progression module imports"""
        try:
            from age_progression import SimpleAgeProgression
            assert SimpleAgeProgression is not None
        except ImportError:
            pytest.skip("age_progression module not available")

    def test_aging_confidence_calculation(self):
        """Test aging confidence decreases with years"""
        try:
            from age_progression import SimpleAgeProgression

            ap = SimpleAgeProgression()

            conf_5y = ap._calculate_aging_confidence(5)
            conf_10y = ap._calculate_aging_confidence(10)
            conf_15y = ap._calculate_aging_confidence(15)

            assert conf_5y > conf_10y > conf_15y
        except ImportError:
            pytest.skip("age_progression module not available")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
