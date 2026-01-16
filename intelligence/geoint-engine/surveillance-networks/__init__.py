"""
Surveillance Networks Module
Apollo Platform - GEOINT Facial Recognition System

This module provides facial recognition capabilities for:
- Face detection and encoding
- Face matching against databases
- Real-time video stream processing
- Age progression estimation
- Surveillance camera integration

Author: Apollo Platform - Agent 4
"""

from .facial_recognition_service import (
    FacialRecognitionService,
    FaceEncodingDatabase,
    RealTimeVideoMatcher,
    FaceDetection,
    FaceMatch,
    FaceEnrollment,
    get_facial_recognition_service,
    FACE_RECOGNITION_AVAILABLE,
    CV2_AVAILABLE,
)

__all__ = [
    'FacialRecognitionService',
    'FaceEncodingDatabase',
    'RealTimeVideoMatcher',
    'FaceDetection',
    'FaceMatch',
    'FaceEnrollment',
    'get_facial_recognition_service',
    'FACE_RECOGNITION_AVAILABLE',
    'CV2_AVAILABLE',
]

__version__ = '1.0.0'
