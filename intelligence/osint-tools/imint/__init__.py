"""
IMINT - Image and Video Intelligence System
Comprehensive OSINT image analysis toolkit
"""

from .imint_engine import IMINT
from .reverse_image_search import ReverseImageSearch
from .face_recognition import FaceRecognition
from .pimeyes_integration import PimEyesIntegration
from .exif_analyzer import EXIFAnalyzer
from .object_detector import ObjectDetector
from .video_analyzer import VideoAnalyzer
from .image_forensics import ImageForensics

__version__ = '1.0.0'
__author__ = 'Apollo Intelligence'

__all__ = [
    'IMINT',
    'ReverseImageSearch',
    'FaceRecognition',
    'PimEyesIntegration',
    'EXIFAnalyzer',
    'ObjectDetector',
    'VideoAnalyzer',
    'ImageForensics'
]
