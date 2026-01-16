"""
Facial Recognition Routes - API Endpoints for Face Detection and Matching
Apollo Platform - GEOINT Facial Recognition System

Provides endpoints for:
- Face detection and search
- Face database management
- Face comparison
- Match verification
- Real-time video feed processing
- Age progression queries

Author: Apollo Platform - Agent 4
"""

import os
import io
import logging
import tempfile
from datetime import datetime
from typing import Optional, List
from pathlib import Path

from fastapi import APIRouter, HTTPException, Depends, UploadFile, File, Form, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

# Import authentication middleware
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from middleware.auth import JWTBearer
from middleware.rate_limiter import RateLimiter

logger = logging.getLogger(__name__)
router = APIRouter()
rate_limiter = RateLimiter(requests_per_minute=30)

# Lazy load facial recognition service to handle import errors gracefully
_facial_service = None


def get_facial_service():
    """Lazy load the facial recognition service"""
    global _facial_service

    if _facial_service is None:
        # Try multiple import paths
        import_paths = [
            str(Path(__file__).parent.parent / "geoint-engine" / "surveillance-networks"),
            str(Path(__file__).parent.parent),
        ]

        for import_path in import_paths:
            if import_path not in sys.path:
                sys.path.insert(0, import_path)

        try:
            from facial_recognition_service import get_facial_recognition_service
            _facial_service = get_facial_recognition_service(
                database_path=str(Path(__file__).parent.parent / "face_database"),
                match_threshold=0.6,
                use_cnn=False
            )
            logger.info("Facial recognition service initialized successfully")
        except ImportError as e:
            logger.warning(f"face_recognition library not available: {e}")
            logger.info("Install with: pip install face-recognition opencv-python")
            return None
        except Exception as e:
            logger.error(f"Failed to initialize facial recognition service: {e}")
            return None

    return _facial_service


# Request/Response Models
class FacialSearchRequest(BaseModel):
    """Request model for facial search by URL"""
    imageUrl: str = Field(..., description="URL of the image to search")
    threshold: Optional[float] = Field(0.6, ge=0.1, le=1.0, description="Match threshold (0.1-1.0)")
    maxResults: Optional[int] = Field(10, ge=1, le=100, description="Maximum number of results")


class FaceEnrollRequest(BaseModel):
    """Request model for face enrollment"""
    targetId: str = Field(..., description="Target ID to associate with the face")
    targetName: Optional[str] = Field(None, description="Display name for the target")


class MatchVerifyRequest(BaseModel):
    """Request model for match verification"""
    verified: bool = Field(..., description="Whether the match is verified")
    notes: Optional[str] = Field(None, description="Verification notes")


class FaceCompareResult(BaseModel):
    """Response model for face comparison"""
    match: bool
    confidence: float
    distance: Optional[float] = None
    threshold: Optional[float] = None


class FacialMatch(BaseModel):
    """Response model for a facial match"""
    id: str
    targetId: str
    confidence: float
    source: Optional[str] = None
    location: Optional[str] = None
    timestamp: str
    verified: bool = False
    matchedTarget: Optional[dict] = None


# API Endpoints

@router.post("/search")
async def search_by_image(
    image: UploadFile = File(..., description="Image file to search"),
    threshold: float = Form(0.6, description="Match threshold"),
    maxResults: int = Form(10, description="Maximum results"),
    token: str = Depends(JWTBearer())
):
    """
    Search for face matches using an uploaded image.

    Upload an image file and search against the enrolled face database.
    Returns a list of potential matches with confidence scores.
    """
    service = get_facial_service()
    if service is None:
        raise HTTPException(
            status_code=503,
            detail="Facial recognition service unavailable. Ensure face_recognition library is installed."
        )

    try:
        # Read image bytes
        image_bytes = await image.read()

        # Perform search
        result = service.search_by_image(
            image=image_bytes,
            threshold=threshold,
            max_results=maxResults
        )

        return JSONResponse(content={
            "success": True,
            "data": {
                "faces_detected": result.get('faces_detected', 0),
                "matches": result.get('matches', [])
            }
        })

    except Exception as e:
        logger.error(f"Face search error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/search/url")
async def search_by_image_url(
    request: FacialSearchRequest,
    token: str = Depends(JWTBearer())
):
    """
    Search for face matches using an image URL.

    Provide a URL to an image and search against the enrolled face database.
    """
    service = get_facial_service()
    if service is None:
        raise HTTPException(
            status_code=503,
            detail="Facial recognition service unavailable"
        )

    try:
        import requests

        # Download image from URL
        response = requests.get(request.imageUrl, timeout=30)
        if response.status_code != 200:
            raise HTTPException(status_code=400, detail="Failed to download image from URL")

        image_bytes = response.content

        # Perform search
        result = service.search_by_image(
            image=image_bytes,
            threshold=request.threshold,
            max_results=request.maxResults
        )

        return JSONResponse(content={
            "success": True,
            "data": {
                "faces_detected": result.get('faces_detected', 0),
                "matches": result.get('matches', [])
            }
        })

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Face search by URL error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/compare")
async def compare_faces(
    image1: UploadFile = File(..., description="First image"),
    image2: UploadFile = File(..., description="Second image"),
    token: str = Depends(JWTBearer())
):
    """
    Compare two face images to determine if they are the same person.

    Upload two images and get a similarity score and match determination.
    """
    service = get_facial_service()
    if service is None:
        raise HTTPException(
            status_code=503,
            detail="Facial recognition service unavailable"
        )

    try:
        # Read both images
        image1_bytes = await image1.read()
        image2_bytes = await image2.read()

        # Compare faces
        result = service.compare_faces(image1_bytes, image2_bytes)

        if not result.get('success'):
            return JSONResponse(content={
                "success": False,
                "match": False,
                "confidence": 0.0,
                "error": result.get('error', 'Comparison failed')
            })

        return JSONResponse(content={
            "success": True,
            "data": {
                "match": result.get('match', False),
                "confidence": result.get('confidence', 0.0),
                "distance": result.get('distance'),
                "threshold": result.get('threshold')
            }
        })

    except Exception as e:
        logger.error(f"Face comparison error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/enroll")
async def enroll_face(
    image: UploadFile = File(..., description="Face image to enroll"),
    targetId: str = Form(..., description="Target ID"),
    targetName: str = Form(None, description="Target name"),
    token: str = Depends(JWTBearer())
):
    """
    Enroll a new face in the database.

    Upload an image and associate it with a target ID for future matching.
    """
    service = get_facial_service()
    if service is None:
        raise HTTPException(
            status_code=503,
            detail="Facial recognition service unavailable"
        )

    try:
        image_bytes = await image.read()

        result = service.enroll_face(
            target_id=targetId,
            target_name=targetName or targetId,
            image=image_bytes
        )

        if not result.get('success'):
            raise HTTPException(status_code=400, detail=result.get('error', 'Enrollment failed'))

        return JSONResponse(content={
            "success": True,
            "data": {
                "faceId": result.get('faceId'),
                "targetId": result.get('targetId'),
                "qualityScore": result.get('qualityScore')
            }
        })

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Face enrollment error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/matches")
async def get_matches(
    targetId: Optional[str] = Query(None, description="Filter by target ID"),
    token: str = Depends(JWTBearer())
):
    """
    Get recent facial recognition matches.

    Returns a list of recent matches, optionally filtered by target ID.
    """
    service = get_facial_service()
    if service is None:
        raise HTTPException(
            status_code=503,
            detail="Facial recognition service unavailable"
        )

    try:
        matches = service.get_matches(target_id=targetId)

        return JSONResponse(content={
            "success": True,
            "data": matches
        })

    except Exception as e:
        logger.error(f"Get matches error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/matches/{match_id}")
async def get_match_by_id(
    match_id: str,
    token: str = Depends(JWTBearer())
):
    """
    Get a specific match by ID.
    """
    service = get_facial_service()
    if service is None:
        raise HTTPException(
            status_code=503,
            detail="Facial recognition service unavailable"
        )

    try:
        matches = service.get_matches()
        match = next((m for m in matches if m.get('id') == match_id), None)

        if not match:
            raise HTTPException(status_code=404, detail="Match not found")

        return JSONResponse(content={
            "success": True,
            "data": match
        })

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get match error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.patch("/matches/{match_id}")
async def verify_match(
    match_id: str,
    request: MatchVerifyRequest,
    token: str = Depends(JWTBearer())
):
    """
    Update match verification status.

    Mark a match as verified or rejected with optional notes.
    """
    service = get_facial_service()
    if service is None:
        raise HTTPException(
            status_code=503,
            detail="Facial recognition service unavailable"
        )

    try:
        result = service.verify_match(
            match_id=match_id,
            verified=request.verified,
            notes=request.notes
        )

        if not result.get('success'):
            raise HTTPException(status_code=404, detail=result.get('message', 'Match not found'))

        return JSONResponse(content={
            "success": True,
            "message": "Match verification updated"
        })

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Verify match error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/database")
async def get_face_database(
    token: str = Depends(JWTBearer())
):
    """
    Get all enrolled faces in the database.

    Returns a list of all enrolled face records.
    """
    service = get_facial_service()
    if service is None:
        raise HTTPException(
            status_code=503,
            detail="Facial recognition service unavailable"
        )

    try:
        faces = service.get_database()

        return JSONResponse(content={
            "success": True,
            "data": faces
        })

    except Exception as e:
        logger.error(f"Get database error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/{target_id}/faces/{face_id}")
async def delete_face(
    target_id: str,
    face_id: str,
    token: str = Depends(JWTBearer())
):
    """
    Delete a face from the database.
    """
    service = get_facial_service()
    if service is None:
        raise HTTPException(
            status_code=503,
            detail="Facial recognition service unavailable"
        )

    try:
        result = service.delete_face(target_id=target_id, face_id=face_id)

        if not result.get('success'):
            raise HTTPException(status_code=404, detail=result.get('message', 'Face not found'))

        return JSONResponse(content={
            "success": True,
            "message": "Face deleted successfully"
        })

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Delete face error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/live-feed/{camera_id}/matches")
async def get_live_feed_matches(
    camera_id: str,
    token: str = Depends(JWTBearer())
):
    """
    Get recent matches from a live camera feed.

    Note: This endpoint requires the real-time video matcher to be running.
    """
    service = get_facial_service()
    if service is None:
        raise HTTPException(
            status_code=503,
            detail="Facial recognition service unavailable"
        )

    try:
        # Filter matches by camera ID
        matches = service.get_matches()
        camera_matches = [m for m in matches if m.get('camera_id') == camera_id]

        return JSONResponse(content={
            "success": True,
            "camera_id": camera_id,
            "data": camera_matches
        })

    except Exception as e:
        logger.error(f"Get live feed matches error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/detect")
async def detect_faces(
    image: UploadFile = File(..., description="Image to analyze"),
    return_landmarks: bool = Form(False, description="Include facial landmarks"),
    token: str = Depends(JWTBearer())
):
    """
    Detect faces in an image without matching.

    Returns face locations, quality scores, and optionally facial landmarks.
    """
    service = get_facial_service()
    if service is None:
        raise HTTPException(
            status_code=503,
            detail="Facial recognition service unavailable"
        )

    try:
        image_bytes = await image.read()

        detections = service.detect_faces(
            image=image_bytes,
            return_encodings=False,
            return_landmarks=return_landmarks
        )

        return JSONResponse(content={
            "success": True,
            "faces_detected": len(detections),
            "detections": [d.to_dict() for d in detections]
        })

    except Exception as e:
        logger.error(f"Face detection error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/stats")
async def get_stats(
    token: str = Depends(JWTBearer())
):
    """
    Get facial recognition service statistics.
    """
    service = get_facial_service()
    if service is None:
        raise HTTPException(
            status_code=503,
            detail="Facial recognition service unavailable"
        )

    try:
        stats = service.get_stats()

        return JSONResponse(content={
            "success": True,
            "stats": stats
        })

    except Exception as e:
        logger.error(f"Get stats error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/health")
async def health_check():
    """
    Health check for facial recognition service.
    """
    service = get_facial_service()

    if service is None:
        return JSONResponse(
            status_code=503,
            content={
                "status": "unavailable",
                "message": "Facial recognition service not initialized. Install face_recognition library."
            }
        )

    return JSONResponse(content={
        "status": "healthy",
        "service": "facial_recognition",
        "enrolled_faces": service.stats.get('total_enrollments', 0),
        "total_matches": service.stats.get('total_matches', 0)
    })
