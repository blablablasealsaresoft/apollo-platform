"""
Voice Recognition Routes - API Endpoints for Audio Transcription and Speaker Identification
Apollo Platform - SIGINT Voice Recognition System

Provides endpoints for:
- Audio transcription using OpenAI Whisper
- Speaker identification and voice matching
- Voice print enrollment and management
- Speaker diarization (who spoke when)
- Language detection

Author: Apollo Platform - Agent 1
Version: 2.0.0
"""

import os
import io
import logging
import tempfile
import uuid
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
rate_limiter = RateLimiter(requests_per_minute=20)

# Lazy load voice recognition service
_voice_service = None


def get_voice_service():
    """Lazy load the voice recognition service"""
    global _voice_service

    if _voice_service is None:
        # Try multiple import paths
        import_paths = [
            str(Path(__file__).parent.parent / "geoint-engine" / "surveillance-networks"),
            str(Path(__file__).parent.parent),
        ]

        for import_path in import_paths:
            if import_path not in sys.path:
                sys.path.insert(0, import_path)

        try:
            from voice_recognition import get_voice_recognition_service
            _voice_service = get_voice_recognition_service(
                voiceprint_database_dir=str(Path(__file__).parent.parent / "voice_database"),
                match_threshold=0.75,
                whisper_model_size=os.environ.get("WHISPER_MODEL_SIZE", "base"),
                use_gpu=os.environ.get("USE_GPU", "true").lower() == "true",
                load_models=True
            )
            logger.info("Voice recognition service initialized successfully")
        except ImportError as e:
            logger.warning(f"Voice recognition dependencies not available: {e}")
            logger.info("Install with: pip install openai-whisper resemblyzer pyannote-audio")
            return None
        except Exception as e:
            logger.error(f"Failed to initialize voice recognition service: {e}")
            return None

    return _voice_service


# Request/Response Models
class TranscriptionRequest(BaseModel):
    """Request model for transcription by URL"""
    audioUrl: str = Field(..., description="URL of the audio file to transcribe")
    language: Optional[str] = Field(None, description="Language code (e.g., 'en', 'de', 'bg') or None for auto-detect")
    task: str = Field("transcribe", description="Task: 'transcribe' or 'translate' (to English)")
    wordTimestamps: bool = Field(True, description="Include word-level timestamps")
    withDiarization: bool = Field(False, description="Include speaker diarization")
    numSpeakers: Optional[int] = Field(None, description="Expected number of speakers for diarization")


class VoiceEnrollRequest(BaseModel):
    """Request model for voice print enrollment"""
    speakerId: str = Field(..., description="Unique speaker ID")
    speakerName: str = Field(..., description="Display name for the speaker")
    metadata: Optional[dict] = Field(None, description="Additional metadata")


class VoiceIdentifyRequest(BaseModel):
    """Request model for speaker identification by URL"""
    audioUrl: str = Field(..., description="URL of the audio file")
    threshold: Optional[float] = Field(0.75, ge=0.1, le=1.0, description="Match threshold (0.1-1.0)")


class TranscriptionSegment(BaseModel):
    """Response model for a transcription segment"""
    text: str
    start: float
    end: float
    confidence: float
    speaker: Optional[str] = None
    words: Optional[List[dict]] = None


class TranscriptionResponse(BaseModel):
    """Response model for transcription"""
    text: str
    language: str
    languageProbability: float
    duration: float
    segments: List[TranscriptionSegment]
    modelUsed: str


class VoicePrintResponse(BaseModel):
    """Response model for voice print"""
    id: str
    name: str
    createdAt: str
    sourceFiles: List[str]
    embeddingShape: List[int]
    metadata: Optional[dict] = None


class SpeakerMatch(BaseModel):
    """Response model for speaker match"""
    id: str
    name: str
    confidence: float
    isMatch: bool
    threshold: float


# Helper function to save uploaded file temporarily
async def save_temp_audio(audio: UploadFile) -> str:
    """Save uploaded audio to a temporary file"""
    suffix = Path(audio.filename).suffix if audio.filename else '.wav'
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        content = await audio.read()
        tmp.write(content)
        return tmp.name


# API Endpoints

@router.post("/transcribe")
async def transcribe_audio(
    audio: UploadFile = File(..., description="Audio file to transcribe"),
    language: Optional[str] = Form(None, description="Language code or None for auto-detect"),
    task: str = Form("transcribe", description="'transcribe' or 'translate'"),
    wordTimestamps: bool = Form(True, description="Include word-level timestamps"),
    withDiarization: bool = Form(False, description="Include speaker diarization"),
    numSpeakers: Optional[int] = Form(None, description="Expected number of speakers"),
    token: str = Depends(JWTBearer())
):
    """
    Transcribe audio file to text using OpenAI Whisper.

    Upload an audio file and get back the transcription with timestamps.
    Supports multiple languages with auto-detection.

    Optionally includes speaker diarization to identify who spoke when.
    """
    service = get_voice_service()
    if service is None:
        raise HTTPException(
            status_code=503,
            detail="Voice recognition service unavailable. Ensure whisper and dependencies are installed."
        )

    try:
        # Save uploaded file temporarily
        temp_path = await save_temp_audio(audio)

        try:
            if withDiarization:
                # Transcribe with speaker labels
                result = service.transcribe_with_diarization(
                    temp_path,
                    language=language,
                    num_speakers=numSpeakers
                )

                return JSONResponse(content={
                    "success": True,
                    "data": {
                        "text": result['full_text'],
                        "language": result['language'],
                        "languageProbability": result['language_probability'],
                        "duration": result['duration'],
                        "speakers": result['speakers'],
                        "segments": result['segments'],
                        "modelUsed": f"whisper-{service.whisper_model_size}"
                    }
                })
            else:
                # Standard transcription
                result = service.transcribe_audio(
                    temp_path,
                    language=language,
                    task=task,
                    word_timestamps=wordTimestamps
                )

                segments = []
                for seg in result.segments:
                    segments.append({
                        "text": seg.text,
                        "start": seg.start,
                        "end": seg.end,
                        "confidence": seg.confidence,
                        "language": seg.language,
                        "words": seg.words
                    })

                return JSONResponse(content={
                    "success": True,
                    "data": {
                        "text": result.text,
                        "language": result.language,
                        "languageProbability": result.language_probability,
                        "duration": result.duration,
                        "segments": segments,
                        "modelUsed": result.model_used
                    }
                })
        finally:
            # Clean up temp file
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    except Exception as e:
        logger.error(f"Transcription error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/transcribe/url")
async def transcribe_audio_url(
    request: TranscriptionRequest,
    token: str = Depends(JWTBearer())
):
    """
    Transcribe audio from URL using OpenAI Whisper.

    Provide a URL to an audio file and get back the transcription.
    """
    service = get_voice_service()
    if service is None:
        raise HTTPException(
            status_code=503,
            detail="Voice recognition service unavailable"
        )

    try:
        import requests as req_lib

        # Download audio from URL
        response = req_lib.get(request.audioUrl, timeout=60)
        if response.status_code != 200:
            raise HTTPException(status_code=400, detail="Failed to download audio from URL")

        # Save to temp file
        suffix = Path(request.audioUrl).suffix or '.wav'
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
            tmp.write(response.content)
            temp_path = tmp.name

        try:
            if request.withDiarization:
                result = service.transcribe_with_diarization(
                    temp_path,
                    language=request.language,
                    num_speakers=request.numSpeakers
                )

                return JSONResponse(content={
                    "success": True,
                    "data": {
                        "text": result['full_text'],
                        "language": result['language'],
                        "languageProbability": result['language_probability'],
                        "duration": result['duration'],
                        "speakers": result['speakers'],
                        "segments": result['segments'],
                        "modelUsed": f"whisper-{service.whisper_model_size}"
                    }
                })
            else:
                result = service.transcribe_audio(
                    temp_path,
                    language=request.language,
                    task=request.task,
                    word_timestamps=request.wordTimestamps
                )

                segments = [{
                    "text": seg.text,
                    "start": seg.start,
                    "end": seg.end,
                    "confidence": seg.confidence,
                    "language": seg.language,
                    "words": seg.words
                } for seg in result.segments]

                return JSONResponse(content={
                    "success": True,
                    "data": {
                        "text": result.text,
                        "language": result.language,
                        "languageProbability": result.language_probability,
                        "duration": result.duration,
                        "segments": segments,
                        "modelUsed": result.model_used
                    }
                })
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Transcription from URL error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/identify")
async def identify_speaker(
    audio: UploadFile = File(..., description="Audio file to identify speaker from"),
    threshold: float = Form(0.75, description="Match threshold (0.1-1.0)"),
    token: str = Depends(JWTBearer())
):
    """
    Identify speaker from audio against enrolled voice prints.

    Upload an audio file and compare against all enrolled voice prints
    to identify the speaker.
    """
    service = get_voice_service()
    if service is None:
        raise HTTPException(
            status_code=503,
            detail="Voice recognition service unavailable"
        )

    try:
        # Save uploaded file temporarily
        temp_path = await save_temp_audio(audio)

        try:
            # Update threshold temporarily
            original_threshold = service.match_threshold
            service.match_threshold = threshold

            # Identify speaker
            matches = service.identify_speaker(temp_path)

            # Restore threshold
            service.match_threshold = original_threshold

            return JSONResponse(content={
                "success": True,
                "data": {
                    "matches": matches,
                    "enrolledPrints": len(service.voice_prints),
                    "threshold": threshold
                }
            })
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    except Exception as e:
        logger.error(f"Speaker identification error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/identify/url")
async def identify_speaker_url(
    request: VoiceIdentifyRequest,
    token: str = Depends(JWTBearer())
):
    """
    Identify speaker from audio URL against enrolled voice prints.
    """
    service = get_voice_service()
    if service is None:
        raise HTTPException(
            status_code=503,
            detail="Voice recognition service unavailable"
        )

    try:
        import requests as req_lib

        # Download audio
        response = req_lib.get(request.audioUrl, timeout=60)
        if response.status_code != 200:
            raise HTTPException(status_code=400, detail="Failed to download audio from URL")

        suffix = Path(request.audioUrl).suffix or '.wav'
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
            tmp.write(response.content)
            temp_path = tmp.name

        try:
            original_threshold = service.match_threshold
            service.match_threshold = request.threshold

            matches = service.identify_speaker(temp_path)

            service.match_threshold = original_threshold

            return JSONResponse(content={
                "success": True,
                "data": {
                    "matches": matches,
                    "enrolledPrints": len(service.voice_prints),
                    "threshold": request.threshold
                }
            })
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Speaker identification from URL error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/enroll")
async def enroll_voice_print(
    audio: UploadFile = File(..., description="Audio file for voice print enrollment"),
    speakerId: str = Form(..., description="Unique speaker ID"),
    speakerName: str = Form(..., description="Speaker display name"),
    metadata: Optional[str] = Form(None, description="JSON metadata string"),
    token: str = Depends(JWTBearer())
):
    """
    Enroll a new voice print in the database.

    Upload an audio sample of a speaker to create their voice print
    for future identification.
    """
    service = get_voice_service()
    if service is None:
        raise HTTPException(
            status_code=503,
            detail="Voice recognition service unavailable"
        )

    try:
        # Check if speaker ID already exists
        if speakerId in service.voice_prints:
            raise HTTPException(
                status_code=400,
                detail=f"Speaker ID '{speakerId}' already enrolled. Use different ID or delete existing."
            )

        # Parse metadata if provided
        meta_dict = None
        if metadata:
            import json
            try:
                meta_dict = json.loads(metadata)
            except json.JSONDecodeError:
                raise HTTPException(status_code=400, detail="Invalid metadata JSON")

        # Save uploaded file temporarily
        temp_path = await save_temp_audio(audio)

        try:
            # Enroll voice print
            voice_print = service.enroll_voice_print(
                audio_path=temp_path,
                speaker_id=speakerId,
                speaker_name=speakerName,
                metadata=meta_dict
            )

            return JSONResponse(content={
                "success": True,
                "data": {
                    "id": voice_print.id,
                    "name": voice_print.name,
                    "createdAt": voice_print.created_at.isoformat(),
                    "embeddingShape": list(voice_print.embedding.shape),
                    "message": "Voice print enrolled successfully"
                }
            })
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Voice print enrollment error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/prints")
async def list_voice_prints(
    token: str = Depends(JWTBearer())
):
    """
    List all enrolled voice prints.

    Returns information about all voice prints in the database.
    """
    service = get_voice_service()
    if service is None:
        raise HTTPException(
            status_code=503,
            detail="Voice recognition service unavailable"
        )

    try:
        voice_prints = service.get_voice_prints()

        return JSONResponse(content={
            "success": True,
            "data": {
                "prints": voice_prints,
                "total": len(voice_prints)
            }
        })

    except Exception as e:
        logger.error(f"List voice prints error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/prints/{speaker_id}")
async def get_voice_print(
    speaker_id: str,
    token: str = Depends(JWTBearer())
):
    """
    Get a specific voice print by speaker ID.
    """
    service = get_voice_service()
    if service is None:
        raise HTTPException(
            status_code=503,
            detail="Voice recognition service unavailable"
        )

    try:
        if speaker_id not in service.voice_prints:
            raise HTTPException(status_code=404, detail="Voice print not found")

        voice_print = service.voice_prints[speaker_id]

        return JSONResponse(content={
            "success": True,
            "data": voice_print.to_dict()
        })

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get voice print error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/prints/{speaker_id}")
async def delete_voice_print(
    speaker_id: str,
    token: str = Depends(JWTBearer())
):
    """
    Delete a voice print from the database.
    """
    service = get_voice_service()
    if service is None:
        raise HTTPException(
            status_code=503,
            detail="Voice recognition service unavailable"
        )

    try:
        deleted = service.delete_voice_print(speaker_id)

        if not deleted:
            raise HTTPException(status_code=404, detail="Voice print not found")

        return JSONResponse(content={
            "success": True,
            "message": f"Voice print '{speaker_id}' deleted successfully"
        })

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Delete voice print error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/detect-language")
async def detect_language(
    audio: UploadFile = File(..., description="Audio file for language detection"),
    token: str = Depends(JWTBearer())
):
    """
    Detect the language spoken in an audio file.

    Uses Whisper's language detection to identify the language.
    """
    service = get_voice_service()
    if service is None:
        raise HTTPException(
            status_code=503,
            detail="Voice recognition service unavailable"
        )

    try:
        temp_path = await save_temp_audio(audio)

        try:
            language, probability = service.detect_language(temp_path)

            return JSONResponse(content={
                "success": True,
                "data": {
                    "language": language,
                    "probability": probability,
                    "languageName": get_language_name(language)
                }
            })
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    except Exception as e:
        logger.error(f"Language detection error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/diarize")
async def speaker_diarization(
    audio: UploadFile = File(..., description="Audio file for speaker diarization"),
    numSpeakers: Optional[int] = Form(None, description="Expected number of speakers"),
    minSpeakers: int = Form(1, description="Minimum number of speakers"),
    maxSpeakers: int = Form(10, description="Maximum number of speakers"),
    token: str = Depends(JWTBearer())
):
    """
    Perform speaker diarization on audio file.

    Identifies who spoke when in a multi-speaker audio file.
    Returns segments with speaker labels.
    """
    service = get_voice_service()
    if service is None:
        raise HTTPException(
            status_code=503,
            detail="Voice recognition service unavailable"
        )

    try:
        temp_path = await save_temp_audio(audio)

        try:
            segments = service.speaker_diarization(
                temp_path,
                num_speakers=numSpeakers,
                min_speakers=minSpeakers,
                max_speakers=maxSpeakers
            )

            # Convert segments to dict
            result_segments = []
            speakers = set()
            for seg in segments:
                result_segments.append({
                    "speaker": seg.speaker,
                    "start": seg.start,
                    "end": seg.end,
                    "confidence": seg.confidence
                })
                speakers.add(seg.speaker)

            return JSONResponse(content={
                "success": True,
                "data": {
                    "segments": result_segments,
                    "speakers": list(speakers),
                    "numSpeakers": len(speakers),
                    "numSegments": len(result_segments)
                }
            })
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    except Exception as e:
        logger.error(f"Speaker diarization error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/compare")
async def compare_voices(
    audio1: UploadFile = File(..., description="First audio file"),
    audio2: UploadFile = File(..., description="Second audio file"),
    token: str = Depends(JWTBearer())
):
    """
    Compare two audio files to determine if they are the same speaker.

    Extracts voice prints from both files and calculates similarity.
    """
    service = get_voice_service()
    if service is None:
        raise HTTPException(
            status_code=503,
            detail="Voice recognition service unavailable"
        )

    try:
        temp_path1 = await save_temp_audio(audio1)
        temp_path2 = await save_temp_audio(audio2)

        try:
            # Extract voice prints
            vp1 = service.extract_voiceprint(temp_path1)
            vp2 = service.extract_voiceprint(temp_path2)

            # Compare
            similarity = service.compare_voiceprints(vp1, vp2)

            return JSONResponse(content={
                "success": True,
                "data": {
                    "similarity": similarity,
                    "isSameSpeaker": similarity >= service.match_threshold,
                    "threshold": service.match_threshold,
                    "confidence": f"{similarity:.2%}"
                }
            })
        finally:
            if os.path.exists(temp_path1):
                os.unlink(temp_path1)
            if os.path.exists(temp_path2):
                os.unlink(temp_path2)

    except Exception as e:
        logger.error(f"Voice comparison error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/stats")
async def get_voice_stats(
    token: str = Depends(JWTBearer())
):
    """
    Get voice recognition service statistics.
    """
    service = get_voice_service()
    if service is None:
        raise HTTPException(
            status_code=503,
            detail="Voice recognition service unavailable"
        )

    try:
        return JSONResponse(content={
            "success": True,
            "data": {
                "enrolledPrints": len(service.voice_prints),
                "whisperModel": service.whisper_model_size,
                "whisperLoaded": service.whisper_model is not None,
                "speakerEncoderLoaded": service.speaker_encoder is not None,
                "diarizationLoaded": service.diarization_pipeline is not None,
                "device": str(service.device),
                "matchThreshold": service.match_threshold
            }
        })

    except Exception as e:
        logger.error(f"Get voice stats error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/health")
async def voice_health_check():
    """
    Health check for voice recognition service.
    """
    service = get_voice_service()

    if service is None:
        return JSONResponse(
            status_code=503,
            content={
                "status": "unavailable",
                "message": "Voice recognition service not initialized. Install openai-whisper, resemblyzer."
            }
        )

    return JSONResponse(content={
        "status": "healthy",
        "service": "voice_recognition",
        "enrolledPrints": len(service.voice_prints),
        "whisperModel": service.whisper_model_size,
        "componentsLoaded": {
            "whisper": service.whisper_model is not None,
            "speakerEncoder": service.speaker_encoder is not None,
            "diarization": service.diarization_pipeline is not None
        }
    })


def get_language_name(code: str) -> str:
    """Get language name from code"""
    language_names = {
        "en": "English",
        "de": "German",
        "bg": "Bulgarian",
        "ru": "Russian",
        "es": "Spanish",
        "fr": "French",
        "it": "Italian",
        "pt": "Portuguese",
        "zh": "Chinese",
        "ja": "Japanese",
        "ko": "Korean",
        "ar": "Arabic",
        "hi": "Hindi",
        "tr": "Turkish",
        "pl": "Polish",
        "nl": "Dutch",
        "sv": "Swedish",
        "da": "Danish",
        "no": "Norwegian",
        "fi": "Finnish",
        "cs": "Czech",
        "ro": "Romanian",
        "hu": "Hungarian",
        "el": "Greek",
        "he": "Hebrew",
        "th": "Thai",
        "vi": "Vietnamese",
        "id": "Indonesian",
        "ms": "Malay",
        "uk": "Ukrainian"
    }
    return language_names.get(code, code)
