"""
Voice Recognition System for Apollo Platform
============================================
Comprehensive voice recognition with:
- OpenAI Whisper transcription (multiple model sizes)
- Speaker diarization using pyannote-audio
- Voice print matching using resemblyzer/speechbrain
- Language detection and timestamp generation

For authorized law enforcement audio surveillance
Target: Ruja Ignatova voice sample from FBI podcast

Author: Apollo Platform - Agent 1
Version: 2.0.0
"""

import torch
import torchaudio
import numpy as np
from typing import List, Dict, Tuple, Optional, Union, Any
from dataclasses import dataclass, field
from datetime import datetime
import logging
from pathlib import Path
import json
import tempfile
import os
import io
import hashlib
from enum import Enum

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class WhisperModelSize(Enum):
    """Supported Whisper model sizes"""
    TINY = "tiny"
    BASE = "base"
    SMALL = "small"
    MEDIUM = "medium"
    LARGE = "large"
    LARGE_V2 = "large-v2"
    LARGE_V3 = "large-v3"


@dataclass
class TranscriptionSegment:
    """Represents a transcription segment with timing"""
    text: str
    start: float
    end: float
    confidence: float = 0.0
    language: Optional[str] = None
    speaker: Optional[str] = None
    words: List[Dict] = field(default_factory=list)


@dataclass
class TranscriptionResult:
    """Complete transcription result"""
    text: str
    segments: List[TranscriptionSegment]
    language: str
    language_probability: float
    duration: float
    audio_file: str
    model_used: str
    processed_at: datetime = field(default_factory=datetime.now)


@dataclass
class VoiceMatch:
    """Represents a voice recognition match"""
    confidence: float
    audio_file: str
    timestamp: datetime
    duration: float
    sample_rate: int
    transcript: Optional[str] = None
    metadata: Dict = field(default_factory=dict)


@dataclass
class VoicePrint:
    """Represents a stored voice print (speaker embedding)"""
    id: str
    name: str
    embedding: np.ndarray
    created_at: datetime
    source_files: List[str]
    metadata: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        """Convert to dictionary (without numpy array)"""
        return {
            'id': self.id,
            'name': self.name,
            'created_at': self.created_at.isoformat(),
            'source_files': self.source_files,
            'metadata': self.metadata,
            'embedding_shape': list(self.embedding.shape)
        }


@dataclass
class SpeakerSegment:
    """Represents a speaker diarization segment"""
    speaker: str
    start: float
    end: float
    confidence: float = 0.0


class VoiceRecognitionSystem:
    """
    Elite voice recognition and matching system

    Features:
    - Real Whisper transcription with multiple model sizes
    - Speaker diarization with pyannote-audio
    - Voice print extraction using resemblyzer/speechbrain
    - Real-time voice matching against known voice prints
    """

    def __init__(
        self,
        voiceprint_path: Optional[str] = None,
        voiceprint_database_dir: Optional[str] = None,
        match_threshold: float = 0.75,
        whisper_model_size: str = "base",
        use_gpu: bool = True,
        load_models: bool = True
    ):
        """
        Initialize voice recognition system

        Args:
            voiceprint_path: Path to target voiceprint (numpy array)
            voiceprint_database_dir: Directory containing voice print database
            match_threshold: Similarity threshold for matches (0-1)
            whisper_model_size: Whisper model size (tiny, base, small, medium, large)
            use_gpu: Use GPU acceleration if available
            load_models: Whether to load models immediately
        """
        self.match_threshold = match_threshold
        self.whisper_model_size = whisper_model_size
        self.device = torch.device('cuda' if use_gpu and torch.cuda.is_available() else 'cpu')

        # Voice print database
        self.voiceprint_database_dir = voiceprint_database_dir or "voice_database"
        self.voice_prints: Dict[str, VoicePrint] = {}

        logger.info(f"Voice recognition initializing on {self.device}")
        logger.info(f"Whisper model size: {whisper_model_size}")

        # Load target voiceprint if provided
        self.target_voiceprint = None
        if voiceprint_path and Path(voiceprint_path).exists():
            self.target_voiceprint = np.load(voiceprint_path)
            logger.info(f"Loaded target voiceprint from {voiceprint_path}")

        # Initialize models
        self.whisper_model = None
        self.speaker_encoder = None
        self.diarization_pipeline = None
        self._models_loaded = False

        if load_models:
            self._init_models()

        # Load existing voice prints
        self._load_voice_print_database()

    def _init_models(self):
        """Initialize pretrained models for transcription, diarization, and speaker embedding"""
        logger.info("Initializing voice recognition models...")

        # Load Whisper model
        self._load_whisper_model()

        # Load speaker encoder (resemblyzer)
        self._load_speaker_encoder()

        # Load diarization pipeline (pyannote)
        self._load_diarization_pipeline()

        self._models_loaded = True
        logger.info("All voice recognition models initialized")

    def _load_whisper_model(self):
        """Load OpenAI Whisper model for transcription"""
        try:
            import whisper
            logger.info(f"Loading Whisper model: {self.whisper_model_size}")
            self.whisper_model = whisper.load_model(
                self.whisper_model_size,
                device=self.device
            )
            logger.info(f"Whisper model loaded successfully on {self.device}")
        except ImportError:
            logger.warning("Whisper not installed. Install with: pip install openai-whisper")
            logger.info("Falling back to faster-whisper if available...")
            try:
                from faster_whisper import WhisperModel
                self.whisper_model = WhisperModel(
                    self.whisper_model_size,
                    device="cuda" if self.device.type == "cuda" else "cpu",
                    compute_type="float16" if self.device.type == "cuda" else "int8"
                )
                self._whisper_type = "faster"
                logger.info("faster-whisper model loaded successfully")
            except ImportError:
                logger.error("Neither whisper nor faster-whisper available")
                self.whisper_model = None
        except Exception as e:
            logger.error(f"Failed to load Whisper model: {e}")
            self.whisper_model = None

    def _load_speaker_encoder(self):
        """Load speaker encoder for voice embeddings"""
        try:
            from resemblyzer import VoiceEncoder
            self.speaker_encoder = VoiceEncoder(device=self.device)
            self._encoder_type = "resemblyzer"
            logger.info("Resemblyzer speaker encoder loaded")
        except ImportError:
            logger.warning("Resemblyzer not installed. Trying SpeechBrain...")
            try:
                from speechbrain.inference.speaker import EncoderClassifier
                self.speaker_encoder = EncoderClassifier.from_hparams(
                    source="speechbrain/spkrec-ecapa-voxceleb",
                    savedir="pretrained_models/spkrec-ecapa-voxceleb",
                    run_opts={"device": str(self.device)}
                )
                self._encoder_type = "speechbrain"
                logger.info("SpeechBrain ECAPA-TDNN encoder loaded")
            except ImportError:
                logger.warning("Neither resemblyzer nor speechbrain available")
                self.speaker_encoder = None
            except Exception as e:
                logger.error(f"Failed to load SpeechBrain encoder: {e}")
                self.speaker_encoder = None
        except Exception as e:
            logger.error(f"Failed to load speaker encoder: {e}")
            self.speaker_encoder = None

    def _load_diarization_pipeline(self):
        """Load pyannote speaker diarization pipeline"""
        try:
            from pyannote.audio import Pipeline

            # Check for HuggingFace token
            hf_token = os.environ.get("HUGGINGFACE_TOKEN") or os.environ.get("HF_TOKEN")

            if hf_token:
                self.diarization_pipeline = Pipeline.from_pretrained(
                    "pyannote/speaker-diarization-3.1",
                    use_auth_token=hf_token
                )
                if self.device.type == "cuda":
                    self.diarization_pipeline.to(self.device)
                logger.info("Pyannote speaker diarization pipeline loaded")
            else:
                logger.warning(
                    "HUGGINGFACE_TOKEN not set. Diarization requires authentication. "
                    "Set HUGGINGFACE_TOKEN environment variable."
                )
                self.diarization_pipeline = None
        except ImportError:
            logger.warning("pyannote-audio not installed. Install with: pip install pyannote-audio")
            self.diarization_pipeline = None
        except Exception as e:
            logger.error(f"Failed to load diarization pipeline: {e}")
            self.diarization_pipeline = None

    def _load_voice_print_database(self):
        """Load existing voice prints from database directory"""
        db_path = Path(self.voiceprint_database_dir)
        if not db_path.exists():
            db_path.mkdir(parents=True, exist_ok=True)
            return

        # Load all .npy files as voice prints
        for npy_file in db_path.glob("*.npy"):
            try:
                embedding = np.load(npy_file)
                json_file = npy_file.with_suffix('.json')

                metadata = {}
                if json_file.exists():
                    with open(json_file, 'r') as f:
                        metadata = json.load(f)

                voice_print = VoicePrint(
                    id=metadata.get('id', npy_file.stem),
                    name=metadata.get('target_name', npy_file.stem),
                    embedding=embedding,
                    created_at=datetime.fromisoformat(
                        metadata.get('created', datetime.now().isoformat())
                    ),
                    source_files=metadata.get('source_files', []),
                    metadata=metadata
                )
                self.voice_prints[voice_print.id] = voice_print
                logger.info(f"Loaded voice print: {voice_print.name} ({voice_print.id})")
            except Exception as e:
                logger.error(f"Failed to load voice print {npy_file}: {e}")

    def transcribe_audio(
        self,
        audio_path: str,
        language: Optional[str] = None,
        task: str = "transcribe",
        word_timestamps: bool = True,
        verbose: bool = False
    ) -> TranscriptionResult:
        """
        Transcribe audio to text using Whisper

        Args:
            audio_path: Path to audio file
            language: Language code (e.g., 'en', 'de', 'bg') or None for auto-detect
            task: 'transcribe' or 'translate' (translate to English)
            word_timestamps: Include word-level timestamps
            verbose: Print progress

        Returns:
            TranscriptionResult with full transcription and segments
        """
        if self.whisper_model is None:
            raise RuntimeError(
                "Whisper model not loaded. Install with: pip install openai-whisper"
            )

        logger.info(f"Transcribing audio: {audio_path}")

        # Get audio duration
        waveform, sample_rate = torchaudio.load(audio_path)
        duration = waveform.shape[1] / sample_rate

        # Check if using faster-whisper
        if hasattr(self, '_whisper_type') and self._whisper_type == "faster":
            return self._transcribe_faster_whisper(
                audio_path, language, task, word_timestamps, duration
            )

        # Standard OpenAI Whisper
        try:
            import whisper

            result = self.whisper_model.transcribe(
                audio_path,
                language=language,
                task=task,
                word_timestamps=word_timestamps,
                verbose=verbose
            )

            # Build transcription segments
            segments = []
            for seg in result.get('segments', []):
                segment = TranscriptionSegment(
                    text=seg['text'].strip(),
                    start=seg['start'],
                    end=seg['end'],
                    confidence=seg.get('avg_logprob', 0),
                    language=result.get('language'),
                    words=seg.get('words', [])
                )
                segments.append(segment)

            transcription_result = TranscriptionResult(
                text=result['text'].strip(),
                segments=segments,
                language=result.get('language', 'unknown'),
                language_probability=result.get('language_probability', 0),
                duration=duration,
                audio_file=audio_path,
                model_used=f"whisper-{self.whisper_model_size}"
            )

            logger.info(
                f"Transcription complete: {len(segments)} segments, "
                f"language: {transcription_result.language}"
            )

            return transcription_result

        except Exception as e:
            logger.error(f"Transcription failed: {e}")
            raise

    def _transcribe_faster_whisper(
        self,
        audio_path: str,
        language: Optional[str],
        task: str,
        word_timestamps: bool,
        duration: float
    ) -> TranscriptionResult:
        """Transcribe using faster-whisper library"""
        segments_result, info = self.whisper_model.transcribe(
            audio_path,
            language=language,
            task=task,
            word_timestamps=word_timestamps,
            vad_filter=True
        )

        segments = []
        full_text = []

        for seg in segments_result:
            segment = TranscriptionSegment(
                text=seg.text.strip(),
                start=seg.start,
                end=seg.end,
                confidence=seg.avg_logprob if hasattr(seg, 'avg_logprob') else 0,
                language=info.language,
                words=[
                    {'word': w.word, 'start': w.start, 'end': w.end, 'probability': w.probability}
                    for w in (seg.words or [])
                ]
            )
            segments.append(segment)
            full_text.append(seg.text)

        return TranscriptionResult(
            text=' '.join(full_text).strip(),
            segments=segments,
            language=info.language,
            language_probability=info.language_probability,
            duration=duration,
            audio_file=audio_path,
            model_used=f"faster-whisper-{self.whisper_model_size}"
        )

    def detect_language(self, audio_path: str) -> Tuple[str, float]:
        """
        Detect language of audio

        Args:
            audio_path: Path to audio file

        Returns:
            Tuple of (language_code, probability)
        """
        if self.whisper_model is None:
            raise RuntimeError("Whisper model not loaded")

        try:
            import whisper

            # Load audio and pad/trim to 30 seconds
            audio = whisper.load_audio(audio_path)
            audio = whisper.pad_or_trim(audio)

            # Make log-Mel spectrogram
            mel = whisper.log_mel_spectrogram(audio).to(self.device)

            # Detect language
            _, probs = self.whisper_model.detect_language(mel)

            # Get best language
            best_lang = max(probs, key=probs.get)

            logger.info(f"Detected language: {best_lang} (probability: {probs[best_lang]:.2%})")

            return best_lang, probs[best_lang]

        except Exception as e:
            logger.error(f"Language detection failed: {e}")
            raise

    def extract_voiceprint(
        self,
        audio_path: str,
        start_time: float = 0.0,
        end_time: Optional[float] = None
    ) -> np.ndarray:
        """
        Extract voiceprint (speaker embedding) from audio file

        Args:
            audio_path: Path to audio file
            start_time: Start time in seconds
            end_time: End time in seconds (None = full audio)

        Returns:
            Voiceprint as numpy array (d-vector, typically 192 or 256 dimensions)
        """
        logger.info(f"Extracting voiceprint from {audio_path}")

        if self.speaker_encoder is None:
            raise RuntimeError(
                "Speaker encoder not loaded. Install resemblyzer or speechbrain."
            )

        # Load audio
        waveform, sample_rate = torchaudio.load(audio_path)

        # Convert to mono if stereo
        if waveform.shape[0] > 1:
            waveform = torch.mean(waveform, dim=0, keepdim=True)

        # Trim to time range
        if end_time:
            start_sample = int(start_time * sample_rate)
            end_sample = int(end_time * sample_rate)
            waveform = waveform[:, start_sample:end_sample]
        elif start_time > 0:
            start_sample = int(start_time * sample_rate)
            waveform = waveform[:, start_sample:]

        # Resample if needed (most models expect 16kHz)
        if sample_rate != 16000:
            resampler = torchaudio.transforms.Resample(sample_rate, 16000)
            waveform = resampler(waveform)
            sample_rate = 16000

        # Extract embedding based on encoder type
        if hasattr(self, '_encoder_type') and self._encoder_type == "speechbrain":
            # SpeechBrain ECAPA-TDNN
            embedding = self.speaker_encoder.encode_batch(waveform)
            embedding = embedding.squeeze().cpu().numpy()
        else:
            # Resemblyzer
            from resemblyzer import preprocess_wav

            # Convert to numpy and preprocess
            wav_np = waveform.squeeze().numpy()
            wav_preprocessed = preprocess_wav(wav_np, source_sr=sample_rate)

            # Get embedding
            embedding = self.speaker_encoder.embed_utterance(wav_preprocessed)

        # Normalize embedding
        embedding = embedding / np.linalg.norm(embedding)

        logger.info(f"Extracted voiceprint: shape {embedding.shape}")

        return embedding

    def compare_voiceprints(
        self,
        voiceprint1: np.ndarray,
        voiceprint2: np.ndarray
    ) -> float:
        """
        Compare two voiceprints using cosine similarity

        Args:
            voiceprint1: First voiceprint
            voiceprint2: Second voiceprint

        Returns:
            Similarity score 0.0-1.0 (1.0 = identical)
        """
        # Cosine similarity
        similarity = np.dot(voiceprint1, voiceprint2) / (
            np.linalg.norm(voiceprint1) * np.linalg.norm(voiceprint2)
        )

        # Convert to 0-1 range (cosine similarity is -1 to 1)
        similarity = (similarity + 1.0) / 2.0

        return float(similarity)

    def identify_speaker(
        self,
        audio_path: str,
        start_time: float = 0.0,
        end_time: Optional[float] = None
    ) -> List[Dict[str, Any]]:
        """
        Identify speaker from audio against enrolled voice prints

        Args:
            audio_path: Path to audio file
            start_time: Start time in seconds
            end_time: End time in seconds

        Returns:
            List of matches sorted by confidence
        """
        if not self.voice_prints:
            logger.warning("No voice prints enrolled in database")
            return []

        # Extract voiceprint from test audio
        test_voiceprint = self.extract_voiceprint(audio_path, start_time, end_time)

        matches = []
        for vp_id, voice_print in self.voice_prints.items():
            similarity = self.compare_voiceprints(test_voiceprint, voice_print.embedding)

            matches.append({
                'id': vp_id,
                'name': voice_print.name,
                'confidence': similarity,
                'is_match': similarity >= self.match_threshold,
                'threshold': self.match_threshold
            })

        # Sort by confidence
        matches.sort(key=lambda x: x['confidence'], reverse=True)

        # Log matches
        for match in matches[:3]:
            if match['is_match']:
                logger.warning(
                    f"VOICE MATCH: {match['name']} "
                    f"(confidence: {match['confidence']:.2%})"
                )

        return matches

    def enroll_voice_print(
        self,
        audio_path: str,
        speaker_id: str,
        speaker_name: str,
        metadata: Optional[Dict] = None
    ) -> VoicePrint:
        """
        Enroll a new voice print in the database

        Args:
            audio_path: Path to audio file
            speaker_id: Unique speaker ID
            speaker_name: Display name for speaker
            metadata: Additional metadata

        Returns:
            Created VoicePrint object
        """
        logger.info(f"Enrolling voice print for {speaker_name} ({speaker_id})")

        # Extract voiceprint
        embedding = self.extract_voiceprint(audio_path)

        # Create voice print object
        voice_print = VoicePrint(
            id=speaker_id,
            name=speaker_name,
            embedding=embedding,
            created_at=datetime.now(),
            source_files=[audio_path],
            metadata=metadata or {}
        )

        # Add to in-memory database
        self.voice_prints[speaker_id] = voice_print

        # Save to disk
        self._save_voice_print(voice_print)

        logger.info(f"Voice print enrolled: {speaker_name}")

        return voice_print

    def _save_voice_print(self, voice_print: VoicePrint):
        """Save voice print to disk"""
        db_path = Path(self.voiceprint_database_dir)
        db_path.mkdir(parents=True, exist_ok=True)

        # Save embedding
        npy_path = db_path / f"{voice_print.id}.npy"
        np.save(npy_path, voice_print.embedding)

        # Save metadata
        json_path = db_path / f"{voice_print.id}.json"
        metadata = voice_print.to_dict()
        metadata['target_name'] = voice_print.name
        with open(json_path, 'w') as f:
            json.dump(metadata, f, indent=2)

        logger.info(f"Saved voice print to {npy_path}")

    def get_voice_prints(self) -> List[Dict]:
        """Get all enrolled voice prints"""
        return [vp.to_dict() for vp in self.voice_prints.values()]

    def delete_voice_print(self, speaker_id: str) -> bool:
        """Delete a voice print from the database"""
        if speaker_id not in self.voice_prints:
            return False

        # Remove from memory
        del self.voice_prints[speaker_id]

        # Remove from disk
        db_path = Path(self.voiceprint_database_dir)
        npy_path = db_path / f"{speaker_id}.npy"
        json_path = db_path / f"{speaker_id}.json"

        if npy_path.exists():
            npy_path.unlink()
        if json_path.exists():
            json_path.unlink()

        logger.info(f"Deleted voice print: {speaker_id}")
        return True

    def match_audio(
        self,
        audio_path: str,
        transcribe: bool = True
    ) -> VoiceMatch:
        """
        Match audio file against target voiceprint

        Args:
            audio_path: Path to audio file to analyze
            transcribe: Whether to transcribe speech to text

        Returns:
            VoiceMatch object with results
        """
        if self.target_voiceprint is None:
            raise ValueError("No target voiceprint loaded")

        logger.info(f"Matching audio: {audio_path}")

        # Extract voiceprint from test audio
        test_voiceprint = self.extract_voiceprint(audio_path)

        # Compare with target
        confidence = self.compare_voiceprints(
            self.target_voiceprint,
            test_voiceprint
        )

        # Get audio metadata
        waveform, sample_rate = torchaudio.load(audio_path)
        duration = waveform.shape[1] / sample_rate

        # Transcribe if requested
        transcript = None
        if transcribe:
            try:
                result = self.transcribe_audio(audio_path)
                transcript = result.text
            except Exception as e:
                logger.warning(f"Transcription failed: {e}")

        match = VoiceMatch(
            confidence=confidence,
            audio_file=audio_path,
            timestamp=datetime.now(),
            duration=duration,
            sample_rate=sample_rate,
            transcript=transcript,
            metadata={
                'is_match': confidence >= self.match_threshold,
                'threshold': self.match_threshold
            }
        )

        if match.metadata['is_match']:
            logger.warning(
                f"VOICE MATCH DETECTED! "
                f"Confidence: {confidence:.2%} "
                f"File: {audio_path}"
            )

        return match

    def speaker_diarization(
        self,
        audio_path: str,
        num_speakers: Optional[int] = None,
        min_speakers: int = 1,
        max_speakers: int = 10
    ) -> List[SpeakerSegment]:
        """
        Identify who spoke when in audio using pyannote

        Args:
            audio_path: Path to audio file
            num_speakers: Exact number of speakers (if known)
            min_speakers: Minimum expected speakers
            max_speakers: Maximum expected speakers

        Returns:
            List of SpeakerSegment objects
        """
        if self.diarization_pipeline is None:
            logger.warning(
                "Diarization pipeline not available. "
                "Install pyannote-audio and set HUGGINGFACE_TOKEN."
            )
            # Return placeholder
            return [
                SpeakerSegment(
                    speaker='SPEAKER_00',
                    start=0.0,
                    end=10.0,
                    confidence=0.0
                )
            ]

        logger.info(f"Performing speaker diarization: {audio_path}")

        try:
            # Run diarization
            diarization_params = {}
            if num_speakers is not None:
                diarization_params['num_speakers'] = num_speakers
            else:
                diarization_params['min_speakers'] = min_speakers
                diarization_params['max_speakers'] = max_speakers

            diarization = self.diarization_pipeline(
                audio_path,
                **diarization_params
            )

            # Convert to segments
            segments = []
            for turn, _, speaker in diarization.itertracks(yield_label=True):
                segment = SpeakerSegment(
                    speaker=speaker,
                    start=turn.start,
                    end=turn.end,
                    confidence=1.0  # pyannote doesn't provide segment-level confidence
                )
                segments.append(segment)

            logger.info(f"Diarization complete: {len(segments)} segments, "
                       f"{len(set(s.speaker for s in segments))} speakers")

            return segments

        except Exception as e:
            logger.error(f"Diarization failed: {e}")
            raise

    def transcribe_with_diarization(
        self,
        audio_path: str,
        language: Optional[str] = None,
        num_speakers: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Transcribe audio with speaker labels

        Args:
            audio_path: Path to audio file
            language: Language code
            num_speakers: Expected number of speakers

        Returns:
            Dictionary with transcription and speaker-labeled segments
        """
        logger.info(f"Transcribing with diarization: {audio_path}")

        # Get transcription
        transcription = self.transcribe_audio(audio_path, language=language)

        # Get diarization
        diarization_segments = self.speaker_diarization(
            audio_path, num_speakers=num_speakers
        )

        # Merge transcription segments with speaker labels
        labeled_segments = []
        for trans_seg in transcription.segments:
            # Find overlapping speaker segment
            best_speaker = None
            best_overlap = 0

            for diar_seg in diarization_segments:
                # Calculate overlap
                overlap_start = max(trans_seg.start, diar_seg.start)
                overlap_end = min(trans_seg.end, diar_seg.end)
                overlap = max(0, overlap_end - overlap_start)

                if overlap > best_overlap:
                    best_overlap = overlap
                    best_speaker = diar_seg.speaker

            labeled_segments.append({
                'text': trans_seg.text,
                'start': trans_seg.start,
                'end': trans_seg.end,
                'speaker': best_speaker or 'UNKNOWN',
                'confidence': trans_seg.confidence
            })

        return {
            'full_text': transcription.text,
            'language': transcription.language,
            'language_probability': transcription.language_probability,
            'duration': transcription.duration,
            'segments': labeled_segments,
            'speakers': list(set(s['speaker'] for s in labeled_segments))
        }

    def process_long_audio(
        self,
        audio_path: str,
        segment_duration: float = 10.0
    ) -> List[VoiceMatch]:
        """
        Process long audio file in segments
        Useful for phone calls, podcasts, etc.

        Args:
            audio_path: Path to audio file
            segment_duration: Duration of each segment in seconds

        Returns:
            List of VoiceMatch objects for each segment with matches
        """
        if self.target_voiceprint is None:
            raise ValueError("No target voiceprint loaded")

        logger.info(f"Processing long audio: {audio_path}")

        # Get audio duration
        waveform, sample_rate = torchaudio.load(audio_path)
        total_duration = waveform.shape[1] / sample_rate

        matches = []
        current_time = 0.0

        while current_time < total_duration:
            end_time = min(current_time + segment_duration, total_duration)

            try:
                # Extract voiceprint for segment
                segment_voiceprint = self.extract_voiceprint(
                    audio_path,
                    start_time=current_time,
                    end_time=end_time
                )

                # Compare with target
                confidence = self.compare_voiceprints(
                    self.target_voiceprint,
                    segment_voiceprint
                )

                if confidence >= self.match_threshold:
                    match = VoiceMatch(
                        confidence=confidence,
                        audio_file=audio_path,
                        timestamp=datetime.now(),
                        duration=end_time - current_time,
                        sample_rate=sample_rate,
                        metadata={
                            'segment_start': current_time,
                            'segment_end': end_time,
                            'is_match': True
                        }
                    )
                    matches.append(match)

                    logger.warning(
                        f"Voice match in segment {current_time:.1f}s-{end_time:.1f}s "
                        f"(confidence: {confidence:.2%})"
                    )

            except Exception as e:
                logger.error(f"Error processing segment {current_time:.1f}s: {e}")

            current_time += segment_duration

        logger.info(f"Found {len(matches)} matching segments")
        return matches

    def save_voiceprint(
        self,
        voiceprint: np.ndarray,
        output_path: str,
        metadata: Optional[Dict] = None
    ):
        """Save voiceprint to disk"""
        # Save numpy array
        np.save(output_path, voiceprint)

        # Save metadata
        if metadata:
            metadata_path = Path(output_path).with_suffix('.json')
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)

        logger.info(f"Saved voiceprint to {output_path}")

    def create_ignatova_voiceprint(
        self,
        audio_path: str = "intelligence/geoint-engine/surveillance-networks/ignatova-voice-sample.mp3",
        output_path: str = "voice_database/ignatova_voiceprint.npy"
    ):
        """
        Create voiceprint from Ignatova audio sample
        Source: FBI podcast or other authenticated audio
        """
        logger.info("Creating Ignatova voiceprint from FBI audio sample...")

        if not Path(audio_path).exists():
            logger.error(f"Audio sample not found: {audio_path}")
            logger.info("Please place Ignatova audio sample at the specified path")
            return None

        # Extract voiceprint
        voiceprint = self.extract_voiceprint(audio_path)

        # Save voiceprint
        output_dir = Path(output_path).parent
        output_dir.mkdir(parents=True, exist_ok=True)

        metadata = {
            'target_name': 'Ruja Plamenova Ignatova',
            'source_audio': audio_path,
            'created': datetime.now().isoformat(),
            'dimensions': int(voiceprint.shape[0]),
            'notes': 'Extracted from FBI podcast audio sample',
            'id': 'ignatova_001'
        }

        self.save_voiceprint(voiceprint, output_path, metadata)

        # Also enroll in database
        self.voice_prints['ignatova_001'] = VoicePrint(
            id='ignatova_001',
            name='Ruja Plamenova Ignatova',
            embedding=voiceprint,
            created_at=datetime.now(),
            source_files=[audio_path],
            metadata=metadata
        )

        logger.info(f"Ignatova voiceprint created: {output_path}")
        logger.info("This voiceprint can now be used for real-time audio monitoring")

        return voiceprint


# Global service instance
_voice_service = None


def get_voice_recognition_service(
    voiceprint_database_dir: Optional[str] = None,
    match_threshold: float = 0.75,
    whisper_model_size: str = "base",
    use_gpu: bool = True,
    load_models: bool = True
) -> VoiceRecognitionSystem:
    """
    Get or create voice recognition service singleton

    Args:
        voiceprint_database_dir: Directory for voice print database
        match_threshold: Similarity threshold for matches
        whisper_model_size: Whisper model size
        use_gpu: Use GPU if available
        load_models: Load models immediately

    Returns:
        VoiceRecognitionSystem instance
    """
    global _voice_service

    if _voice_service is None:
        _voice_service = VoiceRecognitionSystem(
            voiceprint_database_dir=voiceprint_database_dir,
            match_threshold=match_threshold,
            whisper_model_size=whisper_model_size,
            use_gpu=use_gpu,
            load_models=load_models
        )

    return _voice_service


def main():
    """Create Ignatova voiceprint and test system"""
    print("=" * 60)
    print("APOLLO VOICE RECOGNITION SYSTEM")
    print("Target: Ruja Plamenova Ignatova (CryptoQueen)")
    print("=" * 60)

    # Initialize system
    voice_system = VoiceRecognitionSystem(
        use_gpu=torch.cuda.is_available(),
        whisper_model_size="base"
    )

    # Print system status
    print(f"\nDevice: {voice_system.device}")
    print(f"Whisper model: {voice_system.whisper_model_size}")
    print(f"Whisper loaded: {voice_system.whisper_model is not None}")
    print(f"Speaker encoder loaded: {voice_system.speaker_encoder is not None}")
    print(f"Diarization loaded: {voice_system.diarization_pipeline is not None}")

    # Create voiceprint from FBI audio if available
    voice_system.create_ignatova_voiceprint()

    print("\n" + "=" * 60)
    print("Voice recognition system initialized")
    print("=" * 60)
    print("\nSystem capabilities:")
    print("  - Real Whisper transcription (multiple model sizes)")
    print("  - Language detection (auto-detect)")
    print("  - Word-level timestamps")
    print("  - Speaker voiceprint extraction")
    print("  - Real-time voice matching")
    print("  - Speaker diarization (who spoke when)")
    print("  - Multi-segment audio analysis")
    print("\nIntegration ready for:")
    print("  - Phone call monitoring")
    print("  - Audio surveillance feeds")
    print("  - Podcast/video analysis")
    print("  - Real-time alert system")


if __name__ == "__main__":
    main()
