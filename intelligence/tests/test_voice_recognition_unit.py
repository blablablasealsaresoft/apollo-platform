"""
Unit Tests for Voice Recognition Module
Apollo Platform - Voice Recognition System

Comprehensive unit tests for:
- Data models (TranscriptionSegment, VoiceMatch, VoicePrint, SpeakerSegment)
- Voice comparison algorithms
- Audio processing utilities
- Database operations
- Configuration management

Author: Apollo Platform - Agent 9
"""

import pytest
import numpy as np
import json
import tempfile
from pathlib import Path
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock
from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Optional, Any
from enum import Enum


# ============================================================
# Enum Definitions
# ============================================================

class WhisperModelSize(Enum):
    """Supported Whisper model sizes"""
    TINY = "tiny"
    BASE = "base"
    SMALL = "small"
    MEDIUM = "medium"
    LARGE = "large"
    LARGE_V2 = "large-v2"
    LARGE_V3 = "large-v3"


# ============================================================
# Data Model Definitions
# ============================================================

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

    @property
    def duration(self) -> float:
        """Get segment duration"""
        return self.end - self.start


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

    @property
    def duration(self) -> float:
        """Get segment duration"""
        return self.end - self.start


# ============================================================
# TranscriptionSegment Unit Tests
# ============================================================

class TestTranscriptionSegment:
    """Unit tests for TranscriptionSegment data model"""

    def test_creation_minimal(self):
        """Test minimal creation"""
        segment = TranscriptionSegment(
            text="Hello world",
            start=0.0,
            end=2.5
        )

        assert segment.text == "Hello world"
        assert segment.start == 0.0
        assert segment.end == 2.5
        assert segment.confidence == 0.0

    def test_creation_full(self):
        """Test full creation"""
        words = [
            {'word': 'Hello', 'start': 0.0, 'end': 0.5, 'probability': 0.95},
            {'word': 'world', 'start': 0.6, 'end': 1.0, 'probability': 0.92}
        ]

        segment = TranscriptionSegment(
            text="Hello world",
            start=0.0,
            end=1.0,
            confidence=0.93,
            language="en",
            speaker="SPEAKER_00",
            words=words
        )

        assert segment.confidence == 0.93
        assert segment.language == "en"
        assert segment.speaker == "SPEAKER_00"
        assert len(segment.words) == 2

    def test_duration_property(self):
        """Test duration calculation"""
        segment = TranscriptionSegment(
            text="Test",
            start=5.0,
            end=10.0
        )

        assert segment.duration == 5.0

    def test_duration_property_precise(self):
        """Test precise duration calculation"""
        segment = TranscriptionSegment(
            text="Test",
            start=1.234,
            end=3.567
        )

        assert segment.duration == pytest.approx(2.333)

    def test_words_default_empty(self):
        """Test words defaults to empty list"""
        segment = TranscriptionSegment(
            text="Test",
            start=0.0,
            end=1.0
        )

        assert segment.words == []


# ============================================================
# TranscriptionResult Unit Tests
# ============================================================

class TestTranscriptionResult:
    """Unit tests for TranscriptionResult data model"""

    def test_creation_minimal(self):
        """Test minimal creation"""
        result = TranscriptionResult(
            text="Hello world",
            segments=[],
            language="en",
            language_probability=0.99,
            duration=5.0,
            audio_file="test.wav",
            model_used="whisper-base"
        )

        assert result.text == "Hello world"
        assert result.language == "en"
        assert result.model_used == "whisper-base"

    def test_creation_with_segments(self):
        """Test creation with segments"""
        segments = [
            TranscriptionSegment("Hello", 0.0, 0.5),
            TranscriptionSegment("world", 0.6, 1.0)
        ]

        result = TranscriptionResult(
            text="Hello world",
            segments=segments,
            language="en",
            language_probability=0.95,
            duration=1.0,
            audio_file="test.wav",
            model_used="whisper-small"
        )

        assert len(result.segments) == 2
        assert result.segments[0].text == "Hello"

    def test_processed_at_default(self):
        """Test processed_at defaults to now"""
        result = TranscriptionResult(
            text="Test",
            segments=[],
            language="en",
            language_probability=0.9,
            duration=1.0,
            audio_file="test.wav",
            model_used="whisper-tiny"
        )

        assert result.processed_at is not None
        assert isinstance(result.processed_at, datetime)


# ============================================================
# VoiceMatch Unit Tests
# ============================================================

class TestVoiceMatch:
    """Unit tests for VoiceMatch data model"""

    def test_creation_minimal(self):
        """Test minimal creation"""
        match = VoiceMatch(
            confidence=0.85,
            audio_file="test.wav",
            timestamp=datetime.now(),
            duration=30.0,
            sample_rate=16000
        )

        assert match.confidence == 0.85
        assert match.sample_rate == 16000
        assert match.transcript is None

    def test_creation_with_transcript(self):
        """Test creation with transcript"""
        match = VoiceMatch(
            confidence=0.92,
            audio_file="call.wav",
            timestamp=datetime.now(),
            duration=120.0,
            sample_rate=44100,
            transcript="This is a test call."
        )

        assert match.transcript == "This is a test call."

    def test_creation_with_metadata(self):
        """Test creation with metadata"""
        metadata = {
            'is_match': True,
            'threshold': 0.75,
            'segment_start': 10.0,
            'segment_end': 20.0
        }

        match = VoiceMatch(
            confidence=0.88,
            audio_file="recording.wav",
            timestamp=datetime.now(),
            duration=60.0,
            sample_rate=16000,
            metadata=metadata
        )

        assert match.metadata['is_match'] is True
        assert match.metadata['threshold'] == 0.75

    def test_confidence_boundary_values(self):
        """Test confidence boundary values"""
        # Low confidence
        low_match = VoiceMatch(
            confidence=0.0,
            audio_file="test.wav",
            timestamp=datetime.now(),
            duration=10.0,
            sample_rate=16000
        )
        assert low_match.confidence == 0.0

        # High confidence
        high_match = VoiceMatch(
            confidence=1.0,
            audio_file="test.wav",
            timestamp=datetime.now(),
            duration=10.0,
            sample_rate=16000
        )
        assert high_match.confidence == 1.0


# ============================================================
# VoicePrint Unit Tests
# ============================================================

class TestVoicePrint:
    """Unit tests for VoicePrint data model"""

    def test_creation_minimal(self):
        """Test minimal creation"""
        embedding = np.random.rand(256)

        voice_print = VoicePrint(
            id="speaker-001",
            name="John Doe",
            embedding=embedding,
            created_at=datetime.now(),
            source_files=["sample.wav"]
        )

        assert voice_print.id == "speaker-001"
        assert voice_print.name == "John Doe"
        assert voice_print.embedding.shape == (256,)

    def test_creation_with_metadata(self):
        """Test creation with metadata"""
        embedding = np.random.rand(192)
        metadata = {
            'source': 'FBI podcast',
            'quality': 'high',
            'notes': 'Clear audio sample'
        }

        voice_print = VoicePrint(
            id="target-001",
            name="Target Person",
            embedding=embedding,
            created_at=datetime.now(),
            source_files=["podcast.mp3", "interview.wav"],
            metadata=metadata
        )

        assert voice_print.metadata['source'] == 'FBI podcast'
        assert len(voice_print.source_files) == 2

    def test_to_dict(self):
        """Test conversion to dictionary"""
        embedding = np.random.rand(256)
        created = datetime(2024, 1, 15, 12, 0, 0)

        voice_print = VoicePrint(
            id="test-001",
            name="Test Speaker",
            embedding=embedding,
            created_at=created,
            source_files=["file1.wav", "file2.wav"],
            metadata={'key': 'value'}
        )

        data = voice_print.to_dict()

        assert data['id'] == "test-001"
        assert data['name'] == "Test Speaker"
        assert data['created_at'] == "2024-01-15T12:00:00"
        assert data['source_files'] == ["file1.wav", "file2.wav"]
        assert data['embedding_shape'] == [256]

    def test_to_dict_no_embedding(self):
        """Test to_dict doesn't include raw embedding"""
        embedding = np.random.rand(256)

        voice_print = VoicePrint(
            id="test-001",
            name="Test",
            embedding=embedding,
            created_at=datetime.now(),
            source_files=[]
        )

        data = voice_print.to_dict()

        # Should have shape but not raw embedding
        assert 'embedding_shape' in data
        assert 'embedding' not in data


# ============================================================
# SpeakerSegment Unit Tests
# ============================================================

class TestSpeakerSegment:
    """Unit tests for SpeakerSegment data model"""

    def test_creation_minimal(self):
        """Test minimal creation"""
        segment = SpeakerSegment(
            speaker="SPEAKER_00",
            start=0.0,
            end=5.0
        )

        assert segment.speaker == "SPEAKER_00"
        assert segment.start == 0.0
        assert segment.end == 5.0

    def test_creation_with_confidence(self):
        """Test creation with confidence"""
        segment = SpeakerSegment(
            speaker="SPEAKER_01",
            start=5.0,
            end=10.0,
            confidence=0.95
        )

        assert segment.confidence == 0.95

    def test_duration_property(self):
        """Test duration calculation"""
        segment = SpeakerSegment(
            speaker="SPEAKER_00",
            start=10.5,
            end=25.3
        )

        assert segment.duration == pytest.approx(14.8)


# ============================================================
# Voice Comparison Algorithm Unit Tests
# ============================================================

class VoiceComparer:
    """Voice comparison utilities"""

    @staticmethod
    def cosine_similarity(embedding1: np.ndarray, embedding2: np.ndarray) -> float:
        """
        Compute cosine similarity between two embeddings

        Returns:
            Similarity score (-1 to 1)
        """
        dot_product = np.dot(embedding1, embedding2)
        norm1 = np.linalg.norm(embedding1)
        norm2 = np.linalg.norm(embedding2)

        if norm1 == 0 or norm2 == 0:
            return 0.0

        return float(dot_product / (norm1 * norm2))

    @staticmethod
    def normalize_similarity(similarity: float) -> float:
        """
        Normalize cosine similarity to 0-1 range

        Args:
            similarity: Cosine similarity (-1 to 1)

        Returns:
            Normalized score (0 to 1)
        """
        return (similarity + 1.0) / 2.0

    @staticmethod
    def euclidean_distance(embedding1: np.ndarray, embedding2: np.ndarray) -> float:
        """Compute Euclidean distance between embeddings"""
        return float(np.linalg.norm(embedding1 - embedding2))

    @staticmethod
    def is_match(similarity: float, threshold: float = 0.75) -> bool:
        """Determine if similarity indicates a match"""
        return similarity >= threshold

    @staticmethod
    def normalize_embedding(embedding: np.ndarray) -> np.ndarray:
        """L2 normalize embedding"""
        norm = np.linalg.norm(embedding)
        if norm == 0:
            return embedding
        return embedding / norm


class TestVoiceComparer:
    """Unit tests for VoiceComparer"""

    def test_cosine_similarity_identical(self):
        """Test cosine similarity for identical embeddings"""
        embedding = np.random.rand(256)

        similarity = VoiceComparer.cosine_similarity(embedding, embedding)

        assert similarity == pytest.approx(1.0)

    def test_cosine_similarity_orthogonal(self):
        """Test cosine similarity for orthogonal embeddings"""
        embedding1 = np.array([1.0, 0.0, 0.0])
        embedding2 = np.array([0.0, 1.0, 0.0])

        similarity = VoiceComparer.cosine_similarity(embedding1, embedding2)

        assert similarity == pytest.approx(0.0)

    def test_cosine_similarity_opposite(self):
        """Test cosine similarity for opposite embeddings"""
        embedding1 = np.array([1.0, 1.0, 1.0])
        embedding2 = np.array([-1.0, -1.0, -1.0])

        similarity = VoiceComparer.cosine_similarity(embedding1, embedding2)

        assert similarity == pytest.approx(-1.0)

    def test_cosine_similarity_zero_vector(self):
        """Test cosine similarity with zero vector"""
        embedding1 = np.zeros(256)
        embedding2 = np.random.rand(256)

        similarity = VoiceComparer.cosine_similarity(embedding1, embedding2)

        assert similarity == 0.0

    def test_normalize_similarity(self):
        """Test similarity normalization"""
        assert VoiceComparer.normalize_similarity(1.0) == 1.0
        assert VoiceComparer.normalize_similarity(-1.0) == 0.0
        assert VoiceComparer.normalize_similarity(0.0) == 0.5

    def test_euclidean_distance_identical(self):
        """Test Euclidean distance for identical embeddings"""
        embedding = np.random.rand(256)

        distance = VoiceComparer.euclidean_distance(embedding, embedding)

        assert distance == pytest.approx(0.0)

    def test_euclidean_distance_different(self):
        """Test Euclidean distance for different embeddings"""
        embedding1 = np.zeros(3)
        embedding2 = np.ones(3)

        distance = VoiceComparer.euclidean_distance(embedding1, embedding2)

        assert distance == pytest.approx(np.sqrt(3))

    def test_is_match_above_threshold(self):
        """Test match detection above threshold"""
        assert VoiceComparer.is_match(0.80, threshold=0.75) is True
        assert VoiceComparer.is_match(0.90, threshold=0.75) is True

    def test_is_match_below_threshold(self):
        """Test match detection below threshold"""
        assert VoiceComparer.is_match(0.70, threshold=0.75) is False
        assert VoiceComparer.is_match(0.50, threshold=0.75) is False

    def test_is_match_at_threshold(self):
        """Test match detection at threshold"""
        assert VoiceComparer.is_match(0.75, threshold=0.75) is True

    def test_normalize_embedding(self):
        """Test embedding normalization"""
        embedding = np.array([3.0, 4.0])  # Length 5

        normalized = VoiceComparer.normalize_embedding(embedding)

        assert np.linalg.norm(normalized) == pytest.approx(1.0)
        assert normalized[0] == pytest.approx(0.6)
        assert normalized[1] == pytest.approx(0.8)

    def test_normalize_embedding_zero(self):
        """Test normalizing zero vector"""
        embedding = np.zeros(256)

        normalized = VoiceComparer.normalize_embedding(embedding)

        assert np.all(normalized == 0)


# ============================================================
# Voice Print Database Unit Tests
# ============================================================

class VoicePrintDatabase:
    """In-memory voice print database"""

    def __init__(self, storage_dir: Optional[str] = None):
        self.storage_dir = storage_dir
        self.voice_prints: Dict[str, VoicePrint] = {}

    def add(self, voice_print: VoicePrint) -> str:
        """Add voice print to database"""
        self.voice_prints[voice_print.id] = voice_print
        return voice_print.id

    def get(self, speaker_id: str) -> Optional[VoicePrint]:
        """Get voice print by ID"""
        return self.voice_prints.get(speaker_id)

    def delete(self, speaker_id: str) -> bool:
        """Delete voice print by ID"""
        if speaker_id in self.voice_prints:
            del self.voice_prints[speaker_id]
            return True
        return False

    def get_all(self) -> List[VoicePrint]:
        """Get all voice prints"""
        return list(self.voice_prints.values())

    def search_by_name(self, name: str) -> List[VoicePrint]:
        """Search voice prints by name"""
        name_lower = name.lower()
        return [
            vp for vp in self.voice_prints.values()
            if name_lower in vp.name.lower()
        ]

    def count(self) -> int:
        """Count voice prints"""
        return len(self.voice_prints)

    def clear(self):
        """Clear database"""
        self.voice_prints.clear()

    def find_matches(
        self,
        query_embedding: np.ndarray,
        threshold: float = 0.75,
        top_k: int = 5
    ) -> List[Tuple[VoicePrint, float]]:
        """Find matching voice prints"""
        matches = []

        for vp in self.voice_prints.values():
            similarity = VoiceComparer.cosine_similarity(
                query_embedding,
                vp.embedding
            )
            normalized = VoiceComparer.normalize_similarity(similarity)

            if normalized >= threshold:
                matches.append((vp, normalized))

        # Sort by similarity
        matches.sort(key=lambda x: x[1], reverse=True)

        return matches[:top_k]


class TestVoicePrintDatabase:
    """Unit tests for VoicePrintDatabase"""

    @pytest.fixture
    def database(self):
        """Create database instance"""
        return VoicePrintDatabase()

    @pytest.fixture
    def sample_voice_print(self):
        """Create sample voice print"""
        return VoicePrint(
            id="speaker-001",
            name="John Doe",
            embedding=np.random.rand(256),
            created_at=datetime.now(),
            source_files=["sample.wav"]
        )

    def test_add_voice_print(self, database, sample_voice_print):
        """Test adding voice print"""
        vp_id = database.add(sample_voice_print)

        assert vp_id == "speaker-001"
        assert database.count() == 1

    def test_get_voice_print(self, database, sample_voice_print):
        """Test getting voice print"""
        database.add(sample_voice_print)

        retrieved = database.get("speaker-001")

        assert retrieved is not None
        assert retrieved.name == "John Doe"

    def test_get_voice_print_not_found(self, database):
        """Test getting non-existent voice print"""
        retrieved = database.get("non-existent")

        assert retrieved is None

    def test_delete_voice_print(self, database, sample_voice_print):
        """Test deleting voice print"""
        database.add(sample_voice_print)

        result = database.delete("speaker-001")

        assert result is True
        assert database.count() == 0

    def test_delete_voice_print_not_found(self, database):
        """Test deleting non-existent voice print"""
        result = database.delete("non-existent")

        assert result is False

    def test_get_all(self, database):
        """Test getting all voice prints"""
        for i in range(3):
            vp = VoicePrint(
                id=f"speaker-{i:03d}",
                name=f"Speaker {i}",
                embedding=np.random.rand(256),
                created_at=datetime.now(),
                source_files=[]
            )
            database.add(vp)

        all_vps = database.get_all()

        assert len(all_vps) == 3

    def test_search_by_name(self, database):
        """Test searching by name"""
        database.add(VoicePrint(
            id="001", name="John Smith",
            embedding=np.random.rand(256),
            created_at=datetime.now(), source_files=[]
        ))
        database.add(VoicePrint(
            id="002", name="Jane Doe",
            embedding=np.random.rand(256),
            created_at=datetime.now(), source_files=[]
        ))
        database.add(VoicePrint(
            id="003", name="John Doe",
            embedding=np.random.rand(256),
            created_at=datetime.now(), source_files=[]
        ))

        results = database.search_by_name("John")

        assert len(results) == 2
        assert all("john" in r.name.lower() for r in results)

    def test_search_by_name_case_insensitive(self, database):
        """Test case-insensitive name search"""
        database.add(VoicePrint(
            id="001", name="JOHN DOE",
            embedding=np.random.rand(256),
            created_at=datetime.now(), source_files=[]
        ))

        results = database.search_by_name("john")

        assert len(results) == 1

    def test_clear(self, database, sample_voice_print):
        """Test clearing database"""
        database.add(sample_voice_print)
        database.clear()

        assert database.count() == 0

    def test_find_matches(self, database):
        """Test finding matching voice prints"""
        # Create a reference embedding
        reference = np.random.rand(256)

        # Add voice print with similar embedding
        similar = VoicePrint(
            id="similar",
            name="Similar Speaker",
            embedding=reference + np.random.rand(256) * 0.1,  # Small noise
            created_at=datetime.now(),
            source_files=[]
        )
        database.add(similar)

        # Add voice print with different embedding
        different = VoicePrint(
            id="different",
            name="Different Speaker",
            embedding=np.random.rand(256),  # Random
            created_at=datetime.now(),
            source_files=[]
        )
        database.add(different)

        matches = database.find_matches(reference, threshold=0.5)

        # Should find at least the similar one
        assert len(matches) >= 1

    def test_find_matches_respects_threshold(self, database):
        """Test find matches respects threshold"""
        reference = np.array([1.0, 0.0, 0.0])

        # Add orthogonal embedding (similarity ~0.5 normalized)
        orthogonal = VoicePrint(
            id="orthogonal",
            name="Orthogonal",
            embedding=np.array([0.0, 1.0, 0.0]),
            created_at=datetime.now(),
            source_files=[]
        )
        database.add(orthogonal)

        # High threshold should exclude orthogonal
        matches = database.find_matches(reference, threshold=0.8)

        assert len(matches) == 0


# ============================================================
# Audio Processing Utility Unit Tests
# ============================================================

class AudioUtils:
    """Audio processing utilities"""

    @staticmethod
    def calculate_duration(num_samples: int, sample_rate: int) -> float:
        """Calculate duration from samples and sample rate"""
        return num_samples / sample_rate

    @staticmethod
    def time_to_samples(time_seconds: float, sample_rate: int) -> int:
        """Convert time in seconds to sample count"""
        return int(time_seconds * sample_rate)

    @staticmethod
    def samples_to_time(samples: int, sample_rate: int) -> float:
        """Convert sample count to time in seconds"""
        return samples / sample_rate

    @staticmethod
    def db_to_amplitude(db: float) -> float:
        """Convert decibels to amplitude ratio"""
        return 10 ** (db / 20)

    @staticmethod
    def amplitude_to_db(amplitude: float) -> float:
        """Convert amplitude ratio to decibels"""
        if amplitude <= 0:
            return float('-inf')
        return 20 * np.log10(amplitude)

    @staticmethod
    def calculate_rms(samples: np.ndarray) -> float:
        """Calculate RMS (root mean square) of samples"""
        return float(np.sqrt(np.mean(samples ** 2)))

    @staticmethod
    def is_silent(samples: np.ndarray, threshold: float = 0.01) -> bool:
        """Check if audio segment is silent"""
        rms = AudioUtils.calculate_rms(samples)
        return rms < threshold


class TestAudioUtils:
    """Unit tests for AudioUtils"""

    def test_calculate_duration(self):
        """Test duration calculation"""
        # 16000 samples at 16kHz = 1 second
        assert AudioUtils.calculate_duration(16000, 16000) == 1.0

        # 44100 samples at 44100Hz = 1 second
        assert AudioUtils.calculate_duration(44100, 44100) == 1.0

        # 8000 samples at 16000Hz = 0.5 seconds
        assert AudioUtils.calculate_duration(8000, 16000) == 0.5

    def test_time_to_samples(self):
        """Test time to samples conversion"""
        assert AudioUtils.time_to_samples(1.0, 16000) == 16000
        assert AudioUtils.time_to_samples(0.5, 16000) == 8000
        assert AudioUtils.time_to_samples(2.5, 44100) == 110250

    def test_samples_to_time(self):
        """Test samples to time conversion"""
        assert AudioUtils.samples_to_time(16000, 16000) == 1.0
        assert AudioUtils.samples_to_time(8000, 16000) == 0.5

    def test_db_to_amplitude(self):
        """Test dB to amplitude conversion"""
        assert AudioUtils.db_to_amplitude(0) == pytest.approx(1.0)
        assert AudioUtils.db_to_amplitude(20) == pytest.approx(10.0)
        assert AudioUtils.db_to_amplitude(-20) == pytest.approx(0.1)
        assert AudioUtils.db_to_amplitude(6) == pytest.approx(2.0, rel=0.01)

    def test_amplitude_to_db(self):
        """Test amplitude to dB conversion"""
        assert AudioUtils.amplitude_to_db(1.0) == pytest.approx(0.0)
        assert AudioUtils.amplitude_to_db(10.0) == pytest.approx(20.0)
        assert AudioUtils.amplitude_to_db(0.1) == pytest.approx(-20.0)

    def test_amplitude_to_db_zero(self):
        """Test amplitude to dB for zero"""
        result = AudioUtils.amplitude_to_db(0)
        assert result == float('-inf')

    def test_calculate_rms(self):
        """Test RMS calculation"""
        # Constant signal
        samples = np.ones(1000)
        assert AudioUtils.calculate_rms(samples) == 1.0

        # Zero signal
        samples = np.zeros(1000)
        assert AudioUtils.calculate_rms(samples) == 0.0

    def test_is_silent(self):
        """Test silence detection"""
        # Silent
        silent_samples = np.zeros(1000)
        assert AudioUtils.is_silent(silent_samples) is True

        # Loud
        loud_samples = np.ones(1000) * 0.5
        assert AudioUtils.is_silent(loud_samples) is False

    def test_is_silent_threshold(self):
        """Test silence detection with custom threshold"""
        samples = np.ones(1000) * 0.005  # Very quiet

        # Default threshold (0.01) - should be silent
        assert AudioUtils.is_silent(samples) is True

        # Lower threshold - should not be silent
        assert AudioUtils.is_silent(samples, threshold=0.001) is False


# ============================================================
# Model Configuration Unit Tests
# ============================================================

class WhisperConfig:
    """Whisper model configuration"""

    MODEL_SPECS = {
        'tiny': {'params': '39M', 'vram': '1GB', 'relative_speed': 32.0},
        'base': {'params': '74M', 'vram': '1GB', 'relative_speed': 16.0},
        'small': {'params': '244M', 'vram': '2GB', 'relative_speed': 6.0},
        'medium': {'params': '769M', 'vram': '5GB', 'relative_speed': 2.0},
        'large': {'params': '1550M', 'vram': '10GB', 'relative_speed': 1.0},
        'large-v2': {'params': '1550M', 'vram': '10GB', 'relative_speed': 1.0},
        'large-v3': {'params': '1550M', 'vram': '10GB', 'relative_speed': 1.0},
    }

    @classmethod
    def get_model_info(cls, model_size: str) -> Optional[Dict]:
        """Get model specifications"""
        return cls.MODEL_SPECS.get(model_size)

    @classmethod
    def is_valid_model(cls, model_size: str) -> bool:
        """Check if model size is valid"""
        return model_size in cls.MODEL_SPECS

    @classmethod
    def get_available_models(cls) -> List[str]:
        """Get list of available models"""
        return list(cls.MODEL_SPECS.keys())

    @classmethod
    def recommend_model(cls, vram_gb: float) -> str:
        """Recommend model based on available VRAM"""
        if vram_gb >= 10:
            return 'large-v3'
        elif vram_gb >= 5:
            return 'medium'
        elif vram_gb >= 2:
            return 'small'
        elif vram_gb >= 1:
            return 'base'
        else:
            return 'tiny'


class TestWhisperConfig:
    """Unit tests for WhisperConfig"""

    def test_get_model_info_valid(self):
        """Test getting valid model info"""
        info = WhisperConfig.get_model_info('base')

        assert info is not None
        assert info['params'] == '74M'
        assert info['vram'] == '1GB'

    def test_get_model_info_invalid(self):
        """Test getting invalid model info"""
        info = WhisperConfig.get_model_info('invalid')

        assert info is None

    def test_is_valid_model(self):
        """Test model validation"""
        assert WhisperConfig.is_valid_model('tiny') is True
        assert WhisperConfig.is_valid_model('base') is True
        assert WhisperConfig.is_valid_model('large-v3') is True
        assert WhisperConfig.is_valid_model('invalid') is False

    def test_get_available_models(self):
        """Test getting available models"""
        models = WhisperConfig.get_available_models()

        assert 'tiny' in models
        assert 'base' in models
        assert 'large-v3' in models
        assert len(models) == 7

    def test_recommend_model_high_vram(self):
        """Test model recommendation for high VRAM"""
        assert WhisperConfig.recommend_model(12.0) == 'large-v3'
        assert WhisperConfig.recommend_model(10.0) == 'large-v3'

    def test_recommend_model_medium_vram(self):
        """Test model recommendation for medium VRAM"""
        assert WhisperConfig.recommend_model(6.0) == 'medium'
        assert WhisperConfig.recommend_model(5.0) == 'medium'

    def test_recommend_model_low_vram(self):
        """Test model recommendation for low VRAM"""
        assert WhisperConfig.recommend_model(2.0) == 'small'
        assert WhisperConfig.recommend_model(1.5) == 'base'
        assert WhisperConfig.recommend_model(0.5) == 'tiny'


# ============================================================
# Language Detection Unit Tests
# ============================================================

class LanguageDetector:
    """Language detection utilities"""

    SUPPORTED_LANGUAGES = {
        'en': 'English',
        'de': 'German',
        'fr': 'French',
        'es': 'Spanish',
        'it': 'Italian',
        'pt': 'Portuguese',
        'ru': 'Russian',
        'bg': 'Bulgarian',
        'zh': 'Chinese',
        'ja': 'Japanese',
        'ko': 'Korean',
        'ar': 'Arabic'
    }

    @classmethod
    def is_supported(cls, language_code: str) -> bool:
        """Check if language is supported"""
        return language_code in cls.SUPPORTED_LANGUAGES

    @classmethod
    def get_language_name(cls, language_code: str) -> Optional[str]:
        """Get full language name from code"""
        return cls.SUPPORTED_LANGUAGES.get(language_code)

    @classmethod
    def get_supported_count(cls) -> int:
        """Get count of supported languages"""
        return len(cls.SUPPORTED_LANGUAGES)


class TestLanguageDetector:
    """Unit tests for LanguageDetector"""

    def test_is_supported(self):
        """Test language support check"""
        assert LanguageDetector.is_supported('en') is True
        assert LanguageDetector.is_supported('de') is True
        assert LanguageDetector.is_supported('bg') is True
        assert LanguageDetector.is_supported('xx') is False

    def test_get_language_name(self):
        """Test getting language name"""
        assert LanguageDetector.get_language_name('en') == 'English'
        assert LanguageDetector.get_language_name('de') == 'German'
        assert LanguageDetector.get_language_name('bg') == 'Bulgarian'
        assert LanguageDetector.get_language_name('xx') is None

    def test_get_supported_count(self):
        """Test getting supported language count"""
        count = LanguageDetector.get_supported_count()
        assert count >= 12


# ============================================================
# Run tests
# ============================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
