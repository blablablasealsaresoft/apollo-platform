"""
Intelligence Fusion Engine
Advanced multi-source intelligence correlation and entity resolution
"""

from .fusion_engine import IntelligenceFusion, IntelligenceSource, EntityProfile
from .entity_resolver import EntityResolver, ResolvedEntity
from .correlation_algorithm import CorrelationEngine
from .confidence_scorer import ConfidenceScorer
from .risk_assessor import RiskAssessor
from .timeline_builder import TimelineBuilder
from .graph_analyzer import GraphAnalyzer

__version__ = "1.0.0"
__author__ = "APOLLO Intelligence Team"

__all__ = [
    'IntelligenceFusion',
    'IntelligenceSource',
    'EntityProfile',
    'EntityResolver',
    'ResolvedEntity',
    'CorrelationEngine',
    'ConfidenceScorer',
    'RiskAssessor',
    'TimelineBuilder',
    'GraphAnalyzer'
]
