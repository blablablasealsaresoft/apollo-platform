"""
Anti-Money Laundering (AML) Module

Risk scoring and compliance for cryptocurrency addresses

Features:
- OFAC sanctioned address detection
- Mixer/tumbler interaction detection
- Darknet market connection detection
- Ransomware address detection
- Behavioral pattern analysis
- Transaction velocity analysis
- Structuring detection
"""

from .scoring_engine import AMLScoringEngine, RiskScore
from .real_aml_scoring import (
    RealAMLScoringEngine,
    AMLRiskScore,
    RiskLevel,
    RiskCategory,
    RiskFactor,
    OFAC_SANCTIONED_ADDRESSES,
    TORNADO_CASH_ADDRESSES,
    RANSOMWARE_ADDRESSES,
    quick_aml_screen,
)

__all__ = [
    # Original engine
    "AMLScoringEngine",
    "RiskScore",
    # Real AML engine
    "RealAMLScoringEngine",
    "AMLRiskScore",
    "RiskLevel",
    "RiskCategory",
    "RiskFactor",
    # Sanctioned lists
    "OFAC_SANCTIONED_ADDRESSES",
    "TORNADO_CASH_ADDRESSES",
    "RANSOMWARE_ADDRESSES",
    # Quick functions
    "quick_aml_screen",
]
