"""
Email Intelligence System
Comprehensive email OSINT and intelligence gathering
"""

from .email_intel import EmailIntelligence, EmailProfile
from .email_validator import EmailValidator
from .email_reputation import EmailReputation
from .holehe_integration import HoleheIntegration, AccountResult
from .email_hunter import EmailHunter
from .email_format import EmailFormatFinder, PermutationGenerator
from .email_header_analyzer import EmailHeaderAnalyzer
from .email_correlator import EmailCorrelator

__all__ = [
    'EmailIntelligence',
    'EmailProfile',
    'EmailValidator',
    'EmailReputation',
    'HoleheIntegration',
    'AccountResult',
    'EmailHunter',
    'EmailFormatFinder',
    'PermutationGenerator',
    'EmailHeaderAnalyzer',
    'EmailCorrelator'
]

__version__ = '1.0.0'
__author__ = 'Agent 10 - Email Intelligence Specialist'
