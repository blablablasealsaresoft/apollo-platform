"""
Breach Database Integration & Correlation System

Comprehensive breach database search and correlation system integrating
multiple breach databases including DeHashed, HaveIBeenPwned, Snusbase, and more.
"""

from .breach_search import BreachSearch, SearchResults, SearchType, BreachRecord
from .dehashed_integration import DeHashedIntegration
from .hibp_integration import HaveIBeenPwnedIntegration
from .snusbase_integration import SnusbaseIntegration
from .breach_correlator import BreachCorrelator, CredentialCluster
from .credential_analyzer import CredentialAnalyzer
from .breach_monitor import BreachMonitor, MonitorTarget, BreachAlert

__version__ = '1.0.0'
__author__ = 'Apollo Intelligence Framework'

__all__ = [
    # Main search engine
    'BreachSearch',
    'SearchResults',
    'SearchType',
    'BreachRecord',

    # Integrations
    'DeHashedIntegration',
    'HaveIBeenPwnedIntegration',
    'SnusbaseIntegration',

    # Analysis
    'BreachCorrelator',
    'CredentialCluster',
    'CredentialAnalyzer',

    # Monitoring
    'BreachMonitor',
    'MonitorTarget',
    'BreachAlert',
]
