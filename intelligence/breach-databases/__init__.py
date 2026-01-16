"""
Breach Database Integration
DeHashed, Have I Been Pwned, and other breach data sources

Enhanced by Agent 5 with:
- Full DeHashed API integration
- Complete HIBP API support
- Pwned Passwords k-anonymity checking
- Credential monitoring capabilities
"""

from .breach_engine import BreachDatabaseEngine, BreachRecord, BreachSummary
from .dehashed import DeHashedClient, DeHashedEntry, DeHashedSearchResult
from .hibp import HIBPClient, HIBPBreach, HIBPPaste, HIBPCheckResult, PasswordCheckResult

__all__ = [
    # Main Engine
    'BreachDatabaseEngine',
    'BreachRecord',
    'BreachSummary',

    # DeHashed
    'DeHashedClient',
    'DeHashedEntry',
    'DeHashedSearchResult',

    # HIBP
    'HIBPClient',
    'HIBPBreach',
    'HIBPPaste',
    'HIBPCheckResult',
    'PasswordCheckResult',
]
