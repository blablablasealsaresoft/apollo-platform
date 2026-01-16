"""
Authorization and Audit System for Red Team Operations

CRITICAL: All operations must be authorized and logged.
Unauthorized use is strictly prohibited and may violate laws.
"""

from .authorization import AuthorizationManager
from .audit_logger import AuditLogger
from .legal_disclaimer import LegalDisclaimer
from .scope_limiter import ScopeLimiter

__all__ = [
    'AuthorizationManager',
    'AuditLogger',
    'LegalDisclaimer',
    'ScopeLimiter'
]
