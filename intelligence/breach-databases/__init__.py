"""
Breach Database Integration
DeHashed, Have I Been Pwned, and other breach data sources
"""

from .breach_engine import BreachDatabaseEngine
from .dehashed import DeHashedClient
from .hibp import HIBPClient

__all__ = [
    'BreachDatabaseEngine',
    'DeHashedClient',
    'HIBPClient',
]
