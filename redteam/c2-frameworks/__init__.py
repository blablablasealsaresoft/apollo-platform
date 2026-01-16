"""
Command & Control Framework Integration

Integrates multiple C2 frameworks for authorized operations.
"""

from .sliver_integration import SliverC2Manager
from .havoc_integration import HavocC2Manager
from .mythic_integration import MythicC2Manager
from .c2_orchestrator import C2Orchestrator

__all__ = [
    'SliverC2Manager',
    'HavocC2Manager',
    'MythicC2Manager',
    'C2Orchestrator'
]
