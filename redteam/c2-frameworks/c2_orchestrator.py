"""
C2 Orchestrator

Unified interface for managing multiple C2 frameworks.
"""

from typing import Dict, List, Optional, Any
from datetime import datetime
from .sliver_integration import SliverC2Manager
from .havoc_integration import HavocC2Manager
from .mythic_integration import MythicC2Manager


class C2Orchestrator:
    """
    Unified C2 orchestration layer

    Manages multiple C2 frameworks from single interface
    """

    def __init__(self):
        """Initialize C2 orchestrator"""
        self.sliver = SliverC2Manager()
        self.havoc = HavocC2Manager()
        self.mythic = MythicC2Manager()

        self.operations: Dict[str, Dict] = {}

    def create_operation(self, name: str, description: str, **kwargs) -> str:
        """Create new C2 operation"""
        import uuid
        operation_id = str(uuid.uuid4())

        self.operations[operation_id] = {
            'operation_id': operation_id,
            'name': name,
            'description': description,
            'created_at': datetime.utcnow().isoformat(),
            'status': 'active',
            'frameworks': {
                'sliver': {'enabled': True, 'sessions': []},
                'havoc': {'enabled': True, 'sessions': []},
                'mythic': {'enabled': True, 'callbacks': []}
            },
            **kwargs
        }

        return operation_id

    def get_all_sessions(self) -> Dict[str, List]:
        """Get sessions from all frameworks"""
        return {
            'sliver': [s.to_dict() for s in self.sliver.list_sessions()],
            'havoc': list(self.havoc.sessions.values()),
            'mythic': list(self.mythic.callbacks.values())
        }

    def get_combined_stats(self) -> Dict:
        """Get statistics from all C2 frameworks"""
        return {
            'sliver': self.sliver.get_stats(),
            'havoc': self.havoc.get_stats(),
            'mythic': self.mythic.get_stats(),
            'total_operations': len(self.operations)
        }

    def shutdown_all(self):
        """Gracefully shutdown all C2 operations"""
        print("[C2 Orchestrator] Shutting down all frameworks...")
        # Close all sessions, save state, etc.
