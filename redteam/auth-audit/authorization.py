"""
Authorization Manager for Red Team Operations

Ensures all operations have proper authorization before execution.
"""

import os
import json
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set
from pathlib import Path
import uuid
from enum import Enum


class AuthorizationLevel(Enum):
    """Authorization levels for operations"""
    RECONNAISSANCE = "reconnaissance"
    SCANNING = "scanning"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    C2_OPERATIONS = "c2_operations"
    PHISHING = "phishing"
    PASSWORD_ATTACKS = "password_attacks"
    WIRELESS_ATTACKS = "wireless_attacks"


class AuthorizationStatus(Enum):
    """Status of authorization"""
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"
    REVOKED = "revoked"


class Authorization:
    """Represents a single authorization"""

    def __init__(
        self,
        operation_id: str,
        operation_type: AuthorizationLevel,
        target_scope: List[str],
        authorized_by: str,
        valid_from: datetime,
        valid_until: datetime,
        constraints: Optional[Dict] = None
    ):
        self.operation_id = operation_id
        self.operation_type = operation_type
        self.target_scope = target_scope
        self.authorized_by = authorized_by
        self.valid_from = valid_from
        self.valid_until = valid_until
        self.constraints = constraints or {}
        self.status = AuthorizationStatus.APPROVED
        self.created_at = datetime.utcnow()

    def is_valid(self) -> bool:
        """Check if authorization is currently valid"""
        now = datetime.utcnow()
        return (
            self.status == AuthorizationStatus.APPROVED and
            self.valid_from <= now <= self.valid_until
        )

    def is_target_in_scope(self, target: str) -> bool:
        """Check if target is within authorized scope"""
        for scope_pattern in self.target_scope:
            if self._matches_scope(target, scope_pattern):
                return True
        return False

    @staticmethod
    def _matches_scope(target: str, pattern: str) -> bool:
        """Check if target matches scope pattern"""
        # Support wildcards and CIDR notation
        if '*' in pattern:
            import re
            regex = pattern.replace('.', r'\.').replace('*', '.*')
            return bool(re.match(regex, target))
        return target == pattern

    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            'operation_id': self.operation_id,
            'operation_type': self.operation_type.value,
            'target_scope': self.target_scope,
            'authorized_by': self.authorized_by,
            'valid_from': self.valid_from.isoformat(),
            'valid_until': self.valid_until.isoformat(),
            'constraints': self.constraints,
            'status': self.status.value,
            'created_at': self.created_at.isoformat()
        }

    @classmethod
    def from_dict(cls, data: Dict) -> 'Authorization':
        """Create from dictionary"""
        auth = cls(
            operation_id=data['operation_id'],
            operation_type=AuthorizationLevel(data['operation_type']),
            target_scope=data['target_scope'],
            authorized_by=data['authorized_by'],
            valid_from=datetime.fromisoformat(data['valid_from']),
            valid_until=datetime.fromisoformat(data['valid_until']),
            constraints=data.get('constraints', {})
        )
        auth.status = AuthorizationStatus(data['status'])
        auth.created_at = datetime.fromisoformat(data['created_at'])
        return auth


class AuthorizationManager:
    """
    Manages authorization for red team operations

    CRITICAL: No operation should execute without valid authorization
    """

    def __init__(self, auth_db_path: Optional[str] = None):
        """Initialize authorization manager"""
        if auth_db_path is None:
            auth_db_path = os.path.join(
                os.path.dirname(__file__),
                '../../data/authorizations.json'
            )
        self.auth_db_path = Path(auth_db_path)
        self.auth_db_path.parent.mkdir(parents=True, exist_ok=True)
        self.authorizations: Dict[str, Authorization] = {}
        self._load_authorizations()

    def _load_authorizations(self):
        """Load authorizations from database"""
        if self.auth_db_path.exists():
            try:
                with open(self.auth_db_path, 'r') as f:
                    data = json.load(f)
                    for auth_data in data.get('authorizations', []):
                        auth = Authorization.from_dict(auth_data)
                        self.authorizations[auth.operation_id] = auth
            except Exception as e:
                print(f"Error loading authorizations: {e}")

    def _save_authorizations(self):
        """Save authorizations to database"""
        try:
            data = {
                'authorizations': [
                    auth.to_dict() for auth in self.authorizations.values()
                ],
                'updated_at': datetime.utcnow().isoformat()
            }
            with open(self.auth_db_path, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"Error saving authorizations: {e}")

    def create_authorization(
        self,
        operation_type: AuthorizationLevel,
        target_scope: List[str],
        authorized_by: str,
        duration_hours: int = 24,
        constraints: Optional[Dict] = None
    ) -> Authorization:
        """
        Create a new authorization

        Args:
            operation_type: Type of operation
            target_scope: List of authorized targets (supports wildcards)
            authorized_by: Identity of authorizing entity
            duration_hours: How long authorization is valid
            constraints: Additional constraints (e.g., rate limits)

        Returns:
            Authorization object
        """
        operation_id = str(uuid.uuid4())
        now = datetime.utcnow()

        auth = Authorization(
            operation_id=operation_id,
            operation_type=operation_type,
            target_scope=target_scope,
            authorized_by=authorized_by,
            valid_from=now,
            valid_until=now + timedelta(hours=duration_hours),
            constraints=constraints
        )

        self.authorizations[operation_id] = auth
        self._save_authorizations()

        return auth

    def verify_authorization(
        self,
        operation_type: AuthorizationLevel,
        target: str,
        operation_id: Optional[str] = None
    ) -> tuple[bool, Optional[str]]:
        """
        Verify if operation is authorized

        Args:
            operation_type: Type of operation
            target: Target of operation
            operation_id: Specific authorization ID (optional)

        Returns:
            (authorized: bool, reason: str)
        """
        # If specific operation_id provided, check that one
        if operation_id:
            if operation_id not in self.authorizations:
                return False, f"Authorization {operation_id} not found"

            auth = self.authorizations[operation_id]

            if not auth.is_valid():
                return False, f"Authorization {operation_id} is not valid"

            if auth.operation_type != operation_type:
                return False, f"Operation type mismatch"

            if not auth.is_target_in_scope(target):
                return False, f"Target {target} not in authorized scope"

            return True, None

        # Otherwise check all authorizations
        for auth in self.authorizations.values():
            if (
                auth.is_valid() and
                auth.operation_type == operation_type and
                auth.is_target_in_scope(target)
            ):
                return True, None

        return False, f"No valid authorization found for {operation_type.value} on {target}"

    def revoke_authorization(self, operation_id: str) -> bool:
        """Revoke an authorization"""
        if operation_id in self.authorizations:
            self.authorizations[operation_id].status = AuthorizationStatus.REVOKED
            self._save_authorizations()
            return True
        return False

    def list_active_authorizations(self) -> List[Authorization]:
        """List all active authorizations"""
        return [
            auth for auth in self.authorizations.values()
            if auth.is_valid()
        ]

    def cleanup_expired(self):
        """Remove expired authorizations"""
        expired = [
            op_id for op_id, auth in self.authorizations.items()
            if not auth.is_valid()
        ]
        for op_id in expired:
            del self.authorizations[op_id]
        self._save_authorizations()


# Decorator for authorization checks
def require_authorization(operation_type: AuthorizationLevel):
    """
    Decorator to require authorization for function execution

    Usage:
        @require_authorization(AuthorizationLevel.SCANNING)
        def perform_scan(target, auth_manager, operation_id=None):
            pass
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            # Extract auth_manager and target from arguments
            auth_manager = kwargs.get('auth_manager')
            target = kwargs.get('target')
            operation_id = kwargs.get('operation_id')

            if not auth_manager or not target:
                raise ValueError("auth_manager and target required")

            authorized, reason = auth_manager.verify_authorization(
                operation_type, target, operation_id
            )

            if not authorized:
                raise PermissionError(
                    f"Operation not authorized: {reason}\n"
                    f"This operation requires proper authorization."
                )

            return func(*args, **kwargs)

        return wrapper
    return decorator
