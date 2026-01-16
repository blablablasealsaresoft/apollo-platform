"""
Tests for Authorization System
"""

import pytest
from datetime import datetime, timedelta
from auth_audit.authorization import (
    AuthorizationManager,
    AuthorizationLevel,
    Authorization
)


def test_create_authorization():
    """Test creating an authorization"""
    auth_manager = AuthorizationManager()

    auth = auth_manager.create_authorization(
        operation_type=AuthorizationLevel.SCANNING,
        target_scope=["192.168.1.0/24"],
        authorized_by="Test Operator",
        duration_hours=24
    )

    assert auth is not None
    assert auth.operation_type == AuthorizationLevel.SCANNING
    assert auth.is_valid()


def test_verify_authorization_valid():
    """Test verifying valid authorization"""
    auth_manager = AuthorizationManager()

    auth = auth_manager.create_authorization(
        operation_type=AuthorizationLevel.SCANNING,
        target_scope=["192.168.1.0/24"],
        authorized_by="Test Operator",
        duration_hours=24
    )

    authorized, reason = auth_manager.verify_authorization(
        AuthorizationLevel.SCANNING,
        "192.168.1.50"
    )

    assert authorized is True


def test_verify_authorization_out_of_scope():
    """Test authorization denial for out-of-scope target"""
    auth_manager = AuthorizationManager()

    auth = auth_manager.create_authorization(
        operation_type=AuthorizationLevel.SCANNING,
        target_scope=["192.168.1.0/24"],
        authorized_by="Test Operator",
        duration_hours=24
    )

    authorized, reason = auth_manager.verify_authorization(
        AuthorizationLevel.SCANNING,
        "10.0.0.1"
    )

    assert authorized is False
    assert "not in authorized scope" in reason


def test_revoke_authorization():
    """Test revoking authorization"""
    auth_manager = AuthorizationManager()

    auth = auth_manager.create_authorization(
        operation_type=AuthorizationLevel.SCANNING,
        target_scope=["192.168.1.0/24"],
        authorized_by="Test Operator",
        duration_hours=24
    )

    result = auth_manager.revoke_authorization(auth.operation_id)
    assert result is True
    assert not auth.is_valid()


def test_target_scope_matching():
    """Test target scope pattern matching"""
    auth = Authorization(
        operation_id="test",
        operation_type=AuthorizationLevel.RECONNAISSANCE,
        target_scope=["*.example.com", "192.168.1.0/24"],
        authorized_by="Test",
        valid_from=datetime.utcnow(),
        valid_until=datetime.utcnow() + timedelta(hours=24)
    )

    assert auth.is_target_in_scope("www.example.com")
    assert auth.is_target_in_scope("api.example.com")
    assert not auth.is_target_in_scope("example.org")
