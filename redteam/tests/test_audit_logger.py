"""
Tests for Audit Logger
"""

import pytest
from auth_audit.audit_logger import (
    AuditLogger,
    AuditEventType,
    AuditSeverity
)


def test_log_event():
    """Test logging an event"""
    logger = AuditLogger()

    event = logger.log_event(
        event_type=AuditEventType.OPERATION_STARTED,
        operator="test_user",
        target="192.168.1.1",
        details={"operation": "test_scan"}
    )

    assert event is not None
    assert event.event_type == AuditEventType.OPERATION_STARTED
    assert event.operator == "test_user"


def test_query_events_by_operator():
    """Test querying events by operator"""
    logger = AuditLogger()

    logger.log_event(
        event_type=AuditEventType.OPERATION_STARTED,
        operator="operator1",
        details={}
    )

    logger.log_event(
        event_type=AuditEventType.OPERATION_STARTED,
        operator="operator2",
        details={}
    )

    events = logger.query_events(operator="operator1")
    assert len(events) >= 1
    assert all(e.operator == "operator1" for e in events)


def test_verify_log_integrity():
    """Test audit log integrity verification"""
    logger = AuditLogger()

    logger.log_event(
        event_type=AuditEventType.OPERATION_COMPLETED,
        operator="test",
        details={}
    )

    valid, errors = logger.verify_log_integrity()
    assert valid is True
    assert len(errors) == 0


def test_operation_context():
    """Test operation context manager"""
    from auth_audit.audit_logger import OperationContext

    logger = AuditLogger()

    with OperationContext(
        audit_logger=logger,
        operation_type="test_operation",
        operator="test_user",
        target="test_target"
    ) as ctx:
        pass  # Operation logic here

    events = logger.query_events(operation_id=ctx.operation_id)
    assert len(events) >= 2  # Start and complete events
