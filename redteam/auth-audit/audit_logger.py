"""
Audit Logger for Red Team Operations

Comprehensive logging of all operations for accountability and forensics.
"""

import os
import json
import hashlib
from datetime import datetime
from typing import Dict, List, Optional, Any
from pathlib import Path
from enum import Enum
import uuid


class AuditEventType(Enum):
    """Types of audit events"""
    AUTHORIZATION_CREATED = "authorization_created"
    AUTHORIZATION_VERIFIED = "authorization_verified"
    AUTHORIZATION_DENIED = "authorization_denied"
    AUTHORIZATION_REVOKED = "authorization_revoked"
    OPERATION_STARTED = "operation_started"
    OPERATION_COMPLETED = "operation_completed"
    OPERATION_FAILED = "operation_failed"
    TARGET_SCANNED = "target_scanned"
    EXPLOIT_ATTEMPTED = "exploit_attempted"
    PAYLOAD_DEPLOYED = "payload_deployed"
    C2_SESSION_ESTABLISHED = "c2_session_established"
    C2_TASK_EXECUTED = "c2_task_executed"
    DATA_EXFILTRATED = "data_exfiltrated"
    CREDENTIALS_CAPTURED = "credentials_captured"
    FINDING_IDENTIFIED = "finding_identified"
    SECURITY_VIOLATION = "security_violation"


class AuditSeverity(Enum):
    """Severity levels for audit events"""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class AuditEvent:
    """Represents a single audit event"""

    def __init__(
        self,
        event_type: AuditEventType,
        severity: AuditSeverity,
        operation_id: Optional[str],
        target: Optional[str],
        operator: str,
        details: Dict[str, Any],
        success: bool = True
    ):
        self.event_id = str(uuid.uuid4())
        self.timestamp = datetime.utcnow()
        self.event_type = event_type
        self.severity = severity
        self.operation_id = operation_id
        self.target = target
        self.operator = operator
        self.details = details
        self.success = success
        self.hash = self._compute_hash()

    def _compute_hash(self) -> str:
        """Compute hash for integrity verification"""
        data = f"{self.event_id}{self.timestamp.isoformat()}{self.event_type.value}{self.operator}"
        return hashlib.sha256(data.encode()).hexdigest()

    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            'event_id': self.event_id,
            'timestamp': self.timestamp.isoformat(),
            'event_type': self.event_type.value,
            'severity': self.severity.value,
            'operation_id': self.operation_id,
            'target': self.target,
            'operator': self.operator,
            'details': self.details,
            'success': self.success,
            'hash': self.hash
        }

    @classmethod
    def from_dict(cls, data: Dict) -> 'AuditEvent':
        """Create from dictionary"""
        event = cls(
            event_type=AuditEventType(data['event_type']),
            severity=AuditSeverity(data['severity']),
            operation_id=data.get('operation_id'),
            target=data.get('target'),
            operator=data['operator'],
            details=data['details'],
            success=data.get('success', True)
        )
        event.event_id = data['event_id']
        event.timestamp = datetime.fromisoformat(data['timestamp'])
        event.hash = data['hash']
        return event


class AuditLogger:
    """
    Comprehensive audit logging for red team operations

    CRITICAL: All operations must be logged for accountability
    """

    def __init__(self, log_dir: Optional[str] = None):
        """Initialize audit logger"""
        if log_dir is None:
            log_dir = os.path.join(
                os.path.dirname(__file__),
                '../../data/audit-logs'
            )
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.current_log_file = self._get_log_file()
        self.events: List[AuditEvent] = []

    def _get_log_file(self) -> Path:
        """Get current log file path"""
        date_str = datetime.utcnow().strftime('%Y-%m-%d')
        return self.log_dir / f"audit-{date_str}.jsonl"

    def log_event(
        self,
        event_type: AuditEventType,
        operator: str,
        severity: AuditSeverity = AuditSeverity.INFO,
        operation_id: Optional[str] = None,
        target: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        success: bool = True
    ) -> AuditEvent:
        """
        Log an audit event

        Args:
            event_type: Type of event
            operator: Identity of operator
            severity: Severity level
            operation_id: Associated operation ID
            target: Target of operation
            details: Additional details
            success: Whether operation succeeded

        Returns:
            AuditEvent object
        """
        event = AuditEvent(
            event_type=event_type,
            severity=severity,
            operation_id=operation_id,
            target=target,
            operator=operator,
            details=details or {},
            success=success
        )

        self.events.append(event)
        self._write_event(event)

        # Alert on critical events
        if severity == AuditSeverity.CRITICAL:
            self._alert_critical_event(event)

        return event

    def _write_event(self, event: AuditEvent):
        """Write event to log file"""
        try:
            # Check if we need to rotate log file
            if self.current_log_file != self._get_log_file():
                self.current_log_file = self._get_log_file()

            with open(self.current_log_file, 'a') as f:
                f.write(json.dumps(event.to_dict()) + '\n')
        except Exception as e:
            print(f"CRITICAL: Failed to write audit log: {e}")

    def _alert_critical_event(self, event: AuditEvent):
        """Alert on critical events"""
        # In production, this would send alerts via SIEM, email, etc.
        print(f"\n{'='*80}")
        print(f"CRITICAL AUDIT EVENT")
        print(f"{'='*80}")
        print(f"Event: {event.event_type.value}")
        print(f"Operator: {event.operator}")
        print(f"Target: {event.target}")
        print(f"Time: {event.timestamp.isoformat()}")
        print(f"Details: {json.dumps(event.details, indent=2)}")
        print(f"{'='*80}\n")

    def query_events(
        self,
        event_type: Optional[AuditEventType] = None,
        operation_id: Optional[str] = None,
        target: Optional[str] = None,
        operator: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        severity: Optional[AuditSeverity] = None
    ) -> List[AuditEvent]:
        """
        Query audit events

        Args:
            event_type: Filter by event type
            operation_id: Filter by operation ID
            target: Filter by target
            operator: Filter by operator
            start_time: Filter by start time
            end_time: Filter by end time
            severity: Filter by severity

        Returns:
            List of matching audit events
        """
        results = []

        # Load events from all log files
        for log_file in self.log_dir.glob("audit-*.jsonl"):
            try:
                with open(log_file, 'r') as f:
                    for line in f:
                        event_data = json.loads(line.strip())
                        event = AuditEvent.from_dict(event_data)

                        # Apply filters
                        if event_type and event.event_type != event_type:
                            continue
                        if operation_id and event.operation_id != operation_id:
                            continue
                        if target and event.target != target:
                            continue
                        if operator and event.operator != operator:
                            continue
                        if start_time and event.timestamp < start_time:
                            continue
                        if end_time and event.timestamp > end_time:
                            continue
                        if severity and event.severity != severity:
                            continue

                        results.append(event)
            except Exception as e:
                print(f"Error reading log file {log_file}: {e}")

        return sorted(results, key=lambda e: e.timestamp)

    def verify_log_integrity(self) -> tuple[bool, List[str]]:
        """
        Verify integrity of audit logs

        Returns:
            (valid: bool, errors: List[str])
        """
        errors = []

        for log_file in self.log_dir.glob("audit-*.jsonl"):
            try:
                with open(log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        event_data = json.loads(line.strip())
                        event = AuditEvent.from_dict(event_data)

                        # Recompute hash
                        expected_hash = event._compute_hash()
                        if event.hash != expected_hash:
                            errors.append(
                                f"{log_file}:{line_num} - Hash mismatch"
                            )
            except Exception as e:
                errors.append(f"{log_file} - Read error: {e}")

        return len(errors) == 0, errors

    def generate_operation_report(self, operation_id: str) -> Dict:
        """
        Generate report for specific operation

        Args:
            operation_id: Operation ID

        Returns:
            Dictionary containing operation report
        """
        events = self.query_events(operation_id=operation_id)

        if not events:
            return {'error': 'No events found for operation'}

        # Analyze events
        event_types = {}
        targets = set()
        operators = set()
        failures = []

        for event in events:
            event_types[event.event_type.value] = event_types.get(
                event.event_type.value, 0
            ) + 1
            if event.target:
                targets.add(event.target)
            operators.add(event.operator)
            if not event.success:
                failures.append(event)

        return {
            'operation_id': operation_id,
            'start_time': events[0].timestamp.isoformat(),
            'end_time': events[-1].timestamp.isoformat(),
            'duration': str(events[-1].timestamp - events[0].timestamp),
            'total_events': len(events),
            'event_types': event_types,
            'targets': list(targets),
            'operators': list(operators),
            'failures': len(failures),
            'events': [e.to_dict() for e in events]
        }


# Context manager for operation logging
class OperationContext:
    """Context manager for logging operation lifecycle"""

    def __init__(
        self,
        audit_logger: AuditLogger,
        operation_type: str,
        operator: str,
        operation_id: Optional[str] = None,
        target: Optional[str] = None,
        details: Optional[Dict] = None
    ):
        self.audit_logger = audit_logger
        self.operation_type = operation_type
        self.operator = operator
        self.operation_id = operation_id or str(uuid.uuid4())
        self.target = target
        self.details = details or {}

    def __enter__(self):
        """Log operation start"""
        self.audit_logger.log_event(
            event_type=AuditEventType.OPERATION_STARTED,
            operator=self.operator,
            operation_id=self.operation_id,
            target=self.target,
            details={
                'operation_type': self.operation_type,
                **self.details
            }
        )
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Log operation completion or failure"""
        if exc_type is None:
            self.audit_logger.log_event(
                event_type=AuditEventType.OPERATION_COMPLETED,
                operator=self.operator,
                operation_id=self.operation_id,
                target=self.target,
                details={
                    'operation_type': self.operation_type,
                    **self.details
                },
                success=True
            )
        else:
            self.audit_logger.log_event(
                event_type=AuditEventType.OPERATION_FAILED,
                operator=self.operator,
                severity=AuditSeverity.WARNING,
                operation_id=self.operation_id,
                target=self.target,
                details={
                    'operation_type': self.operation_type,
                    'error': str(exc_val),
                    **self.details
                },
                success=False
            )
        return False  # Don't suppress exceptions
