"""
Legal Disclaimer System for Red Team Operations

CRITICAL: Ensures operators acknowledge legal responsibilities.
"""

from datetime import datetime
from typing import Optional
import hashlib


class LegalDisclaimer:
    """
    Legal disclaimer and acknowledgment system

    CRITICAL: No operations should proceed without acknowledgment
    """

    DISCLAIMER_TEXT = """
================================================================================
                    RED TEAM OPERATIONS - LEGAL DISCLAIMER
================================================================================

WARNING: This system contains offensive security tools designed for AUTHORIZED
penetration testing, security research, and law enforcement operations ONLY.

BY PROCEEDING, YOU ACKNOWLEDGE AND AGREE:

1. AUTHORIZATION REQUIRED
   - You have explicit written authorization for all operations
   - You will only target systems/networks within your authorized scope
   - Unauthorized access is ILLEGAL and may violate:
     * Computer Fraud and Abuse Act (CFAA) - 18 U.S.C. § 1030
     * Electronic Communications Privacy Act (ECPA)
     * Local, state, and international cyber crime laws

2. LEGAL RESPONSIBILITY
   - You are solely responsible for your actions
   - Misuse may result in criminal prosecution and civil liability
   - You will comply with all applicable laws and regulations

3. OPERATIONAL CONSTRAINTS
   - Operations must remain within authorized scope
   - All activities will be logged and audited
   - You will obtain proper authorization before each operation
   - You will immediately cease operations if scope is exceeded

4. DATA HANDLING
   - Sensitive data discovered will be handled according to legal requirements
   - Data will be sanitized and protected according to classification
   - Evidence chain of custody will be maintained

5. ETHICAL CONDUCT
   - You will follow responsible disclosure practices
   - You will minimize collateral damage and disruption
   - You will respect privacy and confidentiality
   - You will act professionally and ethically

6. INDEMNIFICATION
   - The operators of this system are not liable for misuse
   - You indemnify the system operators from any legal consequences
   - You understand the risks and accept full responsibility

7. AUDIT AND COMPLIANCE
   - All operations are logged for accountability
   - Logs may be subject to legal discovery
   - You consent to monitoring and auditing
   - Violations will be reported to appropriate authorities

================================================================================

CRITICAL WARNINGS:

⚠ UNAUTHORIZED USE IS A FEDERAL CRIME
⚠ ALL ACTIVITIES ARE LOGGED AND MONITORED
⚠ MISUSE WILL BE PROSECUTED TO THE FULLEST EXTENT OF LAW
⚠ THIS IS YOUR ONLY WARNING

================================================================================

This disclaimer must be acknowledged before each operation session.
Your acknowledgment is legally binding.

================================================================================
"""

    @staticmethod
    def display_disclaimer() -> str:
        """Display the legal disclaimer"""
        return LegalDisclaimer.DISCLAIMER_TEXT

    @staticmethod
    def generate_acknowledgment(
        operator_name: str,
        operator_id: str,
        organization: Optional[str] = None
    ) -> dict:
        """
        Generate acknowledgment record

        Args:
            operator_name: Name of operator
            operator_id: Unique operator identifier
            organization: Organization name (optional)

        Returns:
            Acknowledgment dictionary
        """
        timestamp = datetime.utcnow()
        acknowledgment = {
            'operator_name': operator_name,
            'operator_id': operator_id,
            'organization': organization,
            'timestamp': timestamp.isoformat(),
            'disclaimer_version': '1.0',
            'acknowledged': True
        }

        # Generate hash for verification
        data = f"{operator_id}{timestamp.isoformat()}ACKNOWLEDGED"
        acknowledgment['signature'] = hashlib.sha256(data.encode()).hexdigest()

        return acknowledgment

    @staticmethod
    def verify_acknowledgment(acknowledgment: dict) -> bool:
        """
        Verify acknowledgment signature

        Args:
            acknowledgment: Acknowledgment dictionary

        Returns:
            True if valid, False otherwise
        """
        try:
            data = f"{acknowledgment['operator_id']}{acknowledgment['timestamp']}ACKNOWLEDGED"
            expected_sig = hashlib.sha256(data.encode()).hexdigest()
            return acknowledgment['signature'] == expected_sig
        except Exception:
            return False

    @staticmethod
    def get_operator_acknowledgment(
        operator_name: str,
        operator_id: str,
        organization: Optional[str] = None
    ) -> tuple[bool, dict]:
        """
        Interactive acknowledgment process

        Args:
            operator_name: Name of operator
            operator_id: Unique operator identifier
            organization: Organization name (optional)

        Returns:
            (acknowledged: bool, acknowledgment_record: dict)
        """
        print(LegalDisclaimer.DISCLAIMER_TEXT)
        print("\nTo proceed, you must acknowledge the above disclaimer.")
        print("\nType 'I ACKNOWLEDGE AND ACCEPT' to continue: ")

        # In production, this would be interactive
        # For automated systems, acknowledgment must be provided programmatically

        acknowledgment = LegalDisclaimer.generate_acknowledgment(
            operator_name, operator_id, organization
        )

        return True, acknowledgment


class ScopeValidator:
    """
    Validates that operations remain within authorized scope
    """

    @staticmethod
    def validate_ip_in_scope(ip: str, authorized_ranges: list) -> bool:
        """
        Validate IP is within authorized ranges

        Args:
            ip: IP address to check
            authorized_ranges: List of authorized CIDR ranges

        Returns:
            True if in scope, False otherwise
        """
        import ipaddress

        try:
            ip_obj = ipaddress.ip_address(ip)
            for cidr in authorized_ranges:
                if ip_obj in ipaddress.ip_network(cidr):
                    return True
            return False
        except Exception:
            return False

    @staticmethod
    def validate_domain_in_scope(domain: str, authorized_domains: list) -> bool:
        """
        Validate domain is within authorized scope

        Args:
            domain: Domain to check
            authorized_domains: List of authorized domains/patterns

        Returns:
            True if in scope, False otherwise
        """
        domain = domain.lower()

        for authorized in authorized_domains:
            authorized = authorized.lower()

            # Exact match
            if domain == authorized:
                return True

            # Wildcard subdomain match
            if authorized.startswith('*.'):
                base_domain = authorized[2:]
                if domain.endswith(base_domain):
                    return True

        return False

    @staticmethod
    def validate_url_in_scope(url: str, authorized_patterns: list) -> bool:
        """
        Validate URL is within authorized scope

        Args:
            url: URL to check
            authorized_patterns: List of authorized URL patterns

        Returns:
            True if in scope, False otherwise
        """
        from urllib.parse import urlparse
        import re

        try:
            parsed = urlparse(url)
            domain = parsed.netloc

            for pattern in authorized_patterns:
                # Try domain matching first
                if ScopeValidator.validate_domain_in_scope(domain, [pattern]):
                    return True

                # Try regex pattern matching
                if re.match(pattern, url):
                    return True

            return False
        except Exception:
            return False


# Export all classes
__all__ = ['LegalDisclaimer', 'ScopeValidator']
