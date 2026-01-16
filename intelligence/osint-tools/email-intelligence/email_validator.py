"""
Email Validator - Comprehensive email validation
Syntax, MX records, SMTP verification, disposable detection
"""

import re
import dns.resolver
import dns.exception
import socket
import smtplib
from typing import Dict, List, Optional, Any, Tuple
import logging
from dataclasses import dataclass
import json
from datetime import datetime


@dataclass
class ValidationResult:
    """Email validation result"""
    email: str
    valid: bool
    syntax_valid: bool
    domain_valid: bool
    mx_valid: bool
    smtp_valid: bool
    disposable: bool
    role_based: bool
    free_provider: bool
    errors: List[str]
    warnings: List[str]
    mx_records: List[str]
    validation_timestamp: str


class EmailValidator:
    """
    Comprehensive email validation system
    Validates syntax, domain, MX records, and SMTP
    """

    # Email regex pattern (RFC 5322 simplified)
    EMAIL_REGEX = re.compile(
        r'^[a-zA-Z0-9.!#$%&\'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
    )

    # Disposable email domains
    DISPOSABLE_DOMAINS = {
        '10minutemail.com', 'guerrillamail.com', 'mailinator.com', 'temp-mail.org',
        'throwaway.email', 'maildrop.cc', 'yopmail.com', 'tempmail.com',
        'getnada.com', 'trashmail.com', 'fakeinbox.com', 'sharklasers.com',
        'guerrillamail.info', 'guerrillamail.biz', 'guerrillamail.de',
        'grr.la', 'guerrillamail.org', 'spam4.me', 'tmpeml.info',
        'emailondeck.com', '10minutemail.net', 'mintemail.com', 'mytemp.email',
        'tempmail.net', 'throwawaymail.com', 'mohmal.com', 'mailnesia.com',
        'harakirimail.com', 'getairmail.com', 'rootfest.net', 'spamgourmet.com',
        'jetable.org', 'bobmail.info', 'anonymbox.com', 'discard.email'
    }

    # Role-based email prefixes
    ROLE_BASED_PREFIXES = {
        'admin', 'administrator', 'info', 'support', 'sales', 'contact',
        'help', 'service', 'noreply', 'no-reply', 'postmaster', 'webmaster',
        'hostmaster', 'marketing', 'abuse', 'security', 'privacy', 'billing',
        'feedback', 'careers', 'jobs', 'hr', 'legal', 'press', 'media'
    }

    # Free email providers
    FREE_PROVIDERS = {
        'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com',
        'icloud.com', 'mail.com', 'protonmail.com', 'yandex.com', 'zoho.com',
        'gmx.com', 'live.com', 'msn.com', 'yahoo.co.uk', 'yahoo.fr',
        'googlemail.com', 'me.com', 'mac.com', 'tutanota.com', 'mailbox.org',
        'fastmail.com', 'hushmail.com', 'inbox.com', 'aim.com'
    }

    def __init__(self,
                 smtp_timeout: int = 10,
                 dns_timeout: int = 5,
                 verify_smtp: bool = False):
        """
        Initialize Email Validator

        Args:
            smtp_timeout: SMTP connection timeout
            dns_timeout: DNS lookup timeout
            verify_smtp: Enable SMTP verification (can be slow/blocked)
        """
        self.smtp_timeout = smtp_timeout
        self.dns_timeout = dns_timeout
        self.verify_smtp = verify_smtp
        self.logger = self._setup_logging()

        # Configure DNS resolver
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = dns_timeout
        self.resolver.lifetime = dns_timeout

    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration"""
        logger = logging.getLogger('EmailValidator')
        logger.setLevel(logging.INFO)

        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)

        return logger

    def validate(self, email: str) -> Dict[str, Any]:
        """
        Comprehensive email validation

        Args:
            email: Email address to validate

        Returns:
            Validation result dictionary
        """
        email = email.strip().lower()
        errors = []
        warnings = []

        # Syntax validation
        syntax_valid = self._validate_syntax(email)
        if not syntax_valid:
            errors.append("Invalid email syntax")

        # Extract parts
        try:
            local_part, domain = email.split('@')
        except ValueError:
            return self._create_invalid_result(email, ["Invalid email format: missing @"])

        # Domain validation
        domain_valid = self._validate_domain(domain)
        if not domain_valid:
            errors.append(f"Invalid domain: {domain}")

        # MX record check
        mx_valid, mx_records = self._check_mx_records(domain)
        if not mx_valid:
            errors.append(f"No valid MX records for domain: {domain}")

        # SMTP verification (optional)
        smtp_valid = False
        if self.verify_smtp and mx_valid:
            smtp_valid = self._verify_smtp(email, mx_records)
            if not smtp_valid:
                warnings.append("SMTP verification failed (mailbox may not exist)")

        # Disposable email check
        disposable = self._is_disposable(domain)
        if disposable:
            warnings.append("Disposable email detected")

        # Role-based email check
        role_based = self._is_role_based(local_part)
        if role_based:
            warnings.append("Role-based email detected")

        # Free provider check
        free_provider = self._is_free_provider(domain)
        if free_provider:
            warnings.append("Free email provider")

        # Overall validity
        valid = syntax_valid and domain_valid and mx_valid and not disposable

        return {
            'email': email,
            'valid': valid,
            'syntax_valid': syntax_valid,
            'domain_valid': domain_valid,
            'mx_valid': mx_valid,
            'smtp_valid': smtp_valid,
            'disposable': disposable,
            'role_based': role_based,
            'free_provider': free_provider,
            'errors': errors,
            'warnings': warnings,
            'mx_records': mx_records,
            'validation_timestamp': datetime.now().isoformat(),
            'local_part': local_part,
            'domain': domain
        }

    def _validate_syntax(self, email: str) -> bool:
        """
        Validate email syntax

        Args:
            email: Email to validate

        Returns:
            True if syntax is valid
        """
        if not email or len(email) > 320:
            return False

        if not self.EMAIL_REGEX.match(email):
            return False

        try:
            local_part, domain = email.split('@')

            # Local part checks
            if len(local_part) > 64:
                return False
            if local_part.startswith('.') or local_part.endswith('.'):
                return False
            if '..' in local_part:
                return False

            # Domain checks
            if len(domain) > 253:
                return False
            if domain.startswith('-') or domain.endswith('-'):
                return False
            if '..' in domain:
                return False

            # Check domain labels
            labels = domain.split('.')
            if len(labels) < 2:
                return False

            for label in labels:
                if not label or len(label) > 63:
                    return False
                if label.startswith('-') or label.endswith('-'):
                    return False

            return True

        except Exception as e:
            self.logger.error(f"Syntax validation error: {str(e)}")
            return False

    def _validate_domain(self, domain: str) -> bool:
        """
        Validate domain format

        Args:
            domain: Domain to validate

        Returns:
            True if domain is valid
        """
        if not domain or len(domain) > 253:
            return False

        # Check domain regex
        domain_regex = re.compile(
            r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        )

        return bool(domain_regex.match(domain))

    def _check_mx_records(self, domain: str) -> Tuple[bool, List[str]]:
        """
        Check MX records for domain

        Args:
            domain: Domain to check

        Returns:
            Tuple of (valid, mx_records)
        """
        try:
            mx_records = self.resolver.resolve(domain, 'MX')
            mx_hosts = [str(rdata.exchange).rstrip('.') for rdata in mx_records]
            return len(mx_hosts) > 0, mx_hosts
        except dns.resolver.NoAnswer:
            self.logger.warning(f"No MX records for {domain}")
            return False, []
        except dns.resolver.NXDOMAIN:
            self.logger.warning(f"Domain does not exist: {domain}")
            return False, []
        except dns.exception.Timeout:
            self.logger.warning(f"DNS timeout for {domain}")
            return False, []
        except Exception as e:
            self.logger.error(f"MX lookup error for {domain}: {str(e)}")
            return False, []

    def _verify_smtp(self, email: str, mx_records: List[str]) -> bool:
        """
        Verify email via SMTP

        Args:
            email: Email to verify
            mx_records: List of MX hosts

        Returns:
            True if email can receive mail
        """
        if not mx_records:
            return False

        # Try each MX record
        for mx_host in mx_records[:3]:  # Try first 3 MX records
            try:
                # Connect to SMTP server
                server = smtplib.SMTP(timeout=self.smtp_timeout)
                server.set_debuglevel(0)
                server.connect(mx_host)
                server.helo('emailvalidator.com')
                server.mail('verify@emailvalidator.com')
                code, message = server.rcpt(email)
                server.quit()

                # Check response code
                if code == 250:
                    return True
                elif code >= 500:
                    return False

            except smtplib.SMTPServerDisconnected:
                continue
            except smtplib.SMTPConnectError:
                continue
            except socket.timeout:
                continue
            except Exception as e:
                self.logger.debug(f"SMTP verification error for {mx_host}: {str(e)}")
                continue

        return False

    def _is_disposable(self, domain: str) -> bool:
        """
        Check if domain is disposable

        Args:
            domain: Domain to check

        Returns:
            True if disposable
        """
        return domain.lower() in self.DISPOSABLE_DOMAINS

    def _is_role_based(self, local_part: str) -> bool:
        """
        Check if email is role-based

        Args:
            local_part: Local part of email

        Returns:
            True if role-based
        """
        return local_part.lower() in self.ROLE_BASED_PREFIXES

    def _is_free_provider(self, domain: str) -> bool:
        """
        Check if domain is free provider

        Args:
            domain: Domain to check

        Returns:
            True if free provider
        """
        return domain.lower() in self.FREE_PROVIDERS

    def _create_invalid_result(self, email: str, errors: List[str]) -> Dict[str, Any]:
        """Create result for invalid email"""
        return {
            'email': email,
            'valid': False,
            'syntax_valid': False,
            'domain_valid': False,
            'mx_valid': False,
            'smtp_valid': False,
            'disposable': False,
            'role_based': False,
            'free_provider': False,
            'errors': errors,
            'warnings': [],
            'mx_records': [],
            'validation_timestamp': datetime.now().isoformat()
        }

    def get_mx_records(self, domain: str) -> List[str]:
        """Get MX records for domain"""
        _, mx_records = self._check_mx_records(domain)
        return mx_records

    def get_spf_record(self, domain: str) -> Optional[str]:
        """
        Get SPF record for domain

        Args:
            domain: Domain to check

        Returns:
            SPF record string or None
        """
        try:
            txt_records = self.resolver.resolve(domain, 'TXT')
            for record in txt_records:
                txt = str(record).strip('"')
                if txt.startswith('v=spf1'):
                    return txt
            return None
        except Exception as e:
            self.logger.error(f"SPF lookup error for {domain}: {str(e)}")
            return None

    def get_dmarc_record(self, domain: str) -> Optional[str]:
        """
        Get DMARC record for domain

        Args:
            domain: Domain to check

        Returns:
            DMARC record string or None
        """
        try:
            dmarc_domain = f'_dmarc.{domain}'
            txt_records = self.resolver.resolve(dmarc_domain, 'TXT')
            for record in txt_records:
                txt = str(record).strip('"')
                if txt.startswith('v=DMARC1'):
                    return txt
            return None
        except Exception as e:
            self.logger.debug(f"DMARC lookup error for {domain}: {str(e)}")
            return None

    def batch_validate(self, emails: List[str]) -> List[Dict[str, Any]]:
        """
        Validate multiple emails

        Args:
            emails: List of emails to validate

        Returns:
            List of validation results
        """
        return [self.validate(email) for email in emails]

    def add_disposable_domain(self, domain: str) -> None:
        """Add domain to disposable list"""
        self.DISPOSABLE_DOMAINS.add(domain.lower())

    def remove_disposable_domain(self, domain: str) -> None:
        """Remove domain from disposable list"""
        self.DISPOSABLE_DOMAINS.discard(domain.lower())

    def load_disposable_domains(self, filepath: str) -> None:
        """Load disposable domains from file"""
        try:
            with open(filepath, 'r') as f:
                domains = [line.strip().lower() for line in f if line.strip()]
                self.DISPOSABLE_DOMAINS.update(domains)
            self.logger.info(f"Loaded {len(domains)} disposable domains")
        except Exception as e:
            self.logger.error(f"Failed to load disposable domains: {str(e)}")


if __name__ == "__main__":
    # Example usage
    validator = EmailValidator(verify_smtp=False)

    # Single validation
    result = validator.validate("test@example.com")
    print(json.dumps(result, indent=2))

    # Batch validation
    emails = ["user@gmail.com", "admin@company.com", "temp@10minutemail.com"]
    results = validator.batch_validate(emails)

    for result in results:
        print(f"{result['email']}: Valid={result['valid']}")
