"""
Scope Limiter for Red Team Operations

Ensures operations remain within authorized boundaries.
"""

from typing import List, Set, Optional, Dict
from datetime import datetime
import ipaddress
import re
from urllib.parse import urlparse


class ScopeLimiter:
    """
    Enforces scope limitations for red team operations

    CRITICAL: Prevents scope creep and unauthorized targets
    """

    def __init__(
        self,
        authorized_ips: Optional[List[str]] = None,
        authorized_domains: Optional[List[str]] = None,
        authorized_urls: Optional[List[str]] = None,
        excluded_ips: Optional[List[str]] = None,
        excluded_domains: Optional[List[str]] = None,
        constraints: Optional[Dict] = None
    ):
        """
        Initialize scope limiter

        Args:
            authorized_ips: List of authorized IP addresses/CIDR ranges
            authorized_domains: List of authorized domains (supports wildcards)
            authorized_urls: List of authorized URL patterns
            excluded_ips: List of explicitly excluded IPs
            excluded_domains: List of explicitly excluded domains
            constraints: Additional constraints (rate limits, etc.)
        """
        self.authorized_ips = authorized_ips or []
        self.authorized_domains = authorized_domains or []
        self.authorized_urls = authorized_urls or []
        self.excluded_ips = excluded_ips or []
        self.excluded_domains = excluded_domains or []
        self.constraints = constraints or {}

        # Parse IP ranges
        self.ip_networks = []
        for ip_range in self.authorized_ips:
            try:
                self.ip_networks.append(ipaddress.ip_network(ip_range))
            except Exception as e:
                print(f"Warning: Invalid IP range {ip_range}: {e}")

        self.excluded_networks = []
        for ip_range in self.excluded_ips:
            try:
                self.excluded_networks.append(ipaddress.ip_network(ip_range))
            except Exception as e:
                print(f"Warning: Invalid excluded IP range {ip_range}: {e}")

    def is_ip_in_scope(self, ip: str) -> tuple[bool, str]:
        """
        Check if IP is within authorized scope

        Args:
            ip: IP address to check

        Returns:
            (in_scope: bool, reason: str)
        """
        try:
            ip_obj = ipaddress.ip_address(ip)

            # Check if excluded
            for network in self.excluded_networks:
                if ip_obj in network:
                    return False, f"IP {ip} is explicitly excluded"

            # Check if in authorized scope
            if not self.ip_networks:
                return False, "No authorized IP ranges configured"

            for network in self.ip_networks:
                if ip_obj in network:
                    return True, "In scope"

            return False, f"IP {ip} not in authorized ranges"

        except Exception as e:
            return False, f"Invalid IP address: {e}"

    def is_domain_in_scope(self, domain: str) -> tuple[bool, str]:
        """
        Check if domain is within authorized scope

        Args:
            domain: Domain to check

        Returns:
            (in_scope: bool, reason: str)
        """
        domain = domain.lower().strip()

        # Check if excluded
        for excluded in self.excluded_domains:
            excluded = excluded.lower()
            if domain == excluded or domain.endswith(f".{excluded}"):
                return False, f"Domain {domain} is explicitly excluded"

        # Check if in authorized scope
        if not self.authorized_domains:
            return False, "No authorized domains configured"

        for authorized in self.authorized_domains:
            authorized = authorized.lower()

            # Exact match
            if domain == authorized:
                return True, "Exact match"

            # Wildcard subdomain
            if authorized.startswith('*.'):
                base_domain = authorized[2:]
                if domain == base_domain or domain.endswith(f".{base_domain}"):
                    return True, "Wildcard match"

            # Subdomain of authorized domain
            if domain.endswith(f".{authorized}"):
                return True, "Subdomain match"

        return False, f"Domain {domain} not in authorized scope"

    def is_url_in_scope(self, url: str) -> tuple[bool, str]:
        """
        Check if URL is within authorized scope

        Args:
            url: URL to check

        Returns:
            (in_scope: bool, reason: str)
        """
        try:
            parsed = urlparse(url)
            domain = parsed.netloc

            # Extract domain without port
            if ':' in domain:
                domain = domain.split(':')[0]

            # Check domain scope
            in_scope, reason = self.is_domain_in_scope(domain)
            if not in_scope:
                return False, reason

            # Check URL patterns if specified
            if self.authorized_urls:
                for pattern in self.authorized_urls:
                    if re.match(pattern, url):
                        return True, "URL pattern match"
                return False, "URL doesn't match authorized patterns"

            return True, "In scope"

        except Exception as e:
            return False, f"Invalid URL: {e}"

    def validate_target(self, target: str) -> tuple[bool, str]:
        """
        Validate any type of target (IP, domain, or URL)

        Args:
            target: Target to validate

        Returns:
            (valid: bool, reason: str)
        """
        target = target.strip()

        # Try as IP first
        try:
            ipaddress.ip_address(target)
            return self.is_ip_in_scope(target)
        except:
            pass

        # Try as URL
        if target.startswith(('http://', 'https://')):
            return self.is_url_in_scope(target)

        # Try as domain
        return self.is_domain_in_scope(target)

    def validate_targets(self, targets: List[str]) -> Dict[str, tuple[bool, str]]:
        """
        Validate multiple targets

        Args:
            targets: List of targets to validate

        Returns:
            Dictionary mapping target to (valid, reason)
        """
        results = {}
        for target in targets:
            results[target] = self.validate_target(target)
        return results

    def get_valid_targets(self, targets: List[str]) -> List[str]:
        """
        Filter list of targets to only valid ones

        Args:
            targets: List of targets

        Returns:
            List of valid targets
        """
        valid = []
        for target in targets:
            is_valid, _ = self.validate_target(target)
            if is_valid:
                valid.append(target)
        return valid

    def check_rate_limit(self, operation_type: str) -> tuple[bool, str]:
        """
        Check if rate limit allows operation

        Args:
            operation_type: Type of operation

        Returns:
            (allowed: bool, reason: str)
        """
        if 'rate_limits' not in self.constraints:
            return True, "No rate limits configured"

        rate_limits = self.constraints['rate_limits']
        if operation_type not in rate_limits:
            return True, "No rate limit for this operation"

        # In production, this would track actual rates
        # For now, just return the limit info
        limit = rate_limits[operation_type]
        return True, f"Rate limit: {limit}"

    def to_dict(self) -> Dict:
        """Export scope configuration"""
        return {
            'authorized_ips': self.authorized_ips,
            'authorized_domains': self.authorized_domains,
            'authorized_urls': self.authorized_urls,
            'excluded_ips': self.excluded_ips,
            'excluded_domains': self.excluded_domains,
            'constraints': self.constraints
        }

    @classmethod
    def from_dict(cls, data: Dict) -> 'ScopeLimiter':
        """Create from configuration dictionary"""
        return cls(
            authorized_ips=data.get('authorized_ips'),
            authorized_domains=data.get('authorized_domains'),
            authorized_urls=data.get('authorized_urls'),
            excluded_ips=data.get('excluded_ips'),
            excluded_domains=data.get('excluded_domains'),
            constraints=data.get('constraints')
        )


# Decorator for scope validation
def require_scope_validation(scope_limiter: ScopeLimiter):
    """
    Decorator to validate target scope before execution

    Usage:
        @require_scope_validation(scope_limiter)
        def scan_target(target, **kwargs):
            pass
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            target = kwargs.get('target') or (args[0] if args else None)

            if not target:
                raise ValueError("Target required for scope validation")

            valid, reason = scope_limiter.validate_target(target)

            if not valid:
                raise PermissionError(
                    f"Target {target} is out of scope: {reason}\n"
                    f"This operation would violate authorized scope."
                )

            return func(*args, **kwargs)

        return wrapper
    return decorator
