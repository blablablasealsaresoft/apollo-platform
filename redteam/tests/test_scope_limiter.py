"""
Tests for Scope Limiter
"""

import pytest
from auth_audit.scope_limiter import ScopeLimiter


def test_ip_in_scope():
    """Test IP address scope validation"""
    limiter = ScopeLimiter(
        authorized_ips=["192.168.1.0/24", "10.0.0.100"]
    )

    in_scope, reason = limiter.is_ip_in_scope("192.168.1.50")
    assert in_scope is True

    in_scope, reason = limiter.is_ip_in_scope("10.0.0.100")
    assert in_scope is True

    in_scope, reason = limiter.is_ip_in_scope("172.16.0.1")
    assert in_scope is False


def test_domain_in_scope():
    """Test domain scope validation"""
    limiter = ScopeLimiter(
        authorized_domains=["example.com", "*.test.com"]
    )

    in_scope, reason = limiter.is_domain_in_scope("example.com")
    assert in_scope is True

    in_scope, reason = limiter.is_domain_in_scope("api.test.com")
    assert in_scope is True

    in_scope, reason = limiter.is_domain_in_scope("malicious.com")
    assert in_scope is False


def test_excluded_targets():
    """Test excluded target handling"""
    limiter = ScopeLimiter(
        authorized_ips=["192.168.1.0/24"],
        excluded_ips=["192.168.1.1"]
    )

    in_scope, reason = limiter.is_ip_in_scope("192.168.1.1")
    assert in_scope is False
    assert "excluded" in reason.lower()


def test_validate_target_auto_detect():
    """Test automatic target type detection"""
    limiter = ScopeLimiter(
        authorized_ips=["192.168.1.0/24"],
        authorized_domains=["example.com"]
    )

    # IP
    valid, reason = limiter.validate_target("192.168.1.50")
    assert valid is True

    # Domain
    valid, reason = limiter.validate_target("example.com")
    assert valid is True

    # URL
    valid, reason = limiter.validate_target("https://example.com/path")
    assert valid is True
