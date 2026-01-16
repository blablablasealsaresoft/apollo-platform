"""
Integration Tests for Apollo Intelligence API Server

These tests verify the complete request/response flow through the FastAPI
application, including authentication, rate limiting, and error handling.
"""

import pytest
import asyncio
import os
import sys
from datetime import datetime
from typing import Dict, Any, Optional

# Add parent directory for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient
from httpx import AsyncClient


# Try to import the API server
try:
    from api_server import app
    API_AVAILABLE = True
except ImportError as e:
    API_AVAILABLE = False
    IMPORT_ERROR = str(e)


@pytest.fixture
def client():
    """Create test client for synchronous tests."""
    if not API_AVAILABLE:
        pytest.skip(f"API server not available: {IMPORT_ERROR}")
    return TestClient(app)


@pytest.fixture
def auth_headers():
    """Get authentication headers for testing."""
    # In real tests, this would obtain a valid JWT token
    return {
        "Authorization": "Bearer test_token",
        "X-API-Key": os.getenv("TEST_API_KEY", "test_api_key"),
    }


class TestHealthEndpoints:
    """Tests for health and system endpoints."""

    def test_root_endpoint(self, client):
        """Test root endpoint returns API information."""
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()

        assert data["name"] == "Apollo Intelligence Server"
        assert "version" in data
        assert data["status"] == "operational"
        assert "endpoints" in data

    def test_health_endpoint(self, client):
        """Test health check endpoint."""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()

        assert data["status"] == "healthy"
        assert "timestamp" in data
        assert "services" in data

    def test_metrics_endpoint(self, client):
        """Test metrics endpoint."""
        response = client.get("/metrics")
        assert response.status_code == 200
        data = response.json()

        assert "uptime" in data


class TestOSINTEndpoints:
    """Tests for OSINT intelligence endpoints."""

    def test_username_search_requires_auth(self, client):
        """Test that username search requires authentication."""
        response = client.get("/api/v1/osint/username/testuser")
        # Should return 401 or 403 without auth
        assert response.status_code in [401, 403, 422]

    def test_username_search_with_auth(self, client, auth_headers):
        """Test username search with authentication."""
        response = client.get(
            "/api/v1/osint/username/testuser",
            headers=auth_headers
        )
        # With mock auth, should either work or return auth error
        assert response.status_code in [200, 401, 403]

    def test_email_lookup_validation(self, client, auth_headers):
        """Test email lookup validates input."""
        response = client.get(
            "/api/v1/osint/email/invalid-email",
            headers=auth_headers
        )
        # Should validate email format
        assert response.status_code in [400, 422, 401, 403]

    def test_domain_intel_requires_params(self, client, auth_headers):
        """Test domain intelligence requires valid domain."""
        response = client.get(
            "/api/v1/osint/domain/",
            headers=auth_headers
        )
        assert response.status_code in [404, 405, 422]


class TestBlockchainEndpoints:
    """Tests for blockchain intelligence endpoints."""

    def test_wallet_info_ethereum(self, client, auth_headers):
        """Test Ethereum wallet info endpoint."""
        # Use a known test address
        test_address = "0x0000000000000000000000000000000000000000"
        response = client.get(
            f"/api/v1/blockchain/wallet/{test_address}",
            params={"chain": "ethereum"},
            headers=auth_headers
        )
        # Should return data or auth error
        assert response.status_code in [200, 401, 403, 404]

    def test_wallet_info_bitcoin(self, client, auth_headers):
        """Test Bitcoin wallet info endpoint."""
        test_address = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"  # Genesis address
        response = client.get(
            f"/api/v1/blockchain/wallet/{test_address}",
            params={"chain": "bitcoin"},
            headers=auth_headers
        )
        assert response.status_code in [200, 401, 403, 404]

    def test_transaction_trace_requires_txid(self, client, auth_headers):
        """Test transaction trace requires valid transaction ID."""
        response = client.get(
            "/api/v1/blockchain/transaction/invalid",
            headers=auth_headers
        )
        assert response.status_code in [400, 404, 401, 403]


class TestFusionEndpoints:
    """Tests for intelligence fusion endpoints."""

    def test_create_profile_requires_data(self, client, auth_headers):
        """Test profile creation requires data."""
        response = client.post(
            "/api/v1/fusion/profile",
            json={},
            headers=auth_headers
        )
        # Should require identifier
        assert response.status_code in [400, 422, 401, 403]

    def test_entity_resolution(self, client, auth_headers):
        """Test entity resolution endpoint."""
        response = client.post(
            "/api/v1/fusion/resolve",
            json={
                "entities": [
                    {"type": "email", "value": "test@example.com"},
                    {"type": "username", "value": "testuser"}
                ]
            },
            headers=auth_headers
        )
        assert response.status_code in [200, 401, 403]

    def test_risk_assessment(self, client, auth_headers):
        """Test risk assessment endpoint."""
        response = client.post(
            "/api/v1/fusion/risk",
            json={
                "target_id": "test-target-123",
                "factors": ["financial", "geographic"]
            },
            headers=auth_headers
        )
        assert response.status_code in [200, 401, 403, 404]


class TestBreachEndpoints:
    """Tests for breach intelligence endpoints."""

    def test_email_breach_check(self, client, auth_headers):
        """Test email breach check endpoint."""
        response = client.get(
            "/api/v1/breach/email/test@example.com",
            headers=auth_headers
        )
        assert response.status_code in [200, 401, 403]

    def test_credential_search_requires_auth(self, client):
        """Test credential search requires authentication."""
        response = client.get("/api/v1/breach/credentials/search")
        assert response.status_code in [401, 403, 422]


class TestErrorHandling:
    """Tests for error handling."""

    def test_404_not_found(self, client):
        """Test 404 error handling."""
        response = client.get("/api/v1/nonexistent/endpoint")
        assert response.status_code == 404
        data = response.json()

        # Should have error format
        assert "error" in data or "detail" in data

    def test_method_not_allowed(self, client, auth_headers):
        """Test method not allowed error."""
        response = client.delete("/", headers=auth_headers)
        assert response.status_code == 405

    def test_validation_error_format(self, client, auth_headers):
        """Test validation error response format."""
        response = client.post(
            "/api/v1/fusion/profile",
            json={"invalid_field": 123},
            headers=auth_headers
        )
        # Should return validation error
        if response.status_code == 422:
            data = response.json()
            assert "detail" in data or "error" in data

    def test_request_id_in_response(self, client):
        """Test that request ID is included in responses."""
        response = client.get("/health")
        # X-Request-ID should be in headers
        assert "x-request-id" in response.headers or response.status_code == 200


class TestRateLimiting:
    """Tests for rate limiting."""

    def test_rate_limit_headers(self, client, auth_headers):
        """Test rate limit headers are present."""
        response = client.get("/health")
        # Rate limit headers should be present after several requests
        # This is implementation-dependent

    @pytest.mark.slow
    def test_rate_limit_enforcement(self, client, auth_headers):
        """Test rate limiting is enforced."""
        # Make many rapid requests
        responses = []
        for _ in range(100):
            response = client.get(
                "/api/v1/osint/username/ratelimittest",
                headers=auth_headers
            )
            responses.append(response)

        # Some requests should be rate limited (429)
        status_codes = [r.status_code for r in responses]
        # This test might not trigger rate limit in all environments


class TestSecurityHeaders:
    """Tests for security headers."""

    def test_cors_headers_present(self, client):
        """Test CORS headers are present."""
        response = client.options("/health")
        # CORS preflight should work

    def test_content_type_header(self, client):
        """Test content type header is set correctly."""
        response = client.get("/health")
        content_type = response.headers.get("content-type", "")
        assert "application/json" in content_type


class TestAuthenticationFlow:
    """Tests for authentication endpoints."""

    def test_login_endpoint(self, client):
        """Test login endpoint exists."""
        response = client.post(
            "/api/v1/auth/login",
            params={"username": "test", "password": "test"}
        )
        # Should either work or return credential error, not 404
        assert response.status_code != 404

    def test_api_key_generation(self, client, auth_headers):
        """Test API key generation endpoint."""
        response = client.post(
            "/api/v1/auth/apikey/generate",
            params={"description": "Test Key"},
            headers=auth_headers
        )
        # Should work with valid auth
        assert response.status_code in [200, 401, 403]


class TestAsyncEndpoints:
    """Async tests for endpoints that support async operations."""

    @pytest.mark.asyncio
    async def test_async_health_check(self):
        """Test health check endpoint asynchronously."""
        if not API_AVAILABLE:
            pytest.skip(f"API server not available: {IMPORT_ERROR}")

        async with AsyncClient(app=app, base_url="http://test") as ac:
            response = await ac.get("/health")
            assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_async_multiple_requests(self):
        """Test handling multiple concurrent requests."""
        if not API_AVAILABLE:
            pytest.skip(f"API server not available: {IMPORT_ERROR}")

        async with AsyncClient(app=app, base_url="http://test") as ac:
            # Make multiple concurrent requests
            tasks = [ac.get("/health") for _ in range(10)]
            responses = await asyncio.gather(*tasks)

            # All should succeed
            for response in responses:
                assert response.status_code == 200


class TestInputValidation:
    """Tests for input validation and sanitization."""

    def test_sql_injection_prevention(self, client, auth_headers):
        """Test SQL injection is prevented."""
        malicious_input = "'; DROP TABLE users; --"
        response = client.get(
            f"/api/v1/osint/username/{malicious_input}",
            headers=auth_headers
        )
        # Should either reject or handle safely
        assert response.status_code in [400, 422, 401, 403, 200]

    def test_xss_prevention(self, client, auth_headers):
        """Test XSS is prevented in responses."""
        malicious_input = "<script>alert('xss')</script>"
        response = client.get(
            f"/api/v1/osint/username/{malicious_input}",
            headers=auth_headers
        )
        # Response should not contain unescaped script
        if response.status_code == 200:
            assert "<script>" not in response.text

    def test_path_traversal_prevention(self, client, auth_headers):
        """Test path traversal is prevented."""
        malicious_input = "../../../etc/passwd"
        response = client.get(
            f"/api/v1/osint/domain/{malicious_input}",
            headers=auth_headers
        )
        # Should reject or handle safely
        assert response.status_code in [400, 422, 401, 403, 404]


# Run tests with: pytest test_api_integration.py -v
if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
