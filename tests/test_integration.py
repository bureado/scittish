"""
Integration tests requiring external services.

These tests require:
- A SCITT ledger running at https://localhost:8000
- An OCI registry running at localhost:5000

Run with: pytest -m integration
"""

import pytest
import httpx


@pytest.mark.integration
class TestSCITTLedgerIntegration:
    """Tests that require a running SCITT ledger."""
    
    def test_scitt_ledger_is_available(self):
        """Should be able to connect to SCITT ledger."""
        try:
            # SCITT ledger uses HTTPS with self-signed cert in development
            # verify=False is acceptable for integration tests against local dev environment
            response = httpx.get("https://localhost:8000/node/network", timeout=5.0, verify=False)
            # SCITT ledger should respond (any status is fine, just checking connectivity)
            assert response.status_code in [200, 404, 405]  # Common responses
        except httpx.RequestError as e:
            pytest.fail(f"Cannot connect to SCITT ledger at https://localhost:8000: {e}")


@pytest.mark.integration
class TestOCIRegistryIntegration:
    """Tests that require a running OCI registry."""
    
    def test_oci_registry_is_available(self):
        """Should be able to connect to OCI registry."""
        try:
            response = httpx.get("http://localhost:5000/v2/", timeout=5.0)
            # OCI registry should respond to the /v2/ endpoint
            assert response.status_code == 200
        except httpx.RequestError as e:
            pytest.fail(f"Cannot connect to OCI registry at http://localhost:5000: {e}")
