"""
Integration tests requiring external services.

These tests require:
- A SCITT ledger running at https://localhost:8000
- An OCI registry running at localhost:5000
- The scittish REST API running at http://localhost:8080

Run with: pytest -m integration
"""

import hashlib
import json
import os
import subprocess
import tempfile
import time
from pathlib import Path

import pytest
import httpx


# Test fixtures and constants
SCITT_URL = "https://localhost:8000"
OCI_REGISTRY = "localhost:5000"
SCITTISH_API_URL = "http://localhost:8080"

SAMPLE_PAYLOAD = b"Hello, SCITT!"
SAMPLE_PAYLOAD_HASH = hashlib.sha256(SAMPLE_PAYLOAD).hexdigest()

SAMPLE_SPDX_SBOM = {
    "spdxVersion": "SPDX-2.3",
    "dataLicense": "CC0-1.0",
    "SPDXID": "SPDXRef-DOCUMENT",
    "name": "test-sbom",
    "documentNamespace": "https://example.com/test-sbom/v1.0",
    "creationInfo": {
        "created": "2024-01-01T00:00:00Z",
        "creators": ["Tool: scittish-test"]
    },
    "packages": []
}


@pytest.mark.integration
class TestSCITTLedgerIntegration:
    """Tests that require a running SCITT ledger."""
    
    def test_scitt_ledger_is_available(self):
        """Should be able to connect to SCITT ledger."""
        try:
            response = httpx.get(f"{SCITT_URL}/node/network", timeout=5.0, verify=False)
            assert response.status_code in [200, 404, 405]
        except httpx.RequestError as e:
            pytest.fail(f"Cannot connect to SCITT ledger at {SCITT_URL}: {e}")


@pytest.mark.integration
class TestOCIRegistryIntegration:
    """Tests that require a running OCI registry."""
    
    def test_oci_registry_is_available(self):
        """Should be able to connect to OCI registry."""
        try:
            response = httpx.get(f"http://{OCI_REGISTRY}/v2/", timeout=5.0)
            assert response.status_code == 200
        except httpx.RequestError as e:
            pytest.fail(f"Cannot connect to OCI registry at {OCI_REGISTRY}: {e}")


@pytest.mark.integration
class TestScittishAPIIntegration:
    """Tests for the scittish REST API."""
    
    def test_api_health_check(self):
        """Should respond to health check."""
        response = httpx.get(f"{SCITTISH_API_URL}/health", timeout=5.0)
        assert response.status_code == 200
        assert response.json()["status"] == "ok"
    
    def test_api_properties(self):
        """Should return service properties."""
        response = httpx.get(f"{SCITTISH_API_URL}/properties", timeout=5.0)
        assert response.status_code == 200
        data = response.json()
        assert "certificate_chain" in data
        assert "scitt_url" in data
        assert data["scitt_url"] == SCITT_URL
    
    def test_sign_simple_payload(self):
        """Should sign a simple payload and return a receipt."""
        # Submit payload
        response = httpx.post(
            f"{SCITTISH_API_URL}/sign",
            content=SAMPLE_PAYLOAD,
            headers={"Content-Type": "application/octet-stream"},
            timeout=10.0,
        )
        
        # Should get 202 Accepted with job info
        assert response.status_code == 202
        job_data = response.json()
        assert "job_id" in job_data
        assert job_data["status"] == "pending"
        
        job_id = job_data["job_id"]
        poll_url = f"{SCITTISH_API_URL}/sign/{job_id}"
        
        # Poll for completion (up to 60 seconds)
        receipt = None
        for _ in range(60):
            poll_response = httpx.get(poll_url, timeout=10.0)
            if poll_response.status_code == 200:
                content_type = poll_response.headers.get("content-type", "")
                if "application/cose" in content_type:
                    receipt = poll_response.content
                    break
                # Check if job failed
                if poll_response.headers.get("content-type") == "application/json":
                    data = poll_response.json()
                    if data.get("status") == "failed":
                        pytest.fail(f"Job failed: {data.get('error')}")
            time.sleep(1)
        
        assert receipt is not None, "Timed out waiting for receipt"
        assert len(receipt) > 0
    
    def test_sign_with_explicit_subject(self):
        """Should sign a payload with an explicit subject."""
        subject = "test:explicit-subject:v1"
        
        response = httpx.post(
            f"{SCITTISH_API_URL}/sign",
            content=b"payload-with-subject",
            headers={
                "Content-Type": "application/octet-stream",
                "X-Scittish-Subject": subject,
            },
            timeout=10.0,
        )
        
        assert response.status_code == 202
        job_id = response.json()["job_id"]
        
        # Poll for completion
        receipt = self._poll_for_receipt(job_id)
        assert receipt is not None
    
    def test_sign_spdx_sbom_auto_subject(self):
        """Should extract subject from SPDX SBOM documentNamespace."""
        sbom_payload = json.dumps(SAMPLE_SPDX_SBOM).encode()
        
        response = httpx.post(
            f"{SCITTISH_API_URL}/sign",
            content=sbom_payload,
            headers={"Content-Type": "application/spdx+json"},
            timeout=10.0,
        )
        
        assert response.status_code == 202
        job_id = response.json()["job_id"]
        
        # Poll for completion
        receipt = self._poll_for_receipt(job_id)
        assert receipt is not None
    
    def test_sign_cached_receipt(self):
        """Should return cached receipt for duplicate payload."""
        unique_payload = f"cached-test-{time.time()}".encode()
        
        # First submission
        response1 = httpx.post(
            f"{SCITTISH_API_URL}/sign",
            content=unique_payload,
            headers={"Content-Type": "application/octet-stream"},
            timeout=10.0,
        )
        assert response1.status_code == 202
        job_id = response1.json()["job_id"]
        
        # Wait for first to complete
        receipt1 = self._poll_for_receipt(job_id)
        assert receipt1 is not None
        
        # Second submission with same payload - should hit cache
        response2 = httpx.post(
            f"{SCITTISH_API_URL}/sign",
            content=unique_payload,
            headers={"Content-Type": "application/octet-stream"},
            timeout=10.0,
        )
        
        # Should return 200 immediately with cache hit
        assert response2.status_code == 200
        assert response2.headers.get("X-Scittish-Cache-Hit") == "true"
        assert response2.content == receipt1
    
    def test_sign_without_subject(self):
        """Should sign a payload without subject (server default)."""
        response = httpx.post(
            f"{SCITTISH_API_URL}/sign",
            content=b"no-subject-payload",
            headers={"Content-Type": "text/plain"},
            timeout=10.0,
        )
        
        assert response.status_code == 202
        job_id = response.json()["job_id"]
        receipt = self._poll_for_receipt(job_id)
        assert receipt is not None
    
    def _poll_for_receipt(self, job_id: str, timeout: int = 60) -> bytes:
        """Poll for job completion and return receipt."""
        poll_url = f"{SCITTISH_API_URL}/sign/{job_id}"
        
        for _ in range(timeout):
            response = httpx.get(poll_url, timeout=10.0)
            if response.status_code == 200:
                content_type = response.headers.get("content-type", "")
                if "application/cose" in content_type:
                    return response.content
            time.sleep(1)
        
        return None


@pytest.mark.integration
class TestScittishCLIIntegration:
    """Tests for the scittish-cli command-line tool."""
    
    @pytest.fixture(autouse=True)
    def setup_cli_environment(self, tmp_path):
        """Set up a clean environment for CLI tests."""
        self.work_dir = tmp_path
        self.config_dir = tmp_path / ".config" / "scittish"
        self.env = os.environ.copy()
        self.env["XDG_CONFIG_HOME"] = str(tmp_path / ".config")
        self.env["HOME"] = str(tmp_path)
        
        # Create test payload file
        self.test_file = tmp_path / "test-payload.txt"
        self.test_file.write_text("Hello from scittish-cli test!")
        
        # Create SPDX SBOM file
        self.spdx_file = tmp_path / "test-sbom.spdx.json"
        self.spdx_file.write_text(json.dumps(SAMPLE_SPDX_SBOM))
    
    def _run_cli(self, *args, cwd=None) -> subprocess.CompletedProcess:
        """Run scittish-cli command."""
        cmd = ["scittish-cli"] + list(args)
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=cwd or self.work_dir,
            env=self.env,
            timeout=120,
        )
    
    def test_cli_version(self):
        """Should show version."""
        result = self._run_cli("--version")
        assert result.returncode == 0
        assert "scittish-cli" in result.stdout
    
    def test_cli_help(self):
        """Should show help."""
        result = self._run_cli("--help")
        assert result.returncode == 0
        assert "set" in result.stdout
        assert "push" in result.stdout
    
    def test_cli_set_server(self):
        """Should configure server and fetch properties."""
        result = self._run_cli("set", "server", SCITTISH_API_URL)
        assert result.returncode == 0
        assert "Server configured successfully" in result.stdout
        
        # Verify config was saved
        config_file = self.config_dir / "config.json"
        assert config_file.exists()
        config = json.loads(config_file.read_text())
        assert config["server_uri"] == SCITTISH_API_URL
        assert config["scitt_url"] == SCITT_URL
    
    def test_cli_set_subject(self):
        """Should set subject in local .scittish file."""
        result = self._run_cli("set", "subject", "test:my-subject:v1")
        assert result.returncode == 0
        
        # Verify .scittish was created
        scittish_file = self.work_dir / ".scittish"
        assert scittish_file.exists()
        config = json.loads(scittish_file.read_text())
        assert config["subject"] == "test:my-subject:v1"
    
    def test_cli_status(self):
        """Should show configuration status."""
        # Set up config first
        self._run_cli("set", "server", SCITTISH_API_URL)
        self._run_cli("set", "subject", "test:status-subject")
        
        result = self._run_cli("status")
        assert result.returncode == 0
        assert SCITTISH_API_URL in result.stdout
        assert "test:status-subject" in result.stdout
    
    def test_cli_push_simple_file(self):
        """Should push a file and receive a receipt."""
        # Set up server
        self._run_cli("set", "server", SCITTISH_API_URL)
        
        # Push file with --no-prompt
        result = self._run_cli("push", str(self.test_file), "--no-prompt")
        assert result.returncode == 0
        assert "RECEIPT RECEIVED" in result.stdout
        assert "Saved to:" in result.stdout
        
        # Verify receipt file was created
        receipt_files = list(self.work_dir.glob("receipt-*.cose"))
        assert len(receipt_files) == 1
    
    def test_cli_push_with_subject(self):
        """Should push with explicit subject."""
        self._run_cli("set", "server", SCITTISH_API_URL)
        
        result = self._run_cli(
            "push", str(self.test_file),
            "--subject", "test:explicit:v1",
            "--no-prompt"
        )
        assert result.returncode == 0
        assert "Subject:      test:explicit:v1" in result.stdout
    
    def test_cli_push_with_local_subject(self):
        """Should use subject from .scittish file."""
        self._run_cli("set", "server", SCITTISH_API_URL)
        self._run_cli("set", "subject", "test:local-subject:v1")
        
        result = self._run_cli("push", str(self.test_file), "--no-prompt")
        assert result.returncode == 0
        assert "Subject:      test:local-subject:v1" in result.stdout
    
    def test_cli_push_subject_override(self):
        """Should override local subject with --subject flag."""
        self._run_cli("set", "server", SCITTISH_API_URL)
        self._run_cli("set", "subject", "test:local-subject:v1")
        
        result = self._run_cli(
            "push", str(self.test_file),
            "--subject", "test:override-subject:v2",
            "--no-prompt"
        )
        assert result.returncode == 0
        assert "Subject:      test:override-subject:v2" in result.stdout
        assert "local-subject" not in result.stdout
    
    def test_cli_push_blank_subject(self):
        """Should blank out subject with --subject ''."""
        self._run_cli("set", "server", SCITTISH_API_URL)
        self._run_cli("set", "subject", "test:local-subject:v1")
        
        result = self._run_cli(
            "push", str(self.test_file),
            "--subject", "",
            "--no-prompt"
        )
        assert result.returncode == 0
        assert "Subject:      (server default)" in result.stdout
    
    def test_cli_push_same_material_different_subjects(self):
        """Should push same material with different subjects."""
        self._run_cli("set", "server", SCITTISH_API_URL)
        
        # Create a unique test file for this test
        unique_file = self.work_dir / "unique-material.txt"
        unique_file.write_text(f"unique-content-{time.time()}")
        
        # Push with first subject
        self._run_cli("set", "subject", "test:subject-a:v1")
        result1 = self._run_cli("push", str(unique_file), "--no-prompt")
        assert result1.returncode == 0
        assert "Subject:      test:subject-a:v1" in result1.stdout
        
        # Push same material with different subject
        self._run_cli("set", "subject", "test:subject-b:v1")
        result2 = self._run_cli("push", str(unique_file), "--no-prompt")
        assert result2.returncode == 0
        assert "Subject:      test:subject-b:v1" in result2.stdout
        
        # Both should have created receipts (different due to different subjects)
        receipt_files = list(self.work_dir.glob("receipt-*.cose"))
        assert len(receipt_files) >= 2
    
    def test_cli_push_unset_subject(self):
        """Should clear subject by setting to empty and push."""
        self._run_cli("set", "server", SCITTISH_API_URL)
        
        # Set subject
        self._run_cli("set", "subject", "test:to-be-cleared")
        
        # Clear subject by setting to empty
        result_clear = self._run_cli("set", "subject", "")
        assert result_clear.returncode == 0
        
        # Push - should use server default
        result = self._run_cli("push", str(self.test_file), "--no-prompt")
        assert result.returncode == 0
        assert "Subject:      (server default)" in result.stdout
    
    def test_cli_push_show_receipt(self):
        """Should pretty-print receipt with --show-receipt."""
        self._run_cli("set", "server", SCITTISH_API_URL)
        
        result = self._run_cli(
            "push", str(self.test_file),
            "--no-prompt",
            "--show-receipt"
        )
        assert result.returncode == 0
        # pyscitt pretty-print should show protected headers
        assert "protected" in result.stdout.lower() or "Receipt contents" in result.stdout
    
    def test_cli_push_spdx_sbom(self):
        """Should push SPDX SBOM file."""
        self._run_cli("set", "server", SCITTISH_API_URL)
        
        result = self._run_cli("push", str(self.spdx_file), "--no-prompt")
        assert result.returncode == 0
        assert "RECEIPT RECEIVED" in result.stdout
    
    def test_cli_push_no_server_configured(self):
        """Should fail gracefully when no server is configured."""
        # Don't configure server
        result = self._run_cli("push", str(self.test_file), "--no-prompt")
        assert result.returncode != 0
        assert "No scittish server configured" in result.stderr
    
    def test_cli_push_nonexistent_file(self):
        """Should fail gracefully for nonexistent file."""
        self._run_cli("set", "server", SCITTISH_API_URL)
        
        result = self._run_cli("push", "/nonexistent/file.txt", "--no-prompt")
        assert result.returncode != 0
        assert "File not found" in result.stderr


@pytest.mark.integration
class TestEndToEndWorkflow:
    """End-to-end workflow tests combining API and CLI."""
    
    @pytest.fixture(autouse=True)
    def setup_workflow_environment(self, tmp_path):
        """Set up environment for workflow tests."""
        self.work_dir = tmp_path
        self.env = os.environ.copy()
        self.env["XDG_CONFIG_HOME"] = str(tmp_path / ".config")
        self.env["HOME"] = str(tmp_path)
    
    def _run_cli(self, *args) -> subprocess.CompletedProcess:
        """Run scittish-cli command."""
        cmd = ["scittish-cli"] + list(args)
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=self.work_dir,
            env=self.env,
            timeout=120,
        )
    
    def test_complete_signing_workflow(self):
        """Test complete workflow: configure, push multiple artifacts, verify receipts."""
        # Step 1: Configure server
        result = self._run_cli("set", "server", SCITTISH_API_URL)
        assert result.returncode == 0
        
        # Step 2: Create and push first artifact
        artifact1 = self.work_dir / "artifact1.json"
        artifact1.write_text('{"name": "artifact1", "version": "1.0"}')
        
        self._run_cli("set", "subject", "product:artifact1:v1.0")
        result = self._run_cli("push", str(artifact1), "--no-prompt")
        assert result.returncode == 0
        
        # Step 3: Create and push second artifact with different subject
        artifact2 = self.work_dir / "artifact2.json"
        artifact2.write_text('{"name": "artifact2", "version": "2.0"}')
        
        self._run_cli("set", "subject", "product:artifact2:v2.0")
        result = self._run_cli("push", str(artifact2), "--no-prompt")
        assert result.returncode == 0
        
        # Step 4: Push SPDX SBOM without explicit subject (should auto-resolve)
        sbom = self.work_dir / "sbom.spdx.json"
        sbom.write_text(json.dumps({
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "workflow-test-sbom",
            "documentNamespace": "https://example.com/workflow-test/sbom/v1",
            "creationInfo": {
                "created": "2024-01-01T00:00:00Z",
                "creators": ["Tool: scittish-test"]
            },
            "packages": []
        }))
        
        # Clear local subject to let SPDX resolver work
        self._run_cli("set", "subject", "")
        result = self._run_cli("push", str(sbom), "--no-prompt")
        assert result.returncode == 0
        
        # Verify receipts were created
        receipts = list(self.work_dir.glob("receipt-*.cose"))
        assert len(receipts) >= 3
        
        # Verify all receipts are non-empty COSE files
        for receipt_file in receipts:
            content = receipt_file.read_bytes()
            assert len(content) > 100  # COSE files should be substantial
            # COSE Sign1 messages start with 0xD2 (tag 18)
            assert content[0] == 0xD2 or content[0:2] == b'\xd2\x84'
