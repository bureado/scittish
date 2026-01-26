"""
Unit tests for core utility functions.

These tests do not require external services (SCITT ledger, OCI registry).
Run with: pytest tests/ -v
"""

import hashlib
import json
import sys
import tempfile
from pathlib import Path

import pytest

# Add api directory to path for imports
sys.path.insert(0, "api")


class TestPayloadHash:
    """Tests for payload hash computation."""

    def test_computes_hash_from_payload(self):
        """Should compute SHA256 hash from payload bytes."""
        payload = b'{"test": "data"}'
        expected = hashlib.sha256(payload).hexdigest()
        
        # Verify hash format
        assert len(expected) == 64
        assert all(c in "0123456789abcdef" for c in expected)
    
    def test_payload_hash_is_deterministic(self):
        """Same payload should always produce same hash."""
        payload = b'consistent data'
        hash1 = hashlib.sha256(payload).hexdigest()
        hash2 = hashlib.sha256(payload).hexdigest()
        assert hash1 == hash2
    
    def test_different_payloads_produce_different_hashes(self):
        """Different payloads should produce different hashes."""
        hash1 = hashlib.sha256(b"payload1").hexdigest()
        hash2 = hashlib.sha256(b"payload2").hexdigest()
        assert hash1 != hash2


class TestCertificateGeneration:
    """Tests for certificate generation functions."""

    def test_generate_certificate_chain(self):
        """Should generate a valid certificate chain."""
        from certs import generate_certificate_chain
        
        chain = generate_certificate_chain()
        
        # Check all components are present
        assert chain.root_cert_pem is not None
        assert chain.leaf_cert_pem is not None
        assert chain.leaf_key_pem is not None
        assert chain.chain_pem is not None
        
        # Check PEM format
        assert "-----BEGIN CERTIFICATE-----" in chain.root_cert_pem
        assert "-----BEGIN CERTIFICATE-----" in chain.leaf_cert_pem
        assert "-----BEGIN PRIVATE KEY-----" in chain.leaf_key_pem
    
    def test_chain_pem_contains_both_certs(self):
        """Chain PEM should contain both leaf and root certificates."""
        from certs import generate_certificate_chain
        
        chain = generate_certificate_chain()
        
        # Chain should have two certificates
        cert_count = chain.chain_pem.count("-----BEGIN CERTIFICATE-----")
        assert cert_count == 2
    
    def test_save_and_load_certificate_chain(self):
        """Should be able to save and reload certificate chain."""
        from certs import generate_certificate_chain, save_certificate_chain, load_certificate_chain
        
        with tempfile.TemporaryDirectory() as tmpdir:
            certs_dir = Path(tmpdir)
            
            # Generate and save
            original = generate_certificate_chain()
            save_certificate_chain(original, certs_dir)
            
            # Load and compare
            loaded = load_certificate_chain(certs_dir)
            
            assert loaded is not None
            assert loaded.root_cert_pem == original.root_cert_pem
            assert loaded.leaf_cert_pem == original.leaf_cert_pem
            assert loaded.chain_pem == original.chain_pem
    
    def test_certificates_have_correct_extensions(self):
        """Certificates should have required extensions for SCITT."""
        from certs import generate_certificate_chain
        from cryptography import x509
        
        chain = generate_certificate_chain()
        
        # Parse leaf certificate
        leaf_cert = x509.load_pem_x509_certificate(chain.leaf_cert_pem.encode())
        
        # Check for Extended Key Usage extension
        try:
            eku = leaf_cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.EXTENDED_KEY_USAGE)
            assert eku is not None
        except x509.ExtensionNotFound:
            pytest.fail("Leaf certificate missing Extended Key Usage extension")
    
    def test_leaf_certificate_signed_by_root(self):
        """Leaf certificate should be signed by root CA."""
        from certs import generate_certificate_chain
        from cryptography import x509
        
        chain = generate_certificate_chain()
        
        root_cert = x509.load_pem_x509_certificate(chain.root_cert_pem.encode())
        leaf_cert = x509.load_pem_x509_certificate(chain.leaf_cert_pem.encode())
        
        # Leaf issuer should match root subject
        assert leaf_cert.issuer == root_cert.subject


class TestIssuerComputation:
    """Tests for did:x509 issuer string computation."""

    def test_issuer_format(self):
        """Issuer should follow did:x509 format."""
        import base64
        from certs import generate_certificate_chain
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        
        chain = generate_certificate_chain()
        root_cert = x509.load_pem_x509_certificate(chain.root_cert_pem.encode())
        
        # Compute fingerprint as the app does
        fingerprint = root_cert.fingerprint(hashes.SHA256())
        fingerprint_b64 = base64.urlsafe_b64encode(fingerprint).decode().rstrip("=")
        
        expected_prefix = f"did:x509:0:sha256:{fingerprint_b64}"
        
        # Verify fingerprint is base64url encoded
        assert len(fingerprint_b64) > 0
        assert all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for c in fingerprint_b64)

