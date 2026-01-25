"""
Simple REST API for SCITT signing operations.
Designed to run in a Docker container.
"""

import base64
import hashlib
import json
import logging
import os
import sys
from pathlib import Path
from typing import Optional

from flask import Flask, jsonify, request

from certs import (
    CertificateChain,
    generate_certificate_chain,
    load_certificate_chain,
    save_certificate_chain,
)

# pyscitt imports for signing and submission
from pyscitt.crypto import Signer, sign_statement
from pyscitt.client import Client

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Configuration
CACHE_DIR = Path(os.environ.get("SCITT_CACHE_DIR", "/var/cache/scittish"))
CERTS_DIR = Path(os.environ.get("SCITT_CERTS_DIR", "/var/lib/scittish/certs"))
SCITT_URL = os.environ.get("SCITT_URL", "https://localhost:8000")

# Global certificate chain (initialized on startup)
_certificate_chain: Optional[CertificateChain] = None


def initialize_certificate_chain() -> CertificateChain:
    """Initialize or load the certificate chain."""
    global _certificate_chain
    
    # Try to load existing chain
    _certificate_chain = load_certificate_chain(CERTS_DIR)
    
    if _certificate_chain is None:
        # Generate new chain
        logger.info("Generating new certificate chain...")
        _certificate_chain = generate_certificate_chain()
        save_certificate_chain(_certificate_chain, CERTS_DIR)
        logger.info("Certificate chain generated and saved.")
    else:
        logger.info("Loaded existing certificate chain.")
    
    # Print certificate chain to logs
    print("=" * 60, file=sys.stderr)
    print("CERTIFICATE CHAIN", file=sys.stderr)
    print("=" * 60, file=sys.stderr)
    print(_certificate_chain.chain_pem, file=sys.stderr)
    print("=" * 60, file=sys.stderr)
    
    return _certificate_chain


def get_certificate_chain() -> CertificateChain:
    """Get the current certificate chain, initializing if needed."""
    global _certificate_chain
    if _certificate_chain is None:
        _certificate_chain = initialize_certificate_chain()
    return _certificate_chain


def _get_payload_hash(payload: Optional[bytes], payload_hash: Optional[str]) -> str:
    """
    Get or compute the SHA256 hash for the payload.
    Returns the hex-encoded hash string.
    """
    if payload_hash:
        return payload_hash.lower()
    if payload is not None:
        return hashlib.sha256(payload).hexdigest()
    raise ValueError("Either payload or payload_hash must be provided")


def _get_cache_path(payload_hash: str) -> Path:
    """Get the filesystem path for a cached receipt."""
    return CACHE_DIR / f"{payload_hash}.receipt"


def _get_cached_receipt(payload_hash: str) -> Optional[bytes]:
    """Retrieve a cached receipt if it exists."""
    cache_path = _get_cache_path(payload_hash)
    if cache_path.exists():
        logger.info(f"Cache hit for payload hash {payload_hash[:16]}...")
        return cache_path.read_bytes()
    return None


def _store_receipt(payload_hash: str, receipt: bytes) -> None:
    """Store a receipt in the cache."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cache_path = _get_cache_path(payload_hash)
    cache_path.write_bytes(receipt)
    logger.info(f"Stored receipt in cache for payload hash {payload_hash[:16]}...")


def _get_issuer(root_cert_pem: str) -> str:
    """
    Compute the did:x509 issuer string from the root certificate.
    
    Format: did:x509:0:sha256:<root_fingerprint_b64url>::eku:<eku_oid>
    """
    from cryptography import x509 as crypto_x509
    from cryptography.hazmat.primitives import hashes as crypto_hashes
    
    root_cert = crypto_x509.load_pem_x509_certificate(root_cert_pem.encode("ascii"))
    root_fingerprint = base64.urlsafe_b64encode(
        root_cert.fingerprint(crypto_hashes.SHA256())
    ).decode("ascii").rstrip("=")
    
    # EKU OID for SCITT
    eku = "1.3.6.1.5.5.7.3.36"
    
    return f"did:x509:0:sha256:{root_fingerprint}::eku:{eku}"


def _sign_payload(
    payload: Optional[bytes], payload_hash: str, content_type: str, subject: Optional[str] = None
) -> bytes:
    """
    Sign the payload using pyscitt.
    
    Args:
        payload: The raw payload bytes (if provided)
        payload_hash: The SHA256 hash of the payload
        content_type: The content type of the payload
        subject: Optional subject string for the signed statement (used as feed)
    
    Returns:
        The signed COSE statement bytes.
    
    Raises:
        NotImplementedError: If only payload_hash is provided (not yet supported)
    """
    if payload is None:
        raise NotImplementedError(
            "Signing by hash only is not yet implemented. Please provide the full payload."
        )
    
    logger.info(f"Signing payload with hash {payload_hash[:16]}...")
    
    chain = get_certificate_chain()
    
    # Compute issuer from root cert
    issuer = _get_issuer(chain.root_cert_pem)
    
    # Create signer with x5c chain (leaf first, then root)
    signer = Signer(
        private_key=chain.leaf_key_pem,
        issuer=issuer,
        algorithm="ES256",
        x5c=[chain.leaf_cert_pem, chain.root_cert_pem],
    )
    
    signed_statement = sign_statement(
        signer=signer,
        statement=payload,
        content_type=content_type,
        feed=subject,  # Use subject as feed if provided
        cwt=True,  # Use CWT claims format
    )
    
    logger.info(f"Signed statement created ({len(signed_statement)} bytes)")
    
    return signed_statement


def _submit_statement(signed_statement: bytes) -> bytes:
    """
    Submit a signed statement to the SCITT ledger and get a transparent statement.
    
    Args:
        signed_statement: The signed COSE statement bytes
    
    Returns:
        The transparent statement (signed statement with embedded receipt) bytes.
    """
    logger.info(f"Submitting signed statement to SCITT ledger at {SCITT_URL} ({len(signed_statement)} bytes)...")
    
    client = Client(url=SCITT_URL, development=True)
    
    submission = client.submit_signed_statement_and_wait(signed_statement)
    
    logger.info(f"Received transparent statement from SCITT ledger (tx={submission.tx})")
    
    return submission.response_bytes


@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint."""
    return jsonify({"status": "ok"})


@app.route("/properties", methods=["GET"])
def properties():
    """
    Return service properties including the certificate chain.
    
    Response (JSON):
        - certificate_chain: The PEM-encoded certificate chain
        - scitt_url: The URL of the SCITT ledger
    """
    chain = get_certificate_chain()
    return jsonify({
        "certificate_chain": chain.chain_pem,
        "scitt_url": SCITT_URL,
    })


@app.route("/sign", methods=["POST"])
def sign():
    """
    Sign a payload and return a SCITT transparent statement.
    
    Request:
        - Body: Raw payload bytes (required unless X-Scittish-Payload-Hash is provided)
        - Content-Type: The content type of the payload (default: application/octet-stream)
    
    Request headers:
        - X-Scittish-Subject: Optional subject string for the signed statement
        - X-Scittish-Payload-Hash: SHA256 hash of the payload (if provided, body is ignored)
    
    Response:
        - transparent_statement: The SCITT transparent statement (base64 encoded)
    
    Response headers:
        - X-Scittish-Cache-Hit: "true" if served from cache, "false" otherwise
    """
    logger.info(f"Received sign request from {request.remote_addr}")
    
    # Get metadata from headers
    subject = request.headers.get("X-Scittish-Subject")
    payload_hash = request.headers.get("X-Scittish-Payload-Hash")
    content_type = request.content_type or "application/octet-stream"
    
    # Get raw payload from body
    payload = request.get_data() if not payload_hash else None
    
    # Validate: need either payload or payload_hash
    if not payload and not payload_hash:
        return jsonify({"error": "Either request body or X-Scittish-Payload-Hash header must be provided"}), 400
    
    # Validate payload_hash format if provided
    if payload_hash:
        if len(payload_hash) != 64:
            return jsonify({"error": "X-Scittish-Payload-Hash must be a 64-character hex string (SHA256)"}), 400
        try:
            int(payload_hash, 16)
        except ValueError:
            return jsonify({"error": "X-Scittish-Payload-Hash must be a valid hex string"}), 400

    try:
        computed_hash = _get_payload_hash(payload, payload_hash)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    logger.info(f"Processing payload with hash {computed_hash[:16]}...")

    # Check cache first
    cached_receipt = _get_cached_receipt(computed_hash)
    if cached_receipt is not None:
        response = jsonify({"transparent_statement": base64.b64encode(cached_receipt).decode("utf-8")})
        response.headers["X-Scittish-Cache-Hit"] = "true"
        return response

    # Sign the payload
    try:
        signed_statement = _sign_payload(payload, computed_hash, content_type, subject)
    except NotImplementedError as e:
        return jsonify({"error": f"Not yet implemented: {e}"}), 501
    except Exception as e:
        logger.error(f"Signing failed: {e}")
        return jsonify({"error": f"Signing failed: {e}"}), 500

    # Submit to SCITT ledger
    try:
        transparent_statement = _submit_statement(signed_statement)
    except Exception as e:
        logger.error(f"Submission failed: {e}")
        return jsonify({"error": f"Submission to SCITT ledger failed: {e}"}), 502

    # Cache the transparent statement
    _store_receipt(computed_hash, transparent_statement)

    response = jsonify({"transparent_statement": base64.b64encode(transparent_statement).decode("utf-8")})
    response.headers["X-Scittish-Cache-Hit"] = "false"
    return response


# Initialize certificate chain on module load
initialize_certificate_chain()


if __name__ == "__main__":
    # For local development only; use gunicorn in production
    app.run(host="0.0.0.0", port=8080)
