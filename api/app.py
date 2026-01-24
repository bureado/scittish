"""
Simple REST API for SCITT signing operations.
Designed to run in a Docker container.
"""

import hashlib
import json
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

# Stub imports - will use actual pyscitt functions later
# from pyscitt.client import Client
# from pyscitt.crypto import sign_statement

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
        print("Generating new certificate chain...", file=sys.stderr)
        _certificate_chain = generate_certificate_chain()
        save_certificate_chain(_certificate_chain, CERTS_DIR)
        print("Certificate chain generated and saved.", file=sys.stderr)
    else:
        print("Loaded existing certificate chain.", file=sys.stderr)
    
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


def _get_payload_hash(payload: Optional[dict], payload_hash: Optional[str]) -> str:
    """
    Get or compute the SHA256 hash for the payload.
    Returns the hex-encoded hash string.
    """
    if payload_hash:
        return payload_hash.lower()
    if payload is not None:
        # Canonical JSON serialization for consistent hashing
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    raise ValueError("Either payload or payload_hash must be provided")


def _get_cache_path(payload_hash: str) -> Path:
    """Get the filesystem path for a cached receipt."""
    return CACHE_DIR / f"{payload_hash}.receipt"


def _get_cached_receipt(payload_hash: str) -> Optional[bytes]:
    """Retrieve a cached receipt if it exists."""
    cache_path = _get_cache_path(payload_hash)
    if cache_path.exists():
        return cache_path.read_bytes()
    return None


def _store_receipt(payload_hash: str, receipt: bytes) -> None:
    """Store a receipt in the cache."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cache_path = _get_cache_path(payload_hash)
    cache_path.write_bytes(receipt)


def _sign_payload(
    payload: Optional[dict], payload_hash: str, subject: Optional[str] = None
) -> bytes:
    """
    Sign the payload using pyscitt.
    
    STUB: This will be implemented to use pyscitt's sign functionality.
    
    Args:
        payload: The full payload dict (if provided)
        payload_hash: The SHA256 hash of the payload
        subject: Optional subject string for the signed statement
    """
    # TODO: Implement using pyscitt.crypto or similar
    # chain = get_certificate_chain()
    # signed_statement = sign_statement(payload or payload_hash, chain.leaf_key_pem, subject=subject, ...)
    raise NotImplementedError("sign_payload stub - implement with pyscitt")


def _submit_statement(signed_statement: bytes) -> bytes:
    """
    Submit a signed statement to the SCITT ledger and get a receipt.
    
    STUB: This will be implemented to use pyscitt's submit functionality.
    """
    # TODO: Implement using pyscitt.client.Client
    # client = Client(url=SCITT_URL, ...)
    # submission = client.submit_signed_statement_and_wait_for_receipt(signed_statement)
    # return submission.receipt
    raise NotImplementedError("submit_statement stub - implement with pyscitt")


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
    Sign a payload and return a SCITT receipt.
    
    Request body (JSON):
        - payload: The full JSON payload to sign (optional if payload_hash provided)
        - payload_hash: SHA256 hash of the payload (optional if payload provided)
        - subject: Optional subject string for the signed statement
    
    Response:
        - receipt: The SCITT receipt (base64 encoded)
    
    Response headers:
        - X-Scittish-Cache-Hit: "true" if served from cache, "false" otherwise
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body must be JSON"}), 400

    payload = data.get("payload")
    payload_hash = data.get("payload_hash")
    subject = data.get("subject")  # Optional subject string

    if payload is None and payload_hash is None:
        return jsonify({"error": "Either 'payload' or 'payload_hash' must be provided"}), 400

    # Validate payload_hash format if provided
    if payload_hash:
        if not isinstance(payload_hash, str) or len(payload_hash) != 64:
            return jsonify({"error": "payload_hash must be a 64-character hex string (SHA256)"}), 400
        try:
            int(payload_hash, 16)
        except ValueError:
            return jsonify({"error": "payload_hash must be a valid hex string"}), 400

    try:
        computed_hash = _get_payload_hash(payload, payload_hash)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    # Check cache first
    cached_receipt = _get_cached_receipt(computed_hash)
    if cached_receipt is not None:
        import base64
        response = jsonify({"receipt": base64.b64encode(cached_receipt).decode("utf-8")})
        response.headers["X-Scittish-Cache-Hit"] = "true"
        return response

    # Sign and submit
    try:
        signed_statement = _sign_payload(payload, computed_hash, subject)
        receipt = _submit_statement(signed_statement)
    except NotImplementedError as e:
        return jsonify({"error": f"Not yet implemented: {e}"}), 501
    except Exception as e:
        return jsonify({"error": f"Signing failed: {e}"}), 500

    # Cache the receipt
    _store_receipt(computed_hash, receipt)

    import base64
    response = jsonify({"receipt": base64.b64encode(receipt).decode("utf-8")})
    response.headers["X-Scittish-Cache-Hit"] = "false"
    return response


# Initialize certificate chain on module load
initialize_certificate_chain()


if __name__ == "__main__":
    # For local development only; use gunicorn in production
    app.run(host="0.0.0.0", port=8080)
