"""
Simple REST API for SCITT signing operations.
Designed to run in a Docker container.
"""

import base64
import hashlib
import json
import logging
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
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
MAA_ENDPOINT = os.environ.get("MAA_ENDPOINT", "sharedeus.eus.attest.azure.net")
ATTEST_HELPER_PATH = os.environ.get("ATTEST_HELPER_PATH", "/app/attest-helper")
ALLOW_FAKE_ATTESTATION = os.environ.get("ALLOW_FAKE_ATTESTATION", "false").lower() == "true"

# Token cache: key -> (token, expiry_time)
_token_cache: dict[str, Tuple[str, float]] = {}

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
    payload: Optional[dict], payload_hash: str, subject: Optional[str] = None
) -> bytes:
    """
    Sign the payload using pyscitt.
    
    Args:
        payload: The full payload dict (if provided)
        payload_hash: The SHA256 hash of the payload
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
    
    # Sign the statement
    statement_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    
    signed_statement = sign_statement(
        signer=signer,
        statement=statement_bytes,
        content_type="application/json",
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
    
    Request body (JSON):
        - payload: The full JSON payload to sign (optional if payload_hash provided)
        - payload_hash: SHA256 hash of the payload (optional if payload provided)
        - subject: Optional subject string for the signed statement
    
    Response:
        - transparent_statement: The SCITT transparent statement (base64 encoded)
    
    Response headers:
        - X-Scittish-Cache-Hit: "true" if served from cache, "false" otherwise
    """
    logger.info(f"Received sign request from {request.remote_addr}")
    
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

    logger.info(f"Processing payload with hash {computed_hash[:16]}...")

    # Check cache first
    cached_receipt = _get_cached_receipt(computed_hash)
    if cached_receipt is not None:
        response = jsonify({"transparent_statement": base64.b64encode(cached_receipt).decode("utf-8")})
        response.headers["X-Scittish-Cache-Hit"] = "true"
        return response

    # Sign the payload
    try:
        signed_statement = _sign_payload(payload, computed_hash, subject)
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


def _sign_nonce_with_key(nonce: bytes) -> bytes:
    """
    Sign a nonce with the leaf private key to prove key control.
    Returns the signature bytes.
    """
    chain = get_certificate_chain()
    
    # Load the private key
    private_key = serialization.load_pem_private_key(
        chain.leaf_key_pem.encode("utf-8"),
        password=None,
    )
    
    # Sign the nonce
    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        signature = private_key.sign(nonce, ec.ECDSA(hashes.SHA256()))
    else:
        raise ValueError("Unsupported key type for signing")
    
    return signature


def _get_token_cache_key(nonce: Optional[str], maa_endpoint: str) -> str:
    """Generate a cache key for attestation tokens."""
    data = f"{nonce or ''}:{maa_endpoint}"
    return hashlib.sha256(data.encode()).hexdigest()


def _get_cached_token(cache_key: str) -> Optional[str]:
    """Get a cached token if it exists and is not expired."""
    if cache_key in _token_cache:
        token, expiry = _token_cache[cache_key]
        if time.time() < expiry:
            logger.info(f"Token cache hit for key {cache_key[:16]}...")
            return token
        else:
            # Token expired, remove from cache
            del _token_cache[cache_key]
            logger.info(f"Token expired for key {cache_key[:16]}...")
    return None


def _cache_token(cache_key: str, token: str, ttl_seconds: float = 3600) -> None:
    """Cache a token with TTL."""
    expiry = time.time() + ttl_seconds
    _token_cache[cache_key] = (token, expiry)
    logger.info(f"Cached token for key {cache_key[:16]}... (TTL: {ttl_seconds}s)")


def _get_token_expiry(token: str) -> Optional[float]:
    """Extract expiry time from JWT token."""
    try:
        # JWT is base64url encoded: header.payload.signature
        parts = token.split(".")
        if len(parts) != 3:
            return None
        
        # Decode payload (add padding if needed)
        payload_b64 = parts[1]
        padding = 4 - len(payload_b64) % 4
        if padding != 4:
            payload_b64 += "=" * padding
        
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        exp = payload.get("exp")
        if exp:
            return float(exp)
    except Exception as e:
        logger.warning(f"Failed to parse token expiry: {e}")
    return None


def _call_attest_helper(runtime_data: bytes, maa_endpoint: str, raw_only: bool = False) -> dict:
    """Call the attest-helper Go binary."""
    cmd = [
        ATTEST_HELPER_PATH,
        "-runtime-data", base64.b64encode(runtime_data).decode("utf-8"),
        "-maa-endpoint", maa_endpoint,
    ]
    
    if raw_only:
        cmd.append("-raw")
    
    if ALLOW_FAKE_ATTESTATION:
        cmd.append("-allow-fake")
    
    logger.info(f"Calling attest-helper: {' '.join(cmd)}")
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
        )
        
        if result.returncode != 0:
            logger.error(f"attest-helper failed: {result.stderr}")
            return {"error": f"attest-helper failed: {result.stderr}"}
        
        return json.loads(result.stdout)
    except subprocess.TimeoutExpired:
        return {"error": "attest-helper timed out"}
    except json.JSONDecodeError as e:
        return {"error": f"failed to parse attest-helper output: {e}"}
    except FileNotFoundError:
        return {"error": f"attest-helper not found at {ATTEST_HELPER_PATH}"}


@app.route("/attest", methods=["POST"])
def attest():
    """
    Get an attestation token (EAT) from Microsoft Azure Attestation.
    
    Request body (JSON):
        - nonce: Optional base64-encoded nonce for freshness
        - maa_endpoint: Optional MAA endpoint (default: sharedeus.eus.attest.azure.net)
    
    Response:
        - token: The MAA JWT token (Entity Attestation Token)
    
    Response headers:
        - X-Scittish-Cache-Hit: "true" if served from cache, "false" otherwise
    """
    logger.info(f"Received attest request from {request.remote_addr}")
    
    data = request.get_json() or {}
    nonce_b64 = data.get("nonce")
    maa_endpoint = data.get("maa_endpoint", MAA_ENDPOINT)
    
    # Decode nonce if provided
    nonce_bytes = b""
    if nonce_b64:
        try:
            nonce_bytes = base64.b64decode(nonce_b64)
        except Exception as e:
            return jsonify({"error": f"Invalid nonce encoding: {e}"}), 400
    
    # Check cache
    cache_key = _get_token_cache_key(nonce_b64, maa_endpoint)
    cached_token = _get_cached_token(cache_key)
    if cached_token:
        response = jsonify({"token": cached_token})
        response.headers["X-Scittish-Cache-Hit"] = "true"
        return response
    
    # Construct runtime_data: nonce + signature over nonce
    # This proves we control the signing key
    try:
        signature = _sign_nonce_with_key(nonce_bytes) if nonce_bytes else b""
        runtime_data = json.dumps({
            "nonce": nonce_b64 or "",
            "signature": base64.b64encode(signature).decode("utf-8") if signature else "",
            "certificate_chain": get_certificate_chain().chain_pem,
        }).encode("utf-8")
    except Exception as e:
        logger.error(f"Failed to construct runtime_data: {e}")
        return jsonify({"error": f"Failed to construct runtime_data: {e}"}), 500
    
    logger.info(f"Requesting attestation from {maa_endpoint}...")
    
    # Call attest-helper
    result = _call_attest_helper(runtime_data, maa_endpoint)
    
    if "error" in result:
        logger.error(f"Attestation failed: {result['error']}")
        return jsonify({"error": result["error"]}), 502
    
    token = result.get("token")
    if not token:
        return jsonify({"error": "No token in attestation response"}), 502
    
    # Cache the token
    expiry = _get_token_expiry(token)
    if expiry:
        # Cache until 5 minutes before expiry
        ttl = max(0, expiry - time.time() - 300)
    else:
        # Default 1 hour TTL
        ttl = 3600
    
    _cache_token(cache_key, token, ttl)
    
    logger.info("Attestation successful")
    
    response = jsonify({"token": token})
    response.headers["X-Scittish-Cache-Hit"] = "false"
    return response


# Initialize certificate chain on module load
initialize_certificate_chain()


if __name__ == "__main__":
    # For local development only; use gunicorn in production
    app.run(host="0.0.0.0", port=8080)
