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
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from flask import Flask, jsonify, request, url_for

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
JOBS_DIR = Path(os.environ.get("SCITT_JOBS_DIR", "/var/cache/scittish/jobs"))
SCITT_URL = os.environ.get("SCITT_URL", "https://localhost:8000")
MAA_ENDPOINT = os.environ.get("MAA_ENDPOINT", "sharedeus.eus.attest.azure.net")
ATTEST_HELPER_PATH = os.environ.get("ATTEST_HELPER_PATH", "/app/attest-helper")
ALLOW_FAKE_ATTESTATION = os.environ.get("ALLOW_FAKE_ATTESTATION", "false").lower() == "true"

# Token cache: key -> (token, expiry_time)
_token_cache: dict[str, Tuple[str, float]] = {}

# Global certificate chain (initialized on startup)
_certificate_chain: Optional[CertificateChain] = None

# Thread pool for async signing
_executor = ThreadPoolExecutor(max_workers=4)


class JobStatus(str, Enum):
    """Status of a signing job."""
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class JobInfo:
    """Information about a signing job."""
    job_id: str
    status: JobStatus
    error: Optional[str] = None
    created_at: float = 0.0
    updated_at: float = 0.0


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


def _get_cache_key(payload_hash: str, subject: Optional[str]) -> str:
    """Compute cache key from payload hash and subject."""
    key_input = f"{payload_hash}:{subject or ''}"
    return hashlib.sha256(key_input.encode("utf-8")).hexdigest()


def _get_cache_path(cache_key: str) -> Path:
    """Get the filesystem path for a cached receipt."""
    return CACHE_DIR / f"{cache_key}.receipt"


def _get_cached_receipt(cache_key: str) -> Optional[bytes]:
    """Retrieve a cached receipt if it exists."""
    cache_path = _get_cache_path(cache_key)
    if cache_path.exists():
        logger.info(f"Cache hit for cache key {cache_key[:16]}...")
        return cache_path.read_bytes()
    return None


def _store_receipt(cache_key: str, receipt: bytes) -> None:
    """Store a receipt in the cache."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cache_path = _get_cache_path(cache_key)
    cache_path.write_bytes(receipt)
    logger.info(f"Stored receipt in cache for cache key {cache_key[:16]}...")


# --- Job management functions ---

def _get_job_path(job_id: str) -> Path:
    """Get the filesystem path for a job status file."""
    return JOBS_DIR / f"{job_id}.job"


def _get_job_payload_path(job_id: str) -> Path:
    """Get the filesystem path for a job's payload."""
    return JOBS_DIR / f"{job_id}.payload"


def _get_job(job_id: str) -> Optional[JobInfo]:
    """Retrieve job info if it exists."""
    job_path = _get_job_path(job_id)
    if not job_path.exists():
        return None
    try:
        data = json.loads(job_path.read_text())
        return JobInfo(
            job_id=data["job_id"],
            status=JobStatus(data["status"]),
            error=data.get("error"),
            created_at=data.get("created_at", 0.0),
            updated_at=data.get("updated_at", 0.0),
        )
    except Exception as e:
        logger.error(f"Failed to load job {job_id}: {e}")
        return None


def _save_job(job: JobInfo) -> None:
    """Save job info to filesystem."""
    JOBS_DIR.mkdir(parents=True, exist_ok=True)
    job_path = _get_job_path(job.job_id)
    job.updated_at = time.time()
    data = {
        "job_id": job.job_id,
        "status": job.status.value,
        "error": job.error,
        "created_at": job.created_at,
        "updated_at": job.updated_at,
    }
    job_path.write_text(json.dumps(data))


def _save_job_payload(job_id: str, payload: bytes, content_type: str, subject: Optional[str]) -> None:
    """Save job payload and metadata for background processing."""
    JOBS_DIR.mkdir(parents=True, exist_ok=True)
    payload_path = _get_job_payload_path(job_id)
    metadata = {
        "content_type": content_type,
        "subject": subject,
    }
    # Store as JSON with base64-encoded payload
    data = {
        "metadata": metadata,
        "payload": base64.b64encode(payload).decode("utf-8"),
    }
    payload_path.write_text(json.dumps(data))


def _load_job_payload(job_id: str) -> Optional[Tuple[bytes, str, Optional[str]]]:
    """Load job payload and metadata. Returns (payload, content_type, subject) or None."""
    payload_path = _get_job_payload_path(job_id)
    if not payload_path.exists():
        return None
    try:
        data = json.loads(payload_path.read_text())
        payload = base64.b64decode(data["payload"])
        metadata = data["metadata"]
        return payload, metadata["content_type"], metadata.get("subject")
    except Exception as e:
        logger.error(f"Failed to load payload for job {job_id}: {e}")
        return None


def _cleanup_job_payload(job_id: str) -> None:
    """Remove job payload file after processing."""
    payload_path = _get_job_payload_path(job_id)
    if payload_path.exists():
        payload_path.unlink()


def _process_signing_job(job_id: str) -> None:
    """Background worker function to process a signing job."""
    logger.info(f"Processing job {job_id[:16]}...")
    
    # Update status to processing
    job = _get_job(job_id)
    if job is None:
        logger.error(f"Job {job_id[:16]}... not found")
        return
    
    job.status = JobStatus.PROCESSING
    _save_job(job)
    
    # Load payload
    payload_data = _load_job_payload(job_id)
    if payload_data is None:
        job.status = JobStatus.FAILED
        job.error = "Payload not found"
        _save_job(job)
        return
    
    payload, content_type, subject = payload_data
    payload_hash = hashlib.sha256(payload).hexdigest()
    
    try:
        # Sign the payload
        signed_statement = _sign_payload(payload, payload_hash, content_type, subject)
        
        # Submit to SCITT ledger
        transparent_statement = _submit_statement(signed_statement)
        
        # Store in cache (job_id is the cache key)
        _store_receipt(job_id, transparent_statement)
        
        # Mark job as completed
        job.status = JobStatus.COMPLETED
        _save_job(job)
        
        # Clean up payload file
        _cleanup_job_payload(job_id)
        
        logger.info(f"Job {job_id[:16]}... completed successfully")
        
    except Exception as e:
        logger.error(f"Job {job_id[:16]}... failed: {e}")
        job.status = JobStatus.FAILED
        job.error = str(e)
        _save_job(job)
        _cleanup_job_payload(job_id)


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
    Submit a payload for signing. Returns a job ID for polling.
    
    Request:
        - Body: Raw payload bytes (required unless X-Scittish-Payload-Hash is provided)
        - Content-Type: The content type of the payload (default: application/octet-stream)
    
    Request headers:
        - X-Scittish-Subject: Optional subject string for the signed statement
        - X-Scittish-Payload-Hash: SHA256 hash of the payload (if provided, body is ignored)
    
    Response (202 Accepted):
        - job_id: The job ID for polling
        - status: "pending"
    
    Response (200 OK - if already cached):
        - Raw COSE bytes (application/cose)
    
    Response headers:
        - Location: URL to poll for job status (on 202)
        - X-Scittish-Cache-Hit: "true" if served from cache
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

    logger.info(f"Processing payload with hash {computed_hash[:16]}..., subject={subject}")

    # Compute cache key from payload hash and subject (this becomes the job_id)
    job_id = _get_cache_key(computed_hash, subject)

    # Check cache first - if we have a receipt, return it immediately
    cached_receipt = _get_cached_receipt(job_id)
    if cached_receipt is not None:
        response = app.response_class(cached_receipt, mimetype="application/cose")
        response.headers["X-Scittish-Cache-Hit"] = "true"
        return response

    # Check if job already exists
    existing_job = _get_job(job_id)
    if existing_job is not None:
        # Job exists - return its current status
        if existing_job.status == JobStatus.COMPLETED:
            # Job completed, receipt should be in cache
            receipt = _get_cached_receipt(job_id)
            if receipt:
                response = app.response_class(receipt, mimetype="application/cose")
                response.headers["X-Scittish-Cache-Hit"] = "true"
                return response
        
        # Return job status (pending, processing, or failed)
        response = jsonify({
            "job_id": job_id,
            "status": existing_job.status.value,
            "error": existing_job.error,
        })
        response.status_code = 202 if existing_job.status in (JobStatus.PENDING, JobStatus.PROCESSING) else 200
        response.headers["Location"] = url_for("get_sign_job", job_id=job_id, _external=True)
        return response

    # Validate we have the payload for hash-only mode
    if payload_hash and not payload:
        return jsonify({"error": "Not yet implemented: Signing by hash only is not supported"}), 501

    # Create new job
    job = JobInfo(
        job_id=job_id,
        status=JobStatus.PENDING,
        created_at=time.time(),
        updated_at=time.time(),
    )
    _save_job(job)
    
    # Save payload for background processing
    _save_job_payload(job_id, payload, content_type, subject)
    
    # Submit to thread pool
    _executor.submit(_process_signing_job, job_id)
    
    logger.info(f"Created job {job_id[:16]}... for signing")

    response = jsonify({
        "job_id": job_id,
        "status": "pending",
    })
    response.status_code = 202
    response.headers["Location"] = url_for("get_sign_job", job_id=job_id, _external=True)
    return response


@app.route("/sign/<job_id>", methods=["GET"])
def get_sign_job(job_id: str):
    """
    Poll for the status of a signing job.
    
    Response (200 OK - completed):
        - Raw COSE bytes (application/cose)
    
    Response (202 Accepted - still processing):
        - job_id: The job ID
        - status: "pending" or "processing"
    
    Response (200 OK - failed):
        - job_id: The job ID
        - status: "failed"
        - error: Error message
    
    Response (404 Not Found):
        - error: "Job not found"
    """
    logger.info(f"Polling job {job_id[:16]}... from {request.remote_addr}")
    
    # Check cache first - completed jobs have their receipt cached
    cached_receipt = _get_cached_receipt(job_id)
    if cached_receipt is not None:
        response = app.response_class(cached_receipt, mimetype="application/cose")
        response.headers["X-Scittish-Cache-Hit"] = "true"
        return response
    
    # Check job status
    job = _get_job(job_id)
    if job is None:
        return jsonify({"error": "Job not found"}), 404
    
    if job.status == JobStatus.COMPLETED:
        # Job completed but receipt not found (shouldn't happen)
        return jsonify({"error": "Job completed but receipt not found"}), 500
    
    if job.status == JobStatus.FAILED:
        return jsonify({
            "job_id": job_id,
            "status": "failed",
            "error": job.error,
        }), 200
    
    # Job still in progress
    return jsonify({
        "job_id": job_id,
        "status": job.status.value,
    }), 202


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
