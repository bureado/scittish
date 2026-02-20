"""Push command implementation for scittish-cli."""

import hashlib
import mimetypes
import sys
import tempfile
import time
from pathlib import Path
from typing import Optional, Tuple

import httpx

from .config import GlobalConfig, get_effective_subject, fetch_server_properties


def compute_file_hash(file_path: Path) -> str:
    """Compute SHA256 hash of a file."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def get_file_type(file_path: Path) -> str:
    """Get the MIME type of a file."""
    mime_type, _ = mimetypes.guess_type(str(file_path))
    return mime_type or "application/octet-stream"


def format_size(size: int) -> str:
    """Format file size in human-readable form."""
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024:
            return f"{size:.1f} {unit}" if unit != "B" else f"{size} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def display_push_info(
    file_path: Optional[Path],
    file_size: Optional[int],
    payload_hash: str,
    file_type: str,
    server_uri: str,
    scitt_url: str,
    subject: Optional[str],
) -> None:
    """Display information about the push operation."""
    print("\n" + "=" * 60)
    print("SCITTISH PUSH")
    print("=" * 60)
    
    if file_path:
        print(f"  File path:    {file_path}")
        print(f"  File size:    {format_size(file_size)}")
    print(f"  SHA256:       {payload_hash}")
    print(f"  Content type: {file_type}")
    print()
    print(f"  Scittish:     {server_uri}")
    print(f"  SCITT Ledger: {scitt_url}")
    print(f"  Subject:      {subject or '(server default)'}")
    print("=" * 60 + "\n")


def save_receipt(receipt_data: bytes) -> Path:
    """Save receipt to current directory with truncated hash filename."""
    receipt_hash = hashlib.sha256(receipt_data).hexdigest()[:16]
    receipt_path = Path.cwd() / f"receipt-{receipt_hash}.cose"
    receipt_path.write_bytes(receipt_data)
    return receipt_path


def display_receipt_info(
    receipt_data: bytes,
    original_file_path: Optional[Path],
    original_hash: str,
    saved_path: Path,
    subject: Optional[str] = None,
    oci_registry: Optional[str] = None,
    oci_namespace: Optional[str] = None,
) -> None:
    """Display information about the received receipt."""
    receipt_hash = hashlib.sha256(receipt_data).hexdigest()
    
    print("\n" + "=" * 60)
    print("RECEIPT RECEIVED")
    print("=" * 60)
    if original_file_path:
        print(f"  Original file:  {original_file_path}")
    print(f"  Original SHA256: {original_hash}")
    print(f"  Receipt size:    {format_size(len(receipt_data))}")
    print(f"  Receipt SHA256:  {receipt_hash}")
    print(f"  Receipt type:    application/cose")
    print(f"  Saved to:        {saved_path}")
    
    if subject and oci_registry and oci_namespace:
        subject_hash = hashlib.sha256(subject.encode()).hexdigest()
        oci_ref = f"{oci_registry}/{oci_namespace}/{subject_hash}:latest"
        print()
        print(f"  OCI subject:     {oci_ref}")
        print(f"  Discover:        oras discover --insecure {oci_ref}")
    
    print("=" * 60 + "\n")


def pretty_print_receipt(receipt_data: bytes) -> None:
    """Pretty-print a receipt using pyscitt."""
    try:
        # Write receipt to temp file for pyscitt
        with tempfile.NamedTemporaryFile(suffix=".cose", delete=False) as f:
            f.write(receipt_data)
            temp_path = Path(f.name)
        
        try:
            from pyscitt.cli.pretty_receipt import prettyprint_receipt
            output = prettyprint_receipt(temp_path)
            print("\nReceipt contents:")
            print(output)
        finally:
            temp_path.unlink()
    except ImportError:
        print("\nWarning: pyscitt not available for receipt pretty-printing")
    except Exception as e:
        print(f"\nWarning: Could not pretty-print receipt: {e}")


def submit_and_poll(
    server_uri: str,
    payload: Optional[bytes],
    payload_hash: str,
    content_type: str,
    subject: Optional[str],
) -> bytes:
    """
    Submit payload to scittish and poll for completion.
    
    Returns the receipt bytes.
    """
    url = server_uri.rstrip("/") + "/sign"
    headers = {
        "Content-Type": content_type,
    }
    if subject:
        headers["X-Scittish-Subject"] = subject
    if payload is None:
        headers["X-Scittish-Payload-Hash"] = payload_hash
    
    print("Submitting to scittish...")
    
    try:
        response = httpx.post(
            url,
            content=payload,
            headers=headers,
            timeout=60.0,
        )
    except httpx.HTTPError as e:
        raise RuntimeError(f"Failed to submit to scittish: {e}")
    
    # Check for immediate cache hit
    if response.status_code == 200 and response.headers.get("content-type") == "application/cose":
        cache_hit = response.headers.get("X-Scittish-Cache-Hit", "false") == "true"
        if cache_hit:
            print("Cache hit - receipt already available.")
        return response.content
    
    # Handle async job
    if response.status_code == 202:
        job_data = response.json()
        job_id = job_data.get("job_id")
        poll_url = response.headers.get("Location") or f"{server_uri.rstrip('/')}/sign/{job_id}"
        
        print(f"Job submitted (ID: {job_id[:16]}...)")
        print("Waiting for completion", end="", flush=True)
        
        # Poll for completion
        max_wait = 300  # 5 minutes
        poll_interval = 2
        elapsed = 0
        
        while elapsed < max_wait:
            time.sleep(poll_interval)
            elapsed += poll_interval
            print(".", end="", flush=True)
            
            try:
                poll_response = httpx.get(poll_url, timeout=30.0)
            except httpx.HTTPError:
                continue
            
            if poll_response.status_code == 200:
                if poll_response.headers.get("content-type") == "application/cose":
                    print(" done!")
                    return poll_response.content
                # Check for failure
                data = poll_response.json()
                if data.get("status") == "failed":
                    print(" failed!")
                    raise RuntimeError(f"Job failed: {data.get('error', 'Unknown error')}")
            elif poll_response.status_code == 202:
                # Still processing
                continue
            elif poll_response.status_code == 404:
                print(" failed!")
                raise RuntimeError("Job not found - may have been cleaned up")
        
        print(" timeout!")
        raise RuntimeError("Timed out waiting for job completion")
    
    # Unexpected response
    try:
        error_data = response.json()
        error_msg = error_data.get("error", response.text)
    except Exception:
        error_msg = response.text
    
    raise RuntimeError(f"Unexpected response ({response.status_code}): {error_msg}")


def push(
    target: str,
    subject: Optional[str] = None,
    no_prompt: bool = False,
    show_receipt: bool = False,
) -> int:
    """
    Push a file or hash to scittish for signing.
    
    Args:
        target: File path or 'sha256:xxx' hash string
        subject: Explicit subject override (None = use .scittish, '' = blank)
        no_prompt: Skip confirmation prompt
        show_receipt: Pretty-print the receipt after receiving
    
    Returns:
        Exit code (0 for success, non-zero for failure)
    """
    # Load global config
    config = GlobalConfig.load()
    if not config.server_uri:
        print("Error: No scittish server configured.", file=sys.stderr)
        print("Run: scittish-cli set server <url>", file=sys.stderr)
        return 1
    
    # Determine if target is a hash or file
    file_path: Optional[Path] = None
    payload: Optional[bytes] = None
    file_size: Optional[int] = None
    
    if target.startswith("sha256:"):
        # Hash-only mode
        payload_hash = target[7:]
        if len(payload_hash) != 64:
            print("Error: Invalid SHA256 hash (must be 64 hex characters)", file=sys.stderr)
            return 1
        file_type = "application/octet-stream"
    else:
        # File mode
        file_path = Path(target)
        if not file_path.exists():
            print(f"Error: File not found: {file_path}", file=sys.stderr)
            return 1
        
        payload = file_path.read_bytes()
        file_size = len(payload)
        payload_hash = hashlib.sha256(payload).hexdigest()
        file_type = get_file_type(file_path)
    
    # Get effective subject
    effective_subject = get_effective_subject(subject)
    
    # Display info
    display_push_info(
        file_path=file_path,
        file_size=file_size,
        payload_hash=payload_hash,
        file_type=file_type,
        server_uri=config.server_uri,
        scitt_url=config.scitt_url,
        subject=effective_subject,
    )
    
    # Confirm unless --no-prompt
    if not no_prompt:
        try:
            response = input("Proceed with push? [y/N] ")
            if response.lower() not in ("y", "yes"):
                print("Aborted.")
                return 1
        except (KeyboardInterrupt, EOFError):
            print("\nAborted.")
            return 1
    
    # Submit and poll
    try:
        receipt_data = submit_and_poll(
            server_uri=config.server_uri,
            payload=payload,
            payload_hash=payload_hash,
            content_type=file_type,
            subject=effective_subject,
        )
    except RuntimeError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    
    # Save receipt to disk
    saved_path = save_receipt(receipt_data)
    
    # Fetch OCI indexer info for receipt display
    oci_registry = None
    oci_namespace = None
    try:
        properties = fetch_server_properties(config.server_uri)
        for idx in properties.get("indexers", []):
            if idx.get("enabled"):
                oci_registry = idx.get("registry")
                oci_namespace = idx.get("namespace")
                break
    except RuntimeError:
        pass  # Non-critical, just won't show OCI ref
    
    # Display receipt info
    display_receipt_info(
        receipt_data=receipt_data,
        original_file_path=file_path,
        original_hash=payload_hash,
        saved_path=saved_path,
        subject=effective_subject,
        oci_registry=oci_registry,
        oci_namespace=oci_namespace,
    )
    
    # Pretty-print receipt if requested
    if show_receipt:
        pretty_print_receipt(receipt_data)
    
    return 0
