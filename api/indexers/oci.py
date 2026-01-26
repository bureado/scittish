"""
OCI Registry indexer using oras CLI.

Pushes receipts to an OCI registry as artifacts, using the OCI Referrers API
to link receipts to their subjects.
"""

import hashlib
import logging
import os
import shutil
import subprocess
import tempfile
from typing import Optional

from .base import Indexer, IndexerContext, IndexerResult

logger = logging.getLogger(__name__)

# OCI artifact media type for SCITT receipts
RECEIPT_MEDIA_TYPE = "application/cose"
# Artifact type for SCITT transparent statements  
ARTIFACT_TYPE = "application/vnd.scitt.receipt"


def subject_to_repo_name(subject: str) -> str:
    """
    Convert a subject string to a valid OCI repository name component.
    
    OCI repository names must match: [a-z0-9]+([._-][a-z0-9]+)*
    We use SHA256 hash of the subject to ensure validity.
    
    Args:
        subject: The subject string (e.g., "https://example.com/sbom/v1")
    
    Returns:
        A valid repository name component (hex hash)
    """
    return hashlib.sha256(subject.encode("utf-8")).hexdigest()


class OciIndexer(Indexer):
    """
    Indexer that pushes receipts to an OCI registry using oras CLI.
    
    The indexer uses the OCI Referrers API to link receipts to subjects:
    1. Creates a subject artifact containing the subject text
    2. Attaches the receipt to the subject using oras attach
    
    This allows clients to discover all receipts for a subject using
    the OCI Referrers API.
    
    Configuration via environment:
        OCI_REGISTRY: Registry hostname:port (default: empty = disabled)
        OCI_NAMESPACE: Repository namespace (default: scittish)
        OCI_USERNAME: Registry username (optional)
        OCI_PASSWORD: Registry password (optional)
        OCI_INSECURE: Allow HTTP connections (default: false)
        ORAS_PATH: Path to oras binary (default: oras)
    """
    
    def __init__(self):
        self._registry = os.environ.get("OCI_REGISTRY", "")
        self._namespace = os.environ.get("OCI_NAMESPACE", "scittish")
        self._username = os.environ.get("OCI_USERNAME", "")
        self._password = os.environ.get("OCI_PASSWORD", "")
        self._insecure = os.environ.get("OCI_INSECURE", "false").lower() == "true"
        self._oras_path = os.environ.get("ORAS_PATH", "oras")
    
    @property
    def name(self) -> str:
        return "oci-registry"
    
    @property
    def description(self) -> str:
        return f"Pushes receipts to OCI registry as referrers (registry: {self._registry or 'not configured'})"
    
    @property
    def enabled(self) -> bool:
        if not self._registry:
            return False
        # Check if oras is available
        return shutil.which(self._oras_path) is not None
    
    def _run_oras(self, args: list[str], cwd: Optional[str] = None) -> tuple[bool, str, str]:
        """Run oras command with authentication."""
        cmd = [self._oras_path] + args
        
        # Add authentication if configured
        if self._username and self._password:
            cmd.extend(["--username", self._username, "--password", self._password])
        
        # Add insecure flag if needed (use --plain-http for oras)
        if self._insecure:
            cmd.append("--plain-http")
        
        logger.debug(f"Running: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
                cwd=cwd,
            )
            logger.debug(f"stdout: {result.stdout}")
            logger.debug(f"stderr: {result.stderr}")
            return result.returncode == 0, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return False, "", "Command timed out"
        except FileNotFoundError:
            return False, "", f"oras not found at {self._oras_path}"
    
    def index(self, context: IndexerContext) -> IndexerResult:
        if not self.enabled:
            error = "OCI registry not configured" if not self._registry else "oras CLI not found"
            return IndexerResult(
                success=False,
                indexer_name=self.name,
                error=f"{error} (set OCI_REGISTRY env var and ensure oras is in PATH)",
            )
        
        try:
            # Convert subject to valid repo name
            subject_hash = subject_to_repo_name(context.subject)
            
            # Full reference for subject: registry/namespace/hash:subject
            subject_repo = f"{self._registry}/{self._namespace}/{subject_hash}"
            subject_ref = f"{subject_repo}:subject"
            
            # Create temp directory for files
            tmp_dir = tempfile.mkdtemp(prefix="scittish-oci-")
            
            try:
                # Step 1: Push subject artifact (text file with subject string)
                subject_file = os.path.join(tmp_dir, "subject.txt")
                with open(subject_file, 'w') as f:
                    f.write(context.subject)
                
                success, stdout, stderr = self._run_oras([
                    "push", subject_ref,
                    "subject.txt:text/plain",
                    "--annotation", f"scittish.subject={context.subject}",
                ], cwd=tmp_dir)
                
                if not success:
                    # Check if it already exists (that's ok)
                    if "exists" not in stderr.lower():
                        logger.warning(f"Failed to push subject artifact: {stderr}")
                else:
                    logger.info(f"Pushed subject artifact: {subject_ref}")
                
                # Get subject digest
                success, stdout, stderr = self._run_oras([
                    "manifest", "fetch", subject_ref, "--descriptor",
                ], cwd=tmp_dir)
                
                subject_digest = None
                if success:
                    import json
                    try:
                        desc = json.loads(stdout)
                        subject_digest = desc.get("digest")
                    except json.JSONDecodeError:
                        pass
                
                if not subject_digest:
                    return IndexerResult(
                        success=False,
                        indexer_name=self.name,
                        error="Failed to get subject digest",
                    )
                
                # Step 2: Attach receipt to subject using oras attach
                receipt_file = os.path.join(tmp_dir, "receipt.cose")
                with open(receipt_file, 'wb') as f:
                    f.write(context.receipt)
                
                # oras attach pushes an artifact as a referrer
                success, stdout, stderr = self._run_oras([
                    "attach", subject_ref,
                    "--artifact-type", ARTIFACT_TYPE,
                    "receipt.cose:" + RECEIPT_MEDIA_TYPE,
                    "--annotation", f"scittish.payload_hash={context.payload_hash}",
                    "--annotation", f"scittish.subject={context.subject}",
                ], cwd=tmp_dir)
                
                if not success:
                    logger.error(f"Failed to attach receipt: {stderr}")
                    return IndexerResult(
                        success=False,
                        indexer_name=self.name,
                        error=f"Failed to attach receipt: {stderr}",
                    )
                
                # Parse receipt digest from oras attach output
                receipt_ref = f"{subject_repo}@{subject_digest}"
                if "Digest:" in stdout:
                    for line in stdout.splitlines():
                        if "Digest:" in line:
                            receipt_digest = line.split("Digest:")[-1].strip()
                            receipt_ref = f"{subject_repo}@{receipt_digest}"
                            break
                
                logger.info(f"Attached receipt artifact: {receipt_ref}")
                logger.info(f"Indexed receipt to {subject_repo} as referrer of {subject_ref}")
                
                return IndexerResult(
                    success=True,
                    indexer_name=self.name,
                    reference=f"{subject_repo}@{subject_digest}",
                    metadata={
                        "subject_ref": subject_ref,
                        "subject_digest": subject_digest,
                        "subject_hash": subject_hash,
                    },
                )
                
            finally:
                # Cleanup temp directory
                shutil.rmtree(tmp_dir, ignore_errors=True)
            
        except Exception as e:
            logger.error(f"OCI indexing failed: {e}")
            return IndexerResult(
                success=False,
                indexer_name=self.name,
                error=str(e),
            )
    
    def to_dict(self) -> dict:
        """Serialize indexer info for /properties endpoint."""
        return {
            "name": self.name,
            "description": self.description,
            "enabled": self.enabled,
            "registry": self._registry if self._registry else None,
            "namespace": self._namespace if self._registry else None,
        }
