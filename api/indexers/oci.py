"""
OCI Registry indexer using ORAS.

Pushes receipts to an OCI registry as artifacts, using the OCI Referrers API
to link receipts to their subjects.
"""

import base64
import hashlib
import logging
import os
import re
import subprocess
from typing import Optional

from .base import Indexer, IndexerContext, IndexerResult

logger = logging.getLogger(__name__)

# OCI artifact media type for SCITT receipts
RECEIPT_MEDIA_TYPE = "application/cose"
# Artifact type for SCITT transparent statements
ARTIFACT_TYPE = "application/vnd.scitt.receipt"


def subject_to_imageref(subject: str, registry: str, namespace: str) -> str:
    """
    Convert a subject string to a valid OCI image reference.
    
    OCI image references have restrictions on allowed characters.
    We use base64url encoding for arbitrary subject strings.
    
    Args:
        subject: The subject string (e.g., "product:myproduct:v1")
        registry: OCI registry hostname:port
        namespace: Repository namespace (e.g., "scittish/subjects")
    
    Returns:
        Image reference like "registry/namespace/b64subject:latest"
    """
    # Base64url encode the subject (without padding)
    encoded = base64.urlsafe_b64encode(subject.encode("utf-8")).decode("ascii").rstrip("=")
    
    # Truncate if too long (OCI has limits)
    # Repository name can be up to 256 chars, tag up to 128
    max_len = 128
    if len(encoded) > max_len:
        # Use hash suffix for uniqueness
        hash_suffix = hashlib.sha256(subject.encode()).hexdigest()[:8]
        encoded = encoded[:max_len - 9] + "_" + hash_suffix
    
    # Replace any remaining invalid chars (shouldn't be any with base64url)
    encoded = re.sub(r'[^a-zA-Z0-9_.-]', '_', encoded.lower())
    
    return f"{registry}/{namespace}/{encoded}"


def compute_digest(data: bytes) -> str:
    """Compute OCI digest for data."""
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


class OciIndexer(Indexer):
    """
    Indexer that pushes receipts to an OCI registry using ORAS.
    
    The indexer uses the OCI Referrers API to link receipts to subjects:
    1. Creates/ensures a subject artifact exists in the registry
    2. Pushes the receipt as a referrer to the subject
    
    This allows clients to discover all receipts for a subject using
    the OCI Referrers API.
    
    Configuration via environment:
        OCI_REGISTRY: Registry hostname:port (default: localhost:5000)
        OCI_NAMESPACE: Repository namespace (default: scittish/subjects)
        OCI_USERNAME: Registry username (optional)
        OCI_PASSWORD: Registry password (optional)
        ORAS_PATH: Path to oras binary (default: oras)
    """
    
    def __init__(self):
        self._registry = os.environ.get("OCI_REGISTRY", "")
        self._namespace = os.environ.get("OCI_NAMESPACE", "scittish/subjects")
        self._username = os.environ.get("OCI_USERNAME", "")
        self._password = os.environ.get("OCI_PASSWORD", "")
        self._oras_path = os.environ.get("ORAS_PATH", "oras")
        self._insecure = os.environ.get("OCI_INSECURE", "false").lower() == "true"
    
    @property
    def name(self) -> str:
        return "oci-registry"
    
    @property
    def description(self) -> str:
        return f"Pushes receipts to OCI registry as referrers (registry: {self._registry or 'not configured'})"
    
    @property
    def enabled(self) -> bool:
        return bool(self._registry)
    
    def index(self, context: IndexerContext) -> IndexerResult:
        if not self.enabled:
            return IndexerResult(
                success=False,
                indexer_name=self.name,
                error="OCI registry not configured (set OCI_REGISTRY env var)",
            )
        
        try:
            # Step 1: Ensure subject artifact exists
            subject_ref = subject_to_imageref(context.subject, self._registry, self._namespace)
            subject_digest = self._ensure_subject_artifact(subject_ref, context.subject)
            
            if not subject_digest:
                return IndexerResult(
                    success=False,
                    indexer_name=self.name,
                    error="Failed to create/verify subject artifact",
                )
            
            # Step 2: Push receipt as referrer
            receipt_ref = self._push_receipt_as_referrer(
                context.receipt,
                subject_ref,
                subject_digest,
                context.payload_hash,
            )
            
            if not receipt_ref:
                return IndexerResult(
                    success=False,
                    indexer_name=self.name,
                    error="Failed to push receipt as referrer",
                )
            
            logger.info(f"Indexed receipt to {receipt_ref}")
            
            return IndexerResult(
                success=True,
                indexer_name=self.name,
                reference=receipt_ref,
                metadata={
                    "subject_ref": subject_ref,
                    "subject_digest": subject_digest,
                },
            )
            
        except Exception as e:
            logger.error(f"OCI indexing failed: {e}")
            return IndexerResult(
                success=False,
                indexer_name=self.name,
                error=str(e),
            )
    
    def _run_oras(self, args: list[str], input_data: Optional[bytes] = None) -> tuple[bool, str, str]:
        """Run oras command with authentication."""
        cmd = [self._oras_path] + args
        
        # Add authentication if configured
        if self._username and self._password:
            cmd.extend(["--username", self._username, "--password", self._password])
        
        # Add insecure flag if needed
        if self._insecure:
            cmd.append("--insecure")
        
        logger.debug(f"Running: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(
                cmd,
                input=input_data,
                capture_output=True,
                text=True,
                timeout=60,
            )
            return result.returncode == 0, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return False, "", "Command timed out"
        except FileNotFoundError:
            return False, "", f"oras not found at {self._oras_path}"
    
    def _ensure_subject_artifact(self, subject_ref: str, subject: str) -> Optional[str]:
        """
        Ensure a subject artifact exists in the registry.
        
        Creates a minimal manifest if the subject doesn't exist.
        Returns the digest of the subject artifact.
        """
        # Check if subject already exists
        success, stdout, stderr = self._run_oras([
            "manifest", "fetch", subject_ref, "--descriptor"
        ])
        
        if success:
            # Parse digest from descriptor
            import json
            try:
                desc = json.loads(stdout)
                return desc.get("digest")
            except json.JSONDecodeError:
                pass
        
        # Subject doesn't exist - create it
        # We push an empty config with subject annotation
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write('{}')
            config_file = f.name
        
        try:
            # Push empty artifact as subject placeholder
            success, stdout, stderr = self._run_oras([
                "push", subject_ref,
                "--config", f"{config_file}:application/vnd.oci.empty.v1+json",
                "--annotation", f"scittish.subject={subject}",
            ])
            
            if not success:
                logger.error(f"Failed to create subject artifact: {stderr}")
                return None
            
            # Fetch the digest we just created
            success, stdout, stderr = self._run_oras([
                "manifest", "fetch", subject_ref, "--descriptor"
            ])
            
            if success:
                import json
                try:
                    desc = json.loads(stdout)
                    return desc.get("digest")
                except json.JSONDecodeError:
                    pass
            
            return None
            
        finally:
            os.unlink(config_file)
    
    def _push_receipt_as_referrer(
        self,
        receipt: bytes,
        subject_ref: str,
        subject_digest: str,
        payload_hash: str,
    ) -> Optional[str]:
        """
        Push receipt as a referrer to the subject.
        
        Uses ORAS to push the receipt with the --subject flag to create
        the referrer relationship.
        """
        import tempfile
        
        # Write receipt to temp file
        with tempfile.NamedTemporaryFile(delete=False, suffix='.cose') as f:
            f.write(receipt)
            receipt_file = f.name
        
        try:
            # Parse registry/repo from subject_ref
            # Format: registry/namespace/name:tag or registry/namespace/name@digest
            ref_base = subject_ref.split(":")[0].split("@")[0]
            
            # Tag for the receipt (use payload hash for uniqueness)
            receipt_tag = f"receipt-{payload_hash[:12]}"
            receipt_ref = f"{ref_base}:{receipt_tag}"
            
            # Push with subject reference
            success, stdout, stderr = self._run_oras([
                "push", receipt_ref,
                receipt_file + ":" + RECEIPT_MEDIA_TYPE,
                "--artifact-type", ARTIFACT_TYPE,
                "--subject", f"{subject_ref}@{subject_digest}",
                "--annotation", f"scittish.payload_hash={payload_hash}",
            ])
            
            if not success:
                logger.error(f"Failed to push receipt: {stderr}")
                return None
            
            return receipt_ref
            
        finally:
            os.unlink(receipt_file)
    
    def to_dict(self) -> dict:
        """Serialize indexer info for /properties endpoint."""
        return {
            "name": self.name,
            "description": self.description,
            "enabled": self.enabled,
            "registry": self._registry if self.enabled else None,
            "namespace": self._namespace if self.enabled else None,
        }
