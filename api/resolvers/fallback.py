"""
Fallback subject resolvers.

These resolvers provide fallback subject resolution when payload-based
resolvers cannot determine a subject.
"""

import logging
from typing import Optional

try:
    import jwt
except ImportError:
    jwt = None  # type: ignore

from .base import SubjectResolver, ResolverContext, ResolverResult

logger = logging.getLogger(__name__)


class EkuFallbackResolver(SubjectResolver):
    """
    Resolver that uses the certificate's EKU as a fallback subject.
    
    This is a fallback resolver that derives a subject from the signing
    certificate's Extended Key Usage OID. This provides a stable subject
    based on the signer's identity.
    
    Note: This is a stub implementation. The actual EKU extraction
    would need access to the certificate chain.
    """
    
    @property
    def name(self) -> str:
        return "eku-fallback"
    
    @property
    def priority(self) -> int:
        return 200  # Identity-derived fallback
    
    @property
    def description(self) -> str:
        return "Derives subject from certificate EKU (stub)"
    
    def resolve(self, context: ResolverContext) -> ResolverResult:
        # STUB: In a real implementation, this would:
        # 1. Access the certificate chain from the signing context
        # 2. Extract the EKU OID from the leaf certificate
        # 3. Construct a subject like "eku:1.3.6.1.5.5.7.3.36"
        
        # For now, check if EKU is in metadata (set by signing flow)
        eku = context.metadata.get("eku")
        if eku:
            subject = f"eku:{eku}"
            return ResolverResult(
                subject=subject,
                resolver_name=self.name,
                confidence=0.5,
                metadata={"source": "certificate EKU"},
                # EKU-derived subjects are less useful for indexing
                indexable=False,
            )
        
        logger.debug("EKU fallback resolver: no EKU in context metadata")
        return ResolverResult(subject=None, resolver_name=self.name)


class BearerTokenResolver(SubjectResolver):
    """
    Resolver that derives subject from an Authorization bearer token.
    
    This resolver extracts identity information from a JWT bearer token
    provided in the Authorization header and uses it to derive a subject.
    
    For OIDC JWT tokens, it extracts claims like 'sub', 'oid', 
    'preferred_username', or 'email' to construct a subject identifier.
    
    Note: This performs unvalidated JWT parsing - it extracts claims
    without cryptographic verification. This is suitable for subject
    resolution but should NOT be used for authentication/authorization.
    """
    
    @property
    def name(self) -> str:
        return "bearer-token"
    
    @property
    def priority(self) -> int:
        return 210  # Identity-derived fallback
    
    @property
    def description(self) -> str:
        return "Derives subject from OIDC JWT claims in Authorization bearer token"
    
    def resolve(self, context: ResolverContext) -> ResolverResult:
        """
        Extract subject from JWT bearer token claims.
        
        Attempts to extract claims in the following priority order:
        1. 'sub' (subject) - standard OIDC claim
        2. 'repository' - GitHub Actions repository claim (e.g., "owner/repo")
        3. 'job_workflow_ref' - GitHub Actions reusable workflow ref
        4. 'workflow_ref' - GitHub Actions workflow ref
        5. 'oid' (object ID) - Azure AD claim
        6. 'preferred_username' - OIDC claim
        7. 'email' - common claim
        
        For GitHub Actions tokens, also captures additional metadata like
        workflow_sha, event_name, actor, etc. for use in indexing.
        
        Returns a subject in the format: jwt:<claim_type>:<claim_value>
        """
        auth_header = context.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            logger.debug("Bearer token resolver: no Bearer token in Authorization header")
            return ResolverResult(subject=None, resolver_name=self.name)
        
        # Extract token (remove "Bearer " prefix)
        token = auth_header[7:].strip()
        
        # Check if PyJWT is available
        if jwt is None:
            logger.warning("Bearer token resolver: PyJWT not installed - cannot parse JWT tokens")
            return ResolverResult(
                subject=None,
                resolver_name=self.name,
                metadata={"error": "PyJWT not installed"},
            )
        
        try:
            # Decode WITHOUT verification - we only need claims for subject resolution
            # This is safe because we're not using this for authn/authz
            # We allow common algorithms (excluding 'none' for security)
            claims = jwt.decode(
                token, 
                options={"verify_signature": False},
                algorithms=["HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"]
            )
            
            # Try to extract identity claims in priority order
            # Inspired by sigstore/cosign's certificate extensions mapping
            # See: https://github.com/sigstore/cosign/blob/main/pkg/cosign/certextensions.go
            claim_priority = [
                ("sub", "subject"),                      # Standard OIDC subject claim
                ("repository", "repository"),             # GitHub Actions: owner/repo
                ("job_workflow_ref", "job-workflow"),    # GitHub Actions: reusable workflow ref
                ("workflow_ref", "workflow"),             # GitHub Actions: workflow file ref
                ("oid", "object-id"),                     # Azure AD object ID
                ("preferred_username", "username"),       # OIDC preferred username
                ("email", "email"),                       # Email claim
            ]
            
            for claim_name, claim_type in claim_priority:
                claim_value = claims.get(claim_name)
                if claim_value:
                    subject = f"jwt:{claim_type}:{claim_value}"
                    logger.info(f"Bearer token resolver: extracted {claim_name} claim")
                    
                    # Build metadata - capture GitHub Actions-specific claims if present
                    metadata = {
                        "source": "JWT bearer token",
                        "claim_type": claim_name,
                        "issuer": claims.get("iss", "unknown"),
                    }
                    
                    # Add GitHub Actions workflow metadata if available (for indexing hints)
                    if "repository" in claims:
                        metadata["gh_repository"] = claims["repository"]
                    if "workflow" in claims:
                        metadata["gh_workflow"] = claims["workflow"]
                    if "event_name" in claims:
                        metadata["gh_event"] = claims["event_name"]
                    if "actor" in claims:
                        metadata["gh_actor"] = claims["actor"]
                    if "run_id" in claims:
                        metadata["gh_run_id"] = claims["run_id"]
                    if "sha" in claims:
                        metadata["gh_sha"] = claims["sha"]
                    
                    return ResolverResult(
                        subject=subject,
                        resolver_name=self.name,
                        confidence=0.8,
                        metadata=metadata,
                        indexable=True,
                    )
            
            # Token decoded but no useful claims found
            logger.debug(f"Bearer token resolver: no usable identity claims in token (claims: {list(claims.keys())})")
            return ResolverResult(
                subject=None,
                resolver_name=self.name,
                metadata={"note": "JWT present but no identity claims found"},
            )
            
        except (jwt.DecodeError, jwt.InvalidTokenError) as e:
            logger.debug(f"Bearer token resolver: invalid JWT token - {e}")
            return ResolverResult(
                subject=None,
                resolver_name=self.name,
                metadata={"error": f"Invalid JWT: {str(e)}"},
            )
        except Exception as e:
            logger.warning(f"Bearer token resolver: unexpected error - {e}")
            return ResolverResult(
                subject=None,
                resolver_name=self.name,
                metadata={"error": f"Unexpected error: {str(e)}"},
            )


class HashFallbackResolver(SubjectResolver):
    """
    Resolver that uses the payload hash as a last-resort subject.
    
    This resolver always succeeds but produces subjects that are not
    particularly meaningful for human consumption. Use as a last resort.
    """
    
    @property
    def name(self) -> str:
        return "hash-fallback"
    
    @property
    def priority(self) -> int:
        return 999  # Absolute last resort
    
    @property
    def description(self) -> str:
        return "Uses payload SHA256 hash as subject (last resort)"
    
    def resolve(self, context: ResolverContext) -> ResolverResult:
        subject = f"sha256:{context.payload_hash}"
        return ResolverResult(
            subject=subject,
            resolver_name=self.name,
            confidence=0.1,
            metadata={"source": "payload hash"},
            # Hash-based subjects are poor for indexing
            indexable=False,
        )
