"""
Fallback subject resolvers.

These resolvers provide fallback subject resolution when payload-based
resolvers cannot determine a subject.
"""

import logging
from typing import Optional

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
    
    Note: This is a stub implementation. A real implementation would
    validate the token and extract claims.
    """
    
    @property
    def name(self) -> str:
        return "bearer-token"
    
    @property
    def priority(self) -> int:
        return 210  # Identity-derived fallback
    
    @property
    def description(self) -> str:
        return "Derives subject from Authorization bearer token (stub)"
    
    def resolve(self, context: ResolverContext) -> ResolverResult:
        # STUB: In a real implementation, this would:
        # 1. Extract the Authorization header
        # 2. Validate the JWT token
        # 3. Extract claims (sub, oid, preferred_username, etc.)
        # 4. Construct a subject from the claims
        
        auth_header = context.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return ResolverResult(subject=None, resolver_name=self.name)
        
        # STUB: Just acknowledge we have a token but don't process it
        logger.debug("Bearer token resolver: token present but processing not implemented")
        
        # Return None - this is a stub
        return ResolverResult(
            subject=None,
            resolver_name=self.name,
            metadata={"note": "stub implementation - token validation not implemented"},
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
