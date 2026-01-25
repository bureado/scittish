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
        2. 'oid' (object ID) - Azure AD claim
        3. 'preferred_username' - OIDC claim
        4. 'email' - common claim
        
        Returns a subject in the format: jwt:<claim_type>:<claim_value>
        """
        auth_header = context.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            logger.debug("Bearer token resolver: no Bearer token in Authorization header")
            return ResolverResult(subject=None, resolver_name=self.name)
        
        # Extract token (remove "Bearer " prefix)
        token = auth_header[7:].strip()
        
        try:
            # Import here to avoid dependency issues if PyJWT not installed
            import jwt
            
            # Decode WITHOUT verification - we only need claims for subject resolution
            # This is safe because we're not using this for authn/authz
            claims = jwt.decode(token, options={"verify_signature": False})
            
            # Try to extract identity claims in priority order
            claim_priority = [
                ("sub", "subject"),
                ("oid", "object-id"),
                ("preferred_username", "username"),
                ("email", "email"),
            ]
            
            for claim_name, claim_type in claim_priority:
                claim_value = claims.get(claim_name)
                if claim_value:
                    subject = f"jwt:{claim_type}:{claim_value}"
                    logger.info(f"Bearer token resolver: extracted {claim_name} claim")
                    
                    return ResolverResult(
                        subject=subject,
                        resolver_name=self.name,
                        confidence=0.8,
                        metadata={
                            "source": "JWT bearer token",
                            "claim_type": claim_name,
                            "issuer": claims.get("iss", "unknown"),
                        },
                        indexable=True,
                    )
            
            # Token decoded but no useful claims found
            logger.debug(f"Bearer token resolver: no usable identity claims in token (claims: {list(claims.keys())})")
            return ResolverResult(
                subject=None,
                resolver_name=self.name,
                metadata={"note": "JWT present but no identity claims found"},
            )
            
        except ImportError:
            logger.warning("Bearer token resolver: PyJWT not installed - cannot parse JWT tokens")
            return ResolverResult(
                subject=None,
                resolver_name=self.name,
                metadata={"error": "PyJWT not installed"},
            )
        except jwt.DecodeError as e:
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
