"""
SLSA in-toto subject resolver.

Extracts subject from SLSA provenance / in-toto attestation documents.
"""

import json
import logging
from typing import Optional

from .base import SubjectResolver, ResolverContext, ResolverResult

logger = logging.getLogger(__name__)


class SlsaInTotoResolver(SubjectResolver):
    """
    Resolver that extracts subject from SLSA/in-toto attestations.
    
    In-toto attestations contain a subject array that identifies what
    the attestation is about. This resolver extracts the first subject's
    name (or digest) as the indexing subject.
    
    Supported formats:
    - In-toto statement (application/vnd.in-toto+json)
    - DSSE envelope containing in-toto
    - Generic JSON that looks like in-toto/SLSA
    """
    
    @property
    def name(self) -> str:
        return "slsa-intoto"
    
    @property
    def priority(self) -> int:
        return 110  # Payload-derived, after SPDX
    
    @property
    def description(self) -> str:
        return "Extracts subject from SLSA/in-toto attestation subject field"
    
    @property
    def supported_content_types(self) -> list[str]:
        return [
            "application/vnd.in-toto+json",
            "application/json",
        ]
    
    def resolve(self, context: ResolverContext) -> ResolverResult:
        if context.payload is None:
            return ResolverResult(subject=None, resolver_name=self.name)
        
        subject = self._extract_subject(context.payload)
        if subject:
            return ResolverResult(
                subject=subject,
                resolver_name=self.name,
                confidence=0.9,
                metadata={
                    "source": "in-toto statement subject",
                    "format": "intoto",
                },
            )
        
        return ResolverResult(subject=None, resolver_name=self.name)
    
    def _extract_subject(self, payload: bytes) -> Optional[str]:
        """Extract subject from in-toto statement or DSSE envelope."""
        try:
            data = json.loads(payload.decode("utf-8"))
            
            # Handle DSSE envelope
            if data.get("payloadType") == "application/vnd.in-toto+json":
                # DSSE envelope - decode the payload
                import base64
                inner_payload = base64.b64decode(data.get("payload", ""))
                data = json.loads(inner_payload.decode("utf-8"))
            
            # Check if this looks like an in-toto statement
            if not self._is_intoto_statement(data):
                return None
            
            # Extract subject
            subjects = data.get("subject", [])
            if not subjects:
                return None
            
            # Use first subject
            first_subject = subjects[0]
            
            # Prefer name over digest
            name = first_subject.get("name")
            if name:
                return name
            
            # Fall back to digest
            digest = first_subject.get("digest", {})
            if digest:
                # Return first digest in format "alg:value"
                for alg, value in digest.items():
                    return f"{alg}:{value}"
            
            return None
            
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            logger.debug(f"Failed to parse payload as JSON: {e}")
            return None
        except Exception as e:
            logger.debug(f"Failed to extract in-toto subject: {e}")
            return None
    
    def _is_intoto_statement(self, data: dict) -> bool:
        """Check if the JSON data looks like an in-toto statement."""
        # In-toto statement type
        statement_type = data.get("_type")
        if statement_type == "https://in-toto.io/Statement/v0.1":
            return True
        if statement_type == "https://in-toto.io/Statement/v1":
            return True
        
        # SLSA provenance predicate types
        predicate_type = data.get("predicateType", "")
        if "slsa.dev/provenance" in predicate_type:
            return True
        
        # Check for in-toto specific fields
        return "subject" in data and "predicateType" in data
