"""
SPDX SBOM subject resolver.

Extracts subject from SPDX SBOM documents using the documentNamespace field.
"""

import json
import logging
from typing import Optional

from .base import SubjectResolver, ResolverContext, ResolverResult

logger = logging.getLogger(__name__)


class SpdxSbomResolver(SubjectResolver):
    """
    Resolver that extracts subject from SPDX SBOM documents.
    
    SPDX SBOMs contain a documentNamespace field that uniquely identifies
    the document. This is used as the subject for indexing.
    
    Supported formats:
    - SPDX JSON (application/spdx+json)
    - Generic JSON that looks like SPDX
    """
    
    @property
    def name(self) -> str:
        return "spdx-sbom"
    
    @property
    def priority(self) -> int:
        return 100  # Payload-derived
    
    @property
    def description(self) -> str:
        return "Extracts subject from SPDX SBOM documentNamespace field"
    
    @property
    def supported_content_types(self) -> list[str]:
        return [
            "application/spdx+json",
            "application/json",  # May contain SPDX
        ]
    
    def resolve(self, context: ResolverContext) -> ResolverResult:
        if context.payload is None:
            return ResolverResult(subject=None, resolver_name=self.name)
        
        namespace = self._extract_namespace(context.payload)
        if namespace:
            return ResolverResult(
                subject=namespace,
                resolver_name=self.name,
                confidence=0.9,
                metadata={
                    "source": "SPDX documentNamespace",
                    "format": "spdx-json",
                },
            )
        
        return ResolverResult(subject=None, resolver_name=self.name)
    
    def _extract_namespace(self, payload: bytes) -> Optional[str]:
        """Extract documentNamespace from SPDX JSON."""
        try:
            data = json.loads(payload.decode("utf-8"))
            
            # Check if this looks like an SPDX document
            if not self._is_spdx_document(data):
                return None
            
            # SPDX 2.x uses documentNamespace
            namespace = data.get("documentNamespace")
            if namespace:
                return namespace
            
            # SPDX 3.x might use different structure
            # TODO: Add SPDX 3.x support when finalized
            
            return None
            
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            logger.debug(f"Failed to parse payload as JSON: {e}")
            return None
    
    def _is_spdx_document(self, data: dict) -> bool:
        """Check if the JSON data looks like an SPDX document."""
        # SPDX 2.x indicators
        if data.get("spdxVersion", "").startswith("SPDX-"):
            return True
        
        # Check for SPDX-specific fields
        spdx_fields = ["documentNamespace", "SPDXID", "creationInfo"]
        return any(field in data for field in spdx_fields)
