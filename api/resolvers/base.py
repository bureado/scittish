"""
Base classes for subject resolvers.

This module defines the interface that all subject resolvers must implement.
The architecture is designed to support a future policy engine (Rego) that
can control resolver selection and subject transformation.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class ResolverContext:
    """
    Context passed to subject resolvers.
    
    Contains all information about the signing request that resolvers
    may use to determine the subject.
    
    Attributes:
        payload: Raw payload bytes (may be None for hash-only signing)
        payload_hash: SHA256 hash of the payload
        content_type: Content-Type of the payload
        client_subject: Subject provided by client via X-Scittish-Subject header
        headers: All request headers (for bearer token extraction, etc.)
        metadata: Additional metadata that may be populated by earlier resolvers
    """
    payload: Optional[bytes]
    payload_hash: str
    content_type: str
    client_subject: Optional[str] = None
    headers: dict[str, str] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ResolverResult:
    """
    Result from a subject resolver.
    
    Attributes:
        subject: The resolved subject string (None if resolver couldn't determine)
        resolver_name: Name of the resolver that produced this result
        confidence: Confidence score (0.0-1.0) for policy decisions
        metadata: Additional metadata about the resolution (e.g., source field)
        indexable: Whether this subject should be indexed in OCI registry
        index_hint: Optional hint for OCI indexing (registry, namespace override)
    """
    subject: Optional[str]
    resolver_name: str
    confidence: float = 1.0
    metadata: dict[str, Any] = field(default_factory=dict)
    indexable: bool = True
    index_hint: Optional[dict[str, str]] = None


class SubjectResolver(ABC):
    """
    Abstract base class for subject resolvers.
    
    Subject resolvers examine the signing request context and attempt
    to determine a canonical subject identifier. Resolvers are called
    in priority order; the first resolver to return a non-None subject wins.
    
    Subclasses must implement:
        - name: Human-readable name for the resolver
        - priority: Numeric priority (lower = higher priority)
        - resolve(): The resolution logic
    
    The architecture supports future policy integration:
        - pre_resolve_hook: Called before resolution for policy checks
        - post_resolve_hook: Called after resolution for policy transforms
    """
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable name for this resolver."""
        pass
    
    @property
    @abstractmethod
    def priority(self) -> int:
        """
        Priority for resolver ordering. Lower values = higher priority.
        
        Suggested ranges:
            0-99: Client-provided/explicit subjects
            100-199: Payload-derived subjects (SBOM, in-toto, etc.)
            200-299: Identity-derived subjects (EKU, bearer token)
            300+: Fallback resolvers
        """
        pass
    
    @property
    def description(self) -> str:
        """Optional description of what this resolver does."""
        return ""
    
    @property
    def supported_content_types(self) -> list[str]:
        """
        List of content types this resolver can handle.
        Empty list means all content types.
        """
        return []
    
    def can_resolve(self, context: ResolverContext) -> bool:
        """
        Check if this resolver can handle the given context.
        
        Default implementation checks content type if supported_content_types is set.
        Override for more complex logic.
        """
        if not self.supported_content_types:
            return True
        return context.content_type in self.supported_content_types
    
    @abstractmethod
    def resolve(self, context: ResolverContext) -> ResolverResult:
        """
        Attempt to resolve a subject from the context.
        
        Returns a ResolverResult with subject=None if this resolver
        cannot determine a subject from the given context.
        """
        pass
    
    # --- Policy integration hooks (for future Rego integration) ---
    
    def pre_resolve_hook(self, context: ResolverContext) -> Optional[ResolverContext]:
        """
        Hook called before resolution. Can modify context or return None to skip.
        
        Future: Will be replaced by policy decision point.
        """
        return context
    
    def post_resolve_hook(self, result: ResolverResult, context: ResolverContext) -> ResolverResult:
        """
        Hook called after resolution. Can modify or reject the result.
        
        Future: Will be replaced by policy enforcement point.
        """
        return result
    
    def to_dict(self) -> dict[str, Any]:
        """Serialize resolver info for /properties endpoint."""
        return {
            "name": self.name,
            "priority": self.priority,
            "description": self.description,
            "supported_content_types": self.supported_content_types,
        }
