"""
Subject resolver registry.

Manages registration and execution of subject resolvers.
"""

import logging
from typing import Optional

from .base import SubjectResolver, ResolverContext, ResolverResult

logger = logging.getLogger(__name__)


class ResolverRegistry:
    """
    Registry for subject resolvers.
    
    Resolvers are registered and then executed in priority order
    when resolving a subject. The first resolver to return a non-None
    subject wins.
    
    The registry also provides hooks for future policy integration.
    """
    
    def __init__(self):
        self._resolvers: list[SubjectResolver] = []
        self._sorted = False
    
    def register(self, resolver: SubjectResolver) -> None:
        """Register a resolver. Resolvers will be sorted by priority on first use."""
        self._resolvers.append(resolver)
        self._sorted = False
        logger.info(f"Registered subject resolver: {resolver.name} (priority={resolver.priority})")
    
    def _ensure_sorted(self) -> None:
        """Sort resolvers by priority if needed."""
        if not self._sorted:
            self._resolvers.sort(key=lambda r: r.priority)
            self._sorted = True
    
    def resolve(self, context: ResolverContext) -> ResolverResult:
        """
        Resolve a subject using registered resolvers.
        
        Resolvers are tried in priority order. The first resolver
        to return a non-None subject wins.
        
        Returns a ResolverResult with subject=None if no resolver
        could determine a subject.
        """
        self._ensure_sorted()
        
        for resolver in self._resolvers:
            # Check if resolver can handle this context
            if not resolver.can_resolve(context):
                logger.debug(f"Resolver {resolver.name} skipped (cannot handle context)")
                continue
            
            # Pre-resolve hook (for future policy integration)
            modified_context = resolver.pre_resolve_hook(context)
            if modified_context is None:
                logger.debug(f"Resolver {resolver.name} skipped by pre_resolve_hook")
                continue
            
            # Attempt resolution
            try:
                result = resolver.resolve(modified_context)
            except Exception as e:
                logger.warning(f"Resolver {resolver.name} failed: {e}")
                continue
            
            # Post-resolve hook (for future policy integration)
            result = resolver.post_resolve_hook(result, modified_context)
            
            if result.subject is not None:
                logger.info(f"Subject resolved by {resolver.name}: {result.subject[:50]}...")
                return result
        
        # No resolver could determine a subject
        logger.info("No resolver could determine a subject")
        return ResolverResult(
            subject=None,
            resolver_name="none",
            confidence=0.0,
            indexable=False,
        )
    
    def get_resolvers(self) -> list[SubjectResolver]:
        """Get all registered resolvers, sorted by priority."""
        self._ensure_sorted()
        return list(self._resolvers)
    
    def to_dict(self) -> list[dict]:
        """Serialize all resolvers for /properties endpoint."""
        self._ensure_sorted()
        return [r.to_dict() for r in self._resolvers]


# Global registry instance
_default_registry: Optional[ResolverRegistry] = None


def get_default_registry() -> ResolverRegistry:
    """Get the default resolver registry, creating it if needed."""
    global _default_registry
    if _default_registry is None:
        _default_registry = ResolverRegistry()
        _register_default_resolvers(_default_registry)
    return _default_registry


def _register_default_resolvers(registry: ResolverRegistry) -> None:
    """Register the default set of resolvers."""
    # Import here to avoid circular imports
    from .client import ClientProvidedResolver
    from .spdx import SpdxSbomResolver
    from .slsa import SlsaInTotoResolver
    from .fallback import EkuFallbackResolver, BearerTokenResolver
    
    registry.register(ClientProvidedResolver())
    registry.register(SpdxSbomResolver())
    registry.register(SlsaInTotoResolver())
    registry.register(EkuFallbackResolver())
    registry.register(BearerTokenResolver())
