"""
Subject resolver modules for scittish.

Subject resolvers determine the canonical subject identifier for a signing request.
The resolved subject is used for:
- SCITT feed parameter
- OCI registry indexing (as referrer target)
- Cache keying

Resolvers are evaluated in priority order until one returns a subject.
"""

from .base import SubjectResolver, ResolverContext, ResolverResult
from .registry import ResolverRegistry, get_default_registry

__all__ = [
    "SubjectResolver",
    "ResolverContext", 
    "ResolverResult",
    "ResolverRegistry",
    "get_default_registry",
]
