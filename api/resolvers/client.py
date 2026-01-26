"""
Client-provided subject resolver.

Uses the subject provided by the client via X-Scittish-Subject header.
This is the highest priority resolver.
"""

from .base import SubjectResolver, ResolverContext, ResolverResult


class ClientProvidedResolver(SubjectResolver):
    """
    Resolver that uses the client-provided subject.
    
    This resolver simply returns the subject that the client
    explicitly provided in the X-Scittish-Subject header.
    """
    
    @property
    def name(self) -> str:
        return "client-provided"
    
    @property
    def priority(self) -> int:
        return 0  # Highest priority
    
    @property
    def description(self) -> str:
        return "Uses subject provided by client via X-Scittish-Subject header"
    
    def resolve(self, context: ResolverContext) -> ResolverResult:
        if context.client_subject:
            return ResolverResult(
                subject=context.client_subject,
                resolver_name=self.name,
                confidence=1.0,
                metadata={"source": "X-Scittish-Subject header"},
            )
        
        return ResolverResult(
            subject=None,
            resolver_name=self.name,
        )
