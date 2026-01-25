"""
Base classes for indexers.

Indexers push receipts to external systems for discoverability and persistence.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class IndexerContext:
    """
    Context for indexing a receipt.
    
    Attributes:
        receipt: The transparent statement (COSE bytes)
        subject: The resolved subject string
        payload_hash: SHA256 hash of the original payload
        content_type: Content-Type of the original payload
        resolver_metadata: Metadata from the subject resolver
    """
    receipt: bytes
    subject: str
    payload_hash: str
    content_type: str
    resolver_metadata: dict[str, Any] = field(default_factory=dict)


@dataclass 
class IndexerResult:
    """
    Result from an indexer.
    
    Attributes:
        success: Whether indexing succeeded
        indexer_name: Name of the indexer
        reference: Reference to the indexed artifact (e.g., OCI digest)
        error: Error message if failed
        metadata: Additional metadata about the indexing
    """
    success: bool
    indexer_name: str
    reference: Optional[str] = None
    error: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)


class Indexer(ABC):
    """
    Abstract base class for indexers.
    
    Indexers receive a receipt and subject after successful signing/submission,
    and push the receipt to an external system for discoverability.
    """
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable name for this indexer."""
        pass
    
    @property
    def description(self) -> str:
        """Optional description of what this indexer does."""
        return ""
    
    @property
    def enabled(self) -> bool:
        """Whether this indexer is enabled. Override to disable conditionally."""
        return True
    
    @abstractmethod
    def index(self, context: IndexerContext) -> IndexerResult:
        """
        Index the receipt.
        
        Returns an IndexerResult indicating success or failure.
        """
        pass
    
    def to_dict(self) -> dict[str, Any]:
        """Serialize indexer info for /properties endpoint."""
        return {
            "name": self.name,
            "description": self.description,
            "enabled": self.enabled,
        }
