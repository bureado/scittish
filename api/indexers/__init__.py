"""
Indexer modules for scittish.

Indexers are responsible for pushing receipts (transparent statements)
to external storage/index systems for discoverability.
"""

from .base import Indexer, IndexerContext, IndexerResult
from .oci import OciIndexer

__all__ = [
    "Indexer",
    "IndexerContext",
    "IndexerResult",
    "OciIndexer",
]
