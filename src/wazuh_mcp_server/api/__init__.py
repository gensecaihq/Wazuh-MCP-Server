"""Wazuh API integration."""

from .wazuh_client import WazuhClient
from .wazuh_indexer import WazuhIndexerClient, IndexerNotConfiguredError

__all__ = ["WazuhClient", "WazuhIndexerClient", "IndexerNotConfiguredError"]