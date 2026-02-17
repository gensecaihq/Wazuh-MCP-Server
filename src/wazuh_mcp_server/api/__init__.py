"""Wazuh API integration."""

from .wazuh_client import WazuhClient
from .wazuh_indexer import IndexerNotConfiguredError, WazuhIndexerClient

__all__ = ["WazuhClient", "WazuhIndexerClient", "IndexerNotConfiguredError"]
