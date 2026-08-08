"""Optional Graph Compact Format (GCF) encoding for tool responses.

The alert, security-event, and vulnerability tools return uniform record
collections under a ``data.affected_items`` array. GCF factors the repeated
field names of such a collection into a single header, which uses fewer tokens
than JSON when the response crosses the LLM boundary.

Encoding is opt-in via the ``RESPONSE_FORMAT`` environment variable
(``json`` default, or ``gcf``) and lossless: decoding the wire reproduces the
response. Each response stays complete (this is a format change only, no
cross-turn deduplication), so no record is ever omitted from a result.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

logger = logging.getLogger(__name__)


def gcf_enabled() -> bool:
    """Return True when RESPONSE_FORMAT selects the GCF wire format."""
    return os.getenv("RESPONSE_FORMAT", "json").strip().lower() == "gcf"


def render_result(label: str, result: Any, *, compact: bool) -> str:
    """Render a tool result body, honoring RESPONSE_FORMAT.

    Default (``json``) preserves the existing output exactly. ``gcf`` encodes
    the same result as a GCF generic wire. Falls back to JSON if encoding fails
    for any reason, so a fetched result is never lost to an encoding error.

    Args:
        label: Human-readable prefix (e.g. "Wazuh Alerts").
        result: The result dict to serialize.
        compact: Whether the caller requested compact (field-projected) output;
            controls JSON indentation for parity with existing behavior.

    Returns:
        The formatted response body (``"{label}:\\n{payload}"``).
    """
    if gcf_enabled():
        try:
            from gcf import encode_generic

            return f"{label}:\n{encode_generic(result)}"
        except Exception:
            logger.warning("GCF encoding failed; returning JSON output")

    indent = 2 if not compact else None
    return f"{label}:\n{json.dumps(result, indent=indent, default=str)}"
