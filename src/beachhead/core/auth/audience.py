"""Token audience classification.

Reads the ``aud`` claim of an access token we already hold to tell a Graph token from
an ARM token — the most common Beachhead 401 is using the wrong one. This is **not**
token validation: the signature, expiry, and issuer are never checked. Opaque /
encrypted / non-JWT tokens (Graph tokens are sometimes opaque) classify as ``None``,
and callers treat ``None`` as "unknown" (the pwsh cross-check skips on ``None``).
"""

from __future__ import annotations

import base64
import binascii
import json

__all__ = ["Audience", "classify_audience"]


class Audience:
    """Audience labels Beachhead recognises."""

    GRAPH = "graph"
    ARM = "arm"
    ADO = "ado"


# Known `aud` claim values -> our label. Compared after lower-casing and stripping a
# trailing slash, so keys are stored lowercase and slash-free. See docs/api-clients.md.
_AUD_MAP: dict[str, str] = {
    "https://graph.microsoft.com": Audience.GRAPH,
    "00000003-0000-0000-c000-000000000000": Audience.GRAPH,
    "https://management.azure.com": Audience.ARM,
    "https://management.core.windows.net": Audience.ARM,
}


def _decode_segment(segment: str) -> bytes:
    # JWT segments are base64url without padding; restore it before decoding.
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def classify_audience(token: str) -> str | None:
    """Return ``"graph"``/``"arm"`` for a recognised ``aud``, else ``None``. Never raises."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        payload = json.loads(_decode_segment(parts[1]))
    except (ValueError, binascii.Error):
        return None
    if not isinstance(payload, dict):
        return None
    aud = payload.get("aud")
    if not isinstance(aud, str):
        return None
    return _AUD_MAP.get(aud.rstrip("/").lower())
