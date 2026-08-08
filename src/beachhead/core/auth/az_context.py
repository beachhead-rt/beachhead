"""Az-context auth flow — extract tokens from an existing ``az login`` session.

Runs ``az account get-access-token --resource <url> --output json`` as a
lightweight subprocess (no full ``AzSubprocessClient`` needed since this is an
operator-local command, not a tenant-scoped API call). Returns a non-refreshable
``TokenEntry``; when the token expires the operator re-runs the flow or
re-authenticates via ``az login``.
"""

from __future__ import annotations

import asyncio
import json
import time
from datetime import UTC, datetime
from typing import Any

from beachhead.core.auth.token_entry import KNOWN_AUDIENCES, TokenEntry
from beachhead.core.errors import AuthError

__all__ = ["acquire_token_az_context"]

_AUDIENCE_RESOURCES: dict[str, str] = {
    "graph": "https://graph.microsoft.com",
    "arm": "https://management.azure.com",
}


async def acquire_token_az_context(
    *,
    audience: str,
    az_path: str = "az",
) -> TokenEntry:
    """Extract an access token from the operator's ``az`` CLI context.

    Args:
        audience: ``"graph"`` or ``"arm"``.
        az_path: Path to the ``az`` binary.

    Returns:
        A non-refreshable ``TokenEntry`` with ``source="az_context"``.

    Raises:
        AuthError: ``az`` is not logged in or the command failed.
        ValueError: Unknown audience.
    """
    if audience not in _AUDIENCE_RESOURCES:
        supported = sorted(_AUDIENCE_RESOURCES)
        if audience in KNOWN_AUDIENCES:
            raise ValueError(
                f"az-context auth does not support audience {audience!r}; "
                f"use 'ado-pat' for ADO authentication. "
                f"Supported audiences: {supported}"
            )
        raise ValueError(
            f"unknown audience {audience!r}; expected one of {supported}"
        )

    resource = _AUDIENCE_RESOURCES[audience]

    try:
        proc = await asyncio.create_subprocess_exec(
            az_path,
            "account",
            "get-access-token",
            "--resource",
            resource,
            "--output",
            "json",
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except (FileNotFoundError, PermissionError, OSError) as exc:
        raise AuthError(f"could not run az at {az_path!r}: {exc}") from exc

    out_b, err_b = await asyncio.wait_for(proc.communicate(), timeout=30.0)
    stderr = err_b.decode("utf-8", "replace")

    if proc.returncode != 0:
        raise AuthError(f"az account get-access-token failed: {stderr.strip()[-500:]}")

    try:
        result: dict[str, Any] = json.loads(out_b.decode("utf-8", "replace"))
    except (json.JSONDecodeError, ValueError) as exc:
        raise AuthError(f"az returned non-JSON output: {exc}") from exc

    access_token = result.get("accessToken")
    if not access_token:
        raise AuthError("az returned no accessToken")

    expires_at = _parse_expiry(result)

    return TokenEntry(
        access_token=access_token,
        audience=audience,
        expires_at=expires_at,
        source="az_context",
        refresh_token=None,
        client_id=None,
        tenant_id=result.get("tenant"),
        scopes=(),
    )


def _parse_expiry(result: dict[str, Any]) -> float:
    """Extract expiry from az output; fall back to 1 hour from now."""
    if "expires_on" in result:
        try:
            return float(result["expires_on"])
        except (TypeError, ValueError):
            pass
    if "expiresOn" in result:
        try:
            dt = datetime.fromisoformat(result["expiresOn"])
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=UTC)
            return dt.timestamp()
        except (TypeError, ValueError):
            pass
    expires_in: int = result.get("expires_in", 3600)
    return time.time() + expires_in
