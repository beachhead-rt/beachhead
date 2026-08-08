"""Auth broker — token management with expiry tracking and refresh.

The keystone of Phase 2: an async ``get(audience)`` that returns a valid access
token, refreshing transparently when the current one has expired.  Satisfies
both the ``TokenAuthority`` seam (pwsh cross-check) and the new
``TokenProvider`` protocol (module-facing ``ctx.auth``).

Token acquisition sources feed the broker via ``add`` (operator-provided raw
token) or ``add_msal_result`` (output of an MSAL auth flow).  Refresh is
delegated to an injected ``Refresher`` — the default ``MsalRefresher`` wraps
the synchronous ``msal`` library in ``asyncio.to_thread``.
"""

from __future__ import annotations

import asyncio
import binascii
import json
import time
from collections.abc import Sequence
from typing import Any, Protocol, runtime_checkable

import msal

from beachhead.core.auth.audience import _decode_segment, classify_audience
from beachhead.core.auth.token_entry import (
    AUDIENCE_SCOPES,
    EXPIRY_BUFFER_S,
    KNOWN_AUDIENCES,
    TokenEntry,
    _mask,
)
from beachhead.core.errors import AuthError

__all__ = ["AuthBroker", "Refresher", "MsalRefresher"]


# ---------------------------------------------------------------------------
# Refresher protocol + MSAL implementation
# ---------------------------------------------------------------------------
@runtime_checkable
class Refresher(Protocol):
    """Acquires a fresh token from refresh material."""

    async def refresh(self, entry: TokenEntry) -> TokenEntry: ...


class MsalRefresher:
    """Refreshes tokens via the ``msal`` library (sync, run in thread)."""

    def __init__(self) -> None:
        self._apps: dict[tuple[str, str], msal.PublicClientApplication] = {}

    def _get_app(self, client_id: str, tenant_id: str) -> msal.PublicClientApplication:
        key = (client_id, tenant_id)
        if key not in self._apps:
            self._apps[key] = msal.PublicClientApplication(
                client_id,
                authority=f"https://login.microsoftonline.com/{tenant_id}",
            )
        return self._apps[key]

    async def refresh(self, entry: TokenEntry) -> TokenEntry:
        if not entry.refreshable:
            raise AuthError(f"entry for {entry.audience!r} has no refresh material")
        if entry.client_id is None or entry.tenant_id is None or entry.refresh_token is None:
            raise AuthError(
                f"entry for {entry.audience!r} is refreshable but missing "
                "client_id, tenant_id, or refresh_token"
            )

        app = self._get_app(entry.client_id, entry.tenant_id)
        scopes = list(entry.scopes) or list(AUDIENCE_SCOPES.get(entry.audience, ()))

        result: dict[str, Any] = await asyncio.to_thread(
            app.acquire_token_by_refresh_token, entry.refresh_token, scopes=scopes
        )

        if "access_token" not in result:
            detail = result.get("error_description", result.get("error", "unknown"))
            raise AuthError(f"MSAL refresh failed for {entry.audience!r}: {detail}")

        return TokenEntry(
            access_token=result["access_token"],
            audience=entry.audience,
            expires_at=time.time() + result.get("expires_in", 3600),
            source="msal_refresh",
            refresh_token=result.get("refresh_token", entry.refresh_token),
            client_id=entry.client_id,
            tenant_id=entry.tenant_id,
            scopes=entry.scopes,
        )


def _extract_exp(token: str) -> float | None:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        payload = json.loads(_decode_segment(parts[1]))
    except (ValueError, binascii.Error):
        return None
    exp = payload.get("exp") if isinstance(payload, dict) else None
    return float(exp) if isinstance(exp, (int, float)) else None


# ---------------------------------------------------------------------------
# AuthBroker
# ---------------------------------------------------------------------------
_DEFAULT_TTL_S: float = 3600.0


class AuthBroker:
    """Token management with expiry tracking, refresh, and audience classification.

    Satisfies:
      - ``TokenAuthority`` (``audience_of``) for the pwsh cross-check.
      - ``TokenProvider`` (``async get``) for ``RunContext.auth``.
    """

    def __init__(
        self,
        *,
        refresher: Refresher | None = None,
        clock: Any = None,
    ) -> None:
        self._entries: dict[str, TokenEntry] = {}
        self._refresher = refresher
        # Wall-clock (time.time), not monotonic — JWT exp claims are Unix timestamps.
        self._clock = clock or time.time
        self._refresh_locks: dict[str, asyncio.Lock] = {}

    # -- ingest -------------------------------------------------------------

    def add(
        self,
        token: str,
        audience: str | None = None,
        *,
        expires_at: float | None = None,
        refresh_token: str | None = None,
        source: str = "operator",
        client_id: str | None = None,
        tenant_id: str | None = None,
        scopes: Sequence[str] = (),
    ) -> str:
        """File a token and return the audience it was filed under.

        Auto-classifies by ``aud`` claim; ``audience`` is an optional fallback
        label for opaque tokens.  Raises ``ValueError`` on conflicts (same
        rules as ``AuthBroker.add``).
        """
        if audience is not None and audience not in KNOWN_AUDIENCES:
            raise ValueError(
                f"unknown audience {audience!r}; expected one of {sorted(KNOWN_AUDIENCES)}"
            )
        detected = classify_audience(token)
        if detected is not None:
            if audience is not None and audience != detected:
                raise ValueError(
                    f"audience label {audience!r} contradicts the token's aud ({detected!r})"
                )
            filed = detected
        elif audience is not None:
            filed = audience
        else:
            raise ValueError(
                "could not classify token audience (opaque/non-JWT); pass "
                "audience='graph'|'arm' to file it explicitly"
            )

        if expires_at is None:
            jwt_exp = _extract_exp(token)
            expires_at = jwt_exp if jwt_exp is not None else self._clock() + _DEFAULT_TTL_S

        entry = TokenEntry(
            access_token=token,
            audience=filed,
            expires_at=expires_at,
            source=source,
            refresh_token=refresh_token,
            client_id=client_id,
            tenant_id=tenant_id,
            scopes=tuple(scopes),
        )
        self._entries[filed] = entry
        return filed

    def add_msal_result(
        self,
        result: dict[str, Any],
        *,
        audience: str,
        client_id: str,
        tenant_id: str,
    ) -> str:
        """Ingest an MSAL authentication result dict."""
        if audience not in KNOWN_AUDIENCES:
            raise ValueError(f"unknown audience {audience!r}")
        if "access_token" not in result:
            detail = result.get("error_description", result.get("error", "no access_token"))
            raise AuthError(f"cannot ingest MSAL result for {audience!r}: {detail}")

        scopes_str = result.get("scope", "")
        scopes = tuple(scopes_str.split()) if scopes_str else ()

        entry = TokenEntry(
            access_token=result["access_token"],
            audience=audience,
            expires_at=self._clock() + result.get("expires_in", 3600),
            source="msal",
            refresh_token=result.get("refresh_token"),
            client_id=client_id,
            tenant_id=tenant_id,
            scopes=scopes,
        )
        self._entries[audience] = entry
        return audience

    # -- retrieval ----------------------------------------------------------

    async def get(self, audience: str) -> str:
        """Return a valid access token, refreshing if expired.

        Raises ``AuthError`` when no token is loaded, the token is expired and
        cannot be refreshed, or the refresh itself fails.

        Uses a per-audience lock so concurrent callers don't trigger duplicate
        MSAL refreshes (which can invalidate rotating refresh tokens).
        """
        entry = self._entries.get(audience)
        if entry is None:
            raise AuthError(f"no token loaded for audience {audience!r}")

        if not self._needs_refresh(entry):
            return entry.access_token

        lock = self._refresh_locks.setdefault(audience, asyncio.Lock())
        async with lock:
            entry = self._entries.get(audience)
            if entry is None:
                raise AuthError(f"no token loaded for audience {audience!r}")
            if not self._needs_refresh(entry):
                return entry.access_token

            if entry.refreshable and self._refresher is not None:
                new_entry = await self._refresher.refresh(entry)
                self._entries[audience] = new_entry
                return new_entry.access_token

            raise AuthError(
                f"token for {audience!r} expired and no refresh available "
                f"(refreshable={entry.refreshable}, refresher={'set' if self._refresher else 'none'})"
            )

    def get_entry(self, audience: str) -> TokenEntry | None:
        """Inspect the entry (for status display / diagnostics)."""
        return self._entries.get(audience)

    # -- seams --------------------------------------------------------------

    def audience_of(self, token: str) -> str | None:
        """Classify a token's audience.  Satisfies the ``TokenAuthority`` seam."""
        return classify_audience(token)

    def audiences(self) -> tuple[str, ...]:
        return tuple(self._entries)

    # -- internals ----------------------------------------------------------

    def _needs_refresh(self, entry: TokenEntry) -> bool:
        return self._clock() >= (entry.expires_at - EXPIRY_BUFFER_S)

    def __repr__(self) -> str:
        masked = {aud: f"{e.source}, {_mask(e.access_token)}" for aud, e in self._entries.items()}
        return f"AuthBroker(tokens={masked})"

    __str__ = __repr__
