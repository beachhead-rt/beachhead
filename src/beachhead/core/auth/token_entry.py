"""Token entry — enriched token container for core/auth.

From day one the auth broker manages ``TokenEntry`` objects rather than bare
strings so expiry tracking, refresh material, and provenance are carried
structurally.  See the forward-design note in
``docs/superpowers/specs/2026-06-01-core-auth-audience-classifier-design.md``.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from beachhead.core.auth.audience import Audience

__all__ = ["TokenEntry", "KNOWN_AUDIENCES", "AUDIENCE_SCOPES", "EXPIRY_BUFFER_S"]

KNOWN_AUDIENCES: frozenset[str] = frozenset({Audience.GRAPH, Audience.ARM, Audience.ADO})

AUDIENCE_SCOPES: dict[str, tuple[str, ...]] = {
    Audience.GRAPH: ("https://graph.microsoft.com/.default",),
    Audience.ARM: ("https://management.azure.com/.default",),
    Audience.ADO: ("499b84ac-1321-427f-aa17-267ca6975798/.default",),
}

EXPIRY_BUFFER_S: int = 300


def _mask(token: str) -> str:
    return f"…{token[-4:]}" if len(token) >= 4 else "…"


@dataclass(frozen=True, slots=True)
class TokenEntry:
    """An access token with expiry, audience, refresh material, and provenance.

    Frozen and slotted.  The ``expired`` convenience property uses wall-clock
    time; the broker uses its own injected clock for decisions.
    """

    access_token: str
    audience: str
    expires_at: float
    source: str

    display_name: str | None = None
    refresh_token: str | None = None
    client_id: str | None = None
    tenant_id: str | None = None
    scopes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.audience not in KNOWN_AUDIENCES:
            raise ValueError(
                f"unknown audience {self.audience!r}; expected one of {sorted(KNOWN_AUDIENCES)}"
            )
        if not self.access_token:
            raise ValueError("access_token must not be empty")
        if not self.source:
            raise ValueError("source must not be empty")
        object.__setattr__(self, "scopes", tuple(self.scopes))

    @property
    def expired(self) -> bool:
        """Convenience check against wall-clock time (includes buffer)."""
        return time.time() >= (self.expires_at - EXPIRY_BUFFER_S)

    @property
    def refreshable(self) -> bool:
        return (
            self.refresh_token is not None
            and self.client_id is not None
            and self.tenant_id is not None
        )

    def __repr__(self) -> str:
        return (
            f"TokenEntry(audience={self.audience!r}, source={self.source!r}, "
            f"expired={self.expired}, refreshable={self.refreshable}, "
            f"token={_mask(self.access_token)})"
        )

    __str__ = __repr__
