"""Engagement scope enforcement (core/scope.py).

resolve_scope() expands a loaded EngagementConfig into a concrete ResolvedScope snapshot —
management groups resolved to member subscriptions via an injected ManagementGroupResolver
seam (ARM-backed impl deferred; fail-closed). ScopeGuard.check() enforces that snapshot
synchronously on every client/az/pwsh target: out-of-scope or out-of-window raises ScopeError.
See docs/opsec-and-scope.md and docs/superpowers/specs/2026-06-04-core-config-scope-design.md.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol, runtime_checkable
from urllib.parse import urlsplit

from beachhead.core.config import EngagementConfig
from beachhead.core.errors import ConfigError, ScopeError

__all__ = [
    "ManagementGroupResolver",
    "ResolvedScope",
    "ScopeDiff",
    "ScopeGuard",
    "diff_scope",
    "resolve_scope",
]

_SUB_RE = re.compile(r"^/subscriptions/([^/]+)", re.IGNORECASE)
_GUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE
)


@runtime_checkable
class ManagementGroupResolver(Protocol):
    """Seam: resolve a management group to all descendant subscription GUIDs (recursive).

    Tests use a fake.
    """

    async def subscriptions_under(self, management_group_id: str) -> list[str]: ...


@dataclass(frozen=True)
class ResolvedScope:
    """Immutable resolved boundary snapshot consumed by ScopeGuard. Never hashed/mutated."""

    tenants: frozenset[str]
    subscriptions: frozenset[str]
    resource_scopes: tuple[str, ...]
    ado_organizations: frozenset[str]
    window_start: datetime
    window_end: datetime
    resolved_at: datetime
    subscriptions_by_mg: dict[str, tuple[str, ...]] = field(default_factory=dict)
    unresolved_mgs: tuple[str, ...] = ()

    @property
    def is_empty(self) -> bool:
        return not (
            self.tenants or self.subscriptions or self.resource_scopes or self.ado_organizations
        )


@dataclass(frozen=True)
class ScopeDiff:
    """Per-re-resolve subscription delta, for the audited 'scope amended' record."""

    added: frozenset[str]
    removed: frozenset[str]
    by_mg_added: dict[str, frozenset[str]] = field(default_factory=dict)
    by_mg_removed: dict[str, frozenset[str]] = field(default_factory=dict)


async def resolve_scope(
    config: EngagementConfig,
    resolver: ManagementGroupResolver | None = None,
    *,
    clock: Callable[[], datetime],
) -> ResolvedScope:
    """Expand declared management groups into a concrete ResolvedScope snapshot.

    Fail-closed: a management group declared with no resolver raises ConfigError; a resolver
    error for one MG contributes no subscriptions and is recorded in ``unresolved_mgs``.
    """
    subscriptions: set[str] = set(config.subscriptions)
    by_mg: dict[str, tuple[str, ...]] = {}
    unresolved: list[str] = []

    if config.management_groups:
        if resolver is None:
            raise ConfigError("management_groups declared but no ManagementGroupResolver available")
        for mg in sorted(config.management_groups):
            try:
                subs = await resolver.subscriptions_under(mg)
            except Exception:  # fail-closed: this MG contributes nothing; recorded as unresolved
                unresolved.append(mg)
                continue
            by_mg[mg] = tuple(subs)
            subscriptions.update(subs)

    return ResolvedScope(
        tenants=config.tenants,
        subscriptions=frozenset(subscriptions),
        resource_scopes=config.resource_scopes,
        ado_organizations=config.ado_organizations,
        window_start=config.window_start,
        window_end=config.window_end,
        resolved_at=clock(),
        subscriptions_by_mg=by_mg,
        unresolved_mgs=tuple(unresolved),
    )


def diff_scope(old: ResolvedScope, new: ResolvedScope) -> ScopeDiff:
    """Net + per-MG subscription delta between two resolved snapshots. Pure; no I/O."""
    by_mg_added: dict[str, frozenset[str]] = {}
    by_mg_removed: dict[str, frozenset[str]] = {}
    for mg in set(old.subscriptions_by_mg) | set(new.subscriptions_by_mg):
        before = frozenset(old.subscriptions_by_mg.get(mg, ()))
        after = frozenset(new.subscriptions_by_mg.get(mg, ()))
        if after - before:
            by_mg_added[mg] = after - before
        if before - after:
            by_mg_removed[mg] = before - after
    return ScopeDiff(
        added=new.subscriptions - old.subscriptions,
        removed=old.subscriptions - new.subscriptions,
        by_mg_added=by_mg_added,
        by_mg_removed=by_mg_removed,
    )


class ScopeGuard:
    """Synchronous authorization boundary over a ResolvedScope. Implements module.ScopeGuard.

    check() raises ScopeError when the call is outside the engagement window (unless
    allow_outside_window) or the target is not covered by any allowed dimension. Fail-closed:
    empty scope, empty/unparseable target, and unknown kinds all raise.
    """

    def __init__(
        self,
        resolved: ResolvedScope,
        *,
        clock: Callable[[], datetime],
        allow_outside_window: bool = False,
    ) -> None:
        self._scope = resolved
        self._clock = clock
        self._allow_outside_window = allow_outside_window
        self._tenants_lower = frozenset(t.lower() for t in resolved.tenants)
        self._subs_lower = frozenset(s.lower() for s in resolved.subscriptions)
        self._ado_orgs_lower = frozenset(o.lower() for o in resolved.ado_organizations)

    @property
    def allow_outside_window(self) -> bool:
        return self._allow_outside_window

    def check(self, target: str, *, kind: str = "target") -> None:
        self._check_window()
        if self._scope.is_empty:
            raise ScopeError("engagement scope is empty — refuse to run")
        if not target or not target.strip():
            raise ScopeError(f"empty target for kind={kind!r}")
        if not self._in_scope(target.strip(), kind.lower()):
            raise ScopeError(f"target out of scope: {target!r} (kind={kind!r})")

    def _check_window(self) -> None:
        if self.allow_outside_window:
            return
        now = self._clock()
        if now.tzinfo is None:
            raise ScopeError(
                "clock returned a timezone-naive datetime; refusing to evaluate engagement window"
            )
        if self._scope.window_start.tzinfo is None or self._scope.window_end.tzinfo is None:
            raise ScopeError(
                "engagement window bounds are timezone-naive; refusing to evaluate window"
            )
        if not (self._scope.window_start <= now <= self._scope.window_end):
            raise ScopeError(
                "outside engagement window "
                f"[{self._scope.window_start.isoformat()}, {self._scope.window_end.isoformat()}]"
            )

    def _in_scope(self, target: str, kind: str) -> bool:
        if kind in ("tenant", "graph"):
            return self._match_tenant(target)
        if kind == "subscription":
            return self._match_subscription(target)
        if kind in ("resource", "arm"):
            return self._match_resource(target)
        if kind == "ado":
            return self._match_ado(target)
        if kind in ("pwsh", "target"):
            return self._match_any(target)
        return False  # unknown kind -> fail closed

    def _match_tenant(self, target: str) -> bool:
        return target.lower() in self._tenants_lower

    def _match_subscription(self, target: str) -> bool:
        return target.lower() in self._subs_lower

    def _match_resource(self, target: str) -> bool:
        m = _SUB_RE.match(target)
        if m is not None and self._match_subscription(m.group(1)):
            return True
        return self._match_prefix(target)

    def _match_prefix(self, target: str) -> bool:
        norm = target.rstrip("/").lower()
        for prefix in self._scope.resource_scopes:
            p = prefix.rstrip("/").lower()
            if norm == p or norm.startswith(p + "/"):
                return True
        return False

    def _match_ado(self, target: str) -> bool:
        return _ado_org(target) in self._ado_orgs_lower

    def _match_any(self, target: str) -> bool:
        if target.lower().startswith("/subscriptions/"):
            return self._match_resource(target)
        if _GUID_RE.match(target):
            # ADO orgs are never GUID-shaped; a GUID only matches tenant/subscription.
            return self._match_tenant(target) or self._match_subscription(target)
        return self._match_ado(target)


def _ado_org(target: str) -> str:
    """Extract the ADO org token from a bare name or a dev.azure.com / *.visualstudio.com URL.

    Host-based, not substring-based: an attacker-controlled host or a path/query that
    merely *contains* an ADO marker cannot spoof an in-scope org. A URL whose real host
    is not a recognized ADO host returns "" (fail-closed — an empty org matches nothing).
    """
    t = target.strip().rstrip("/")
    if not t:
        return ""
    if not any(c in t for c in "./@:"):
        return t.lower()  # bare org name (ADO org names are letters/digits/hyphens only)
    raw = t if "://" in t else "//" + t
    parts = urlsplit(raw)
    host = (parts.hostname or "").lower()
    if host == "dev.azure.com":
        segments = [s for s in parts.path.split("/") if s]
        return segments[0].lower() if segments else ""
    if host.endswith(".visualstudio.com"):
        label = host[: -len(".visualstudio.com")]
        return label if label and "." not in label else ""
    return ""  # unrecognized host -> fail closed
