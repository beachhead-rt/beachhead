"""Tests for core/scope resolution (resolve_scope, diff_scope). Fake seams; never live."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime

import pytest

from beachhead.core.config import EngagementConfig
from beachhead.core.errors import ConfigError
from beachhead.core.scope import ManagementGroupResolver, ResolvedScope, diff_scope, resolve_scope


def test_resolved_scope_is_empty_flag() -> None:
    base = dict(
        tenants=frozenset(),
        subscriptions=frozenset(),
        resource_scopes=(),
        ado_organizations=frozenset(),
        window_start=datetime(2026, 4, 1, tzinfo=UTC),
        window_end=datetime(2026, 4, 30, tzinfo=UTC),
        resolved_at=datetime(2026, 4, 2, tzinfo=UTC),
    )
    assert ResolvedScope(**base).is_empty is True
    assert ResolvedScope(**{**base, "tenants": frozenset({"t1"})}).is_empty is False


class _FakeResolver:
    async def subscriptions_under(self, management_group_id: str) -> list[str]:
        return []


def test_fake_resolver_satisfies_protocol() -> None:
    assert isinstance(_FakeResolver(), ManagementGroupResolver)


def _fixed_clock() -> Callable[[], datetime]:
    return lambda: datetime(2026, 4, 10, 12, 0, tzinfo=UTC)


def _config(**overrides: object) -> EngagementConfig:
    base = dict(
        engagement="ACME",
        authorization_ref="SOW",
        window_start=datetime(2026, 4, 1, tzinfo=UTC),
        window_end=datetime(2026, 4, 30, tzinfo=UTC),
        tenants=frozenset({"t1"}),
        management_groups=frozenset(),
        subscriptions=frozenset(),
        resource_scopes=(),
        ado_organizations=frozenset(),
        allow_write=False,
    )
    base.update(overrides)
    return EngagementConfig(**base)  # type: ignore[arg-type]


class _Resolver:
    def __init__(self, mapping: dict[str, list[str]], fail: set[str] | None = None) -> None:
        self._mapping = mapping
        self._fail = fail or set()

    async def subscriptions_under(self, management_group_id: str) -> list[str]:
        if management_group_id in self._fail:
            raise RuntimeError("ARM boom")
        return list(self._mapping.get(management_group_id, []))


async def test_resolve_no_mgs_does_not_call_resolver() -> None:
    cfg = _config(subscriptions=frozenset({"sub-A"}))
    resolved = await resolve_scope(cfg, None, clock=_fixed_clock())
    assert resolved.subscriptions == frozenset({"sub-A"})
    assert resolved.resolved_at == datetime(2026, 4, 10, 12, 0, tzinfo=UTC)
    assert resolved.unresolved_mgs == ()


async def test_resolve_expands_mgs_and_unions_explicit_subs() -> None:
    cfg = _config(management_groups=frozenset({"mg-1"}), subscriptions=frozenset({"sub-X"}))
    resolver = _Resolver({"mg-1": ["sub-A", "sub-B"]})
    resolved = await resolve_scope(cfg, resolver, clock=_fixed_clock())
    assert resolved.subscriptions == frozenset({"sub-X", "sub-A", "sub-B"})
    assert resolved.subscriptions_by_mg == {"mg-1": ("sub-A", "sub-B")}


async def test_resolve_mgs_without_resolver_raises() -> None:
    cfg = _config(management_groups=frozenset({"mg-1"}))
    with pytest.raises(ConfigError, match="no ManagementGroupResolver"):
        await resolve_scope(cfg, None, clock=_fixed_clock())


async def test_resolve_failing_mg_is_fail_closed_and_recorded() -> None:
    cfg = _config(management_groups=frozenset({"mg-ok", "mg-bad"}))
    resolver = _Resolver({"mg-ok": ["sub-A"]}, fail={"mg-bad"})
    resolved = await resolve_scope(cfg, resolver, clock=_fixed_clock())
    assert resolved.subscriptions == frozenset({"sub-A"})  # bad MG contributed nothing
    assert resolved.unresolved_mgs == ("mg-bad",)


def _resolved(subs: set[str], by_mg: dict[str, tuple[str, ...]]) -> ResolvedScope:
    return ResolvedScope(
        tenants=frozenset(),
        subscriptions=frozenset(subs),
        resource_scopes=(),
        ado_organizations=frozenset(),
        window_start=datetime(2026, 4, 1, tzinfo=UTC),
        window_end=datetime(2026, 4, 30, tzinfo=UTC),
        resolved_at=datetime(2026, 4, 2, tzinfo=UTC),
        subscriptions_by_mg=by_mg,
    )


def test_diff_scope_reports_net_and_per_mg() -> None:
    old = _resolved({"sub-A", "sub-B"}, {"mg-1": ("sub-A", "sub-B")})
    new = _resolved({"sub-A", "sub-C"}, {"mg-1": ("sub-A", "sub-C")})
    diff = diff_scope(old, new)
    assert diff.added == frozenset({"sub-C"})
    assert diff.removed == frozenset({"sub-B"})
    assert diff.by_mg_added == {"mg-1": frozenset({"sub-C"})}
    assert diff.by_mg_removed == {"mg-1": frozenset({"sub-B"})}


def test_diff_scope_no_change_is_empty() -> None:
    same = _resolved({"sub-A"}, {"mg-1": ("sub-A",)})
    diff = diff_scope(same, same)
    assert diff.added == frozenset()
    assert diff.removed == frozenset()
    assert diff.by_mg_added == {}
    assert diff.by_mg_removed == {}


async def test_resolve_empty_mg_recorded_not_unresolved() -> None:
    """An MG that resolves to [] is recorded in subscriptions_by_mg as {mg: ()} and does
    NOT appear in unresolved_mgs — distinct from an MG whose resolver raises."""
    cfg = _config(management_groups=frozenset({"mg-empty"}))
    resolver = _Resolver({"mg-empty": []})
    resolved = await resolve_scope(cfg, resolver, clock=_fixed_clock())
    assert resolved.subscriptions_by_mg == {"mg-empty": ()}
    assert resolved.unresolved_mgs == ()
    assert frozenset() == resolved.subscriptions - frozenset(cfg.subscriptions)


async def test_resolve_unresolved_mgs_are_sorted() -> None:
    """unresolved_mgs must be in sorted order regardless of declaration order in the config."""
    cfg = _config(management_groups=frozenset({"mg-bad-b", "mg-bad-a"}))
    resolver = _Resolver({}, fail={"mg-bad-a", "mg-bad-b"})
    resolved = await resolve_scope(cfg, resolver, clock=_fixed_clock())
    assert resolved.unresolved_mgs == ("mg-bad-a", "mg-bad-b")
