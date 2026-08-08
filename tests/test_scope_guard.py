"""Tests for core/scope ScopeGuard.check matching + window. Never a live tenant."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from beachhead.core.errors import ScopeError
from beachhead.core.module import ScopeGuard as ScopeGuardProtocol
from beachhead.core.scope import ResolvedScope, ScopeGuard


def _at(*, hour: int = 12):
    return lambda: datetime(2026, 4, 10, hour, 0, tzinfo=UTC)


def make_scope(
    *,
    tenants: tuple[str, ...] = (),
    subscriptions: tuple[str, ...] = (),
    resource_scopes: tuple[str, ...] = (),
    ado: tuple[str, ...] = (),
    start: datetime | None = None,
    end: datetime | None = None,
) -> ResolvedScope:
    return ResolvedScope(
        tenants=frozenset(tenants),
        subscriptions=frozenset(subscriptions),
        resource_scopes=resource_scopes,
        ado_organizations=frozenset(ado),
        window_start=start or datetime(2026, 4, 1, tzinfo=UTC),
        window_end=end or datetime(2026, 4, 30, tzinfo=UTC),
        resolved_at=datetime(2026, 4, 2, tzinfo=UTC),
    )


def test_tenant_in_scope_passes() -> None:
    guard = ScopeGuard(make_scope(tenants=("TEN-1",)), clock=_at())
    guard.check("ten-1", kind="tenant")  # case-insensitive, no raise


def test_tenant_out_of_scope_raises() -> None:
    guard = ScopeGuard(make_scope(tenants=("ten-1",)), clock=_at())
    with pytest.raises(ScopeError, match="out of scope"):
        guard.check("ten-2", kind="tenant")


def test_subscription_in_and_out() -> None:
    guard = ScopeGuard(make_scope(subscriptions=("sub-A",)), clock=_at())
    guard.check("sub-A", kind="subscription")
    with pytest.raises(ScopeError):
        guard.check("sub-B", kind="subscription")


def test_outside_window_raises() -> None:
    guard = ScopeGuard(
        make_scope(
            tenants=("t1",),
            start=datetime(2026, 4, 1, tzinfo=UTC),
            end=datetime(2026, 4, 5, tzinfo=UTC),
        ),
        clock=_at(),  # 2026-04-10 is after the window
    )
    with pytest.raises(ScopeError, match="outside engagement window"):
        guard.check("t1", kind="tenant")


def test_outside_window_with_override_passes() -> None:
    guard = ScopeGuard(
        make_scope(
            tenants=("t1",),
            start=datetime(2026, 4, 1, tzinfo=UTC),
            end=datetime(2026, 4, 5, tzinfo=UTC),
        ),
        clock=_at(),
        allow_outside_window=True,
    )
    guard.check("t1", kind="tenant")  # no raise
    assert guard.allow_outside_window is True


def test_empty_scope_fails_closed() -> None:
    guard = ScopeGuard(make_scope(), clock=_at())
    with pytest.raises(ScopeError, match="scope is empty"):
        guard.check("anything", kind="tenant")


def test_empty_target_fails_closed() -> None:
    guard = ScopeGuard(make_scope(tenants=("t1",)), clock=_at())
    with pytest.raises(ScopeError, match="empty target"):
        guard.check("  ", kind="tenant")


def test_resource_in_scope_via_subscription() -> None:
    guard = ScopeGuard(make_scope(subscriptions=("sub-A",)), clock=_at())
    guard.check("/subscriptions/sub-A/resourceGroups/anything/providers/x/y", kind="resource")


def test_resource_in_scope_via_prefix_in_other_sub() -> None:
    prefix = "/subscriptions/sub-B/resourceGroups/rg-x"
    guard = ScopeGuard(make_scope(subscriptions=("sub-A",), resource_scopes=(prefix,)), clock=_at())
    guard.check(prefix + "/providers/p/r", kind="resource")  # added path, sub not listed


def test_resource_out_of_scope_raises() -> None:
    guard = ScopeGuard(make_scope(subscriptions=("sub-A",)), clock=_at())
    with pytest.raises(ScopeError):
        guard.check("/subscriptions/sub-Z/resourceGroups/rg/providers/p/r", kind="resource")


def test_resource_prefix_is_segment_aware() -> None:
    prefix = "/subscriptions/sub-A/resourceGroups/rg"
    guard = ScopeGuard(make_scope(resource_scopes=(prefix,)), clock=_at())
    guard.check(prefix, kind="resource")  # exact prefix is in scope
    guard.check(prefix + "/providers/p/r", kind="resource")  # under prefix is in scope
    with pytest.raises(ScopeError):
        guard.check(
            "/subscriptions/sub-A/resourceGroups/rg-other/providers/p/r", kind="resource"
        )  # rg-other must NOT match the rg prefix


def test_ado_matches_name_and_url() -> None:
    guard = ScopeGuard(make_scope(ado=("acme-eng",)), clock=_at())
    guard.check("acme-eng", kind="ado")
    guard.check("https://dev.azure.com/acme-eng/project/_git/repo", kind="ado")
    with pytest.raises(ScopeError):
        guard.check("other-org", kind="ado")


def test_pwsh_classifies_guid_resource_and_ado() -> None:
    scope = make_scope(
        tenants=("11111111-1111-1111-1111-111111111111",),
        subscriptions=("22222222-2222-2222-2222-222222222222",),
        resource_scopes=("/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg",),
        ado=("acme-eng",),
    )
    guard = ScopeGuard(scope, clock=_at())
    guard.check("11111111-1111-1111-1111-111111111111", kind="pwsh")  # tenant GUID
    guard.check("22222222-2222-2222-2222-222222222222", kind="pwsh")  # subscription GUID
    guard.check(
        "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg/providers/p/r",
        kind="pwsh",
    )  # resource
    guard.check("acme-eng", kind="pwsh")  # ado name


def test_pwsh_unmatched_target_raises() -> None:
    guard = ScopeGuard(make_scope(tenants=("t1",)), clock=_at())
    with pytest.raises(ScopeError):
        guard.check("not-in-any-dimension", kind="pwsh")


def test_unknown_kind_fails_closed() -> None:
    guard = ScopeGuard(make_scope(tenants=("t1",)), clock=_at())
    with pytest.raises(ScopeError):
        guard.check("t1", kind="banana")


def test_default_kind_is_classify_any() -> None:
    guard = ScopeGuard(make_scope(ado=("acme-eng",)), clock=_at())
    guard.check("acme-eng")  # kind defaults to "target" -> classify-any


def test_ado_url_spoofs_fail_closed() -> None:
    guard = ScopeGuard(make_scope(ado=("acme-eng",)), clock=_at())
    spoofs = [
        "https://acme-eng.visualstudio.com.evil.com/x",
        "https://evil.com/dev.azure.com/acme-eng/x",
        "https://evil.com/redirect?u=dev.azure.com/acme-eng",
        "https://dev.azure.com.evil.com/acme-eng",
        "https://dev.azure.com@evil.com/acme-eng",
    ]
    for s in spoofs:
        with pytest.raises(ScopeError):
            guard.check(s, kind="ado")
        with pytest.raises(ScopeError):
            guard.check(s, kind="target")  # classify-any must also reject


def test_ado_legit_variants_pass() -> None:
    guard = ScopeGuard(make_scope(ado=("acme-eng",)), clock=_at())
    for ok in [
        "acme-eng",
        "ACME-ENG",
        "https://dev.azure.com/acme-eng/project/_git/repo",
        "https://dev.azure.com:443/acme-eng",
        "https://user@dev.azure.com/acme-eng",
        "acme-eng.visualstudio.com",
        "https://acme-eng.visualstudio.com/project",
    ]:
        guard.check(ok, kind="ado")  # no raise


def test_naive_clock_fails_closed() -> None:
    guard = ScopeGuard(
        make_scope(tenants=("t1",)),
        clock=lambda: datetime(2026, 4, 10, 12, 0),  # naive — no tzinfo
    )
    with pytest.raises(ScopeError):
        guard.check("t1", kind="tenant")


def test_classify_any_subscription_path_is_case_insensitive() -> None:
    guard = ScopeGuard(make_scope(subscriptions=("sub-a",)), clock=_at())
    guard.check("/Subscriptions/sub-a/resourceGroups/rg/providers/p/r", kind="target")


def test_allow_outside_window_is_read_only() -> None:
    guard = ScopeGuard(make_scope(tenants=("t1",)), clock=_at())
    with pytest.raises(AttributeError):
        guard.allow_outside_window = True  # type: ignore[misc]


def test_double_slash_and_empty_sub_segment_fail_closed() -> None:
    guard = ScopeGuard(make_scope(subscriptions=("sub-a",)), clock=_at())
    with pytest.raises(ScopeError):
        guard.check("//subscriptions/sub-a/rg", kind="resource")
    with pytest.raises(ScopeError):
        guard.check("/subscriptions//rg", kind="resource")


def test_scope_guard_satisfies_module_protocol() -> None:
    guard = ScopeGuard(make_scope(tenants=("t1",)), clock=_at())
    assert isinstance(guard, ScopeGuardProtocol)


def test_naive_window_bounds_fail_closed() -> None:
    # A snapshot with timezone-naive window bounds must fail closed (ScopeError),
    # not crash with a TypeError when compared against an aware clock.
    guard = ScopeGuard(
        make_scope(
            tenants=("t1",),
            start=datetime(2026, 4, 1),  # naive — no tzinfo
            end=datetime(2026, 4, 30),  # naive — no tzinfo
        ),
        clock=_at(),
    )
    with pytest.raises(ScopeError, match="window bounds are timezone-naive"):
        guard.check("t1", kind="tenant")
