"""Tests for AuthBroker — the Phase 2 keystone.

Uses a fake clock and a fake refresher so all tests are deterministic and
never touch a live tenant.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from beachhead.core.auth.audience import Audience
from beachhead.core.auth.broker import AuthBroker, MsalRefresher, Refresher
from beachhead.core.auth.token_entry import EXPIRY_BUFFER_S, TokenEntry
from beachhead.core.errors import AuthError
from beachhead.core.module import TokenProvider


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
class FakeClock:
    """Deterministic clock: starts at 1_000_000 and advances on each tick() call."""

    def __init__(self, start: float = 1_000_000.0) -> None:
        self._now = start

    def __call__(self) -> float:
        return self._now

    def advance(self, seconds: float) -> None:
        self._now += seconds


class FakeRefresher:
    """Returns a pre-built replacement entry on refresh."""

    def __init__(self, clock: FakeClock) -> None:
        self._clock = clock
        self.call_count = 0

    async def refresh(self, entry: TokenEntry) -> TokenEntry:
        self.call_count += 1
        return TokenEntry(
            access_token=f"refreshed-{self.call_count}",
            audience=entry.audience,
            expires_at=self._clock() + 3600,
            source="msal_refresh",
            refresh_token=entry.refresh_token,
            client_id=entry.client_id,
            tenant_id=entry.tenant_id,
            scopes=entry.scopes,
        )


class FailingRefresher:
    """Always raises AuthError."""

    async def refresh(self, entry: TokenEntry) -> TokenEntry:
        raise AuthError("refresh exploded")


# ---------------------------------------------------------------------------
# add() — auto-classify + operator label
# ---------------------------------------------------------------------------
def test_add_classifies_jwt(make_jwt: Callable[..., str]) -> None:
    broker = AuthBroker()
    tok = make_jwt("https://graph.microsoft.com")
    assert broker.add(tok) == Audience.GRAPH
    assert broker.get_entry(Audience.GRAPH) is not None
    assert broker.get_entry(Audience.GRAPH).access_token == tok  # type: ignore[union-attr]


def test_add_opaque_with_label() -> None:
    broker = AuthBroker()
    assert broker.add("opaque-token", audience=Audience.ARM) == Audience.ARM
    entry = broker.get_entry(Audience.ARM)
    assert entry is not None
    assert entry.access_token == "opaque-token"


def test_add_opaque_without_label_raises() -> None:
    with pytest.raises(ValueError, match="could not classify"):
        AuthBroker().add("opaque-token")


def test_add_label_contradicts_aud_raises(make_jwt: Callable[..., str]) -> None:
    with pytest.raises(ValueError, match="contradicts"):
        AuthBroker().add(make_jwt("https://graph.microsoft.com"), audience=Audience.ARM)


def test_add_unknown_label_raises() -> None:
    with pytest.raises(ValueError, match="unknown audience"):
        AuthBroker().add("tok", audience="keyvault")


def test_add_extracts_exp_from_jwt(make_jwt: Callable[..., str]) -> None:
    tok = make_jwt("https://graph.microsoft.com", exp=2_000_000)
    broker = AuthBroker()
    broker.add(tok)
    entry = broker.get_entry(Audience.GRAPH)
    assert entry is not None
    assert entry.expires_at == 2_000_000.0


def test_add_opaque_defaults_to_clock_plus_ttl() -> None:
    clock = FakeClock(start=500_000.0)
    broker = AuthBroker(clock=clock)
    broker.add("opaque", audience=Audience.GRAPH)
    entry = broker.get_entry(Audience.GRAPH)
    assert entry is not None
    assert entry.expires_at == 500_000.0 + 3600.0


def test_add_explicit_expires_at_overrides() -> None:
    broker = AuthBroker()
    broker.add("opaque", audience=Audience.GRAPH, expires_at=9_999_999.0)
    entry = broker.get_entry(Audience.GRAPH)
    assert entry is not None
    assert entry.expires_at == 9_999_999.0


def test_add_with_refresh_material() -> None:
    broker = AuthBroker()
    broker.add(
        "opaque",
        audience=Audience.GRAPH,
        refresh_token="rt",
        client_id="cid",
        tenant_id="tid",
        scopes=["User.Read"],
    )
    entry = broker.get_entry(Audience.GRAPH)
    assert entry is not None
    assert entry.refreshable is True
    assert entry.scopes == ("User.Read",)


def test_add_overwrites_previous() -> None:
    broker = AuthBroker()
    broker.add("first", audience=Audience.GRAPH)
    broker.add("second", audience=Audience.GRAPH)
    entry = broker.get_entry(Audience.GRAPH)
    assert entry is not None
    assert entry.access_token == "second"


# ---------------------------------------------------------------------------
# add_msal_result()
# ---------------------------------------------------------------------------
def test_add_msal_result_basic() -> None:
    clock = FakeClock()
    broker = AuthBroker(clock=clock)
    result: dict[str, Any] = {
        "access_token": "msal-at",
        "expires_in": 3599,
        "refresh_token": "msal-rt",
        "scope": "User.Read profile",
    }
    aud = broker.add_msal_result(result, audience=Audience.GRAPH, client_id="c", tenant_id="t")
    assert aud == Audience.GRAPH
    entry = broker.get_entry(Audience.GRAPH)
    assert entry is not None
    assert entry.access_token == "msal-at"
    assert entry.refresh_token == "msal-rt"
    assert entry.scopes == ("User.Read", "profile")
    assert entry.expires_at == clock() + 3599


def test_add_msal_result_error_raises() -> None:
    broker = AuthBroker()
    with pytest.raises(AuthError, match="cannot ingest"):
        broker.add_msal_result(
            {"error": "invalid_grant", "error_description": "bad"},
            audience=Audience.GRAPH,
            client_id="c",
            tenant_id="t",
        )


def test_add_msal_result_unknown_audience_raises() -> None:
    with pytest.raises(ValueError, match="unknown audience"):
        AuthBroker().add_msal_result(
            {"access_token": "x"}, audience="keyvault", client_id="c", tenant_id="t"
        )


# ---------------------------------------------------------------------------
# async get() — the keystone
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_get_returns_token_when_not_expired() -> None:
    clock = FakeClock()
    broker = AuthBroker(clock=clock)
    broker.add("tok", audience=Audience.GRAPH, expires_at=clock() + 7200)
    assert await broker.get(Audience.GRAPH) == "tok"


@pytest.mark.asyncio
async def test_get_raises_when_no_token() -> None:
    broker = AuthBroker()
    with pytest.raises(AuthError, match="no token loaded"):
        await broker.get(Audience.GRAPH)


@pytest.mark.asyncio
async def test_get_raises_when_expired_no_refresh() -> None:
    clock = FakeClock()
    broker = AuthBroker(clock=clock)
    broker.add("tok", audience=Audience.GRAPH, expires_at=clock() - 1)
    with pytest.raises(AuthError, match="expired"):
        await broker.get(Audience.GRAPH)


@pytest.mark.asyncio
async def test_get_refreshes_when_expired() -> None:
    clock = FakeClock()
    refresher = FakeRefresher(clock)
    broker = AuthBroker(refresher=refresher, clock=clock)
    broker.add(
        "old-tok",
        audience=Audience.GRAPH,
        expires_at=clock() + 7200,
        refresh_token="rt",
        client_id="cid",
        tenant_id="tid",
    )
    # Not expired yet
    assert await broker.get(Audience.GRAPH) == "old-tok"
    assert refresher.call_count == 0

    # Advance past expiry (with buffer)
    clock.advance(7200)
    result = await broker.get(Audience.GRAPH)
    assert result == "refreshed-1"
    assert refresher.call_count == 1

    # Entry was replaced
    entry = broker.get_entry(Audience.GRAPH)
    assert entry is not None
    assert entry.access_token == "refreshed-1"
    assert entry.source == "msal_refresh"


@pytest.mark.asyncio
async def test_get_raises_when_refresh_fails() -> None:
    clock = FakeClock()
    broker = AuthBroker(refresher=FailingRefresher(), clock=clock)
    broker.add(
        "tok",
        audience=Audience.GRAPH,
        expires_at=clock() - 1,
        refresh_token="rt",
        client_id="cid",
        tenant_id="tid",
    )
    with pytest.raises(AuthError, match="refresh exploded"):
        await broker.get(Audience.GRAPH)


@pytest.mark.asyncio
async def test_get_expired_with_refresh_material_but_no_refresher() -> None:
    clock = FakeClock()
    broker = AuthBroker(clock=clock)  # no refresher injected
    broker.add(
        "tok",
        audience=Audience.GRAPH,
        expires_at=clock() - 1,
        refresh_token="rt",
        client_id="cid",
        tenant_id="tid",
    )
    with pytest.raises(AuthError, match="expired"):
        await broker.get(Audience.GRAPH)


@pytest.mark.asyncio
async def test_get_respects_buffer() -> None:
    clock = FakeClock()
    refresher = FakeRefresher(clock)
    broker = AuthBroker(refresher=refresher, clock=clock)
    broker.add(
        "tok",
        audience=Audience.GRAPH,
        expires_at=clock() + EXPIRY_BUFFER_S - 1,  # within buffer
        refresh_token="rt",
        client_id="cid",
        tenant_id="tid",
    )
    result = await broker.get(Audience.GRAPH)
    assert result == "refreshed-1"


# ---------------------------------------------------------------------------
# audience_of / audiences
# ---------------------------------------------------------------------------
def test_audience_of(make_jwt: Callable[..., str]) -> None:
    broker = AuthBroker()
    assert broker.audience_of(make_jwt("https://graph.microsoft.com")) == Audience.GRAPH
    assert broker.audience_of(make_jwt("https://management.azure.com")) == Audience.ARM
    assert broker.audience_of("opaque") is None


def test_audiences() -> None:
    broker = AuthBroker()
    assert broker.audiences() == ()
    broker.add("tok", audience=Audience.GRAPH)
    assert broker.audiences() == (Audience.GRAPH,)
    broker.add("tok2", audience=Audience.ARM)
    assert set(broker.audiences()) == {Audience.GRAPH, Audience.ARM}


# ---------------------------------------------------------------------------
# Protocol satisfaction
# ---------------------------------------------------------------------------
def test_satisfies_token_provider() -> None:
    assert isinstance(AuthBroker(), TokenProvider)


def test_msal_refresher_satisfies_refresher_protocol() -> None:
    assert isinstance(MsalRefresher(), Refresher)


# ---------------------------------------------------------------------------
# repr
# ---------------------------------------------------------------------------
def test_repr_masks_tokens() -> None:
    broker = AuthBroker()
    broker.add("super-secret-token-ABCD", audience=Audience.GRAPH)
    rendered = repr(broker)
    assert "super-secret-token-ABCD" not in rendered
    assert "ABCD" in rendered


# ---------------------------------------------------------------------------
# ADO PAT (opaque, non-refreshable)
# ---------------------------------------------------------------------------
def test_add_ado_pat() -> None:
    broker = AuthBroker()
    aud = broker.add("my-ado-pat", audience=Audience.ADO)
    assert aud == Audience.ADO
    entry = broker.get_entry(Audience.ADO)
    assert entry is not None
    assert entry.access_token == "my-ado-pat"
    assert entry.refreshable is False


@pytest.mark.asyncio
async def test_get_ado_pat() -> None:
    clock = FakeClock()
    broker = AuthBroker(clock=clock)
    broker.add("my-ado-pat", audience=Audience.ADO, expires_at=clock() + 86400)
    assert await broker.get(Audience.ADO) == "my-ado-pat"


@pytest.mark.asyncio
async def test_get_ado_expired_raises() -> None:
    clock = FakeClock()
    broker = AuthBroker(clock=clock)
    broker.add("my-ado-pat", audience=Audience.ADO, expires_at=clock() - 1)
    with pytest.raises(AuthError, match="expired"):
        await broker.get(Audience.ADO)


def test_audiences_includes_ado() -> None:
    broker = AuthBroker()
    broker.add("pat", audience=Audience.ADO)
    assert Audience.ADO in broker.audiences()
