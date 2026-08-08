from __future__ import annotations

import time

import pytest

from beachhead.core.auth.token_entry import EXPIRY_BUFFER_S, TokenEntry


def test_basic_construction() -> None:
    e = TokenEntry(
        access_token="tok",
        audience="graph",
        expires_at=time.time() + 3600,
        source="operator",
    )
    assert e.audience == "graph"
    assert e.source == "operator"
    assert e.refresh_token is None
    assert e.scopes == ()


def test_rejects_unknown_audience() -> None:
    with pytest.raises(ValueError, match="unknown audience"):
        TokenEntry(access_token="t", audience="keyvault", expires_at=0, source="op")


def test_rejects_empty_access_token() -> None:
    with pytest.raises(ValueError, match="access_token"):
        TokenEntry(access_token="", audience="graph", expires_at=0, source="op")


def test_rejects_empty_source() -> None:
    with pytest.raises(ValueError, match="source"):
        TokenEntry(access_token="t", audience="graph", expires_at=0, source="")


def test_scopes_coerced_to_tuple() -> None:
    e = TokenEntry(
        access_token="t",
        audience="arm",
        expires_at=0,
        source="op",
        scopes=["a", "b"],  # type: ignore[arg-type]
    )
    assert e.scopes == ("a", "b")
    assert isinstance(e.scopes, tuple)


def test_expired_with_buffer() -> None:
    just_inside_buffer = time.time() + EXPIRY_BUFFER_S - 1
    e = TokenEntry(access_token="t", audience="graph", expires_at=just_inside_buffer, source="op")
    assert e.expired is True

    well_in_future = time.time() + EXPIRY_BUFFER_S + 3600
    e2 = TokenEntry(access_token="t", audience="graph", expires_at=well_in_future, source="op")
    assert e2.expired is False


def test_refreshable() -> None:
    e_no = TokenEntry(access_token="t", audience="graph", expires_at=0, source="op")
    assert e_no.refreshable is False

    e_yes = TokenEntry(
        access_token="t",
        audience="graph",
        expires_at=0,
        source="op",
        refresh_token="rt",
        client_id="cid",
        tenant_id="tid",
    )
    assert e_yes.refreshable is True

    e_partial = TokenEntry(
        access_token="t",
        audience="graph",
        expires_at=0,
        source="op",
        refresh_token="rt",
    )
    assert e_partial.refreshable is False


def test_repr_masks_token() -> None:
    e = TokenEntry(
        access_token="super-secret-access-token-1234",
        audience="graph",
        expires_at=0,
        source="op",
    )
    rendered = repr(e)
    assert "super-secret-access-token-1234" not in rendered
    assert "1234" in rendered


def test_ado_audience_accepted() -> None:
    e = TokenEntry(
        access_token="pat-value",
        audience="ado",
        expires_at=time.time() + 3600,
        source="ado_pat",
    )
    assert e.audience == "ado"
    assert e.refreshable is False


def test_is_frozen() -> None:
    import dataclasses

    e = TokenEntry(access_token="t", audience="graph", expires_at=0, source="op")
    with pytest.raises(dataclasses.FrozenInstanceError):
        e.audience = "arm"  # type: ignore[misc]
