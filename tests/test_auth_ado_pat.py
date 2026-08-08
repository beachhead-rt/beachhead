"""Tests for core/auth/ado_pat.py — ADO PAT acquisition."""

from __future__ import annotations

import asyncio
import time

import pytest

from beachhead.core.auth.ado_pat import acquire_token_ado_pat
from beachhead.core.auth.audience import Audience
from beachhead.core.errors import AuthError


def test_basic_acquisition() -> None:
    entry = asyncio.run(acquire_token_ado_pat("my-pat-token-value"))
    assert entry.audience == Audience.ADO
    assert entry.access_token == "my-pat-token-value"
    assert entry.source == "ado_pat"
    assert entry.refreshable is False


def test_strips_whitespace() -> None:
    entry = asyncio.run(acquire_token_ado_pat("  my-pat  \n"))
    assert entry.access_token == "my-pat"


def test_rejects_empty() -> None:
    with pytest.raises(AuthError, match="must not be empty"):
        asyncio.run(acquire_token_ado_pat(""))


def test_rejects_whitespace_only() -> None:
    with pytest.raises(AuthError, match="must not be empty"):
        asyncio.run(acquire_token_ado_pat("   \n  "))


def test_custom_expiry() -> None:
    ts = time.time() + 7200
    entry = asyncio.run(acquire_token_ado_pat("pat", expires_at=ts))
    assert entry.expires_at == ts


def test_default_expiry_is_90_days() -> None:
    before = time.time()
    entry = asyncio.run(acquire_token_ado_pat("pat"))
    after = time.time()
    expected_min = before + 86400 * 90
    expected_max = after + 86400 * 90
    assert expected_min <= entry.expires_at <= expected_max


def test_entry_not_refreshable() -> None:
    entry = asyncio.run(acquire_token_ado_pat("pat"))
    assert entry.refresh_token is None
    assert entry.client_id is None
    assert entry.tenant_id is None
    assert entry.refreshable is False
