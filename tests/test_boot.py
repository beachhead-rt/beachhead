"""Tests for core/boot.py — RunEnv bootstrap."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import pytest
import yaml
from rich.console import Console

from beachhead.core.boot import bootstrap_run_env
from beachhead.core.runner import RunEnv

_GRAPH_TOKEN = (
    "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9."
    "eyJhdWQiOiJodHRwczovL2dyYXBoLm1pY3Jvc29mdC5jb20iLCJleHAiOjk5OTk5OTk5OTl9."
    "sig"
)


def _write_config(path: Path, **overrides: object) -> str:
    base: dict[str, Any] = {
        "engagement": "ACME-TEST",
        "authorization_ref": "SOW-1",
        "window": {"start": "2026-01-01T00:00:00Z", "end": "2030-01-01T00:00:00Z"},
        "subscriptions": ["11111111-1111-1111-1111-111111111111"],
        "allow_write": False,
    }
    base.update(overrides)
    p = path / "engagement.local.yaml"
    p.write_text(yaml.safe_dump(base))
    return str(p)


@pytest.mark.asyncio
async def test_bootstrap_creates_runenv(tmp_path: Path) -> None:
    config_path = _write_config(tmp_path)
    store_path = str(tmp_path / "beachhead.sqlite")

    env = await bootstrap_run_env(
        store_path=store_path,
        config_path=config_path,
        console=Console(quiet=True),
        operator="test-op",
        passphrase="test-key",
    )
    try:
        assert isinstance(env, RunEnv)
        assert env.operator == "test-op"
        assert env.store is not None
        eng = env.store.get_engagement()
        assert eng is not None
        assert eng.name == "ACME-TEST"
    finally:
        env.store.close()


@pytest.mark.asyncio
async def test_bootstrap_store_is_writable(tmp_path: Path) -> None:
    config_path = _write_config(tmp_path)
    store_path = str(tmp_path / "beachhead.sqlite")

    env = await bootstrap_run_env(
        store_path=store_path,
        config_path=config_path,
        console=Console(quiet=True),
        passphrase="test-key",
    )
    try:
        rid = env.store.start_run(module="test.mod", phase="enumerate", operator="op")
        assert rid
        env.store.finish_run(rid, status="ok")
    finally:
        env.store.close()


@pytest.mark.asyncio
async def test_bootstrap_passes_defaults_to_az(tmp_path: Path) -> None:
    from beachhead.core.clients.az_client import AzSubprocessClient

    config_path = _write_config(
        tmp_path,
        ado_organizations=["my-org"],
    )
    store_path = str(tmp_path / "beachhead.sqlite")

    env = await bootstrap_run_env(
        store_path=store_path,
        config_path=config_path,
        console=Console(quiet=True),
        passphrase="test-key",
    )
    try:
        assert isinstance(env.az, AzSubprocessClient)
        assert env.az._default_subscription == "11111111-1111-1111-1111-111111111111"
        assert env.az._default_organization == "my-org"
    finally:
        env.store.close()


@pytest.mark.asyncio
async def test_bootstrap_loads_cached_tokens(tmp_path: Path, monkeypatch) -> None:
    cache_path = tmp_path / "tokens.json"
    data = {
        "graph": {
            "access_token": _GRAPH_TOKEN,
            "audience": "graph",
            "expires_at": time.time() + 3600,
            "source": "cached-test",
        }
    }
    cache_path.write_text(json.dumps(data))
    monkeypatch.setenv("BEACHHEAD_TOKEN_CACHE", str(cache_path))

    config_path = _write_config(tmp_path)
    store_path = str(tmp_path / "beachhead.sqlite")

    env = await bootstrap_run_env(
        store_path=store_path,
        config_path=config_path,
        console=Console(quiet=True),
        passphrase="test-key",
    )
    try:
        entry = env.auth.get_entry("graph")
        assert entry is not None
        assert entry.source == "cached-test"
    finally:
        env.store.close()
