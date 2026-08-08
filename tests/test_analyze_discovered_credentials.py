"""Tests for analyze.discovered_credentials — offline credential display module."""

from __future__ import annotations

import sqlite3
from typing import Any

import pytest
from conftest import FakeClock, FakeIds
from rich.console import Console

from beachhead.core.runner import RunEnv, run_module
from beachhead.core.secret_store import SecretStore
from beachhead.core.store.engine import open_store
from beachhead.modules.analyze.discovered_credentials import DiscoveredCredentials


class FakeAz:
    async def run(self, args: list[str], **kw: Any) -> Any:
        return {}


class FakeScope:
    def check(self, target: str, *, kind: str = "target") -> None:
        pass


class FakeConfig:
    @property
    def engagement(self) -> str:
        return "ACME"

    @property
    def allow_write(self) -> bool:
        return False


@pytest.fixture
def store(tmp_path: Any) -> Any:
    s = open_store(str(tmp_path / "test.db"), clock=FakeClock(), id_factory=FakeIds())
    s.ensure_engagement(name="ACME", scope_hash="h")
    return s


def _secret_store() -> SecretStore:
    conn = sqlite3.connect(":memory:", isolation_level=None, check_same_thread=False)
    return SecretStore(conn)


def _env(store: Any, secrets: SecretStore | None = None) -> RunEnv:
    return RunEnv(
        store=store,
        az=FakeAz(),
        auth=None,
        config=FakeConfig(),
        scope=FakeScope(),
        console=Console(quiet=True),
        operator="op",
        secrets=secrets,
    )


def test_meta() -> None:
    m = DiscoveredCredentials()
    assert m.meta.name == "analyze.discovered_credentials"
    assert m.meta.phase.value == "analyze"
    assert m.meta.access.value == "read"
    assert m.meta.gated is False


@pytest.mark.asyncio
async def test_no_secret_store(store: Any) -> None:
    env = _env(store, secrets=None)
    result = await run_module(DiscoveredCredentials(), env)  # type: ignore[arg-type]
    assert result.ok is True
    assert result.written == 0


@pytest.mark.asyncio
async def test_empty_store(store: Any) -> None:
    secrets = _secret_store()
    env = _env(store, secrets=secrets)
    result = await run_module(DiscoveredCredentials(), env)  # type: ignore[arg-type]
    assert result.ok is True
    assert result.written == 0


@pytest.mark.asyncio
async def test_displays_credentials(store: Any) -> None:
    secrets = _secret_store()
    secrets.store_credential(
        kind="ado_credential_exposure",
        reference="repo:config.json",
        run_id="r1",
        value="DefaultEndpointsProtocol=https;AccountKey=secret123",
        resource_id="ado://org/proj/repo",
        details={
            "credential_type": "Azure Storage Connection String",
            "source_module": "harvest.ado_credential_scan",
            "org": "org",
            "project": "proj",
        },
    )
    secrets.store_credential(
        kind="ado_pipeline_log_secret",
        reference="Build #42 log 3:17",
        run_id="r2",
        value="Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
        details={
            "credential_type": "bearer_token_in_log",
            "source_module": "harvest.ado_pipeline_log_scan",
            "org": "org",
            "project": "proj",
        },
    )

    env = _env(store, secrets=secrets)
    result = await run_module(DiscoveredCredentials(), env)  # type: ignore[arg-type]

    assert result.ok is True
    assert result.written == 0
    assert "2 credential(s)" in result.message
    assert result.details["total"] == 2
    assert result.details["by_kind"]["ado_credential_exposure"] == 1
    assert result.details["by_kind"]["ado_pipeline_log_secret"] == 1
