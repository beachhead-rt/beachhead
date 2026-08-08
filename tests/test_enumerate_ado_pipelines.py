"""Tests for enumerate.ado_pipelines — ADO pipeline enumeration."""

from __future__ import annotations

from typing import Any

import httpx
import pytest
import respx
from conftest import FakeClock, FakeIds
from rich.console import Console

from beachhead.core.errors import AuthError
from beachhead.core.runner import RunEnv, run_module
from beachhead.core.store.engine import open_store
from beachhead.modules.enumerate.ado_pipelines import AdoPipelines



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

    @property
    def ado_organizations(self) -> frozenset[str]:
        return frozenset({"test-org"})


class FakeAuth:
    async def get(self, audience: str) -> str:
        if audience == "ado":
            return "fake-ado-pat"
        return "fake-token"


@pytest.fixture
def store(tmp_path: Any) -> Any:
    s = open_store(str(tmp_path / "test.db"), clock=FakeClock(), id_factory=FakeIds())
    s.ensure_engagement(name="ACME", scope_hash="h")
    return s


def _env(store: Any) -> RunEnv:
    return RunEnv(
        store=store,
        az=FakeAz(),
        auth=FakeAuth(),
        config=FakeConfig(),
        scope=FakeScope(),
        console=Console(quiet=True),
        operator="op",
    )


def test_meta() -> None:
    m = AdoPipelines()
    assert m.meta.name == "enumerate.ado_pipelines"
    assert m.meta.phase.value == "enumerate"
    assert m.meta.access.value == "read"
    assert m.meta.gated is False


@respx.mock
@pytest.mark.asyncio
async def test_enumerates_yaml_classic_release(store: Any) -> None:
    """Enumerates YAML, classic build, and classic release pipelines."""
    respx.get("https://dev.azure.com/test-org/_apis/projects").mock(
        return_value=httpx.Response(200, json={"value": [{"name": "proj1"}]})
    )
    respx.get("https://dev.azure.com/test-org/proj1/_apis/pipelines").mock(
        return_value=httpx.Response(
            200,
            json={
                "value": [
                    {"id": 1, "name": "CI-Build", "folder": "\\", "revision": 5},
                    {"id": 2, "name": "Deploy", "folder": "\\prod", "revision": 2},
                ]
            },
        )
    )
    respx.get("https://dev.azure.com/test-org/proj1/_apis/build/definitions").mock(
        return_value=httpx.Response(
            200,
            json={
                "value": [
                    {
                        "id": 10,
                        "name": "Legacy-Build",
                        "type": "build",
                        "variables": {"BuildConfig": {"value": "Release"}},
                        "queue": {"name": "Default"},
                    }
                ]
            },
        )
    )
    respx.get("https://vsrm.dev.azure.com/test-org/proj1/_apis/release/definitions").mock(
        return_value=httpx.Response(
            200,
            json={
                "value": [
                    {
                        "id": 20,
                        "name": "Prod-Release",
                        "environments": [
                            {"name": "staging"},
                            {"name": "production"},
                        ],
                    }
                ]
            },
        )
    )

    env = _env(store)
    result = await run_module(AdoPipelines(), env)  # type: ignore[arg-type]

    assert result.ok is True
    assert result.written >= 4  # 2 YAML + 1 classic build + 1 release

    resources = store.resources()
    types = {r.type for r in resources}
    assert "ado_pipeline_yaml" in types
    assert "ado_pipeline_classic_build" in types
    assert "ado_pipeline_classic_release" in types


@respx.mock
@pytest.mark.asyncio
async def test_no_ado_orgs(store: Any) -> None:
    """No ADO orgs in scope → skip gracefully."""

    class EmptyConfig:
        @property
        def engagement(self) -> str:
            return "ACME"

        @property
        def allow_write(self) -> bool:
            return False

        @property
        def ado_organizations(self) -> frozenset[str]:
            return frozenset()

    env = _env(store)
    env.config = EmptyConfig()
    result = await run_module(AdoPipelines(), env)  # type: ignore[arg-type]
    assert result.ok is True
    assert result.written == 0


@pytest.mark.asyncio
async def test_no_pat_fails(store: Any) -> None:
    """Without a PAT, the module fails gracefully."""
    import os
    from unittest.mock import patch

    class NoAuth:
        async def get(self, audience: str) -> str:
            raise AuthError("no token")

    env = _env(store)
    env.auth = NoAuth()  # type: ignore[assignment]

    with patch.dict(os.environ, {}, clear=True):
        clean_env = {k: v for k, v in os.environ.items() if k != "BEACHHEAD_ADO_PAT"}
        with patch.dict(os.environ, clean_env, clear=True):
            result = await run_module(AdoPipelines(), env)  # type: ignore[arg-type]

    assert result.ok is False
    assert "PAT" in result.message
