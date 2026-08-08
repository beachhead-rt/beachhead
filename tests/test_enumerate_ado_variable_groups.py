"""Tests for enumerate.ado_variable_groups — ADO variable group enumeration."""

from __future__ import annotations

from typing import Any

import httpx
import pytest
import respx
from conftest import FakeClock, FakeIds
from rich.console import Console

from beachhead.core.runner import RunEnv, run_module
from beachhead.core.store.engine import open_store
from beachhead.modules.enumerate.ado_variable_groups import AdoVariableGroups


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
    m = AdoVariableGroups()
    assert m.meta.name == "enumerate.ado_variable_groups"
    assert m.meta.phase.value == "enumerate"
    assert m.meta.access.value == "read"
    assert m.meta.gated is False


@respx.mock
@pytest.mark.asyncio
async def test_enumerates_variable_groups(store: Any) -> None:
    """Records variable groups with variable names and counts."""
    respx.get("https://dev.azure.com/test-org/_apis/projects").mock(
        return_value=httpx.Response(200, json={"value": [{"name": "proj1"}]})
    )
    respx.get("https://dev.azure.com/test-org/proj1/_apis/distributedtask/variablegroups").mock(
        return_value=httpx.Response(
            200,
            json={
                "value": [
                    {
                        "id": 1,
                        "name": "Build-Vars",
                        "type": "Vsts",
                        "variables": {
                            "BuildConfig": {"value": "Release"},
                            "Region": {"value": "eastus"},
                        },
                    },
                    {
                        "id": 2,
                        "name": "Secrets-Group",
                        "type": "Vsts",
                        "variables": {
                            "DB_Password": {"value": None, "isSecret": True},
                            "API_Key": {"value": None, "isSecret": True},
                        },
                    },
                ]
            },
        )
    )

    env = _env(store)
    result = await run_module(AdoVariableGroups(), env)  # type: ignore[arg-type]

    assert result.ok is True
    assert result.written >= 2

    resources = [r for r in store.resources() if r.type == "ado_variable_group"]
    assert len(resources) == 2


@respx.mock
@pytest.mark.asyncio
async def test_no_ado_orgs(store: Any) -> None:
    """No ADO orgs in scope -> skip gracefully."""

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
    result = await run_module(AdoVariableGroups(), env)  # type: ignore[arg-type]
    assert result.ok is True
    assert result.written == 0
