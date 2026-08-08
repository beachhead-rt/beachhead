"""Tests for enumerate.ado_agent_pools — ADO agent pool enumeration."""

from __future__ import annotations

from typing import Any

import httpx
import pytest
import respx
from conftest import FakeClock, FakeIds
from rich.console import Console

from beachhead.core.runner import RunEnv, run_module
from beachhead.core.store.engine import open_store
from beachhead.modules.enumerate.ado_agent_pools import AdoAgentPools



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
    m = AdoAgentPools()
    assert m.meta.name == "enumerate.ado_agent_pools"
    assert m.meta.phase.value == "enumerate"
    assert m.meta.access.value == "read"
    assert m.meta.gated is False


@respx.mock
@pytest.mark.asyncio
async def test_enumerates_pools_and_agents(store: Any) -> None:
    """Enumerates hosted + self-hosted pools; drills into self-hosted agents."""
    respx.get("https://dev.azure.com/test-org/_apis/distributedtask/pools").mock(
        return_value=httpx.Response(
            200,
            json={
                "value": [
                    {
                        "id": 1,
                        "name": "Azure Pipelines",
                        "isHosted": True,
                        "poolType": "automation",
                        "size": 0,
                    },
                    {
                        "id": 2,
                        "name": "Self-Hosted-Linux",
                        "isHosted": False,
                        "poolType": "automation",
                        "size": 2,
                    },
                ]
            },
        )
    )
    respx.get("https://dev.azure.com/test-org/_apis/distributedtask/pools/2/agents").mock(
        return_value=httpx.Response(
            200,
            json={
                "value": [
                    {
                        "id": 10,
                        "name": "build-agent-1",
                        "status": "online",
                        "version": "3.240.1",
                        "osDescription": "Linux 5.15",
                        "systemCapabilities": {
                            "Agent.OS": "Linux",
                            "npm": "/usr/bin/npm",
                        },
                        "userCapabilities": {},
                    },
                    {
                        "id": 11,
                        "name": "build-agent-2",
                        "status": "offline",
                        "version": "3.240.1",
                        "osDescription": "Linux 5.15",
                        "systemCapabilities": {},
                        "userCapabilities": {},
                    },
                ]
            },
        )
    )

    env = _env(store)
    result = await run_module(AdoAgentPools(), env)  # type: ignore[arg-type]

    assert result.ok is True
    assert result.written >= 4  # 2 pools + 2 agents

    pools = [r for r in store.resources() if r.type == "ado_agent_pool"]
    assert len(pools) == 2

    agents = [r for r in store.resources() if r.type == "ado_agent"]
    assert len(agents) == 2


@respx.mock
@pytest.mark.asyncio
async def test_flags_self_hosted_pool(store: Any) -> None:
    """Self-hosted pools generate a finding."""
    respx.get("https://dev.azure.com/test-org/_apis/distributedtask/pools").mock(
        return_value=httpx.Response(
            200,
            json={
                "value": [
                    {
                        "id": 5,
                        "name": "On-Prem-Pool",
                        "isHosted": False,
                        "poolType": "automation",
                        "size": 0,
                    }
                ]
            },
        )
    )

    env = _env(store)
    result = await run_module(AdoAgentPools(), env)  # type: ignore[arg-type]

    assert result.ok is True
    findings = store.findings(kind="ado_self_hosted_pool")
    assert len(findings) >= 1
    assert "On-Prem-Pool" in findings[0].reference


@respx.mock
@pytest.mark.asyncio
async def test_flags_sensitive_capability(store: Any) -> None:
    """Agents with sensitive capabilities generate a finding."""
    respx.get("https://dev.azure.com/test-org/_apis/distributedtask/pools").mock(
        return_value=httpx.Response(
            200,
            json={
                "value": [
                    {
                        "id": 3,
                        "name": "Secrets-Pool",
                        "isHosted": False,
                        "poolType": "automation",
                        "size": 1,
                    }
                ]
            },
        )
    )
    respx.get("https://dev.azure.com/test-org/_apis/distributedtask/pools/3/agents").mock(
        return_value=httpx.Response(
            200,
            json={
                "value": [
                    {
                        "id": 20,
                        "name": "leaky-agent",
                        "status": "online",
                        "version": "3.240.1",
                        "osDescription": "Windows 10",
                        "systemCapabilities": {
                            "Agent.OS": "Windows_NT",
                        },
                        "userCapabilities": {
                            "DEPLOY_PASSWORD": "redacted",
                            "API_KEY_PROD": "redacted",
                        },
                    }
                ]
            },
        )
    )

    env = _env(store)
    result = await run_module(AdoAgentPools(), env)  # type: ignore[arg-type]

    assert result.ok is True
    findings = store.findings(kind="ado_agent_sensitive_capability")
    assert len(findings) >= 1
    ref = findings[0].reference
    assert "leaky-agent" in ref


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
    result = await run_module(AdoAgentPools(), env)  # type: ignore[arg-type]
    assert result.ok is True
    assert result.written == 0
