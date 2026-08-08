"""Tests for enumerate.ado_service_connections — ADO service endpoint enumeration."""

from __future__ import annotations

from typing import Any

import httpx
import pytest
import respx
from conftest import FakeClock, FakeIds
from rich.console import Console

from beachhead.core.runner import RunEnv, run_module
from beachhead.core.store.engine import open_store
from beachhead.modules.enumerate.ado_service_connections import AdoServiceConnections



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
    m = AdoServiceConnections()
    assert m.meta.name == "enumerate.ado_service_connections"
    assert m.meta.phase.value == "enumerate"
    assert m.meta.access.value == "read"
    assert m.meta.gated is False


@respx.mock
@pytest.mark.asyncio
async def test_enumerates_service_connections(store: Any) -> None:
    """Records service connections from a project."""
    respx.get("https://dev.azure.com/test-org/_apis/projects").mock(
        return_value=httpx.Response(200, json={"value": [{"name": "proj1"}]})
    )
    respx.get("https://dev.azure.com/test-org/proj1/_apis/serviceendpoint/endpoints").mock(
        return_value=httpx.Response(
            200,
            json={
                "value": [
                    {
                        "id": "ep-1",
                        "name": "GitHub-Conn",
                        "type": "github",
                        "url": "https://github.com",
                        "authorization": {"scheme": "PersonalAccessToken"},
                        "isShared": False,
                    },
                    {
                        "id": "ep-2",
                        "name": "Azure-Prod",
                        "type": "azurerm",
                        "url": "https://management.azure.com/",
                        "authorization": {"scheme": "ServicePrincipal"},
                        "isShared": False,
                        "data": {
                            "scopeLevel": "Subscription",
                            "subscriptionId": "sub-1234",
                        },
                    },
                ]
            },
        )
    )

    env = _env(store)
    result = await run_module(AdoServiceConnections(), env)  # type: ignore[arg-type]

    assert result.ok is True
    assert result.written >= 2

    resources = [r for r in store.resources() if r.type == "ado_service_connection"]
    assert len(resources) == 2


@respx.mock
@pytest.mark.asyncio
async def test_flags_subscription_scope_azure_rm(store: Any) -> None:
    """Flags Azure RM connections with subscription-level scope."""
    respx.get("https://dev.azure.com/test-org/_apis/projects").mock(
        return_value=httpx.Response(200, json={"value": [{"name": "proj1"}]})
    )
    respx.get("https://dev.azure.com/test-org/proj1/_apis/serviceendpoint/endpoints").mock(
        return_value=httpx.Response(
            200,
            json={
                "value": [
                    {
                        "id": "ep-azure",
                        "name": "Azure-Prod",
                        "type": "azurerm",
                        "url": "https://management.azure.com/",
                        "authorization": {"scheme": "ServicePrincipal"},
                        "isShared": False,
                        "data": {
                            "scopeLevel": "Subscription",
                            "subscriptionId": "sub-9999",
                        },
                    }
                ]
            },
        )
    )

    env = _env(store)
    result = await run_module(AdoServiceConnections(), env)  # type: ignore[arg-type]

    assert result.ok is True
    findings = store.findings(kind="ado_service_connection_azure")
    assert len(findings) >= 1
    assert "sub-9999" in findings[0].reference


@respx.mock
@pytest.mark.asyncio
async def test_flags_shared_connection(store: Any) -> None:
    """Flags shared service connections."""
    respx.get("https://dev.azure.com/test-org/_apis/projects").mock(
        return_value=httpx.Response(200, json={"value": [{"name": "proj1"}]})
    )
    respx.get("https://dev.azure.com/test-org/proj1/_apis/serviceendpoint/endpoints").mock(
        return_value=httpx.Response(
            200,
            json={
                "value": [
                    {
                        "id": "ep-shared",
                        "name": "Docker-Registry",
                        "type": "dockerregistry",
                        "url": "https://index.docker.io",
                        "authorization": {"scheme": "UsernamePassword"},
                        "isShared": True,
                    }
                ]
            },
        )
    )

    env = _env(store)
    result = await run_module(AdoServiceConnections(), env)  # type: ignore[arg-type]

    assert result.ok is True
    findings = store.findings(kind="ado_service_connection_shared")
    assert len(findings) >= 1
    assert "Docker-Registry" in findings[0].reference


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
    result = await run_module(AdoServiceConnections(), env)  # type: ignore[arg-type]
    assert result.ok is True
    assert result.written == 0
