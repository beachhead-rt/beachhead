"""Tests for enumerate.ado_service_hooks — ADO service hook enumeration."""

from __future__ import annotations

import os
from typing import Any
from unittest.mock import patch

import httpx
import pytest
import respx
from conftest import FakeClock, FakeIds
from rich.console import Console

from beachhead.core.errors import AuthError
from beachhead.core.runner import RunEnv, run_module
from beachhead.core.store.engine import open_store
from beachhead.modules.enumerate.ado_service_hooks import AdoServiceHooks



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
    m = AdoServiceHooks()
    assert m.meta.name == "enumerate.ado_service_hooks"
    assert m.meta.phase.value == "enumerate"
    assert m.meta.access.value == "read"
    assert m.meta.gated is False


@respx.mock
@pytest.mark.asyncio
async def test_enumerates_hooks(store: Any) -> None:
    """Records service hook subscriptions."""
    respx.get("https://dev.azure.com/test-org/_apis/hooks/subscriptions").mock(
        return_value=httpx.Response(
            200,
            json={
                "value": [
                    {
                        "id": "hook-1",
                        "eventType": "build.complete",
                        "consumerId": "webHooks",
                        "consumerActionId": "httpRequest",
                        "publisherId": "pipelines",
                        "status": "enabled",
                        "consumerInputs": {"url": "https://myapp.azure.com/webhook"},
                    },
                    {
                        "id": "hook-2",
                        "eventType": "git.push",
                        "consumerId": "slack",
                        "consumerActionId": "postMessage",
                        "publisherId": "tfs",
                        "status": "enabled",
                        "consumerInputs": {},
                    },
                ]
            },
        )
    )

    env = _env(store)
    result = await run_module(AdoServiceHooks(), env)  # type: ignore[arg-type]

    assert result.ok is True
    assert result.written >= 2

    resources = [r for r in store.resources() if r.type == "ado_service_hook"]
    assert len(resources) == 2


@respx.mock
@pytest.mark.asyncio
async def test_flags_insecure_url(store: Any) -> None:
    """Flags webhook targets using HTTP instead of HTTPS."""
    respx.get("https://dev.azure.com/test-org/_apis/hooks/subscriptions").mock(
        return_value=httpx.Response(
            200,
            json={
                "value": [
                    {
                        "id": "hook-insecure",
                        "eventType": "build.complete",
                        "consumerId": "webHooks",
                        "consumerActionId": "httpRequest",
                        "publisherId": "pipelines",
                        "status": "enabled",
                        "consumerInputs": {"url": "http://internal.corp.local/hook"},
                    },
                ]
            },
        )
    )

    env = _env(store)
    result = await run_module(AdoServiceHooks(), env)  # type: ignore[arg-type]

    assert result.ok is True
    findings = store.findings(kind="ado_hook_insecure_url")
    assert len(findings) >= 1
    assert "non-HTTPS" in findings[0].reference


@respx.mock
@pytest.mark.asyncio
async def test_flags_external_target(store: Any) -> None:
    """Flags webhook targets pointing to external (non-Microsoft) domains."""
    respx.get("https://dev.azure.com/test-org/_apis/hooks/subscriptions").mock(
        return_value=httpx.Response(
            200,
            json={
                "value": [
                    {
                        "id": "hook-ext",
                        "eventType": "git.push",
                        "consumerId": "webHooks",
                        "consumerActionId": "httpRequest",
                        "publisherId": "tfs",
                        "status": "enabled",
                        "consumerInputs": {
                            "url": "https://hooks.slack.com/services/T00/B00/xxx"
                        },
                    },
                ]
            },
        )
    )

    env = _env(store)
    result = await run_module(AdoServiceHooks(), env)  # type: ignore[arg-type]

    assert result.ok is True
    findings = store.findings(kind="ado_hook_external_target")
    assert len(findings) >= 1
    assert "hooks.slack.com" in findings[0].reference


@pytest.mark.asyncio
async def test_no_pat_fails(store: Any) -> None:
    """Without a PAT, the module fails gracefully."""

    class NoAuth:
        async def get(self, audience: str) -> str:
            raise AuthError("no token")

    env = _env(store)
    env.auth = NoAuth()  # type: ignore[assignment]

    with patch.dict(os.environ, {}, clear=True):
        clean_env = {k: v for k, v in os.environ.items() if k != "BEACHHEAD_ADO_PAT"}
        with patch.dict(os.environ, clean_env, clear=True):
            result = await run_module(AdoServiceHooks(), env)  # type: ignore[arg-type]

    assert result.ok is False
    assert "PAT" in result.message
