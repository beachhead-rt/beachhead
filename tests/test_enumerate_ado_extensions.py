"""Tests for enumerate.ado_extensions — ADO installed extension enumeration."""

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
from beachhead.modules.enumerate.ado_extensions import AdoExtensions


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
    m = AdoExtensions()
    assert m.meta.name == "enumerate.ado_extensions"
    assert m.meta.phase.value == "enumerate"
    assert m.meta.access.value == "read"
    assert m.meta.gated is False


@respx.mock
@pytest.mark.asyncio
async def test_enumerates_extensions(store: Any) -> None:
    """Records installed extensions."""
    respx.get("https://extmgmt.dev.azure.com/test-org/_apis/extensionmanagement/installedextensions").mock(
        return_value=httpx.Response(
            200,
            json={
                "value": [
                    {
                        "publisherId": "ms",
                        "extensionId": "vss-code-search",
                        "extensionName": "Code Search",
                        "publisherName": "Microsoft",
                        "version": "1.0.0",
                        "flags": ["builtIn"],
                        "scopes": ["vso.code"],
                        "installState": {"flags": "none"},
                        "lastPublished": "2026-01-01",
                    },
                    {
                        "publisherId": "acme",
                        "extensionId": "build-helper",
                        "extensionName": "Build Helper",
                        "publisherName": "Acme Corp",
                        "version": "2.3.1",
                        "flags": [],
                        "scopes": ["vso.build"],
                        "installState": {"flags": "none"},
                        "lastPublished": "2026-03-15",
                    },
                ]
            },
        )
    )

    env = _env(store)
    result = await run_module(AdoExtensions(), env)  # type: ignore[arg-type]

    assert result.ok is True
    assert result.written >= 2

    resources = [r for r in store.resources() if r.type == "ado_extension"]
    assert len(resources) == 2


@respx.mock
@pytest.mark.asyncio
async def test_flags_high_privilege_extension(store: Any) -> None:
    """Flags third-party extensions with high-privilege scopes."""
    respx.get("https://extmgmt.dev.azure.com/test-org/_apis/extensionmanagement/installedextensions").mock(
        return_value=httpx.Response(
            200,
            json={
                "value": [
                    {
                        "publisherId": "sketchy-pub",
                        "extensionId": "super-tool",
                        "extensionName": "Super Tool",
                        "publisherName": "Sketchy Publisher",
                        "version": "1.0.0",
                        "flags": [],
                        "scopes": ["vso.code_write", "vso.build_execute"],
                        "installState": {"flags": "none"},
                        "lastPublished": "2026-01-01",
                    },
                ]
            },
        )
    )

    env = _env(store)
    result = await run_module(AdoExtensions(), env)  # type: ignore[arg-type]

    assert result.ok is True
    findings = store.findings(kind="ado_extension_high_privilege")
    assert len(findings) >= 1
    assert "Super Tool" in findings[0].reference
    assert "vso.code_write" in findings[0].reference


@respx.mock
@pytest.mark.asyncio
async def test_skips_builtin(store: Any) -> None:
    """Built-in extensions with high-privilege scopes do NOT get flagged."""
    respx.get("https://extmgmt.dev.azure.com/test-org/_apis/extensionmanagement/installedextensions").mock(
        return_value=httpx.Response(
            200,
            json={
                "value": [
                    {
                        "publisherId": "ms",
                        "extensionId": "vss-releaseManagement-web",
                        "extensionName": "Release Management",
                        "publisherName": "Microsoft",
                        "version": "1.0.0",
                        "flags": ["builtIn"],
                        "scopes": [
                            "vso.code_write",
                            "vso.build_execute",
                            "vso.release_execute",
                        ],
                        "installState": {"flags": "none"},
                        "lastPublished": "2026-01-01",
                    },
                ]
            },
        )
    )

    env = _env(store)
    result = await run_module(AdoExtensions(), env)  # type: ignore[arg-type]

    assert result.ok is True
    findings = store.findings(kind="ado_extension_high_privilege")
    assert len(findings) == 0


@respx.mock
@pytest.mark.asyncio
async def test_handles_404_gracefully(store: Any) -> None:
    """Orgs that don't support the extension management API get a warning, not a crash."""
    respx.get("https://extmgmt.dev.azure.com/test-org/_apis/extensionmanagement/installedextensions").mock(
        return_value=httpx.Response(404, text="Not Found")
    )

    env = _env(store)
    result = await run_module(AdoExtensions(), env)  # type: ignore[arg-type]

    assert result.ok is True
    assert result.written == 0


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
            result = await run_module(AdoExtensions(), env)  # type: ignore[arg-type]

    assert result.ok is False
    assert "PAT" in result.message
