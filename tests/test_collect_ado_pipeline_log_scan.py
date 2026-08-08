"""Tests for collect.ado_pipeline_log_scan — ADO pipeline log scanner."""

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
from beachhead.modules.harvest.ado_pipeline_log_scan import AdoPipelineLogScan


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
    m = AdoPipelineLogScan()
    assert m.meta.name == "harvest.ado_pipeline_log_scan"
    assert m.meta.phase.value == "harvest"
    assert m.meta.access.value == "read"
    assert m.meta.gated is False


@respx.mock
@pytest.mark.asyncio
async def test_detects_bearer_token_in_log(store: Any) -> None:
    """Finds a bearer token in a build log."""
    respx.get("https://dev.azure.com/test-org/_apis/projects").mock(
        return_value=httpx.Response(200, json={"value": [{"name": "proj1"}]})
    )
    respx.get("https://dev.azure.com/test-org/proj1/_apis/build/builds").mock(
        return_value=httpx.Response(
            200,
            json={
                "value": [
                    {"id": 100, "buildNumber": "20260628.1"},
                ]
            },
        )
    )
    respx.get("https://dev.azure.com/test-org/proj1/_apis/build/builds/100/logs").mock(
        return_value=httpx.Response(200, json={"value": [{"id": 1}]})
    )
    respx.get("https://dev.azure.com/test-org/proj1/_apis/build/builds/100/logs/1").mock(
        return_value=httpx.Response(
            200,
            text=(
                "Step 1: Authenticate\n"
                "Setting auth header: Bearer "
                "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.Sfl-KxwRJSMeKKF2QT4fwpM\n"
                "Step 2: Deploy\n"
            ),
        )
    )

    env = _env(store)
    result = await run_module(AdoPipelineLogScan(), env)  # type: ignore[arg-type]

    assert result.ok is True
    assert result.written >= 1

    findings = store.findings(kind="ado_pipeline_log_secret")
    assert len(findings) >= 1
    f = findings[0]
    assert f.redacted is True
    ref_lower = f.reference.lower()
    assert "bearer" in ref_lower or "jwt" in ref_lower or "token" in ref_lower


@respx.mock
@pytest.mark.asyncio
async def test_skips_scrubbed_lines(store: Any) -> None:
    """Lines with *** scrub markers are skipped."""
    respx.get("https://dev.azure.com/test-org/_apis/projects").mock(
        return_value=httpx.Response(200, json={"value": [{"name": "proj1"}]})
    )
    respx.get("https://dev.azure.com/test-org/proj1/_apis/build/builds").mock(
        return_value=httpx.Response(
            200,
            json={"value": [{"id": 200, "buildNumber": "20260628.2"}]},
        )
    )
    respx.get("https://dev.azure.com/test-org/proj1/_apis/build/builds/200/logs").mock(
        return_value=httpx.Response(200, json={"value": [{"id": 1}]})
    )
    respx.get("https://dev.azure.com/test-org/proj1/_apis/build/builds/200/logs/1").mock(
        return_value=httpx.Response(
            200,
            text="Step 1: Connect with password=***\nStep 2: Done\n",
        )
    )

    env = _env(store)
    result = await run_module(AdoPipelineLogScan(), env)  # type: ignore[arg-type]

    assert result.ok is True
    findings = store.findings(kind="ado_pipeline_log_secret")
    assert len(findings) == 0


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
    result = await run_module(AdoPipelineLogScan(), env)  # type: ignore[arg-type]
    assert result.ok is True
    assert result.written == 0


@pytest.mark.asyncio
async def test_no_pat(store: Any) -> None:
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
            result = await run_module(AdoPipelineLogScan(), env)  # type: ignore[arg-type]

    assert result.ok is False
    assert "PAT" in result.message
