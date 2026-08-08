"""Tests for the module runner (core/runner.py)."""

from __future__ import annotations

from typing import Any

import pytest
from conftest import FakeClock, FakeIds
from rich.console import Console

from beachhead.core.errors import ScopeError
from beachhead.core.module import (
    ModuleMeta,
    RunContext,
    RunResult,
)
from beachhead.core.runner import RunEnv, run_module
from beachhead.core.store.engine import open_store


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------
class FakeTokenProvider:
    async def get(self, audience: str) -> str:
        return "fake-token"


class FakeAzClient:
    async def run(self, args: list[str], **kwargs: Any) -> Any:
        return {}


class FakeScope:
    def __init__(self, *, fail: bool = False) -> None:
        self._fail = fail

    def check(self, target: str, *, kind: str = "target") -> None:
        if self._fail:
            raise ScopeError("out of scope")


class FakeConfig:
    @property
    def engagement(self) -> str:
        return "ACME-TEST"

    @property
    def allow_write(self) -> bool:
        return False


# ---------------------------------------------------------------------------
# Good module
# ---------------------------------------------------------------------------
class GoodModule:
    meta = ModuleMeta(
        name="enumerate.good",
        phase="enumerate",
        access="read",
        summary="A good test module",
    )
    run_called = False

    async def run(self, ctx: RunContext) -> RunResult:
        self.run_called = True
        return RunResult(ok=True, written=5, message="done")


# ---------------------------------------------------------------------------
# Error module
# ---------------------------------------------------------------------------
class ErrorModule:
    meta = ModuleMeta(
        name="enumerate.bad",
        phase="enumerate",
        access="read",
        summary="A module that errors",
    )

    async def run(self, ctx: RunContext) -> RunResult:
        msg = "boom"
        raise RuntimeError(msg)


# ---------------------------------------------------------------------------
# Scope-failing module
# ---------------------------------------------------------------------------
class ScopeFailModule:
    meta = ModuleMeta(
        name="enumerate.scope_fail",
        phase="enumerate",
        access="read",
        summary="A module that triggers scope error",
    )

    async def run(self, ctx: RunContext) -> RunResult:
        ctx.scope.check("/out-of-scope", kind="graph")
        return RunResult(ok=True)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture
def store(tmp_path: Any) -> Any:
    s = open_store(str(tmp_path / "test.db"), clock=FakeClock(), id_factory=FakeIds())
    s.ensure_engagement(name="ACME-TEST", scope_hash="h")
    return s


@pytest.fixture
def env(store: Any) -> RunEnv:
    return RunEnv(
        store=store,
        az=FakeAzClient(),
        auth=FakeTokenProvider(),
        config=FakeConfig(),
        scope=FakeScope(),
        console=Console(quiet=True),
        operator="test-op",
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_run_module_success(env: RunEnv) -> None:
    mod = GoodModule()
    result = await run_module(mod, env)  # type: ignore[arg-type]
    assert result.ok is True
    assert result.written == 5
    assert mod.run_called is True

    runs = env.store.runs()
    assert len(runs) == 1
    assert runs[0].module == "enumerate.good"
    assert runs[0].status == "ok"


@pytest.mark.asyncio
async def test_run_module_records_error(env: RunEnv) -> None:
    mod = ErrorModule()
    result = await run_module(mod, env)  # type: ignore[arg-type]
    assert result.ok is False
    assert "boom" in result.message

    runs = env.store.runs()
    assert runs[0].status == "error"


@pytest.mark.asyncio
async def test_run_module_scope_error_reraises(env: RunEnv) -> None:
    env.scope = FakeScope(fail=True)
    mod = ScopeFailModule()
    with pytest.raises(ScopeError):
        await run_module(mod, env)  # type: ignore[arg-type]

    runs = env.store.runs()
    assert runs[0].status == "error"


@pytest.mark.asyncio
async def test_run_module_injects_run_id(env: RunEnv) -> None:
    captured_ctx: list[RunContext] = []

    class CapturingModule:
        meta = ModuleMeta(
            name="enumerate.cap",
            phase="enumerate",
            access="read",
            summary="captures ctx",
        )

        async def run(self, ctx: RunContext) -> RunResult:
            captured_ctx.append(ctx)
            return RunResult(ok=True)

    await run_module(CapturingModule(), env)  # type: ignore[arg-type]
    assert len(captured_ctx) == 1
    ctx = captured_ctx[0]
    assert ctx.run_id.startswith("id-")
    assert ctx.operator == "test-op"


@pytest.mark.asyncio
async def test_run_module_default_confirm_denies(env: RunEnv) -> None:
    confirmed: list[bool] = []

    class ConfirmModule:
        meta = ModuleMeta(
            name="exploit.conf",
            phase="exploit",
            access="write",
            summary="confirm test",
        )

        async def run(self, ctx: RunContext) -> RunResult:
            result = await ctx.confirm("do it?")
            confirmed.append(result)
            return RunResult(ok=True)

    await run_module(ConfirmModule(), env)  # type: ignore[arg-type]
    assert confirmed == [False]
