"""Module runner — assembles RunContext and executes a module.

Owns the run lifecycle: creates the ``runs`` row, assembles the
:class:`RunContext` with all injected collaborators, calls ``module.run(ctx)``,
and records the outcome.  The CLI and TUI invoke :func:`run_module`;
they never build a RunContext or call ``module.run()`` directly.
"""

from __future__ import annotations

import traceback
from dataclasses import dataclass
from typing import Any

from rich.console import Console

from beachhead.core.audit import AuditLog
from beachhead.core.errors import ScopeError, StoreError
from beachhead.core.module import (
    AzClient,
    ConfirmGate,
    Module,
    PromptFn,
    RunContext,
    RunResult,
    SecretStoreAccess,
    TokenProvider,
)
from beachhead.core.store.access import Store

__all__ = ["RunEnv", "run_module"]


@dataclass(slots=True)
class RunEnv:
    """Everything the runner needs to assemble a RunContext.

    Built once per session by the CLI/TUI bootstrap; passed to
    :func:`run_module` for each invocation.
    """

    store: Store
    az: AzClient
    auth: TokenProvider | None
    config: Any
    scope: Any
    console: Console
    operator: str
    secrets: SecretStoreAccess | None = None


async def _default_confirm(prompt: str, *, dangerous: bool = False) -> bool:
    return False


def _make_console_prompt(console: Console) -> PromptFn:
    async def _prompt(message: str, *, default: str = "") -> str:
        try:
            answer = console.input(message).strip()
        except (EOFError, KeyboardInterrupt):
            return default
        return answer or default
    return _prompt  # type: ignore[return-value]


async def run_module(
    module: Module,
    env: RunEnv,
    *,
    confirm: ConfirmGate | None = None,
    prompt: PromptFn | None = None,
) -> RunResult:
    """Execute a module within a managed run lifecycle.

    1. Creates a ``runs`` row.
    2. Assembles a :class:`RunContext`.
    3. Calls ``module.run(ctx)``.
    4. Records the outcome (``ok`` or ``error``).
    5. Returns the :class:`RunResult`.

    Write/manual modules are gated via the confirm callback: pass a
    :class:`ConfirmGate` to allow the operator to approve mutations.
    """
    try:
        run_id = env.store.start_run(
            module=module.meta.name,
            phase=module.meta.phase.value,
            operator=env.operator,
        )
    except StoreError:
        raise
    except Exception as exc:
        raise StoreError(f"Failed to start run: {exc}") from exc

    audit = AuditLog(env.store, operator=env.operator, run_id=run_id)

    ctx = RunContext(
        az=env.az,
        store=env.store,
        scope=env.scope,
        audit=audit,
        config=env.config,
        console=env.console,
        confirm=confirm or _default_confirm,
        prompt=prompt or _make_console_prompt(env.console),
        run_id=run_id,
        operator=env.operator,
        auth=env.auth,
        secrets=env.secrets,
    )

    def _finish(status: str) -> None:
        for retry in range(2):
            try:
                env.store.finish_run(run_id, status=status)
                break
            except Exception:  # noqa: BLE001
                if retry == 0:
                    continue
                env.console.print(
                    f"[yellow]Warning: failed to record run status '{status}' "
                    f"for run_id={run_id} — row may be stuck as 'running'[/]"
                )
        if env.secrets is not None:
            try:
                env.secrets.flush()
            except Exception:  # noqa: BLE001
                env.console.print("[yellow]Warning: failed to flush secret store[/]")

    try:
        result = await module.run(ctx)
    except ScopeError:
        _finish("error")
        raise
    except Exception:
        _finish("error")
        env.console.print_exception(show_locals=False)
        return RunResult(
            ok=False,
            message=traceback.format_exc(limit=3),
        )
    else:
        _finish("ok" if result.ok else "error")
        return result
