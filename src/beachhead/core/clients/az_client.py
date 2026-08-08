"""Azure CLI (``az`` / ``az devops``) subprocess wrapper.

Every invocation:
  1. Scope-checks the target BEFORE spawning the process.
  2. Runs with ``--output json`` and parses the result.
  3. Sets explicit ``--subscription`` / ``--organization`` (never relies on ambient).
  4. Audits the command shape (never secret arguments).
  5. Never puts secrets on the command line (visible in ``/proc``/``ps``).
  6. Maps exit codes and stderr onto the shared error taxonomy.

See docs/api-clients.md ("The az wrapper") for the full contract.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import Sequence
from typing import Any

from beachhead.core.clients._subprocess import (
    classify_stderr,
    parse_json_output,
    spawn_subprocess,
)
from beachhead.core.errors import ApiError
from beachhead.core.module import AuditLog, ScopeGuard

__all__ = ["AzSubprocessClient"]

_AUTH_MARKERS = (
    "aadsts",
    "invalidauthenticationtoken",
    "authentication failed",
    "unauthorized",
    "please run 'az login'",
    "refresh token has expired",
)
_THROTTLE_MARKERS = ("429", "throttl", "too many requests", "rate limit")
_NOT_FOUND_MARKERS = ("not found", "does not exist", "resource not found")


class AzSubprocessClient:
    """Spawn-per-call ``az`` CLI wrapper.

    Structurally satisfies :class:`beachhead.core.module.AzClient`.
    """

    def __init__(
        self,
        *,
        scope: ScopeGuard,
        audit: AuditLog,
        az_path: str = "az",
        max_concurrency: int = 4,
        default_subscription: str | None = None,
        default_organization: str | None = None,
    ) -> None:
        self._scope = scope
        self._audit = audit
        self._az_path = az_path
        self._sem = asyncio.Semaphore(max_concurrency)
        self._default_subscription = default_subscription
        self._default_organization = default_organization

    async def run(
        self,
        args: list[str],
        *,
        scope_targets: Sequence[str] = (),
        subscription: str | None = None,
        organization: str | None = None,
        parse_json: bool = True,
        timeout: float | None = 120.0,  # noqa: ASYNC109 — caller timeout is part of the AzClient contract
    ) -> Any:
        """Run an ``az`` command and return the parsed JSON result.

        Args:
            args: The ``az`` command arguments (e.g. ``["group", "list"]``).
            scope_targets: Targets to scope-check before spawning.
            subscription: Explicit ``--subscription``; falls back to default.
            organization: Explicit ``--organization`` (for ``az devops``).
            parse_json: If True, append ``--output json`` and parse stdout.
                Set False for commands that produce no output.
            timeout: Subprocess timeout in seconds; None for no limit.

        Returns:
            Parsed JSON (dict/list) when ``parse_json=True``;
            ``None`` when stdout is empty or ``parse_json=False``.

        Raises:
            ScopeError: Target is outside the engagement scope.
            AuthError: ``az`` reports an auth failure.
            Throttled: ``az`` reports rate limiting.
            Transient: Timeout or transient failure.
            ApiError: Any other ``az`` failure.
        """
        for target in scope_targets:
            self._scope.check(target, kind="target")

        full_args = list(args)
        if parse_json and "--output" not in full_args:
            full_args.extend(["--output", "json"])

        sub = subscription or self._default_subscription
        if sub and "--subscription" not in full_args:
            full_args.extend(["--subscription", sub])

        org = organization or self._default_organization
        if org and "--organization" not in full_args:
            full_args.extend(["--organization", org])

        audit_shape = _audit_shape(full_args)
        target_repr = ",".join(scope_targets) if scope_targets else "-"

        exit_code, stdout, stderr = await self._spawn(full_args, timeout=timeout)

        if exit_code != 0:
            self._audit.record(f"az {audit_shape}", target_repr, result="error")
            raise classify_stderr(
                exit_code,
                stderr,
                auth_markers=_AUTH_MARKERS,
                throttle_markers=_THROTTLE_MARKERS,
                not_found_markers=_NOT_FOUND_MARKERS,
                tool_label="az",
            )

        if not parse_json:
            self._audit.record(f"az {audit_shape}", target_repr, result="ok")
            return None

        try:
            data = parse_json_output(stdout)
        except ValueError as exc:
            raise ApiError(f"az returned {exc}") from exc
        self._audit.record(f"az {audit_shape}", target_repr, result="ok")
        return data

    async def version(self) -> dict[str, Any]:
        """Return ``az version --output json``. No scope check needed."""
        exit_code, stdout, stderr = await self._spawn(["version", "--output", "json"], timeout=30.0)
        if exit_code != 0:
            raise ApiError(
                f"az version failed (exit {exit_code}): {stderr.strip()[-500:]}",
                exit_code=exit_code,
            )
        try:
            result = parse_json_output(stdout)
        except ValueError as exc:
            raise ApiError(f"az version returned {exc}") from exc
        if result is None:
            raise ApiError("az version returned empty output")
        return result if isinstance(result, dict) else {"raw": result}

    async def account_show(self) -> dict[str, Any]:
        """Return the current ``az account show`` context. No scope check."""
        exit_code, stdout, stderr = await self._spawn(
            ["account", "show", "--output", "json"], timeout=30.0
        )
        if exit_code != 0:
            raise classify_stderr(
                exit_code,
                stderr,
                auth_markers=_AUTH_MARKERS,
                throttle_markers=_THROTTLE_MARKERS,
                not_found_markers=_NOT_FOUND_MARKERS,
                tool_label="az",
            )
        try:
            result = parse_json_output(stdout)
        except ValueError as exc:
            raise ApiError(f"az account show returned {exc}") from exc
        if result is None:
            raise ApiError("az account show returned empty output")
        return result if isinstance(result, dict) else {"raw": result}

    # ----------------------------------------------------------------------- #
    # Internals
    # ----------------------------------------------------------------------- #
    async def _spawn(
        self,
        args: list[str],
        *,
        timeout: float | None,  # noqa: ASYNC109 — mirrors run()'s contractual timeout
    ) -> tuple[int, str, str]:
        env = os.environ.copy()
        env.pop("BH_SECRETS_KEY", None)
        env["AZURE_CORE_OUTPUT"] = "json"

        return await spawn_subprocess(
            self._az_path,
            args,
            stdin_data=None,
            env=env,
            timeout=timeout,
            sem=self._sem,
            tool_label="az",
        )


def _audit_shape(args: list[str]) -> str:
    """Extract the command shape for audit logging.

    Keeps the positional command group/verb (e.g. ``group list``,
    ``devops service-endpoint list``), drops values of flag arguments.
    Never includes secret values — only the flag names.
    """
    parts: list[str] = []
    skip_next = False
    for arg in args:
        if skip_next:
            skip_next = False
            continue
        if arg.startswith("--"):
            if "=" in arg:
                parts.append(arg.split("=", 1)[0] + "=…")
            else:
                parts.append(arg)
                skip_next = True
        elif arg.startswith("-"):
            parts.append(arg)
            skip_next = True
        else:
            parts.append(arg)
    return " ".join(parts)
