"""Shared subprocess utilities for ``az_client``.

Standalone functions — composition over inheritance. Both clients call these
for error classification, JSON parsing, and the core spawn-wait-decode loop.
Client-specific behavior (temp files, stdin injection, arg construction, marker
sets) stays in each client.
"""

from __future__ import annotations

import asyncio
import json
import re
from collections.abc import Sequence
from typing import Any

from beachhead.core.errors import ApiError, AuthError, Throttled, Transient

__all__ = ["classify_stderr", "parse_json_output", "spawn_subprocess"]

_SECRET_PATTERNS = re.compile(
    r"(?i)"
    r"(?:bearer\s+)\S+"
    r"|(?:password|pwd|secret|token|key|pat)[=:]\s*\S+"
    r"|[A-Za-z0-9+/]{40,}={0,2}"
    r"|://[^@/\s]+:[^@/\s]+@",
)


def _sanitize_stderr(text: str) -> str:
    """Strip common secret patterns from stderr before including in error messages."""
    return _SECRET_PATTERNS.sub("[REDACTED]", text)


def classify_stderr(
    exit_code: int,
    stderr: str,
    *,
    auth_markers: Sequence[str],
    throttle_markers: Sequence[str],
    not_found_markers: Sequence[str] = (),
    tool_label: str,
) -> Exception:
    """Map subprocess stderr + exit code onto the shared error taxonomy.

    Returns (not raises) a typed exception. The caller raises it.
    """
    low = stderr.lower()
    tail = _sanitize_stderr(stderr.strip()[-500:])
    if any(m in low for m in auth_markers):
        return AuthError(f"{tool_label} reported auth failure (exit {exit_code}): {tail}")
    if any(m in low for m in throttle_markers):
        return Throttled(f"{tool_label} reported throttling (exit {exit_code}): {tail}")
    if not_found_markers and any(m in low for m in not_found_markers):
        return ApiError(
            f"{tool_label} resource not found (exit {exit_code}): {tail}",
            exit_code=exit_code,
        )
    return ApiError(f"{tool_label} exited {exit_code}: {tail}", exit_code=exit_code)


def parse_json_output(stdout: str, *, fallback_last_line: bool = False) -> Any:
    """Parse JSON from subprocess stdout.

    When *fallback_last_line* is False (az-style): returns ``None`` for empty
    output; raises ``ValueError`` on malformed JSON.

    When *fallback_last_line* is True (pwsh-style): raises ``ValueError`` for
    empty output; on initial parse failure, tries the last non-empty line.
    """
    text = stdout.strip()
    if not text:
        if fallback_last_line:
            raise ValueError("empty stdout")
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        if not fallback_last_line:
            raise ValueError(f"non-JSON stdout: {text[:200]}") from None
    for line in reversed(text.splitlines()):
        line = line.strip()
        if not line:
            continue
        try:
            return json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError("no JSON found in stdout") from exc
    raise ValueError("no JSON found in stdout")


async def spawn_subprocess(
    exe: str,
    args: Sequence[str],
    *,
    stdin_data: bytes | None = None,
    env: dict[str, str],
    timeout: float | None,  # noqa: ASYNC109
    sem: asyncio.Semaphore,
    tool_label: str = "subprocess",
) -> tuple[int, str, str]:
    """Spawn a subprocess, wait for it, return (exit_code, stdout, stderr).

    Centralises the create → wait_for → timeout-kill → decode pattern shared by
    ``az_client``.

    Args:
        stdin_data: If ``None``, stdin is DEVNULL. Otherwise bytes piped via PIPE.
        tool_label: Used in error messages (e.g. ``"az"``, ``"pwsh"``).
    """
    stdin_mode = asyncio.subprocess.PIPE if stdin_data is not None else asyncio.subprocess.DEVNULL

    async with sem:
        try:
            proc = await asyncio.create_subprocess_exec(
                exe,
                *args,
                stdin=stdin_mode,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )
        except (FileNotFoundError, PermissionError, OSError) as exc:
            raise ApiError(f"could not spawn {tool_label} at {exe!r}: {exc}") from exc

        try:
            out_b, err_b = await asyncio.wait_for(
                proc.communicate(input=stdin_data),
                timeout=timeout,
            )
        except TimeoutError as exc:
            proc.kill()
            await proc.wait()
            raise Transient(f"{tool_label} invocation timed out after {timeout}s") from exc

    return (
        proc.returncode or 0,
        out_b.decode("utf-8", "replace"),
        err_b.decode("utf-8", "replace"),
    )
