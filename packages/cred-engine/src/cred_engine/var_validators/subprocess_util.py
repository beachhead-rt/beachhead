"""Shared subprocess runner for CLI-based validators.

Wraps subprocess.run with a timeout, captures output, and handles
missing-tool detection so each validator doesn't repeat the boilerplate.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from dataclasses import dataclass

logger = logging.getLogger(__name__)

_DEFAULT_TIMEOUT = 15


@dataclass
class CliResult:
    """Result of a CLI tool invocation."""

    returncode: int
    stdout: str
    stderr: str
    tool_missing: bool = False
    timed_out: bool = False


def run_cli(
    args: list[str],
    *,
    timeout: int = _DEFAULT_TIMEOUT,
    input_text: str | None = None,
) -> CliResult:
    """Run a CLI command and return structured output.

    Checks that the tool binary exists before attempting to run it.
    Returns a CliResult with tool_missing=True if the binary is not found.
    """
    tool = args[0]
    if not shutil.which(tool):
        return CliResult(
            returncode=-1,
            stdout="",
            stderr=f"{tool} not found on PATH",
            tool_missing=True,
        )

    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=input_text,
        )
        return CliResult(
            returncode=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
        )
    except subprocess.TimeoutExpired:
        return CliResult(
            returncode=-1,
            stdout="",
            stderr=f"{tool} timed out after {timeout}s",
            timed_out=True,
        )
    except OSError as exc:
        return CliResult(
            returncode=-1,
            stdout="",
            stderr=f"Failed to run {tool}: {exc}",
        )
