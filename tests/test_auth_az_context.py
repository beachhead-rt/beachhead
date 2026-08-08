"""Tests for the az-context auth flow (core/auth/az_context.py).

Uses a fake ``az`` Python script that returns controlled JSON / exit codes.
No real ``az`` CLI and never a live tenant.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Any

import pytest

from beachhead.core.auth.az_context import acquire_token_az_context
from beachhead.core.errors import AuthError

_FAKE_AZ = """\
#!/usr/bin/env python3
import sys, os
out = os.environ.get("FAKE_AZ_STDOUT", "")
err = os.environ.get("FAKE_AZ_STDERR", "")
code = int(os.environ.get("FAKE_AZ_EXIT", "0"))
sys.stdout.write(out)
sys.stderr.write(err)
sys.exit(code)
"""


@pytest.fixture()
def fake_az(tmp_path: Path) -> str:
    """Write the fake ``az`` stub and return its path."""
    from conftest import write_fake_script

    return str(write_fake_script(tmp_path, "az", _FAKE_AZ))


def _run(
    fake_az: str,
    audience: str = "graph",
    *,
    stdout: str | None = None,
    stderr: str = "",
    exit_code: int = 0,
) -> Any:
    env_patch = {
        "FAKE_AZ_EXIT": str(exit_code),
        "FAKE_AZ_STDERR": stderr,
    }
    if stdout is not None:
        env_patch["FAKE_AZ_STDOUT"] = stdout

    old = {}
    for k, v in env_patch.items():
        old[k] = os.environ.get(k)
        os.environ[k] = v
    try:
        return asyncio.run(acquire_token_az_context(audience=audience, az_path=fake_az))
    finally:
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def test_az_context_success(fake_az: str) -> None:
    payload = json.dumps(
        {
            "accessToken": "az-access-token-123",
            "expiresOn": "2026-07-01T00:00:00",
            "tenant": "tid-001",
        }
    )
    entry = _run(fake_az, stdout=payload)

    assert entry.access_token == "az-access-token-123"
    assert entry.audience == "graph"
    assert entry.source == "az_context"
    assert entry.tenant_id == "tid-001"
    assert entry.refreshable is False
    assert entry.refresh_token is None


def test_az_context_arm_audience(fake_az: str) -> None:
    payload = json.dumps(
        {
            "accessToken": "arm-token",
            "expiresOn": "2026-07-01T00:00:00",
            "tenant": "tid",
        }
    )
    entry = _run(fake_az, audience="arm", stdout=payload)

    assert entry.audience == "arm"
    assert entry.access_token == "arm-token"


def test_az_context_auth_failure(fake_az: str) -> None:
    with pytest.raises(AuthError, match="get-access-token failed"):
        _run(
            fake_az,
            exit_code=1,
            stderr="Please run 'az login' to setup account.",
            stdout="",
        )


def test_az_context_invalid_audience() -> None:
    with pytest.raises(ValueError, match="unknown audience"):
        asyncio.run(acquire_token_az_context(audience="bogus"))


def test_az_context_non_refreshable(fake_az: str) -> None:
    payload = json.dumps(
        {
            "accessToken": "tok",
            "expires_in": 3600,
        }
    )
    entry = _run(fake_az, stdout=payload)

    assert entry.refreshable is False
    assert entry.refresh_token is None
    assert entry.client_id is None


def test_az_context_missing_binary() -> None:
    with pytest.raises(AuthError, match="could not run az"):
        asyncio.run(
            acquire_token_az_context(
                audience="graph",
                az_path="/nonexistent/az",
            )
        )


def test_az_context_expires_on_iso(fake_az: str) -> None:
    payload = json.dumps(
        {
            "accessToken": "tok",
            "expiresOn": "2026-07-01T12:00:00+00:00",
        }
    )
    entry = _run(fake_az, stdout=payload)

    from datetime import UTC, datetime

    expected = datetime(2026, 7, 1, 12, 0, 0, tzinfo=UTC).timestamp()
    assert abs(entry.expires_at - expected) < 2


def test_az_context_expires_on_numeric(fake_az: str) -> None:
    payload = json.dumps(
        {
            "accessToken": "tok",
            "expires_on": "1782000000",
        }
    )
    entry = _run(fake_az, stdout=payload)

    assert abs(entry.expires_at - 1782000000.0) < 2


def test_az_context_no_access_token(fake_az: str) -> None:
    payload = json.dumps({"expiresOn": "2026-07-01T00:00:00"})
    with pytest.raises(AuthError, match="no accessToken"):
        _run(fake_az, stdout=payload)


def test_az_context_non_json_output(fake_az: str) -> None:
    with pytest.raises(AuthError, match="non-JSON"):
        _run(fake_az, stdout="this is not json")
