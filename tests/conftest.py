"""Shared test fixtures.

``make_jwt`` builds an *unsigned*, JWT-shaped string (``b64url(header).b64url(payload).sig``)
with a chosen ``aud`` and optional extra claims. No real crypto — only the shape that
``classify_audience`` reads. Never used against a live tenant.
"""

from __future__ import annotations

import base64
import json
import sys
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import yaml

from beachhead.core.config import load_config
from beachhead.core.store.engine import open_store

IS_WINDOWS = sys.platform == "win32"


def write_fake_script(directory: Path, name: str, body: str) -> Path:
    """Write a fake CLI stub and return the path to pass as exe.

    On Unix: writes the body with a shebang, ``chmod +x``, returns the script path.
    On Windows: writes the body as ``<name>.py`` and creates a ``<name>.cmd`` shim
    that invokes ``python <name>.py %*``, returns the ``.cmd`` path.
    """
    lines = body.splitlines(keepends=True)
    if lines and lines[0].startswith("#!"):
        lines = lines[1:]
    script_body = "".join(lines)

    if IS_WINDOWS:
        py_path = directory / f"{name}.py"
        py_path.write_text(script_body, encoding="utf-8")
        cmd_path = directory / f"{name}.cmd"
        python_exe = sys.executable.replace("/", "\\")
        cmd_path.write_text(
            f'@"{python_exe}" "{py_path}" %*\n',
            encoding="utf-8",
        )
        return cmd_path
    else:
        script_path = directory / name
        script_path.write_text(body, encoding="utf-8")
        script_path.chmod(0o755)
        return script_path


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


@pytest.fixture
def make_jwt() -> Callable[..., str]:
    def _make(aud: str | None, **claims: Any) -> str:
        header = _b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode())
        payload_obj: dict[str, Any] = dict(claims)
        if aud is not None:
            payload_obj["aud"] = aud
        payload = _b64url(json.dumps(payload_obj).encode())
        return f"{header}.{payload}.sig"

    return _make


class FakeClock:
    """Deterministic, monotonically increasing UTC clock for store tests."""

    def __init__(self) -> None:
        self._n = 0

    def __call__(self) -> datetime:
        self._n += 1
        return datetime(2026, 1, 1, tzinfo=UTC) + timedelta(seconds=self._n)


class FakeIds:
    """Deterministic id factory: id-0001, id-0002, ..."""

    def __init__(self) -> None:
        self._n = 0

    def __call__(self) -> str:
        self._n += 1
        return f"id-{self._n:04d}"


@pytest.fixture
def store(tmp_path):
    s = open_store(str(tmp_path / "engagement.db"), clock=FakeClock(), id_factory=FakeIds())
    yield s
    s.close()


@pytest.fixture
def run_id(store):
    store.ensure_engagement(name="ACME", scope_hash="h")
    return store.start_run(
        module="enumerate.ado_pipelines", phase="enumerate", operator="op"
    )


# ---------------------------------------------------------------------------
# Shared engagement_env fixtures (CLI / TUI surface tests)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EngagementEnv:
    store_path: str
    config_path: str


def _config_dict(**overrides: object) -> dict[str, object]:
    base = {
        "engagement": "ACME-2026-Q2",
        "authorization_ref": "SOW-1 / RoE",
        "window": {"start": "2026-01-01T00:00:00Z", "end": "2030-01-01T00:00:00Z"},
        "subscriptions": ["11111111-1111-1111-1111-111111111111"],
        "allow_write": False,
    }
    base.update(overrides)
    return base


@pytest.fixture
def write_config():
    def _write(path: str | Path, **overrides: object) -> str:
        p = Path(path)
        p.write_text(yaml.safe_dump(_config_dict(**overrides)))
        return str(p)

    return _write


@pytest.fixture
def engagement_env(tmp_path, write_config, monkeypatch) -> EngagementEnv:
    monkeypatch.setenv("BH_SECRETS_KEY", "test-key")
    config_path = write_config(tmp_path / "engagement.local.yaml")
    config = load_config(config_path)

    store_path = str(tmp_path / "beachhead.sqlite")
    st = open_store(store_path, clock=FakeClock(), id_factory=FakeIds())
    st.ensure_engagement(name=config.engagement, scope_hash=config.scope_hash)

    r1 = st.start_run(
        module="enumerate.ado_repos", phase="enumerate", operator="jdoe"
    )
    st.insert_audit(
        operator="jdoe",
        action="az.devops",
        target="ado/repos",
        mode="live",
        result="ok",
        run_id=r1,
    )
    st.finish_run(r1, status="ok")

    r2 = st.start_run(
        module="enumerate.ado_pipelines", phase="enumerate", operator="jdoe"
    )
    st.finish_run(r2, status="ok")

    # a third run left "running" (no finish) to exercise the '—' duration path
    st.start_run(
        module="harvest.ado_credential_scan", phase="harvest", operator="jdoe"
    )

    st.close()  # checkpoint WAL so a read-only re-open sees everything
    return EngagementEnv(store_path=store_path, config_path=config_path)
