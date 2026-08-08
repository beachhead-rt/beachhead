"""Tests for the az_client (core/clients/az_client.py).

Exercised against a **fake ``az``** — a small Python stub on disk that the
client invokes exactly as it would the real CLI. The stub records what it was
handed (argv, env) into a capture file and emits controlled stdout/stderr,
exiting with a controlled code. No real ``az`` and never a live tenant.

Coroutines are driven via ``asyncio.run`` so these run with or without
pytest-asyncio installed.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest

from beachhead.core.clients.az_client import AzSubprocessClient, _audit_shape
from beachhead.core.errors import ApiError, AuthError, ScopeError, Throttled, Transient
from beachhead.core.module import AzClient

_FAKE_AZ = """\
#!/usr/bin/env python3
import sys, os, json, time
args = sys.argv[1:]
cap = os.environ.get("FAKE_AZ_CAPTURE")
if cap:
    info = {"argv": args, "env_output": os.environ.get("AZURE_CORE_OUTPUT")}
    with open(cap, "w", encoding="utf-8") as fh:
        json.dump(info, fh)
naptime = os.environ.get("FAKE_AZ_SLEEP")
if naptime:
    time.sleep(float(naptime))
out = os.environ.get("FAKE_AZ_STDOUT", "")
sys.stdout.write(out)
sys.stderr.write(os.environ.get("FAKE_AZ_STDERR", ""))
sys.exit(int(os.environ.get("FAKE_AZ_EXIT", "0")))
"""


class FakeScope:
    def __init__(self, blocked: set[str] | None = None) -> None:
        self.checked: list[tuple[str, str]] = []
        self._blocked = blocked or set()

    def check(self, target: str, *, kind: str = "target") -> None:
        self.checked.append((target, kind))
        if target in self._blocked:
            raise ScopeError(f"out of scope: {target}")


class FakeAudit:
    def __init__(self) -> None:
        self.records: list[tuple[str, str, str]] = []

    def record(
        self,
        action: str,
        target: str,
        *,
        result: str = "ok",
        **extra: Any,
    ) -> None:
        self.records.append((action, target, result))


@pytest.fixture
def fake_az(tmp_path: Path) -> Path:
    from conftest import write_fake_script

    return write_fake_script(tmp_path, "fake-az", _FAKE_AZ)


def _client(
    fake_az: Path,
    *,
    scope: FakeScope | None = None,
    audit: FakeAudit | None = None,
    default_subscription: str | None = None,
    default_organization: str | None = None,
) -> AzSubprocessClient:
    return AzSubprocessClient(
        scope=scope or FakeScope(),
        audit=audit or FakeAudit(),
        az_path=str(fake_az),
        default_subscription=default_subscription,
        default_organization=default_organization,
    )


def _capture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    cap = tmp_path / "capture.json"
    monkeypatch.setenv("FAKE_AZ_CAPTURE", str(cap))
    return cap


# ------------------------------------------------------------------ #
# Protocol satisfaction
# ------------------------------------------------------------------ #
def test_satisfies_az_client_protocol(fake_az: Path) -> None:
    assert isinstance(_client(fake_az), AzClient)


# ------------------------------------------------------------------ #
# Scope checks
# ------------------------------------------------------------------ #
def test_run_scope_checks_before_spawn(
    fake_az: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cap = _capture(tmp_path, monkeypatch)
    scope = FakeScope(blocked={"/sub/bad"})
    client = _client(fake_az, scope=scope)
    with pytest.raises(ScopeError):
        asyncio.run(
            client.run(
                ["group", "list"],
                scope_targets=["/sub/bad"],
            )
        )
    assert not cap.exists()


def test_run_scope_checks_every_target(fake_az: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FAKE_AZ_STDOUT", '{"ok": true}')
    scope = FakeScope()
    client = _client(fake_az, scope=scope)
    asyncio.run(
        client.run(
            ["group", "list"],
            scope_targets=["/sub/a", "/sub/b"],
        )
    )
    assert scope.checked == [("/sub/a", "target"), ("/sub/b", "target")]


# ------------------------------------------------------------------ #
# Arg injection
# ------------------------------------------------------------------ #
def test_run_appends_output_json(
    fake_az: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cap = _capture(tmp_path, monkeypatch)
    monkeypatch.setenv("FAKE_AZ_STDOUT", '{"ok": true}')
    asyncio.run(_client(fake_az).run(["group", "list"]))
    info = json.loads(cap.read_text())
    assert "--output" in info["argv"]
    idx = info["argv"].index("--output")
    assert info["argv"][idx + 1] == "json"


def test_run_does_not_duplicate_output_flag(
    fake_az: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cap = _capture(tmp_path, monkeypatch)
    monkeypatch.setenv("FAKE_AZ_STDOUT", '{"ok": true}')
    asyncio.run(_client(fake_az).run(["group", "list", "--output", "table"]))
    info = json.loads(cap.read_text())
    assert info["argv"].count("--output") == 1


def test_run_appends_subscription(
    fake_az: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cap = _capture(tmp_path, monkeypatch)
    monkeypatch.setenv("FAKE_AZ_STDOUT", '{"ok": true}')
    client = _client(fake_az, default_subscription="sub-123")
    asyncio.run(client.run(["group", "list"]))
    info = json.loads(cap.read_text())
    assert "--subscription" in info["argv"]
    idx = info["argv"].index("--subscription")
    assert info["argv"][idx + 1] == "sub-123"


def test_run_explicit_subscription_overrides_default(
    fake_az: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cap = _capture(tmp_path, monkeypatch)
    monkeypatch.setenv("FAKE_AZ_STDOUT", '{"ok": true}')
    client = _client(fake_az, default_subscription="default-sub")
    asyncio.run(client.run(["group", "list"], subscription="explicit-sub"))
    info = json.loads(cap.read_text())
    idx = info["argv"].index("--subscription")
    assert info["argv"][idx + 1] == "explicit-sub"


def test_run_appends_organization(
    fake_az: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cap = _capture(tmp_path, monkeypatch)
    monkeypatch.setenv("FAKE_AZ_STDOUT", '{"ok": true}')
    client = _client(fake_az, default_organization="my-org")
    asyncio.run(client.run(["devops", "project", "list"]))
    info = json.loads(cap.read_text())
    assert "--organization" in info["argv"]
    idx = info["argv"].index("--organization")
    assert info["argv"][idx + 1] == "my-org"


# ------------------------------------------------------------------ #
# Happy path
# ------------------------------------------------------------------ #
def test_run_parses_json_stdout(fake_az: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FAKE_AZ_STDOUT", '{"items": [1, 2, 3]}')
    result = asyncio.run(_client(fake_az).run(["group", "list"]))
    assert result == {"items": [1, 2, 3]}


def test_run_empty_stdout_returns_none(fake_az: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FAKE_AZ_STDOUT", "")
    result = asyncio.run(_client(fake_az).run(["group", "list"]))
    assert result is None


def test_run_parse_json_false(fake_az: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FAKE_AZ_STDOUT", "irrelevant")
    result = asyncio.run(_client(fake_az).run(["extension", "add"], parse_json=False))
    assert result is None


# ------------------------------------------------------------------ #
# Error taxonomy
# ------------------------------------------------------------------ #
def test_run_nonzero_exit_auth_marker(fake_az: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FAKE_AZ_EXIT", "1")
    monkeypatch.setenv("FAKE_AZ_STDERR", "ERROR: AADSTS700082: token expired")
    with pytest.raises(AuthError):
        asyncio.run(_client(fake_az).run(["account", "show"]))


def test_run_nonzero_exit_throttle(fake_az: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FAKE_AZ_EXIT", "1")
    monkeypatch.setenv("FAKE_AZ_STDERR", "HTTP 429 Too Many Requests")
    with pytest.raises(Throttled):
        asyncio.run(_client(fake_az).run(["group", "list"]))


def test_run_nonzero_exit_not_found(fake_az: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FAKE_AZ_EXIT", "1")
    monkeypatch.setenv("FAKE_AZ_STDERR", "ERROR: Resource not found")
    with pytest.raises(ApiError, match="not found"):
        asyncio.run(_client(fake_az).run(["group", "show"]))


def test_run_nonzero_exit_generic(fake_az: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FAKE_AZ_EXIT", "2")
    monkeypatch.setenv("FAKE_AZ_STDERR", "something broke")
    with pytest.raises(ApiError) as exc:
        asyncio.run(_client(fake_az).run(["group", "list"]))
    assert exc.value.exit_code == 2


def test_run_non_json_stdout_raises_apierror(
    fake_az: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FAKE_AZ_STDOUT", "not json at all")
    with pytest.raises(ApiError):
        asyncio.run(_client(fake_az).run(["group", "list"]))


def test_run_timeout_raises_transient(fake_az: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FAKE_AZ_SLEEP", "5")
    with pytest.raises(Transient):
        asyncio.run(_client(fake_az).run(["group", "list"], timeout=0.3))


def test_run_missing_binary_raises_apierror(tmp_path: Path) -> None:
    client = AzSubprocessClient(
        scope=FakeScope(),
        audit=FakeAudit(),
        az_path=str(tmp_path / "does-not-exist-az"),
    )
    with pytest.raises(ApiError):
        asyncio.run(client.run(["account", "show"]))


# ------------------------------------------------------------------ #
# Audit
# ------------------------------------------------------------------ #
def test_run_audits_success(fake_az: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FAKE_AZ_STDOUT", '{"ok": true}')
    audit = FakeAudit()
    asyncio.run(
        _client(fake_az, audit=audit).run(
            ["group", "list"],
            scope_targets=["/sub/a"],
        )
    )
    assert len(audit.records) == 1
    action, target, result = audit.records[0]
    assert "group" in action
    assert "/sub/a" in target
    assert result == "ok"


def test_run_audits_error(fake_az: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FAKE_AZ_EXIT", "1")
    monkeypatch.setenv("FAKE_AZ_STDERR", "boom")
    audit = FakeAudit()
    with pytest.raises(ApiError):
        asyncio.run(_client(fake_az, audit=audit).run(["group", "list"]))
    assert audit.records and audit.records[0][2] == "error"


# ------------------------------------------------------------------ #
# AZURE_CORE_OUTPUT env
# ------------------------------------------------------------------ #
def test_run_sets_azure_core_output_env(
    fake_az: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cap = _capture(tmp_path, monkeypatch)
    monkeypatch.setenv("FAKE_AZ_STDOUT", '{"ok": true}')
    asyncio.run(_client(fake_az).run(["group", "list"]))
    info = json.loads(cap.read_text())
    assert info["env_output"] == "json"


# ------------------------------------------------------------------ #
# version() and account_show()
# ------------------------------------------------------------------ #
def test_version_returns_dict(fake_az: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(
        "FAKE_AZ_STDOUT",
        json.dumps({"azure-cli": "2.60.0", "azure-cli-core": "2.60.0"}),
    )
    result = asyncio.run(_client(fake_az).version())
    assert result["azure-cli"] == "2.60.0"


def test_version_empty_output_raises(fake_az: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FAKE_AZ_STDOUT", "")
    with pytest.raises(ApiError, match="empty"):
        asyncio.run(_client(fake_az).version())


def test_account_show_returns_dict(fake_az: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(
        "FAKE_AZ_STDOUT",
        json.dumps({"id": "sub-1", "tenantId": "t-1", "name": "My Sub"}),
    )
    result = asyncio.run(_client(fake_az).account_show())
    assert result["id"] == "sub-1"


def test_account_show_auth_failure_raises(fake_az: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FAKE_AZ_EXIT", "1")
    monkeypatch.setenv("FAKE_AZ_STDERR", "Please run 'az login'")
    with pytest.raises(AuthError):
        asyncio.run(_client(fake_az).account_show())


# ------------------------------------------------------------------ #
# _audit_shape (unit)
# ------------------------------------------------------------------ #
def test_audit_shape_keeps_positionals_and_flags() -> None:
    result = _audit_shape(["group", "list", "--output", "json", "--subscription", "sub-1"])
    assert result == "group list --output --subscription"


def test_audit_shape_handles_equals_syntax() -> None:
    result = _audit_shape(["group", "list", "--output=json"])
    assert result == "group list --output=…"


def test_audit_shape_drops_short_flags() -> None:
    result = _audit_shape(["group", "list", "-o", "json"])
    assert result == "group list -o"
