"""Tests for the shared subprocess utilities (core/clients/_subprocess.py).

Exercises ``classify_stderr``, ``parse_json_output``, and ``spawn_subprocess``.
Coroutines are driven via ``asyncio.run`` — no pytest-asyncio needed.
``spawn_subprocess`` tests use a small fake Python script controlled via env vars.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

import pytest

from beachhead.core.clients._subprocess import (
    classify_stderr,
    parse_json_output,
    spawn_subprocess,
)
from beachhead.core.errors import ApiError, AuthError, Throttled, Transient

# ---------------------------------------------------------------------------
# Fake subprocess script — controlled via FAKE_* env vars
# ---------------------------------------------------------------------------
_FAKE_SCRIPT = """\
import sys, os, json, time
stdin_data = ""
if not os.environ.get("FAKE_NO_STDIN"):
    stdin_data = sys.stdin.read()
naptime = os.environ.get("FAKE_SLEEP")
if naptime:
    time.sleep(float(naptime))
out = os.environ.get("FAKE_STDOUT")
if out is None:
    out = json.dumps({"stdin": stdin_data, "args": sys.argv[1:]})
sys.stdout.write(out)
sys.stderr.write(os.environ.get("FAKE_STDERR", ""))
sys.exit(int(os.environ.get("FAKE_EXIT", "0")))
"""


@pytest.fixture
def fake_exe(tmp_path: Path) -> str:
    script = tmp_path / "fake_sub.py"
    script.write_text(_FAKE_SCRIPT, encoding="utf-8")
    return str(script)


def _env(**overrides: str) -> dict[str, str]:
    env = os.environ.copy()
    env.update(overrides)
    env.pop("FAKE_STDOUT", None)
    env.pop("FAKE_STDERR", None)
    env.pop("FAKE_EXIT", None)
    env.pop("FAKE_SLEEP", None)
    env.pop("FAKE_NO_STDIN", None)
    for k, v in overrides.items():
        env[k] = v
    return env


# ========================================================================= #
# classify_stderr
# ========================================================================= #
_AUTH = ("unauthorized", "401")
_THROTTLE = ("429", "too many requests")
_NOT_FOUND = ("not found", "does not exist")


class TestClassifyStderr:
    def test_auth_marker_returns_autherror(self) -> None:
        exc = classify_stderr(
            1,
            "ERROR: Unauthorized access",
            auth_markers=_AUTH,
            throttle_markers=_THROTTLE,
            tool_label="test",
        )
        assert isinstance(exc, AuthError)
        assert "auth failure" in str(exc)

    def test_throttle_marker_returns_throttled(self) -> None:
        exc = classify_stderr(
            1,
            "HTTP 429 Too Many Requests",
            auth_markers=_AUTH,
            throttle_markers=_THROTTLE,
            tool_label="test",
        )
        assert isinstance(exc, Throttled)
        assert "throttling" in str(exc)

    def test_not_found_marker_returns_apierror(self) -> None:
        exc = classify_stderr(
            1,
            "Resource not found in subscription",
            auth_markers=_AUTH,
            throttle_markers=_THROTTLE,
            not_found_markers=_NOT_FOUND,
            tool_label="az",
        )
        assert isinstance(exc, ApiError)
        assert "not found" in str(exc)

    def test_no_match_returns_generic_apierror(self) -> None:
        exc = classify_stderr(
            2,
            "something went wrong",
            auth_markers=_AUTH,
            throttle_markers=_THROTTLE,
            tool_label="test",
        )
        assert isinstance(exc, ApiError)
        assert "exited 2" in str(exc)

    def test_case_insensitive(self) -> None:
        exc = classify_stderr(
            1,
            "UNAUTHORIZED ACCESS DENIED",
            auth_markers=_AUTH,
            throttle_markers=_THROTTLE,
            tool_label="test",
        )
        assert isinstance(exc, AuthError)

    def test_tool_label_in_message(self) -> None:
        exc = classify_stderr(
            1,
            "boom",
            auth_markers=(),
            throttle_markers=(),
            tool_label="mytool",
        )
        assert "mytool" in str(exc)

    def test_auth_takes_priority_over_throttle(self) -> None:
        exc = classify_stderr(
            1,
            "unauthorized 429",
            auth_markers=_AUTH,
            throttle_markers=_THROTTLE,
            tool_label="test",
        )
        assert isinstance(exc, AuthError)

    def test_empty_not_found_markers_skipped(self) -> None:
        exc = classify_stderr(
            1,
            "Resource not found",
            auth_markers=_AUTH,
            throttle_markers=_THROTTLE,
            not_found_markers=(),
            tool_label="test",
        )
        assert isinstance(exc, ApiError)
        assert "not found" not in str(exc).lower().split("exited")[0]

    def test_exit_code_on_apierror(self) -> None:
        exc = classify_stderr(
            42,
            "oops",
            auth_markers=(),
            throttle_markers=(),
            tool_label="t",
        )
        assert isinstance(exc, ApiError)
        assert exc.exit_code == 42  # type: ignore[attr-defined]

    def test_stderr_truncated_to_500(self) -> None:
        long_err = "x" * 1000
        exc = classify_stderr(
            1,
            long_err,
            auth_markers=(),
            throttle_markers=(),
            tool_label="t",
        )
        assert len(str(exc)) < 600


# ========================================================================= #
# parse_json_output
# ========================================================================= #
class TestParseJsonOutput:
    def test_valid_json_dict(self) -> None:
        result = parse_json_output('{"key": "value"}')
        assert result == {"key": "value"}

    def test_valid_json_list(self) -> None:
        result = parse_json_output("[1, 2, 3]")
        assert result == [1, 2, 3]

    def test_empty_no_fallback_returns_none(self) -> None:
        assert parse_json_output("") is None
        assert parse_json_output("   \n  ") is None

    def test_empty_with_fallback_raises(self) -> None:
        with pytest.raises(ValueError, match="empty stdout"):
            parse_json_output("", fallback_last_line=True)

    def test_whitespace_only_with_fallback_raises(self) -> None:
        with pytest.raises(ValueError, match="empty stdout"):
            parse_json_output("   \n  ", fallback_last_line=True)

    def test_invalid_json_no_fallback_raises(self) -> None:
        with pytest.raises(ValueError, match="non-JSON"):
            parse_json_output("not json at all")

    def test_invalid_json_with_fallback_raises(self) -> None:
        with pytest.raises(ValueError, match="no JSON found"):
            parse_json_output("not json at all", fallback_last_line=True)

    def test_last_line_fallback_success(self) -> None:
        stdout = 'WARNING: something\n{"ok": true}'
        result = parse_json_output(stdout, fallback_last_line=True)
        assert result == {"ok": True}

    def test_multiline_json_without_fallback(self) -> None:
        stdout = '{\n  "key": "value"\n}'
        result = parse_json_output(stdout)
        assert result == {"key": "value"}

    def test_json_with_surrounding_whitespace(self) -> None:
        result = parse_json_output('  \n {"a": 1} \n ')
        assert result == {"a": 1}


# ========================================================================= #
# spawn_subprocess
# ========================================================================= #
class TestSpawnSubprocess:
    def test_success_returns_exit_stdout_stderr(self, fake_exe: str) -> None:
        sem = asyncio.Semaphore(1)
        env = _env(FAKE_NO_STDIN="1")
        exit_code, stdout, stderr = asyncio.run(
            spawn_subprocess(
                sys.executable,
                [fake_exe, "hello"],
                stdin_data=None,
                env=env,
                timeout=10.0,
                sem=sem,
                tool_label="test",
            )
        )
        assert exit_code == 0
        parsed = json.loads(stdout)
        assert "hello" in parsed["args"]
        assert stderr == ""

    def test_stdin_data_delivered(self, fake_exe: str) -> None:
        sem = asyncio.Semaphore(1)
        env = _env()
        exit_code, stdout, stderr = asyncio.run(
            spawn_subprocess(
                sys.executable,
                [fake_exe],
                stdin_data=b"secret-token",
                env=env,
                timeout=10.0,
                sem=sem,
                tool_label="test",
            )
        )
        assert exit_code == 0
        parsed = json.loads(stdout)
        assert parsed["stdin"] == "secret-token"

    def test_devnull_stdin(self, fake_exe: str) -> None:
        sem = asyncio.Semaphore(1)
        env = _env(FAKE_NO_STDIN="1")
        exit_code, stdout, _ = asyncio.run(
            spawn_subprocess(
                sys.executable,
                [fake_exe],
                stdin_data=None,
                env=env,
                timeout=10.0,
                sem=sem,
                tool_label="test",
            )
        )
        assert exit_code == 0
        parsed = json.loads(stdout)
        assert parsed["stdin"] == ""

    def test_nonzero_exit(self, fake_exe: str) -> None:
        sem = asyncio.Semaphore(1)
        env = _env(FAKE_EXIT="7", FAKE_NO_STDIN="1")
        exit_code, _, _ = asyncio.run(
            spawn_subprocess(
                sys.executable,
                [fake_exe],
                stdin_data=None,
                env=env,
                timeout=10.0,
                sem=sem,
                tool_label="test",
            )
        )
        assert exit_code == 7

    def test_stderr_captured(self, fake_exe: str) -> None:
        sem = asyncio.Semaphore(1)
        env = _env(FAKE_STDERR="warning!", FAKE_NO_STDIN="1")
        _, _, stderr = asyncio.run(
            spawn_subprocess(
                sys.executable,
                [fake_exe],
                stdin_data=None,
                env=env,
                timeout=10.0,
                sem=sem,
                tool_label="test",
            )
        )
        assert stderr == "warning!"

    def test_custom_stdout(self, fake_exe: str) -> None:
        sem = asyncio.Semaphore(1)
        env = _env(FAKE_STDOUT='{"custom": true}', FAKE_NO_STDIN="1")
        _, stdout, _ = asyncio.run(
            spawn_subprocess(
                sys.executable,
                [fake_exe],
                stdin_data=None,
                env=env,
                timeout=10.0,
                sem=sem,
                tool_label="test",
            )
        )
        assert json.loads(stdout) == {"custom": True}

    def test_timeout_raises_transient(self, fake_exe: str) -> None:
        sem = asyncio.Semaphore(1)
        env = _env(FAKE_SLEEP="10", FAKE_NO_STDIN="1")
        with pytest.raises(Transient, match="timed out"):
            asyncio.run(
                spawn_subprocess(
                    sys.executable,
                    [fake_exe],
                    stdin_data=None,
                    env=env,
                    timeout=0.3,
                    sem=sem,
                    tool_label="test",
                )
            )

    def test_missing_binary_raises_apierror(self) -> None:
        sem = asyncio.Semaphore(1)
        with pytest.raises(ApiError, match="could not spawn"):
            asyncio.run(
                spawn_subprocess(
                    "/no/such/binary",
                    [],
                    stdin_data=None,
                    env=os.environ.copy(),
                    timeout=5.0,
                    sem=sem,
                    tool_label="ghost",
                )
            )

    def test_tool_label_in_timeout_error(self, fake_exe: str) -> None:
        sem = asyncio.Semaphore(1)
        env = _env(FAKE_SLEEP="10", FAKE_NO_STDIN="1")
        with pytest.raises(Transient, match="mytool"):
            asyncio.run(
                spawn_subprocess(
                    sys.executable,
                    [fake_exe],
                    stdin_data=None,
                    env=env,
                    timeout=0.3,
                    sem=sem,
                    tool_label="mytool",
                )
            )

    def test_tool_label_in_spawn_error(self) -> None:
        sem = asyncio.Semaphore(1)
        with pytest.raises(ApiError, match="ghost"):
            asyncio.run(
                spawn_subprocess(
                    "/no/such/binary",
                    [],
                    stdin_data=None,
                    env=os.environ.copy(),
                    timeout=5.0,
                    sem=sem,
                    tool_label="ghost",
                )
            )

    def test_semaphore_limits_concurrency(self, fake_exe: str) -> None:
        sem = asyncio.Semaphore(1)
        env = _env(FAKE_SLEEP="0.15", FAKE_NO_STDIN="1")

        async def _run_two() -> list[int]:
            t1 = spawn_subprocess(
                sys.executable,
                [fake_exe],
                stdin_data=None,
                env=env,
                timeout=5.0,
                sem=sem,
                tool_label="test",
            )
            t2 = spawn_subprocess(
                sys.executable,
                [fake_exe],
                stdin_data=None,
                env=env,
                timeout=5.0,
                sem=sem,
                tool_label="test",
            )
            results = await asyncio.gather(t1, t2)
            return [r[0] for r in results]

        codes = asyncio.run(_run_two())
        assert codes == [0, 0]
