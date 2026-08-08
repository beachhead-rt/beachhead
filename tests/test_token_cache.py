"""Tests for core/auth/token_cache.py — file-based token persistence."""

from __future__ import annotations

import json
import os
import sys
import time

import pytest

from beachhead.core.auth.token_cache import load_tokens, save_tokens
from beachhead.core.auth.token_entry import TokenEntry


def _make_entry(audience: str = "graph", **overrides: object) -> TokenEntry:
    defaults = {
        "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9."
        "eyJhdWQiOiJodHRwczovL2dyYXBoLm1pY3Jvc29mdC5jb20iLCJleHAiOjk5OTk5OTk5OTl9."
        "sig",
        "audience": audience,
        "expires_at": time.time() + 3600,
        "source": "test",
    }
    defaults.update(overrides)
    if audience == "arm":
        defaults["access_token"] = (
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9."
            "eyJhdWQiOiJodHRwczovL21hbmFnZW1lbnQuYXp1cmUuY29tIiwiZXhwIjo5OTk5OTk5OTk5fQ."
            "sig"
        )
    return TokenEntry(**defaults)  # type: ignore[arg-type]


def test_save_and_load_roundtrip(tmp_path):
    path = tmp_path / "tokens.json"
    entries = {"graph": _make_entry("graph")}
    save_tokens(entries, path)
    loaded = load_tokens(path)

    assert "graph" in loaded
    assert loaded["graph"].audience == "graph"
    assert loaded["graph"].source == "test"


def test_save_creates_parent_dirs(tmp_path):
    path = tmp_path / "nested" / "dir" / "tokens.json"
    save_tokens({"graph": _make_entry()}, path)
    assert path.exists()


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions not enforced on Windows")
def test_save_sets_0600_permissions(tmp_path):
    path = tmp_path / "tokens.json"
    save_tokens({"graph": _make_entry()}, path)
    mode = path.stat().st_mode & 0o777
    assert mode == 0o600


def test_load_missing_file_returns_empty(tmp_path):
    result = load_tokens(tmp_path / "nonexistent.json")
    assert result == {}


def test_load_malformed_json_raises(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("not json")
    with pytest.raises(json.JSONDecodeError):
        load_tokens(path)


def test_load_non_object_raises(tmp_path):
    path = tmp_path / "array.json"
    path.write_text("[]")
    with pytest.raises(ValueError, match="not a JSON object"):
        load_tokens(path)


def test_multiple_audiences(tmp_path):
    path = tmp_path / "tokens.json"
    entries = {
        "graph": _make_entry("graph"),
        "arm": _make_entry("arm"),
    }
    save_tokens(entries, path)
    loaded = load_tokens(path)
    assert set(loaded) == {"graph", "arm"}


def test_save_overwrites_existing(tmp_path):
    path = tmp_path / "tokens.json"
    save_tokens({"graph": _make_entry("graph")}, path)
    save_tokens({"arm": _make_entry("arm")}, path)
    loaded = load_tokens(path)
    assert "arm" in loaded
    assert "graph" not in loaded


def test_preserves_refresh_material(tmp_path):
    path = tmp_path / "tokens.json"
    entry = _make_entry(
        refresh_token="rt-123",
        client_id="client-id",
        tenant_id="tenant-id",
        scopes=("scope1", "scope2"),
    )
    save_tokens({"graph": entry}, path)
    loaded = load_tokens(path)
    assert loaded["graph"].refresh_token == "rt-123"
    assert loaded["graph"].client_id == "client-id"
    assert loaded["graph"].tenant_id == "tenant-id"
    assert loaded["graph"].scopes == ("scope1", "scope2")


def test_skips_unknown_audiences(tmp_path):
    path = tmp_path / "tokens.json"
    data = {
        "graph": {
            "access_token": _make_entry().access_token,
            "audience": "graph",
            "expires_at": time.time() + 3600,
            "source": "test",
        },
        "unknown_thing": {"access_token": "x", "audience": "unknown_thing"},
    }
    path.write_text(json.dumps(data))
    loaded = load_tokens(path)
    assert "graph" in loaded
    assert "unknown_thing" not in loaded


def test_ado_roundtrip(tmp_path):
    path = tmp_path / "tokens.json"
    entry = TokenEntry(
        access_token="my-ado-pat-value",
        audience="ado",
        expires_at=time.time() + 3600,
        source="ado_pat",
    )
    save_tokens({"ado": entry}, path)
    loaded = load_tokens(path)
    assert "ado" in loaded
    assert loaded["ado"].audience == "ado"
    assert loaded["ado"].access_token == "my-ado-pat-value"
    assert loaded["ado"].source == "ado_pat"
    assert loaded["ado"].refreshable is False


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions not enforced on Windows")
def test_loose_permissions_warns(tmp_path):
    path = tmp_path / "tokens.json"
    save_tokens({"graph": _make_entry()}, path)
    os.chmod(str(path), 0o644)
    with pytest.warns(match="loose permissions"):
        load_tokens(path)
