"""Tests for ``bh auth`` CLI commands."""

from __future__ import annotations

import json
import time

from typer.testing import CliRunner

from beachhead.cli import app

runner = CliRunner(env={"COLUMNS": "200"})


def test_auth_help_lists_commands() -> None:
    result = runner.invoke(app, ["auth", "--help"])
    assert result.exit_code == 0
    assert "ado-pat" in result.stdout
    assert "status" in result.stdout
    assert "clear" in result.stdout
    assert "device-code" not in result.stdout
    assert "az-context" not in result.stdout


def test_auth_status_help() -> None:
    result = runner.invoke(app, ["auth", "status", "--help"])
    assert result.exit_code == 0
    assert "cached" in result.stdout.lower()


def test_auth_status_no_cache(tmp_path, monkeypatch) -> None:
    cache = tmp_path / "tokens.json"
    monkeypatch.setenv("BEACHHEAD_TOKEN_CACHE", str(cache))
    result = runner.invoke(app, ["auth", "status"])
    assert result.exit_code == 0
    assert "No tokens cached" in result.stdout


def test_auth_status_shows_valid(tmp_path, monkeypatch) -> None:
    cache = tmp_path / "tokens.json"
    data = {
        "ado": {
            "access_token": "some-pat-value",
            "audience": "ado",
            "expires_at": time.time() + 3600,
            "source": "ado_pat",
        }
    }
    cache.write_text(json.dumps(data))
    monkeypatch.setenv("BEACHHEAD_TOKEN_CACHE", str(cache))
    monkeypatch.setattr(
        "beachhead.core.auth.ado_pat._resolve_pat_identity",
        lambda _pat: "Test User",
    )
    result = runner.invoke(app, ["auth", "status"])
    assert result.exit_code == 0
    assert "ado" in result.stdout
    assert "valid" in result.stdout
    assert "Test User" in result.stdout


def test_auth_status_shows_invalid(tmp_path, monkeypatch) -> None:
    cache = tmp_path / "tokens.json"
    data = {
        "ado": {
            "access_token": "bad-pat",
            "audience": "ado",
            "expires_at": time.time() + 3600,
            "source": "ado_pat",
        }
    }
    cache.write_text(json.dumps(data))
    monkeypatch.setenv("BEACHHEAD_TOKEN_CACHE", str(cache))
    monkeypatch.setattr(
        "beachhead.core.auth.ado_pat._resolve_pat_identity",
        lambda _pat: None,
    )
    result = runner.invoke(app, ["auth", "status"])
    assert result.exit_code == 0
    assert "ado" in result.stdout
    assert "invalid" in result.stdout


def test_auth_clear_all(tmp_path, monkeypatch) -> None:
    cache = tmp_path / "tokens.json"
    data = {
        "ado": {
            "access_token": "some-pat-value",
            "audience": "ado",
            "expires_at": time.time() + 3600,
            "source": "ado_pat",
        }
    }
    cache.write_text(json.dumps(data))
    monkeypatch.setenv("BEACHHEAD_TOKEN_CACHE", str(cache))
    result = runner.invoke(app, ["auth", "clear"])
    assert result.exit_code == 0
    assert "removed" in result.stdout
    assert not cache.exists()


def test_auth_clear_single_audience(tmp_path, monkeypatch) -> None:
    cache = tmp_path / "tokens.json"
    data = {
        "ado": {
            "access_token": "some-pat-value",
            "audience": "ado",
            "expires_at": time.time() + 3600,
            "source": "ado_pat",
        }
    }
    cache.write_text(json.dumps(data))
    monkeypatch.setenv("BEACHHEAD_TOKEN_CACHE", str(cache))
    result = runner.invoke(app, ["auth", "clear", "ado"])
    assert result.exit_code == 0
    assert "Cleared ado" in result.stdout


def test_auth_clear_no_cache(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("BEACHHEAD_TOKEN_CACHE", str(tmp_path / "nope.json"))
    result = runner.invoke(app, ["auth", "clear"])
    assert result.exit_code == 0
    assert "No token cache" in result.stdout


def test_auth_clear_invalid_audience() -> None:
    result = runner.invoke(app, ["auth", "clear", "bogus"])
    assert result.exit_code == 1
    assert "Invalid audience" in result.stdout


def test_auth_ado_pat_stores_token(tmp_path, monkeypatch) -> None:
    cache = tmp_path / "tokens.json"
    monkeypatch.setenv("BEACHHEAD_TOKEN_CACHE", str(cache))
    monkeypatch.setattr(
        "beachhead.core.auth.ado_pat._resolve_pat_identity",
        lambda _pat: "Test User",
    )
    result = runner.invoke(app, ["auth", "ado-pat"], input="my-secret-pat\n")
    assert result.exit_code == 0
    assert "ADO PAT stored" in result.stdout
    assert "Test User" in result.stdout
    loaded = json.loads(cache.read_text())
    assert "ado" in loaded
    assert loaded["ado"]["access_token"] == "my-secret-pat"
    assert loaded["ado"]["display_name"] == "Test User"


def test_auth_ado_pat_invalid_rejected(tmp_path, monkeypatch) -> None:
    cache = tmp_path / "tokens.json"
    monkeypatch.setenv("BEACHHEAD_TOKEN_CACHE", str(cache))
    monkeypatch.setattr(
        "beachhead.core.auth.ado_pat._resolve_pat_identity",
        lambda _pat: None,
    )
    result = runner.invoke(app, ["auth", "ado-pat"], input="bad-pat\n")
    assert result.exit_code == 1
    assert "invalid" in result.stdout
    assert not cache.exists()


def test_auth_ado_pat_empty_input(tmp_path, monkeypatch) -> None:
    cache = tmp_path / "tokens.json"
    monkeypatch.setenv("BEACHHEAD_TOKEN_CACHE", str(cache))
    result = runner.invoke(app, ["auth", "ado-pat"], input="\n")
    assert result.exit_code == 1
    assert "Empty input" in result.stdout


def test_auth_ado_pat_help() -> None:
    result = runner.invoke(app, ["auth", "ado-pat", "--help"])
    assert result.exit_code == 0
    assert "ADO" in result.stdout
