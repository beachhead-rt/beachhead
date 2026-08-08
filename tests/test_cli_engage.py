"""CLI engage commands — status, export, teardown via CliRunner."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from beachhead.cli import app

runner = CliRunner(env={"COLUMNS": "200"})

_TEST_KEY = "test-key"


def _args(env, *rest):
    return ["--store", env.store_path, "--config", env.config_path, *rest]


# --- engage status ---


def test_engage_status_table(engagement_env):
    result = runner.invoke(app, _args(engagement_env, "engage", "status"))
    assert result.exit_code == 0
    assert "ACME-2026-Q2" in result.stdout


def test_engage_status_json(engagement_env):
    result = runner.invoke(app, _args(engagement_env, "engage", "status", "--json"))
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["command"] == "engage_status"
    row = payload["rows"][0]
    assert row["engagement"] == "ACME-2026-Q2"


# --- engage export ---


def test_engage_export_json(engagement_env, tmp_path):
    out = str(tmp_path / "report.json")
    result = runner.invoke(app, _args(engagement_env, "engage", "export", "-o", out))
    assert result.exit_code == 0
    assert "Report exported" in result.stdout

    data = json.loads(Path(out).read_text())
    assert data["engagement"]["name"] == "ACME-2026-Q2"
    assert "metadata" in data
    assert data["metadata"]["engagement"] == "ACME-2026-Q2"


def test_engage_export_markdown(engagement_env, tmp_path):
    out = str(tmp_path / "report.md")
    result = runner.invoke(app, _args(engagement_env, "engage", "export", "-o", out))
    assert result.exit_code == 0
    content = Path(out).read_text()
    assert "# Engagement Report" in content


def test_engage_export_explicit_format(engagement_env, tmp_path):
    out = str(tmp_path / "report.txt")
    result = runner.invoke(app, _args(engagement_env, "engage", "export", "-o", out, "-f", "json"))
    assert result.exit_code == 0
    data = json.loads(Path(out).read_text())
    assert data["engagement"] is not None


def test_engage_export_unknown_format(engagement_env, tmp_path):
    out = str(tmp_path / "report.txt")
    result = runner.invoke(app, _args(engagement_env, "engage", "export", "-o", out))
    assert result.exit_code == 1
    assert "Cannot detect format" in result.stdout


# --- engage export --include-secrets ---


def test_export_include_secrets_requires_confirm(engagement_env, tmp_path):
    out = str(tmp_path / "report.json")
    result = runner.invoke(
        app, _args(engagement_env, "engage", "export", "-o", out, "--include-secrets"),
    )
    assert result.exit_code == 1
    assert "--confirm" in result.stdout


def test_export_include_secrets_with_confirm(engagement_env, tmp_path, monkeypatch):
    monkeypatch.setenv("BH_SECRETS_KEY", _TEST_KEY)
    from beachhead.core.secret_store import open_secret_store, secret_store_path

    sec_path = secret_store_path(engagement_env.store_path)
    ss = open_secret_store(sec_path, _TEST_KEY)
    ss.store_credential(kind="pat", reference="ref", run_id="r", value="s3cret")
    ss.close()

    out = str(tmp_path / "report.json")
    result = runner.invoke(
        app,
        _args(
            engagement_env, "engage", "export", "-o", out,
            "--include-secrets", "--confirm",
        ),
    )
    assert result.exit_code == 0
    assert "1 credentials" in result.stdout

    data = json.loads(Path(out).read_text())
    assert len(data["credentials"]) == 1
    assert data["credentials"][0]["value"] == "s3cret"


def test_export_include_secrets_no_secret_store(engagement_env, tmp_path, monkeypatch):
    monkeypatch.setenv("BH_SECRETS_KEY", _TEST_KEY)
    out = str(tmp_path / "report.json")
    result = runner.invoke(
        app,
        _args(
            engagement_env, "engage", "export", "-o", out,
            "--include-secrets", "--confirm",
        ),
    )
    assert result.exit_code == 0
    assert "No secret store found" in result.stdout
    data = json.loads(Path(out).read_text())
    assert "credentials" not in data


def test_export_include_secrets_markdown(engagement_env, tmp_path, monkeypatch):
    monkeypatch.setenv("BH_SECRETS_KEY", _TEST_KEY)
    from beachhead.core.secret_store import open_secret_store, secret_store_path

    sec_path = secret_store_path(engagement_env.store_path)
    ss = open_secret_store(sec_path, _TEST_KEY)
    ss.store_credential(kind="aws_key", reference="file.py", run_id="r", value="AKIATEST")
    ss.close()

    out = str(tmp_path / "report.md")
    result = runner.invoke(
        app,
        _args(
            engagement_env, "engage", "export", "-o", out,
            "--include-secrets", "--confirm",
        ),
    )
    assert result.exit_code == 0
    content = Path(out).read_text()
    assert "## Credentials" in content
    assert "AKIATEST" in content


def test_export_without_secrets_flag_omits_credentials(engagement_env, tmp_path, monkeypatch):
    monkeypatch.setenv("BH_SECRETS_KEY", _TEST_KEY)
    from beachhead.core.secret_store import open_secret_store, secret_store_path

    sec_path = secret_store_path(engagement_env.store_path)
    ss = open_secret_store(sec_path, _TEST_KEY)
    ss.store_credential(kind="pat", reference="ref", run_id="r", value="s3cret")
    ss.close()

    out = str(tmp_path / "report.json")
    result = runner.invoke(
        app, _args(engagement_env, "engage", "export", "-o", out),
    )
    assert result.exit_code == 0
    data = json.loads(Path(out).read_text())
    assert "credentials" not in data


# --- engage teardown ---


def test_teardown_without_confirm(engagement_env):
    result = runner.invoke(app, _args(engagement_env, "engage", "teardown"))
    assert result.exit_code == 1
    assert "--confirm" in result.stdout
    assert Path(engagement_env.store_path).exists()


def test_teardown_removes_store(engagement_env):
    store = Path(engagement_env.store_path)
    assert store.exists()

    result = runner.invoke(app, _args(engagement_env, "engage", "teardown", "--confirm"))
    assert result.exit_code == 0
    assert "Teardown complete" in result.stdout
    assert "store" in result.stdout
    assert not store.exists()


def test_teardown_removes_secrets_store(engagement_env):
    from beachhead.core.secret_store import open_secret_store, secret_store_path

    sec_path = secret_store_path(engagement_env.store_path)
    ss = open_secret_store(sec_path, _TEST_KEY)
    ss.store_credential(kind="pat", reference="ref", run_id="r", value="s3cret")
    ss.close()
    assert Path(sec_path).exists()

    result = runner.invoke(app, _args(engagement_env, "engage", "teardown", "--confirm"))
    assert result.exit_code == 0
    assert not Path(sec_path).exists()


def test_teardown_removes_config(engagement_env):
    config = Path(engagement_env.config_path)
    assert config.exists()

    result = runner.invoke(app, _args(engagement_env, "engage", "teardown", "--confirm"))
    assert result.exit_code == 0
    assert "engagement config" in result.stdout
    assert not config.exists()


def test_teardown_removes_token_cache(engagement_env, tmp_path):
    token_file = tmp_path / "tokens.json"
    token_file.write_text("{}")

    with patch(
        "beachhead.core.auth.token_cache.default_cache_path", return_value=token_file,
    ):
        result = runner.invoke(app, _args(engagement_env, "engage", "teardown", "--confirm"))

    assert result.exit_code == 0
    assert "token cache" in result.stdout
    assert not token_file.exists()


def test_teardown_nothing_to_remove(tmp_path):
    store_path = str(tmp_path / "nonexistent.sqlite")
    config_path = str(tmp_path / "nonexistent.yaml")
    result = runner.invoke(
        app, ["--store", store_path, "--config", config_path, "engage", "teardown", "--confirm"],
    )
    assert result.exit_code == 0
    assert "Nothing to tear down" in result.stdout
