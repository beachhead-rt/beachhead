"""CLI dispatch tests — listing and running modules via ``bh <phase>``."""

from __future__ import annotations

from typing import Any

import yaml
from conftest import FakeClock, FakeIds
from typer.testing import CliRunner

from beachhead.cli import app
from beachhead.core.store.engine import open_store

runner = CliRunner(env={"COLUMNS": "200", "BH_SECRETS_KEY": "test-key"})


def _write_config(path: Any, **overrides: object) -> str:
    base = {
        "engagement": "ACME-DISPATCH",
        "authorization_ref": "SOW-1",
        "window": {"start": "2026-01-01T00:00:00Z", "end": "2030-01-01T00:00:00Z"},
        "subscriptions": ["11111111-1111-1111-1111-111111111111"],
        "allow_write": False,
    }
    base.update(overrides)
    p = path / "engagement.local.yaml"
    p.write_text(yaml.safe_dump(base))
    return str(p)


def test_enumerate_list() -> None:
    result = runner.invoke(app, ["enumerate", "list"])
    assert result.exit_code == 0
    assert "enumerate.ado_pipelines" in result.stdout
    assert "enumerate.ado_service_connections" in result.stdout
    assert "enumerate.ado_agent_pools" in result.stdout
    assert "enumerate.ado_variable_groups" in result.stdout


def test_analyze_list() -> None:
    result = runner.invoke(app, ["analyze", "list"])
    assert result.exit_code == 0
    assert "analyze.ado_attack_paths" in result.stdout


def test_enumerate_list_filter_ado() -> None:
    result = runner.invoke(app, ["enumerate", "list", "ado"])
    assert result.exit_code == 0
    assert "ado_pipelines" in result.stdout
    assert "ado_repos" in result.stdout


def test_analyze_list_filter_attack() -> None:
    result = runner.invoke(app, ["analyze", "list", "attack"])
    assert result.exit_code == 0
    assert "attack_paths" in result.stdout


def test_list_filter_no_match() -> None:
    result = runner.invoke(app, ["enumerate", "list", "zzzznothing"])
    assert result.exit_code == 0
    assert "No enumerate modules matching" in result.stdout


def test_list_filter_by_technique_id() -> None:
    result = runner.invoke(app, ["harvest", "list", "T1552"])
    assert result.exit_code == 0
    assert "ado_credential_scan" in result.stdout


def test_run_unknown_module(tmp_path: Any) -> None:
    result = runner.invoke(
        app,
        [
            "--store",
            str(tmp_path / "unused.db"),
            "--config",
            str(tmp_path / "unused.yaml"),
            "enumerate",
            "run",
            "enumerate.nonexistent",
        ],
    )
    assert result.exit_code == 1
    assert "unknown module" in result.stdout


def test_run_short_name_resolves(tmp_path: Any) -> None:
    """Short name (without phase prefix) resolves within the phase context."""
    config_path = _write_config(tmp_path)
    store_path = str(tmp_path / "test.db")

    st = open_store(store_path, clock=FakeClock(), id_factory=FakeIds())
    st.ensure_engagement(name="ACME-DISPATCH", scope_hash="unused")
    st.close()

    result = runner.invoke(
        app,
        [
            "--store",
            store_path,
            "--config",
            config_path,
            "analyze",
            "run",
            "ado_attack_paths",
        ],
    )
    assert result.exit_code == 0
    assert "Running ado_attack_paths" in result.stdout
    assert "Done" in result.stdout


def test_run_all_analyze_e2e(tmp_path: Any) -> None:
    """Run all analyze modules via run-all."""
    config_path = _write_config(tmp_path)
    store_path = str(tmp_path / "test.db")

    st = open_store(store_path, clock=FakeClock(), id_factory=FakeIds())
    st.ensure_engagement(name="ACME-DISPATCH", scope_hash="unused")
    st.close()

    result = runner.invoke(
        app,
        [
            "--store",
            store_path,
            "--config",
            config_path,
            "analyze",
            "run-all",
        ],
    )
    assert result.exit_code == 0
    assert "Running all" in result.stdout
    assert "Done:" in result.stdout
    assert "passed" in result.stdout


def test_run_analyze_module_e2e(tmp_path: Any) -> None:
    """Run analyze.ado_attack_paths end-to-end through the CLI dispatch."""
    config_path = _write_config(tmp_path)
    store_path = str(tmp_path / "test.db")

    st = open_store(store_path, clock=FakeClock(), id_factory=FakeIds())
    st.ensure_engagement(name="ACME-DISPATCH", scope_hash="unused")
    st.close()

    result = runner.invoke(
        app,
        [
            "--store",
            store_path,
            "--config",
            config_path,
            "analyze",
            "run",
            "analyze.ado_attack_paths",
        ],
    )
    assert result.exit_code == 0
    assert "Done" in result.stdout
