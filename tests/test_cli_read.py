"""CLI read commands over a seeded store via Typer's CliRunner."""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from beachhead.cli import app

runner = CliRunner(env={"COLUMNS": "200"})


@pytest.fixture
def env_missing_config(engagement_env, tmp_path):
    return engagement_env.store_path, str(tmp_path / "absent.yaml")


def _args(env, *rest):
    return ["--store", env.store_path, "--config", env.config_path, *rest]


def test_version():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "beachhead" in result.stdout


def test_missing_config_refuses(env_missing_config):
    store_path, config_path = env_missing_config
    result = runner.invoke(app, ["--store", store_path, "--config", config_path, "status"])
    assert result.exit_code == 2


def test_missing_store_auto_created(engagement_env, tmp_path):
    """When the store doesn't exist, open_surface creates it so the CLI can run."""
    absent_store = str(tmp_path / "nope.sqlite")
    result = runner.invoke(
        app, ["--store", absent_store, "--config", engagement_env.config_path, "status"]
    )
    assert result.exit_code == 0


def test_status_table(engagement_env):
    result = runner.invoke(app, _args(engagement_env, "status"))
    assert result.exit_code == 0
    assert "ACME-2026-Q2" in result.stdout
    assert "ADO orgs" in result.stdout


def test_status_json(engagement_env):
    result = runner.invoke(app, _args(engagement_env, "status", "--json"))
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["command"] == "status"
    row = payload["rows"][0]
    assert row["engagement"] == "ACME-2026-Q2"
    assert row["runs"] == 3
    assert row["attack_paths"] == 0


def test_audit_json(engagement_env):
    result = runner.invoke(app, _args(engagement_env, "audit", "--json"))
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["command"] == "audit"
    assert any(r["action"] == "az.devops" for r in payload["rows"])


def test_audit_filter_by_run(engagement_env):
    all_audit = json.loads(
        runner.invoke(app, _args(engagement_env, "audit", "--json")).stdout
    )
    run_id = next(r["run_id"] for r in all_audit["rows"] if r["run_id"])
    result = runner.invoke(app, _args(engagement_env, "audit", "--run", run_id, "--json"))
    rows = json.loads(result.stdout)["rows"]
    assert len(rows) >= 1
    assert all(r["run_id"] == run_id for r in rows)


def test_paths_json_empty(engagement_env):
    result = runner.invoke(app, _args(engagement_env, "paths", "--json"))
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["command"] == "attack_paths"


def test_paths_table_empty(engagement_env):
    result = runner.invoke(app, _args(engagement_env, "paths"))
    assert result.exit_code == 0
    assert "No attack paths" in result.stdout


def test_findings_json_empty(engagement_env):
    result = runner.invoke(app, _args(engagement_env, "findings", "--json"))
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["command"] == "findings"
    assert payload["rows"] == []


def test_findings_table_empty(engagement_env):
    result = runner.invoke(app, _args(engagement_env, "findings"))
    assert result.exit_code == 0
    assert "No findings" in result.stdout


def test_findings_table_with_ado_links(engagement_env):
    """Findings with ADO details show repo and file link columns."""
    from conftest import FakeClock, FakeIds

    from beachhead.core.store.engine import open_store

    st = open_store(engagement_env.store_path, clock=FakeClock(), id_factory=FakeIds())
    run_id = st.start_run(
        module="collect.ado_credential_scan", phase="collect", operator="op"
    )
    st.insert_finding(
        kind="ado_credential_exposure",
        resource_id="ado://acme-eng/Project1/repo-a",
        reference="AKIA***TEST",
        run_id=run_id,
        redacted=True,
        details={
            "repo_name": "repo-a",
            "project": "Project1",
            "org": "acme-eng",
            "file_path": "/src/keys.env",
            "ado_url": "https://dev.azure.com/acme-eng/Project1/_git/repo-a?path=/src/keys.env&version=GBmain",
        },
    )
    st.finish_run(run_id, status="ok")
    st.close()

    result = runner.invoke(app, _args(engagement_env, "findings"))
    assert result.exit_code == 0
    assert "Project1/repo-a" in result.stdout
    assert "/src/keys.env" in result.stdout


def test_findings_json_with_ado_links(engagement_env):
    """JSON findings include repo_link and file_link fields."""
    from conftest import FakeClock, FakeIds

    from beachhead.core.store.engine import open_store

    st = open_store(engagement_env.store_path, clock=FakeClock(), id_factory=FakeIds())
    run_id = st.start_run(
        module="collect.ado_credential_scan", phase="collect", operator="op"
    )
    st.insert_finding(
        kind="ado_credential_exposure",
        resource_id="ado://acme-eng/Project2/repo-b",
        reference="ghp_***ABCD",
        run_id=run_id,
        redacted=True,
        details={
            "repo_name": "repo-b",
            "project": "Project2",
            "org": "acme-eng",
            "file_path": "/config/prod.yaml",
            "ado_url": "https://dev.azure.com/acme-eng/Project2/_git/repo-b?path=/config/prod.yaml&version=GBmain",
        },
    )
    st.finish_run(run_id, status="ok")
    st.close()

    result = runner.invoke(app, _args(engagement_env, "findings", "--json"))
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    row = payload["rows"][0]
    assert "Project2/repo-b" in row["source_link"]
    assert "dev.azure.com" in row["source_link"]
    assert "/config/prod.yaml" in row["file_link"]
