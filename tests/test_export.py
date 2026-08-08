"""Tests for core/export.py — report generation and serialization."""

from __future__ import annotations

import json

import pytest
from conftest import FakeClock, FakeIds

from beachhead.core.config import load_config
from beachhead.core.export import (
    EngagementReport,
    build_report,
    export_json,
    export_markdown,
)
from beachhead.core.store.engine import open_store


@pytest.fixture
def seeded_store(tmp_path, write_config):
    config_path = write_config(tmp_path / "engagement.local.yaml")
    config = load_config(config_path)

    store_path = str(tmp_path / "test.sqlite")
    st = open_store(store_path, clock=FakeClock(), id_factory=FakeIds())
    st.ensure_engagement(name=config.engagement, scope_hash=config.scope_hash)

    r1 = st.start_run(module="enumerate.ado_repos", phase="enumerate", operator="op")
    st.upsert_resource(
        resource_id="/sub/s1/rg/rg1/p/v/kv1",
        type="Microsoft.KeyVault/vaults",
        name="kv1",
        run_id=r1,
    )
    st.insert_finding(
        kind="credential_exposure",
        reference="repo/file.py:10",
        run_id=r1,
        resource_id="u-1",
    )
    st.insert_finding(
        kind="kv_access",
        reference="vault/secret",
        run_id=r1,
    )
    st.insert_attack_path(
        source_id="u-1",
        target_id="sub-1",
        edges=[{"from": "u-1", "to": "sub-1", "via": "Owner"}],
        technique_ids=["T1078"],
        score=8.5,
        description="User to sub via Owner",
        run_id=r1,
    )
    st.insert_audit(
        operator="op",
        action="graph.get",
        target="/users",
        mode="live",
        result="ok",
        run_id=r1,
    )
    st.finish_run(r1, status="ok")

    return st


def test_build_report_collects_all(seeded_store):
    report = build_report(seeded_store)
    assert isinstance(report, EngagementReport)
    assert report.engagement is not None
    assert report.engagement.name == "ACME-2026-Q2"
    assert report.summary.resources == 1
    assert report.summary.findings == 2
    assert report.summary.attack_paths == 1
    assert len(report.runs) == 1
    assert len(report.findings) == 2
    assert len(report.attack_paths) == 1
    assert len(report.audit_entries) == 1


def test_build_report_includes_findings(seeded_store):
    report = build_report(seeded_store)
    assert len(report.findings) == 2


def test_build_report_with_metadata(seeded_store):
    report = build_report(seeded_store, metadata={"custom": "value"})
    assert report.metadata == {"custom": "value"}


def test_export_json_roundtrip(seeded_store, tmp_path):
    report = build_report(seeded_store, metadata={"test": True})
    out = tmp_path / "report.json"
    export_json(report, out)

    assert out.exists()
    data = json.loads(out.read_text())
    assert data["engagement"]["name"] == "ACME-2026-Q2"
    assert len(data["findings"]) == 2
    assert len(data["attack_paths"]) == 1
    assert len(data["audit_entries"]) == 1
    assert data["metadata"]["test"] is True


def test_export_json_creates_parent_dirs(seeded_store, tmp_path):
    report = build_report(seeded_store)
    out = tmp_path / "nested" / "dir" / "report.json"
    export_json(report, out)
    assert out.exists()


def test_export_markdown_has_sections(seeded_store, tmp_path):
    report = build_report(seeded_store, metadata={"exported_at": "2026-06-28"})
    out = tmp_path / "report.md"
    export_markdown(report, out)

    content = out.read_text()
    assert "# Engagement Report: ACME-2026-Q2" in content
    assert "## Summary" in content
    assert "## Findings" in content
    assert "## Attack Paths" in content
    assert "## Runs" in content
    assert "## Audit Trail" in content
    assert "credential_exposure" in content
    assert "T1078" in content


def test_build_report_no_credentials_by_default(seeded_store):
    report = build_report(seeded_store)
    assert report.credentials == []


def test_build_report_includes_credentials_when_requested(seeded_store, tmp_path):
    from beachhead.core.secret_store import open_secret_store, secret_store_path

    sec_path = secret_store_path(str(tmp_path / "test.sqlite"))
    ss = open_secret_store(sec_path, "test-key")
    ss.store_credential(kind="aws_key", reference="repo/creds.py:5", run_id="r1", value="AKIA1234SECRET")
    ss.store_credential(kind="pat", reference="pipeline/env", run_id="r1", value="ghp_tok123")

    report = build_report(seeded_store, secret_store=ss, include_secrets=True)
    assert len(report.credentials) == 2
    values = {c.value for c in report.credentials}
    assert "AKIA1234SECRET" in values
    assert "ghp_tok123" in values
    ss.close()


def test_build_report_ignores_secrets_flag_without_store(seeded_store):
    report = build_report(seeded_store, include_secrets=True)
    assert report.credentials == []


def test_export_json_includes_credentials(seeded_store, tmp_path):
    from beachhead.core.secret_store import open_secret_store, secret_store_path

    sec_path = secret_store_path(str(tmp_path / "test.sqlite"))
    ss = open_secret_store(sec_path, "test-key")
    ss.store_credential(kind="pat", reference="ref", run_id="r1", value="s3cret")

    report = build_report(seeded_store, secret_store=ss, include_secrets=True)
    out = tmp_path / "report.json"
    export_json(report, out)
    data = json.loads(out.read_text())
    assert len(data["credentials"]) == 1
    assert data["credentials"][0]["value"] == "s3cret"
    ss.close()


def test_export_json_omits_credentials_key_when_empty(seeded_store, tmp_path):
    report = build_report(seeded_store)
    out = tmp_path / "report.json"
    export_json(report, out)
    data = json.loads(out.read_text())
    assert "credentials" not in data


def test_export_markdown_includes_credentials_section(seeded_store, tmp_path):
    from beachhead.core.secret_store import open_secret_store, secret_store_path

    sec_path = secret_store_path(str(tmp_path / "test.sqlite"))
    ss = open_secret_store(sec_path, "test-key")
    ss.store_credential(kind="pat", reference="ref", run_id="r1", value="s3cret_val")

    report = build_report(seeded_store, secret_store=ss, include_secrets=True)
    out = tmp_path / "report.md"
    export_markdown(report, out)
    content = out.read_text()
    assert "## Credentials" in content
    assert "plaintext secrets" in content.lower()
    assert "s3cret_val" in content
    ss.close()


def test_export_markdown_no_credentials_section_when_empty(seeded_store, tmp_path):
    report = build_report(seeded_store)
    out = tmp_path / "report.md"
    export_markdown(report, out)
    content = out.read_text()
    assert "## Credentials" not in content


def test_export_markdown_empty_store(tmp_path, write_config):
    config_path = write_config(tmp_path / "engagement.local.yaml")
    config = load_config(config_path)
    store_path = str(tmp_path / "empty.sqlite")
    st = open_store(store_path, clock=FakeClock(), id_factory=FakeIds())
    st.ensure_engagement(name=config.engagement, scope_hash=config.scope_hash)

    report = build_report(st)
    out = tmp_path / "empty.md"
    export_markdown(report, out)

    content = out.read_text()
    assert "# Engagement Report: ACME-2026-Q2" in content
    assert "## Findings" not in content  # no findings section when empty
    assert "## Attack Paths" not in content
    st.close()
