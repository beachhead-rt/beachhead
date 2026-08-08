"""Tests for the expanded store tables (migration 002): resources, findings, attack_paths."""

from __future__ import annotations

import pytest
from conftest import FakeClock, FakeIds

from beachhead.core.store.engine import open_store
from beachhead.core.store.rows import (
    AttackPath,
    Finding,
    Resource,
)


@pytest.fixture
def store(tmp_path):
    s = open_store(str(tmp_path / "test.db"), clock=FakeClock(), id_factory=FakeIds())
    s.ensure_engagement(name="ACME", scope_hash="h")
    return s


@pytest.fixture
def rid(store):
    return store.start_run(module="enumerate.test", phase="enumerate", operator="op")


# -- resources ---------------------------------------------------------------


def test_upsert_resource(store, rid):
    store.upsert_resource(
        resource_id="/subscriptions/s1/resourceGroups/rg1/providers/M.S/vaults/kv1",
        type="Microsoft.KeyVault/vaults",
        run_id=rid,
        name="kv1",
    )
    res = store.resources()
    assert len(res) == 1
    r = res[0]
    assert isinstance(r, Resource)
    assert r.type == "Microsoft.KeyVault/vaults"


# -- findings ----------------------------------------------------------------


def test_insert_finding(store, rid):
    fid = store.insert_finding(
        kind="exposed_secret",
        reference="keyvault:kv1/secret-name",
        run_id=rid,
        resource_id="kv1",
        redacted=True,
        details={"truncated": "s3cr***"},
    )
    assert fid.startswith("id-")
    findings = store.findings()
    assert len(findings) == 1
    f = findings[0]
    assert isinstance(f, Finding)
    assert f.redacted is True
    assert f.details == {"truncated": "s3cr***"}


def test_findings_filter_by_kind(store, rid):
    store.insert_finding(kind="exposed_secret", reference="a", run_id=rid)
    store.insert_finding(kind="weak_config", reference="b", run_id=rid)
    assert len(store.findings(kind="exposed_secret")) == 1
    assert len(store.findings(kind="weak_config")) == 1
    assert len(store.findings()) == 2


# -- attack_paths ------------------------------------------------------------


def test_insert_attack_path(store, rid):
    pid = store.insert_attack_path(
        source_id="u-1",
        target_id="kv-1",
        edges=[
            {"from": "u-1", "to": "sp-1", "via": "owner"},
            {"from": "sp-1", "to": "kv-1", "via": "rbac"},
        ],
        technique_ids=["T1078.004", "T1552.001"],
        score=8.5,
        description="User owns SP with Key Vault access",
        run_id=rid,
    )
    assert pid.startswith("id-")
    paths = store.attack_paths()
    assert len(paths) == 1
    p = paths[0]
    assert isinstance(p, AttackPath)
    assert p.source_id == "u-1"
    assert p.target_id == "kv-1"
    assert len(p.edges) == 2
    assert p.technique_ids == ["T1078.004", "T1552.001"]
    assert p.score == 8.5


def test_attack_paths_ordered_by_score_desc(store, rid):
    store.insert_attack_path(
        source_id="a",
        target_id="b",
        edges=[],
        technique_ids=[],
        score=3.0,
        description="low",
        run_id=rid,
    )
    store.insert_attack_path(
        source_id="c",
        target_id="d",
        edges=[],
        technique_ids=[],
        score=9.0,
        description="high",
        run_id=rid,
    )
    paths = store.attack_paths()
    assert paths[0].score == 9.0
    assert paths[1].score == 3.0
