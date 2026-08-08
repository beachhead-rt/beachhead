"""Read-side additions to the Store: get_engagement, runs(), summary(), close()."""

from __future__ import annotations

import pytest

from beachhead.core.errors import StoreError
from beachhead.core.store.engine import open_store, open_store_readonly
from beachhead.core.store.rows import StoreSummary


def _seed(store):
    store.ensure_engagement(name="ACME", scope_hash="HASH-OK")
    r1 = store.start_run(module="enumerate.ado_repos", phase="enumerate", operator="op")
    store.upsert_resource(
        resource_id="/sub/s1/rg/rg1/p/v/kv1",
        type="Microsoft.KeyVault/vaults",
        name="kv1",
        run_id=r1,
    )
    store.finish_run(r1, status="ok")
    r2 = store.start_run(module="enumerate.ado_pipelines", phase="enumerate", operator="op")
    store.upsert_resource(
        resource_id="/sub/s1/rg/rg1/p/v/sa1",
        type="Microsoft.Storage/storageAccounts",
        name="sa1",
        run_id=r2,
    )
    store.finish_run(r2, status="ok")
    return r1, r2


def test_get_engagement_returns_row(store):
    _seed(store)
    eng = store.get_engagement()
    assert eng is not None
    assert eng.name == "ACME"
    assert eng.scope_hash == "HASH-OK"


def test_get_engagement_none_when_empty(store):
    assert store.get_engagement() is None


def test_runs_newest_first(store):
    r1, r2 = _seed(store)
    runs = store.runs()
    assert [r.id for r in runs] == [r2, r1]  # r2 started later -> first


def test_summary_counts(store):
    _seed(store)
    s = store.summary()
    assert isinstance(s, StoreSummary)
    assert s.runs == 2
    assert s.resources == 2
    assert s.findings == 0
    assert s.attack_paths == 0


def test_close_is_idempotent(store):
    store.close()
    store.close()  # second call must not raise


def test_open_store_readonly_reads(tmp_path):
    path = str(tmp_path / "ro.sqlite")
    w = open_store(path)
    w.ensure_engagement(name="ACME", scope_hash="H")
    w.close()  # checkpoint WAL into the main db

    ro = open_store_readonly(path)
    eng = ro.get_engagement()
    assert eng is not None and eng.name == "ACME"
    ro.close()


def test_open_store_readonly_rejects_writes(tmp_path):
    path = str(tmp_path / "ro2.sqlite")
    w = open_store(path)
    w.ensure_engagement(name="ACME", scope_hash="H")
    w.close()

    ro = open_store_readonly(path)
    with pytest.raises(StoreError):
        ro.ensure_engagement(name="HACK", scope_hash="X")
    ro.close()
