# tests/test_store_collection.py
"""Collection upserts are latest-wins on the natural key; reads return typed rows."""

from __future__ import annotations

from beachhead.core.store.rows import Resource


def test_upsert_resource_then_read_back(store, run_id) -> None:
    store.upsert_resource(
        resource_id="/sub/s1/rg/rg1/p/v/r1",
        type="Microsoft.KeyVault/vaults",
        name="kv1",
        run_id=run_id,
        properties_summary="sku=standard",
    )
    rows = store.resources()
    assert len(rows) == 1
    assert isinstance(rows[0], Resource)
    assert rows[0].name == "kv1"
    assert rows[0].type == "Microsoft.KeyVault/vaults"


def test_upsert_resource_is_latest_wins(store, run_id) -> None:
    store.upsert_resource(
        resource_id="/sub/s1/rg/rg1/p/v/r1",
        type="Microsoft.KeyVault/vaults",
        name="kv1",
        run_id=run_id,
        properties_summary="sku=standard",
    )
    run2 = store.start_run(
        module="enumerate.resources", phase="enumerate", operator="op"
    )
    store.upsert_resource(
        resource_id="/sub/s1/rg/rg1/p/v/r1",
        type="Microsoft.KeyVault/vaults",
        name="kv1-updated",
        run_id=run2,
        properties_summary="sku=premium",
    )
    rows = store.resources()
    assert len(rows) == 1  # no duplicate row
    assert rows[0].name == "kv1-updated"  # newest observation wins
    assert rows[0].run_id == run2


def test_distinct_resource_keys_insert_separate_rows(store, run_id) -> None:
    store.upsert_resource(
        resource_id="/sub/s1/rg/rg1/p/v/r1",
        type="Microsoft.KeyVault/vaults",
        name="kv1",
        run_id=run_id,
    )
    store.upsert_resource(
        resource_id="/sub/s1/rg/rg1/p/v/r2",
        type="Microsoft.Storage/storageAccounts",
        name="sa1",
        run_id=run_id,
    )
    rows = store.resources()
    assert len(rows) == 2
    assert all(isinstance(r, Resource) for r in rows)


def test_upsert_all_key_columns_does_nothing_on_conflict(store) -> None:
    # White-box: when a table's UNIQUE constraint spans every column, _upsert's
    # `updates` is empty and it must emit DO NOTHING (DO UPDATE SET with no
    # assignments is invalid SQL). A re-observation of the same row is then a no-op.
    store._conn.execute("CREATE TABLE _all_key (a TEXT, b TEXT, UNIQUE (a, b))")
    store._upsert("_all_key", {"a": "x", "b": "y"}, keys=["a", "b"])
    store._upsert("_all_key", {"a": "x", "b": "y"}, keys=["a", "b"])  # conflict -> DO NOTHING
    rows = store._query("SELECT * FROM _all_key")
    assert len(rows) == 1
