# tests/test_store_transactions.py
"""begin() batches commits and rolls back atomically; standalone writes autocommit."""

from __future__ import annotations

import pytest


def test_standalone_write_persists_immediately(store, run_id) -> None:
    store.upsert_resource(
        resource_id="/sub/s1/rg/rg1/p/v/r1",
        type="Microsoft.KeyVault/vaults",
        name="kv1",
        run_id=run_id,
    )
    assert len(store.resources()) == 1


def test_begin_commits_batch_on_clean_exit(store, run_id) -> None:
    with store.begin():
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
    assert len(store.resources()) == 2


def test_begin_rolls_back_entire_batch_on_error(store, run_id) -> None:
    with pytest.raises(RuntimeError):
        with store.begin():
            store.upsert_resource(
                resource_id="/sub/s1/rg/rg1/p/v/r1",
                type="Microsoft.KeyVault/vaults",
                name="kv1",
                run_id=run_id,
            )
            raise RuntimeError("boom")
    assert store.resources() == []  # nothing committed


def test_begin_is_not_reentrant(store, run_id) -> None:
    from beachhead.core.errors import StoreError

    with store.begin():
        store.upsert_resource(
            resource_id="/sub/s1/rg/rg1/p/v/r1",
            type="Microsoft.KeyVault/vaults",
            name="kv1",
            run_id=run_id,
        )
        with pytest.raises(StoreError):
            with store.begin():  # nested begin() must raise, not deadlock
                pass
    # outer transaction still commits cleanly after the inner guard fired
    assert len(store.resources()) == 1
