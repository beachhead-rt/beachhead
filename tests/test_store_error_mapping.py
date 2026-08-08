# tests/test_store_error_mapping.py
"""sqlite IntegrityError -> StoreError; a failing migration -> MigrationError."""

from __future__ import annotations

import pytest

from beachhead.core.errors import MigrationError, StoreError
from beachhead.core.store.engine import open_store


def test_fk_violation_raises_store_error(store) -> None:
    # run_id 'ghost' has no runs row; foreign_keys is ON.
    with pytest.raises(StoreError):
        store.upsert_resource(
            resource_id="/sub/s1/rg/rg1/p/v/r1",
            type="Microsoft.KeyVault/vaults",
            name="kv1",
            run_id="ghost",
        )


def test_failing_migration_raises_migration_error(tmp_path, monkeypatch) -> None:
    # Inject a migration whose SQL is invalid; _apply_migrations must wrap it.
    monkeypatch.setattr(
        "beachhead.core.store.engine._migrations",
        lambda: [(1, "CREATE TABLE (this is not valid sql;")],
    )
    with pytest.raises(MigrationError):
        open_store(str(tmp_path / "broken.db"))
