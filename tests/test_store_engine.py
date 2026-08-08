# tests/test_store_engine.py
"""Engine: open_store applies migrations, sets PRAGMAs, is idempotent on re-open."""

from __future__ import annotations

import sqlite3

import pytest

from beachhead.core.errors import MigrationError
from beachhead.core.store.engine import open_store, read_only_connect

EXPECTED_TABLES = {
    "engagement",
    "runs",
    "resources",
    "findings",
    "attack_paths",
    "audit_log",
}
HIGHEST_MIGRATION = 7


DROPPED_AZURE_TABLES = {
    "identities",
    "role_assignments",
    "service_principals",
    "oauth_grants",
    "managed_identities",
    "group_members",
    "devices",
}


def test_open_creates_all_tables(tmp_path) -> None:
    path = str(tmp_path / "engagement.db")
    open_store(path)
    raw = sqlite3.connect(path)
    names = {r[0] for r in raw.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert EXPECTED_TABLES <= names
    assert names & DROPPED_AZURE_TABLES == set()


def test_open_sets_user_version_to_highest_migration(tmp_path) -> None:
    path = str(tmp_path / "engagement.db")
    open_store(path)
    raw = sqlite3.connect(path)
    assert raw.execute("PRAGMA user_version").fetchone()[0] == HIGHEST_MIGRATION


def test_reopen_is_idempotent(tmp_path) -> None:
    path = str(tmp_path / "engagement.db")
    open_store(path)
    open_store(path)  # must not raise / re-apply
    raw = sqlite3.connect(path)
    assert raw.execute("PRAGMA user_version").fetchone()[0] == HIGHEST_MIGRATION


def test_open_enables_wal_and_foreign_keys(tmp_path) -> None:
    store = open_store(str(tmp_path / "engagement.db"))
    assert store._conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
    assert store._conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1


def test_read_only_connection_cannot_write(tmp_path) -> None:
    path = str(tmp_path / "engagement.db")
    open_store(path)
    ro = read_only_connect(path)
    with pytest.raises(sqlite3.OperationalError):
        ro.execute(
            "INSERT INTO engagement (id, name, started_at, scope_hash) VALUES ('e', 'n', 't', 'h')"
        )


def test_failed_migration_rolls_back_atomically(tmp_path, monkeypatch) -> None:
    # A migration that creates a table then hits invalid SQL must leave NO trace:
    # the table must not persist and user_version must stay 0, so a re-open retries.
    bad = "CREATE TABLE good (x);\nINSERT INTO does_not_exist VALUES (1);"
    monkeypatch.setattr("beachhead.core.store.engine._migrations", lambda: [(1, bad)])
    path = str(tmp_path / "broken.db")
    with pytest.raises(MigrationError):
        open_store(path)
    raw = sqlite3.connect(path)
    tables = {r[0] for r in raw.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert "good" not in tables  # DDL rolled back with the failed transaction
    assert raw.execute("PRAGMA user_version").fetchone()[0] == 0  # version not bumped
