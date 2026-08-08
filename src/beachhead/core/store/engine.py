# src/beachhead/core/store/engine.py
"""Engine: open the SQLite DB, set PRAGMAs, run forward-only user_version migrations,
hand back a Store. Also a read-only connection factory for the TUI.
"""

from __future__ import annotations

import re
import sqlite3
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from importlib.resources import files
from pathlib import Path

from beachhead.core.errors import MigrationError, StoreError
from beachhead.core.store.access import Store

_VERSION_RE = re.compile(r"^(\d+)_.*\.sql$")
_MIGRATIONS_PKG = "beachhead.core.store"


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _uuid_hex() -> str:
    return uuid.uuid4().hex


def _migrations() -> list[tuple[int, str]]:
    found: list[tuple[int, str]] = []
    mig_dir = files(_MIGRATIONS_PKG).joinpath("migrations")
    for entry in mig_dir.iterdir():
        if not entry.name.endswith(".sql"):
            continue
        match = _VERSION_RE.match(entry.name)
        if match is None:
            raise MigrationError(f"migration file not named NNN_*.sql: {entry.name}")
        found.append((int(match.group(1)), entry.read_text(encoding="utf-8")))
    return sorted(found, key=lambda pair: pair[0])


def _apply_migrations(conn: sqlite3.Connection) -> None:
    current = conn.execute("PRAGMA user_version").fetchone()[0]
    for version, sql in _migrations():
        if version <= current:
            continue
        # Apply the DDL and the user_version bump in one transaction so a crash
        # mid-migration leaves no half-applied schema — a re-open then retries
        # cleanly. executescript disregards isolation_level, so the BEGIN/COMMIT
        # in the script body IS the transaction. `version` is a trusted int
        # parsed from the migration filename, never user input.
        script = f"BEGIN;\n{sql}\nPRAGMA user_version = {version};\nCOMMIT;"
        try:
            conn.executescript(script)
        except sqlite3.Error as exc:
            conn.rollback()
            raise MigrationError(f"migration {version} failed: {exc}") from exc


def open_store(
    path: str,
    *,
    clock: Callable[[], datetime] = _utc_now,
    id_factory: Callable[[], str] = _uuid_hex,
) -> Store:
    try:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA busy_timeout = 5000")
        conn.execute("PRAGMA synchronous = NORMAL")
    except (sqlite3.Error, OSError) as exc:
        raise StoreError(f"Cannot open store at {path}: {exc}") from exc
    _apply_migrations(conn)
    return Store(conn, clock=clock, id_factory=id_factory)


def read_only_connect(path: str) -> sqlite3.Connection:
    """Open a read-only connection (for the TUI). WAL permits concurrent reads."""
    uri = f"file:{Path(path).resolve()}?mode=ro"
    try:
        conn = sqlite3.connect(uri, uri=True, isolation_level=None, check_same_thread=False)
        conn.execute("PRAGMA busy_timeout = 5000")
    except sqlite3.Error as exc:
        raise StoreError(f"Cannot open store (read-only) at {path}: {exc}") from exc
    conn.row_factory = sqlite3.Row
    return conn


def open_store_readonly(path: str) -> Store:
    """A Store over a read-only connection. Reads work; writes raise at the SQLite layer
    (mapped to StoreError by the access layer), so read-only is enforced by construction.

    Callers must pre-check the file exists; ``?mode=ro`` errors on a missing file.
    The clock / id_factory seams are unused by reads; the defaults are passed.
    """
    conn = read_only_connect(path)
    return Store(conn, clock=_utc_now, id_factory=_uuid_hex)
