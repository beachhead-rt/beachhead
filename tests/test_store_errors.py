# tests/test_store_errors.py
"""StoreError / MigrationError belong to the shared BeachheadError taxonomy."""

from __future__ import annotations

from beachhead.core.errors import BeachheadError, MigrationError, StoreError


def test_store_error_is_a_beachhead_error() -> None:
    assert issubclass(StoreError, BeachheadError)


def test_migration_error_is_a_store_error() -> None:
    assert issubclass(MigrationError, StoreError)
    assert issubclass(MigrationError, BeachheadError)


def test_errors_carry_a_message() -> None:
    try:
        raise StoreError("disk full")
    except BeachheadError as exc:
        assert str(exc) == "disk full"
