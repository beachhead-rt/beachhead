# tests/test_store_public_api.py
"""The core/store package re-exports the intended public surface."""

from __future__ import annotations


def test_public_exports_importable() -> None:
    from beachhead.core.store import (
        AttackPath,
        AuditEntry,
        Engagement,
        Finding,
        MigrationError,
        Resource,
        Run,
        Store,
        StoreError,
        StoreSummary,
        open_store,
        read_only_connect,
    )

    assert open_store is not None
    assert read_only_connect is not None
    assert Store is not None
    assert len({Engagement, Run, Resource, Finding, AttackPath, AuditEntry, StoreSummary}) == 7
    assert issubclass(MigrationError, StoreError)
