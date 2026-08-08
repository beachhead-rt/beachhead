"""core/store — the SQLite store engine + access layer (the module<->surface contract).

Modules write normalized rows through the access layer; analyze/TUI/CLI read through it.
See docs/architecture.md and docs/superpowers/specs/2026-06-04-core-store-design.md.
"""

from __future__ import annotations

from beachhead.core.errors import MigrationError, StoreError
from beachhead.core.store.access import Store
from beachhead.core.store.engine import open_store, read_only_connect
from beachhead.core.store.rows import (
    AttackPath,
    AuditEntry,
    Engagement,
    Finding,
    Resource,
    Run,
    StoreSummary,
)

__all__ = [
    "open_store",
    "read_only_connect",
    "Store",
    "Engagement",
    "Run",
    "Resource",
    "Finding",
    "AttackPath",
    "AuditEntry",
    "StoreSummary",
    "StoreError",
    "MigrationError",
]
