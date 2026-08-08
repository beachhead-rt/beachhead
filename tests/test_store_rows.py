# tests/test_store_rows.py
"""Read row dataclasses are frozen and carry the expected fields."""

from __future__ import annotations

import dataclasses

import pytest

from beachhead.core.store.rows import (
    AuditEntry,
    Engagement,
    Resource,
    Run,
)


def test_resource_fields_and_frozen() -> None:
    res = Resource(
        resource_id="/sub/s1/rg/rg1/p/v/kv1",
        type="Microsoft.KeyVault/vaults",
        name="kv1",
        properties_summary="sku=standard",
        run_id="run-1",
        collected_at="2026-01-01T00:00:00+00:00",
    )
    assert res.resource_id == "/sub/s1/rg/rg1/p/v/kv1"
    assert res.type == "Microsoft.KeyVault/vaults"
    with pytest.raises(dataclasses.FrozenInstanceError):
        res.name = "changed"  # type: ignore[misc]


def test_all_row_types_constructible() -> None:
    Engagement(id="e1", name="ACME", started_at="t", scope_hash="h")
    Run(
        id="run-1",
        module="enumerate.ado_repos",
        phase="enumerate",
        operator="op",
        started_at="t",
        finished_at=None,
        status="running",
    )
    Resource(
        resource_id="/sub/s1/rg/rg1/p/v/kv1",
        type="Microsoft.KeyVault/vaults",
        name="kv1",
        properties_summary="",
        run_id="run-1",
        collected_at="t",
    )
    AuditEntry(
        id=1,
        ts="t",
        operator="op",
        action="enumerate.ado_repos",
        target="ado",
        mode="live",
        result="ok",
        run_id="run-1",
    )
