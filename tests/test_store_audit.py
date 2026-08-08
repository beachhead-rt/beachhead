# tests/test_store_audit.py
"""Audit log: insert + read back; filter by run_id; preserves insertion order."""

from __future__ import annotations

from beachhead.core.store.rows import AuditEntry


def test_insert_audit_then_read_back(store) -> None:
    store.insert_audit(operator="op", action="enumerate.identities", target="graph", mode="live")
    entries = store.audit_entries()
    assert len(entries) == 1
    assert isinstance(entries[0], AuditEntry)
    assert entries[0].result == "ok"  # default
    assert entries[0].action == "enumerate.identities"


def test_audit_entries_filter_by_run_id(store) -> None:
    # audit_log.run_id is a FK to runs(id) with foreign_keys=ON, so use real run ids.
    store.ensure_engagement(name="ACME", scope_hash="h")
    r1 = store.start_run(module="m1", phase="enumerate", operator="op")
    r2 = store.start_run(module="m2", phase="enumerate", operator="op")
    store.insert_audit(operator="op", action="a", target="t", mode="live", run_id=r1)
    store.insert_audit(operator="op", action="b", target="t", mode="live", run_id=r2)
    only = store.audit_entries(run_id=r1)
    assert [e.action for e in only] == ["a"]


def test_audit_preserves_insertion_order(store) -> None:
    # No run_id -> NULL, which the FK permits; keeps the ordering assertion simple.
    for action in ("a", "b", "c"):
        store.insert_audit(operator="op", action=action, target="t", mode="live")
    assert [e.action for e in store.audit_entries()] == ["a", "b", "c"]
