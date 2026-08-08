"""Tests for core/audit AuditLog — policy over the store's insert_audit. Never a live tenant."""

from __future__ import annotations

import pytest

from beachhead.core.audit import AuditLog
from beachhead.core.errors import AuditError, BeachheadError
from beachhead.core.module import AuditLog as AuditLogProtocol


def test_audit_error_is_beachhead_error() -> None:
    assert issubclass(AuditError, BeachheadError)


def test_record_writes_a_row_bound_to_operator_and_run(store, run_id) -> None:
    audit = AuditLog(store, operator="alice", run_id=run_id)
    audit.record("graph.get", "/users", result="ok")
    entries = store.audit_entries(run_id=run_id)
    assert len(entries) == 1
    e = entries[0]
    assert (e.operator, e.action, e.target, e.mode, e.result, e.run_id) == (
        "alice",
        "graph.get",
        "/users",
        "live",
        "ok",
        run_id,
    )


def test_record_result_defaults_to_ok(store, run_id) -> None:
    AuditLog(store, operator="op", run_id=run_id).record("scope.check", "ten-1")
    assert store.audit_entries(run_id=run_id)[0].result == "ok"


def test_entries_returns_this_runs_rows(store, run_id) -> None:
    audit = AuditLog(store, operator="op", run_id=run_id)
    audit.record("a", "t")
    audit.record("b", "t", result="denied")
    assert [e.action for e in audit.entries()] == ["a", "b"]


def test_invalid_result_raises(store, run_id) -> None:
    audit = AuditLog(store, operator="op", run_id=run_id)
    with pytest.raises(AuditError, match="invalid audit result"):
        audit.record("a", "t", result="maybe")
    assert store.audit_entries(run_id=run_id) == []


def test_empty_action_or_target_raises(store, run_id) -> None:
    audit = AuditLog(store, operator="op", run_id=run_id)
    with pytest.raises(AuditError, match="action"):
        audit.record("  ", "t")
    with pytest.raises(AuditError, match="target"):
        audit.record("a", "")
    assert store.audit_entries(run_id=run_id) == []


def test_unsupported_extra_raises(store, run_id) -> None:
    audit = AuditLog(store, operator="op", run_id=run_id)
    with pytest.raises(AuditError, match="unsupported audit fields"):
        audit.record("a", "t", correlation_id="abc")
    assert store.audit_entries(run_id=run_id) == []


def test_run_id_threading_isolates_runs(store, run_id) -> None:
    AuditLog(store, operator="op", run_id=run_id).record("a", "t")
    run2 = store.start_run(module="m.x", phase="enumerate", operator="op")
    AuditLog(store, operator="op", run_id=run2).record("b", "t")
    assert [e.action for e in store.audit_entries(run_id=run_id)] == ["a"]
    assert [e.action for e in store.audit_entries(run_id=run2)] == ["b"]


def test_audit_log_satisfies_module_protocol(store, run_id) -> None:
    assert isinstance(AuditLog(store, operator="op", run_id=run_id), AuditLogProtocol)
