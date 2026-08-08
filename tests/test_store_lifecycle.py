# tests/test_store_lifecycle.py
"""Engagement single-row upsert + run lifecycle (uses shared store fixture)."""

from __future__ import annotations

from beachhead.core.store.rows import Engagement, Run


def test_ensure_engagement_creates_single_row(store) -> None:
    eng = store.ensure_engagement(name="ACME", scope_hash="h1")
    assert isinstance(eng, Engagement)
    assert eng.name == "ACME"
    assert eng.id == "id-0001"


def test_ensure_engagement_updates_in_place(store) -> None:
    first = store.ensure_engagement(name="ACME", scope_hash="h1")
    second = store.ensure_engagement(name="ACME-RENAMED", scope_hash="h2")
    assert second.id == first.id  # still one row, same id
    assert second.name == "ACME-RENAMED"
    assert second.scope_hash == "h2"


def test_start_run_then_get_run(store) -> None:
    rid = store.start_run(
        module="enumerate.identities", phase="enumerate", operator="op"
    )
    run = store.get_run(rid)
    assert isinstance(run, Run)
    assert run.status == "running"
    assert run.finished_at is None


def test_finish_run_sets_status_and_finished_at(store) -> None:
    rid = store.start_run(
        module="enumerate.identities", phase="enumerate", operator="op"
    )
    store.finish_run(rid, status="ok")
    run = store.get_run(rid)
    assert run is not None
    assert run.status == "ok"
    assert run.finished_at is not None


def test_get_run_missing_returns_none(store) -> None:
    assert store.get_run("nope") is None
