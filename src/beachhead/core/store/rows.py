# src/beachhead/core/store/rows.py
"""Frozen row dataclasses returned by the store access layer's read methods.

Writers pass keyword args to the Store's upsert/insert methods; readers get these
typed rows back. No secrets are ever carried here (see opsec-and-scope.md).
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = [
    "Engagement",
    "Run",
    "Resource",
    "Finding",
    "AttackPath",
    "AuditEntry",
    "StoreSummary",
]


@dataclass(frozen=True, slots=True)
class Engagement:
    id: str
    name: str
    started_at: str
    scope_hash: str


@dataclass(frozen=True, slots=True)
class Run:
    id: str
    module: str
    phase: str
    operator: str
    started_at: str
    finished_at: str | None
    status: str


@dataclass(frozen=True, slots=True)
class Finding:
    id: str
    kind: str
    resource_id: str | None
    reference: str
    redacted: bool
    details: dict[str, object]
    run_id: str
    collected_at: str
    false_positive: bool = False


@dataclass(frozen=True, slots=True)
class AttackPath:
    id: str
    source_id: str
    target_id: str
    edges: list[dict[str, object]]
    technique_ids: list[str]
    score: float
    description: str
    run_id: str
    collected_at: str
    false_positive: bool = False


@dataclass(frozen=True, slots=True)
class AuditEntry:
    id: int
    ts: str
    operator: str
    action: str
    target: str
    mode: str
    result: str
    run_id: str | None


@dataclass(frozen=True, slots=True)
class Resource:
    resource_id: str
    type: str
    name: str
    properties_summary: dict[str, object] | str
    run_id: str
    collected_at: str


@dataclass(frozen=True, slots=True)
class StoreSummary:
    runs: int
    resources: int
    findings: int
    attack_paths: int
