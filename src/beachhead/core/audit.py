"""core/audit.py — append-only operator-action logging (policy over the store).

AuditLog owns the result vocabulary the store deliberately leaves unconstrained and
binds every entry to its operator + run. It writes through core/store's insert_audit
primitive; it never edits or deletes. Records command shapes and targets, never secret
values (redaction is the caller's contract). See docs/opsec-and-scope.md ("Audit log").
"""

from __future__ import annotations

from typing import Any, Protocol

from beachhead.core.errors import AuditError
from beachhead.core.store.rows import AuditEntry

__all__ = ["AuditLog"]

_ALLOWED_RESULTS: frozenset[str] = frozenset({"ok", "error", "denied"})


class _AuditStore(Protocol):
    """Narrow seam: only the store methods AuditLog calls. The real Store satisfies it."""

    def insert_audit(
        self,
        *,
        operator: str,
        action: str,
        target: str,
        mode: str,
        result: str = "ok",
        run_id: str | None = None,
    ) -> None: ...

    def audit_entries(self, *, run_id: str | None = None) -> list[AuditEntry]: ...


class AuditLog:
    """Append-only operator-action log bound to one run. Implements module.AuditLog."""

    def __init__(self, store: _AuditStore, *, operator: str, run_id: str | None = None) -> None:
        self._store = store
        self._operator = operator
        self._run_id = run_id

    def record(
        self,
        action: str,
        target: str,
        *,
        result: str = "ok",
        **extra: Any,
    ) -> None:
        if extra:
            raise AuditError(
                f"unsupported audit fields {sorted(extra)}; the audit_log schema has no "
                "detail column — put shape/correlation detail in action/target"
            )
        if result not in _ALLOWED_RESULTS:
            raise AuditError(
                f"invalid audit result {result!r}; allowed: {sorted(_ALLOWED_RESULTS)}"
            )
        if not action or not action.strip():
            raise AuditError("audit action must be a non-empty string")
        if not target or not target.strip():
            raise AuditError("audit target must be a non-empty string")
        self._store.insert_audit(
            operator=self._operator,
            action=action,
            target=target,
            mode="live",
            result=result,
            run_id=self._run_id,
        )

    def entries(self) -> list[AuditEntry]:
        """This run's audit rows (all rows if constructed with run_id=None)."""
        return self._store.audit_entries(run_id=self._run_id)
