# src/beachhead/core/store/access.py
"""The concrete Store: explicit typed write/read methods over a private _upsert
helper, on a single sqlite3 connection guarded by one write lock.

Transaction-or-autocommit: a write inside begin() joins that transaction (lock held,
deferred commit); a standalone write commits immediately. Reads take the lock briefly
(skipped when already inside begin()). Timestamps/ids come from injected clock/id_factory
seams so tests are deterministic.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import datetime

from beachhead.core.errors import StoreError
from beachhead.core.store.rows import (
    AttackPath,
    AuditEntry,
    Engagement,
    Finding,
    Resource,
    Run,
    StoreSummary,
)


class Store:
    def __init__(
        self,
        conn: sqlite3.Connection,
        *,
        clock: Callable[[], datetime],
        id_factory: Callable[[], str],
    ) -> None:
        if conn.isolation_level is not None:
            raise StoreError(
                "Store requires a connection opened with isolation_level=None (autocommit); "
                f"got isolation_level={conn.isolation_level!r}"
            )
        self._conn = conn
        self._clock = clock
        self._id = id_factory
        self._lock = threading.RLock()
        self._in_txn = False
        conn.row_factory = sqlite3.Row

    # ----------------------------- low-level ----------------------------- #
    def _now(self) -> str:
        return self._clock().isoformat()

    def _write(self, sql: str, params: tuple[object, ...] = ()) -> None:
        try:
            with self._lock:
                self._conn.execute(sql, params)
        except (sqlite3.IntegrityError, sqlite3.OperationalError) as exc:
            raise StoreError(str(exc)) from exc

    def _query(self, sql: str, params: tuple[object, ...] = ()) -> list[sqlite3.Row]:
        try:
            if self._in_txn:
                return list(self._conn.execute(sql, params).fetchall())
            return list(self._conn.execute(sql, params).fetchall())
        except (sqlite3.IntegrityError, sqlite3.OperationalError) as exc:
            raise StoreError(str(exc)) from exc

    @contextmanager
    def begin(self) -> Iterator[None]:
        """Batched-write transaction. Commits on clean exit, rolls back on any error.

        Not reentrant: calling begin() while a transaction is already open raises
        StoreError. The check is inside the lock so concurrent threads cannot both
        pass the check before one sets _in_txn.
        """
        with self._lock:
            if self._in_txn:
                raise StoreError("begin() is not reentrant; a transaction is already open")
            self._in_txn = True
            self._conn.execute("BEGIN")
            try:
                yield
                self._conn.execute("COMMIT")
            except sqlite3.Error as exc:
                self._conn.execute("ROLLBACK")
                raise StoreError(str(exc)) from exc
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
            finally:
                self._in_txn = False

    # ----------------------------- lifecycle ----------------------------- #
    def ensure_engagement(self, *, name: str, scope_hash: str) -> Engagement:
        existing = self._query("SELECT * FROM engagement LIMIT 1")
        if existing:
            row = existing[0]
            self._write(
                "UPDATE engagement SET name = ?, scope_hash = ? WHERE id = ?",
                (name, scope_hash, row["id"]),
            )
            return Engagement(
                id=row["id"], name=name, started_at=row["started_at"], scope_hash=scope_hash
            )
        eid = self._id()
        started = self._now()
        self._write(
            "INSERT INTO engagement (id, name, started_at, scope_hash) VALUES (?, ?, ?, ?)",
            (eid, name, started, scope_hash),
        )
        return Engagement(id=eid, name=name, started_at=started, scope_hash=scope_hash)

    def start_run(self, *, module: str, phase: str, operator: str) -> str:
        run_id = self._id()
        self._write(
            "INSERT INTO runs (id, module, phase, operator, started_at, finished_at, status) "
            "VALUES (?, ?, ?, ?, ?, NULL, 'running')",
            (run_id, module, phase, operator, self._now()),
        )
        return run_id

    def finish_run(self, run_id: str, *, status: str) -> None:
        self._write(
            "UPDATE runs SET finished_at = ?, status = ? WHERE id = ?",
            (self._now(), status, run_id),
        )

    def get_run(self, run_id: str) -> Run | None:
        rows = self._query("SELECT * FROM runs WHERE id = ?", (run_id,))
        return _run(rows[0]) if rows else None

    def get_engagement(self) -> Engagement | None:
        rows = self._query("SELECT * FROM engagement LIMIT 1")
        if not rows:
            return None
        row = rows[0]
        return Engagement(
            id=row["id"],
            name=row["name"],
            started_at=row["started_at"],
            scope_hash=row["scope_hash"],
        )

    def runs(self) -> list[Run]:
        return [
            _run(r) for r in self._query("SELECT * FROM runs ORDER BY started_at DESC, id DESC")
        ]

    def summary(self) -> StoreSummary:
        def _count(sql: str, params: tuple[object, ...] = ()) -> int:
            return int(self._query(sql, params)[0][0])

        return StoreSummary(
            runs=_count("SELECT COUNT(*) FROM runs"),
            resources=_count("SELECT COUNT(*) FROM resources"),
            findings=_count("SELECT COUNT(*) FROM findings WHERE false_positive = 0"),
            attack_paths=_count("SELECT COUNT(*) FROM attack_paths WHERE false_positive = 0"),
        )

    def close(self) -> None:
        """Close the underlying connection. Idempotent."""
        try:
            self._conn.close()
        except Exception:  # noqa: BLE001, S110 - close must never raise on a second call
            pass

    # ------------------------------ upsert ------------------------------- #
    def _upsert(self, table: str, row: dict[str, object], keys: list[str]) -> None:
        cols = list(row)
        col_list = ", ".join(cols)
        placeholders = ", ".join("?" for _ in cols)
        conflict = ", ".join(keys)
        updates = ", ".join(f"{c} = excluded.{c}" for c in cols if c not in keys)
        # When every column is part of the natural key there is nothing to update on
        # a re-observation, so emit DO NOTHING (DO UPDATE SET with no assignments is
        # invalid SQL). Identifiers come from this module's literal call sites (never
        # user input); values are bound with ? placeholders.
        conflict_action = f"DO UPDATE SET {updates}" if updates else "DO NOTHING"
        sql = (
            f"INSERT INTO {table} ({col_list}) VALUES ({placeholders}) "  # noqa: S608
            f"ON CONFLICT ({conflict}) {conflict_action}"
        )
        self._write(sql, tuple(row.values()))

    # ----------------------------- resources ------------------------------ #
    def upsert_resource(
        self,
        *,
        resource_id: str,
        type: str,
        name: str,
        run_id: str,
        properties_summary: str | dict[str, object] = "",
    ) -> None:
        props = json.dumps(properties_summary) if isinstance(properties_summary, dict) else properties_summary
        self._upsert(
            "resources",
            {
                "resource_id": resource_id,
                "type": type,
                "name": name,
                "properties_summary": props,
                "run_id": run_id,
                "collected_at": self._now(),
            },
            keys=["resource_id"],
        )

    def resources(self, *, type: str | None = None) -> list[Resource]:
        if type is None:
            rows = self._query("SELECT * FROM resources ORDER BY collected_at")
        else:
            rows = self._query(
                "SELECT * FROM resources WHERE type = ? ORDER BY collected_at", (type,)
            )
        return [_resource(r) for r in rows]

    # ----------------------------- findings ------------------------------ #
    def insert_finding(
        self,
        *,
        kind: str,
        reference: str,
        run_id: str,
        resource_id: str | None = None,
        redacted: bool = False,
        details: dict[str, object] | None = None,
    ) -> str:
        fid = self._id()
        self._write(
            "INSERT INTO findings "  # noqa: S608
            "(id, kind, resource_id, reference, redacted,"
            " details_json, run_id, collected_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
            " ON CONFLICT (kind, COALESCE(resource_id, ''), reference)"
            " DO UPDATE SET redacted = excluded.redacted,"
            " details_json = excluded.details_json,"
            " run_id = excluded.run_id,"
            " collected_at = excluded.collected_at",
            (
                fid,
                kind,
                resource_id,
                reference,
                int(redacted),
                json.dumps(details or {}),
                run_id,
                self._now(),
            ),
        )
        return fid

    def dismiss_finding(self, finding_id: str) -> bool:
        self._write(
            "UPDATE findings SET false_positive = 1 WHERE id = ?", (finding_id,)
        )
        return bool(self._query("SELECT 1 FROM findings WHERE id = ?", (finding_id,)))

    def restore_finding(self, finding_id: str) -> bool:
        self._write(
            "UPDATE findings SET false_positive = 0 WHERE id = ?", (finding_id,)
        )
        return bool(self._query("SELECT 1 FROM findings WHERE id = ?", (finding_id,)))

    def findings(
        self,
        *,
        kind: str | None = None,
        run_id: str | None = None,
        include_fp: bool = False,
    ) -> list[Finding]:
        clauses: list[str] = []
        params: list[object] = []
        if not include_fp:
            clauses.append("false_positive = 0")
        if kind is not None:
            clauses.append("kind = ?")
            params.append(kind)
        if run_id is not None:
            clauses.append("run_id = ?")
            params.append(run_id)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        rows = self._query(
            f"SELECT * FROM findings{where} ORDER BY collected_at",  # noqa: S608
            tuple(params),
        )
        return [_finding(r) for r in rows]

    # --------------------------- attack_paths ---------------------------- #
    def insert_attack_path(
        self,
        *,
        source_id: str,
        target_id: str,
        edges: list[dict[str, object]],
        technique_ids: list[str],
        score: float,
        description: str,
        run_id: str,
    ) -> str:
        pid = self._id()
        self._write(
            "INSERT INTO attack_paths "
            "(id, source_id, target_id, edges_json, technique_ids, score, description, "
            "run_id, collected_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT (source_id, target_id) DO UPDATE SET "
            "edges_json = excluded.edges_json, "
            "technique_ids = excluded.technique_ids, "
            "score = excluded.score, "
            "description = excluded.description, "
            "run_id = excluded.run_id, "
            "collected_at = excluded.collected_at",
            (
                pid,
                source_id,
                target_id,
                json.dumps(edges),
                json.dumps(technique_ids),
                score,
                description,
                run_id,
                self._now(),
            ),
        )
        return pid

    def dismiss_attack_path(self, path_id: str) -> bool:
        self._write(
            "UPDATE attack_paths SET false_positive = 1 WHERE id = ?", (path_id,)
        )
        return bool(self._query("SELECT 1 FROM attack_paths WHERE id = ?", (path_id,)))

    def restore_attack_path(self, path_id: str) -> bool:
        self._write(
            "UPDATE attack_paths SET false_positive = 0 WHERE id = ?", (path_id,)
        )
        return bool(self._query("SELECT 1 FROM attack_paths WHERE id = ?", (path_id,)))

    def attack_paths(self, *, include_fp: bool = False) -> list[AttackPath]:
        if include_fp:
            sql = "SELECT * FROM attack_paths ORDER BY score DESC, id"
        else:
            sql = (
                "SELECT * FROM attack_paths WHERE false_positive = 0"
                " ORDER BY score DESC, id"
            )
        paths = [_attack_path(r) for r in self._query(sql)]
        if not include_fp:
            paths = self._suppress_fp_paths(paths)
        return paths

    def _suppress_fp_paths(self, paths: list[AttackPath]) -> list[AttackPath]:
        """Filter out paths whose source resource has ONLY FP findings."""
        if not paths:
            return paths
        source_ids = {p.source_id for p in paths}
        fp_sources: set[str] = set()
        for sid in source_ids:
            rows = self._query(
                "SELECT false_positive FROM findings WHERE resource_id = ?", (sid,)
            )
            if rows and all(bool(r["false_positive"]) for r in rows):
                fp_sources.add(sid)
        if not fp_sources:
            return paths
        return [p for p in paths if p.source_id not in fp_sources]

    # ------------------------------- audit ------------------------------- #
    def insert_audit(
        self,
        *,
        operator: str,
        action: str,
        target: str,
        mode: str,
        result: str = "ok",
        run_id: str | None = None,
    ) -> None:
        self._write(
            "INSERT INTO audit_log (ts, operator, action, target, mode, result, run_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (self._now(), operator, action, target, mode, result, run_id),
        )

    def audit_entries(self, *, run_id: str | None = None) -> list[AuditEntry]:
        if run_id is None:
            rows = self._query("SELECT * FROM audit_log ORDER BY id")
        else:
            rows = self._query("SELECT * FROM audit_log WHERE run_id = ? ORDER BY id", (run_id,))
        return [_audit_entry(r) for r in rows]

def _run(row: sqlite3.Row) -> Run:
    return Run(
        id=row["id"],
        module=row["module"],
        phase=row["phase"],
        operator=row["operator"],
        started_at=row["started_at"],
        finished_at=row["finished_at"],
        status=row["status"],
    )


def _audit_entry(row: sqlite3.Row) -> AuditEntry:
    return AuditEntry(
        id=row["id"],
        ts=row["ts"],
        operator=row["operator"],
        action=row["action"],
        target=row["target"],
        mode=row["mode"],
        result=row["result"],
        run_id=row["run_id"],
    )


def _finding(row: sqlite3.Row) -> Finding:
    return Finding(
        id=row["id"],
        kind=row["kind"],
        resource_id=row["resource_id"],
        reference=row["reference"],
        redacted=bool(row["redacted"]),
        details=json.loads(row["details_json"]),
        run_id=row["run_id"],
        collected_at=row["collected_at"],
        false_positive=bool(row["false_positive"]),
    )


def _attack_path(row: sqlite3.Row) -> AttackPath:
    return AttackPath(
        id=row["id"],
        source_id=row["source_id"],
        target_id=row["target_id"],
        edges=json.loads(row["edges_json"]),
        technique_ids=json.loads(row["technique_ids"]),
        score=float(row["score"]),
        description=row["description"],
        run_id=row["run_id"],
        collected_at=row["collected_at"],
        false_positive=bool(row["false_positive"]),
    )


def _resource(row: sqlite3.Row) -> Resource:
    raw = row["properties_summary"]
    try:
        props = json.loads(raw) if raw else {}
    except (json.JSONDecodeError, TypeError):
        props = raw
    return Resource(
        resource_id=row["resource_id"],
        type=row["type"],
        name=row["name"],
        properties_summary=props,
        run_id=row["run_id"],
        collected_at=row["collected_at"],
    )


