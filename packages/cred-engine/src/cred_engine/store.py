"""SQLite-backed findings store with deduplication and triage persistence.

Stores credential scan findings in a single portable SQLite file. Deduplication
uses stable-field hashing (repo + file_path + pattern_id + secret_hash) —
line numbers are deliberately excluded because they shift across code changes.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cred_engine.models import FindingStatus, Severity, ToolSource, UnifiedFinding

_DEFAULT_DB = Path("findings.sqlite")

_SCHEMA_VERSION = 2

_SCHEMA = """\
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    hash TEXT UNIQUE NOT NULL,
    tool TEXT NOT NULL,
    check_id TEXT NOT NULL,
    title TEXT NOT NULL,
    status TEXT NOT NULL,
    severity TEXT NOT NULL,
    description TEXT NOT NULL,
    resource TEXT NOT NULL DEFAULT '',
    project TEXT NOT NULL DEFAULT '',
    url TEXT NOT NULL DEFAULT '',
    evidence TEXT NOT NULL DEFAULT '{}',
    remediation TEXT NOT NULL DEFAULT '',
    commands TEXT NOT NULL DEFAULT '[]',
    metadata TEXT NOT NULL DEFAULT '{}',
    confidence TEXT NOT NULL DEFAULT 'medium',
    confidence_score REAL NOT NULL DEFAULT 0.0,
    entropy REAL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    scan_run_id TEXT NOT NULL,
    triage_status TEXT NOT NULL DEFAULT 'open',
    triage_by TEXT,
    triage_at TEXT,
    triage_reason TEXT,
    secret_hash TEXT,
    secret_value TEXT
);

CREATE INDEX IF NOT EXISTS idx_findings_hash ON findings(hash);
CREATE INDEX IF NOT EXISTS idx_findings_project ON findings(project);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_triage ON findings(triage_status);
CREATE INDEX IF NOT EXISTS idx_findings_tool ON findings(tool);
CREATE INDEX IF NOT EXISTS idx_findings_check_id ON findings(check_id);
CREATE INDEX IF NOT EXISTS idx_findings_confidence ON findings(confidence);
CREATE INDEX IF NOT EXISTS idx_findings_secret_hash ON findings(secret_hash);

CREATE TABLE IF NOT EXISTS scan_runs (
    id TEXT PRIMARY KEY,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    org TEXT NOT NULL DEFAULT '',
    repos_scanned INTEGER NOT NULL DEFAULT 0,
    patterns_used INTEGER NOT NULL DEFAULT 0,
    total_findings INTEGER NOT NULL DEFAULT 0,
    new_findings INTEGER NOT NULL DEFAULT 0,
    deduped_findings INTEGER NOT NULL DEFAULT 0,
    tool TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS run_findings (
    run_id TEXT NOT NULL,
    finding_hash TEXT NOT NULL,
    PRIMARY KEY (run_id, finding_hash)
);

CREATE TABLE IF NOT EXISTS scan_state (
    run_id TEXT PRIMARY KEY,
    config TEXT NOT NULL DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'running',
    completed_patterns TEXT NOT NULL DEFAULT '[]',
    started_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
"""


def finding_hash(
    repo: str,
    file_path: str,
    pattern_id: str,
    secret_value: str = "",
) -> str:
    """Compute stable identity hash for deduplication.

    Excludes line number (unstable across code changes) and scan run
    (irrelevant to identity).
    """
    content = f"{repo}\0{file_path}\0{pattern_id}"
    if secret_value:
        content += f"\0{hashlib.sha256(secret_value.encode()).hexdigest()}"
    return hashlib.sha256(content.encode()).hexdigest()


class TriageStatus:
    OPEN = "open"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "fp"
    IGNORED = "ignored"

    ALL = frozenset({"open", "confirmed", "fp", "ignored"})


class FindingsStore:
    """SQLite findings store with dedup, triage, and query support."""

    def __init__(self, db_path: Path | str = _DEFAULT_DB) -> None:
        self._db_path = Path(db_path)
        self._conn = sqlite3.connect(str(self._db_path))
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._init_schema()

    def _init_schema(self) -> None:
        cur = self._conn.cursor()
        for stmt in _SCHEMA.split(";"):
            stmt = stmt.strip()
            if stmt:
                cur.execute(stmt)

        row = cur.execute("SELECT version FROM schema_version LIMIT 1").fetchone()
        if row is None:
            cur.execute(
                "INSERT INTO schema_version (version) VALUES (?)",
                (_SCHEMA_VERSION,),
            )
        else:
            current = row["version"]
            if current < _SCHEMA_VERSION:
                self._migrate(cur, current)
        self._conn.commit()

    def _migrate(self, cur: sqlite3.Cursor, from_version: int) -> None:
        if from_version < 2:
            cols = {r[1] for r in cur.execute("PRAGMA table_info(findings)").fetchall()}
            if "secret_value" not in cols:
                cur.execute("ALTER TABLE findings ADD COLUMN secret_value TEXT")
            cur.execute("UPDATE schema_version SET version = 2")

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> FindingsStore:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    @property
    def connection(self) -> sqlite3.Connection:
        return self._conn

    # ------------------------------------------------------------------
    # Scan run management
    # ------------------------------------------------------------------

    def start_run(
        self,
        org: str = "",
        repos_scanned: int = 0,
        patterns_used: int = 0,
        tool: str = "",
    ) -> str:
        run_id = uuid.uuid4().hex[:12]
        now = datetime.now(UTC).isoformat()
        self._conn.execute(
            "INSERT INTO scan_runs (id, started_at, org, repos_scanned, patterns_used, tool) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (run_id, now, org, repos_scanned, patterns_used, tool),
        )
        self._conn.commit()
        return run_id

    def finish_run(
        self,
        run_id: str,
        total_findings: int = 0,
        new_findings: int = 0,
        deduped_findings: int = 0,
    ) -> None:
        now = datetime.now(UTC).isoformat()
        self._conn.execute(
            "UPDATE scan_runs SET completed_at=?, total_findings=?, new_findings=?, deduped_findings=? WHERE id=?",
            (now, total_findings, new_findings, deduped_findings, run_id),
        )
        self._conn.commit()

    def save_scan_state(
        self,
        run_id: str,
        config: dict[str, Any],
        completed_patterns: list[str] | None = None,
        status: str = "running",
    ) -> None:
        now = datetime.now(UTC).isoformat()
        config_json = json.dumps(config)
        patterns_json = json.dumps(completed_patterns or [])
        self._conn.execute(
            "INSERT INTO scan_state (run_id, config, status, completed_patterns, started_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(run_id) DO UPDATE SET "
            "completed_patterns=?, status=?, updated_at=?",
            (run_id, config_json, status, patterns_json, now, now,
             patterns_json, status, now),
        )
        self._conn.commit()

    def mark_pattern_complete(self, run_id: str, pattern_key: str) -> None:
        row = self._conn.execute(
            "SELECT completed_patterns FROM scan_state WHERE run_id=?", (run_id,)
        ).fetchone()
        if not row:
            return
        completed: list[str] = json.loads(row["completed_patterns"])
        if pattern_key not in completed:
            completed.append(pattern_key)
        now = datetime.now(UTC).isoformat()
        self._conn.execute(
            "UPDATE scan_state SET completed_patterns=?, updated_at=? WHERE run_id=?",
            (json.dumps(completed), now, run_id),
        )
        self._conn.commit()

    def get_resumable_scan(self) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT * FROM scan_state WHERE status='running' ORDER BY started_at DESC LIMIT 1"
        ).fetchone()
        if not row:
            return None
        d = dict(row)
        d["config"] = json.loads(d["config"])
        d["completed_patterns"] = json.loads(d["completed_patterns"])
        return d

    def finish_scan_state(self, run_id: str) -> None:
        now = datetime.now(UTC).isoformat()
        self._conn.execute(
            "UPDATE scan_state SET status='complete', updated_at=? WHERE run_id=?",
            (now, run_id),
        )
        self._conn.commit()

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        row = self._conn.execute("SELECT * FROM scan_runs WHERE id=?", (run_id,)).fetchone()
        return dict(row) if row else None

    def list_runs(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM scan_runs ORDER BY started_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Finding upsert (dedup on hash)
    # ------------------------------------------------------------------

    def upsert_finding(
        self,
        finding: UnifiedFinding,
        scan_run_id: str,
        *,
        repo: str = "",
        file_path: str = "",
        pattern_id: str = "",
        secret_value: str = "",
        store_secret: bool = False,
    ) -> tuple[str, bool]:
        """Insert or update a finding based on its dedup hash.

        Returns (finding_id, is_new). If a finding with the same hash
        exists, updates last_seen and scan_run_id but preserves triage.

        When store_secret is True, the raw credential value is persisted
        in the secret_value column for later retrieval. The database file
        should be treated as sensitive when this option is used.
        """
        if not repo:
            repo = finding.evidence.get("repository", finding.resource)
        if not file_path:
            file_path = finding.evidence.get("file_path", "")
        if not pattern_id:
            pattern_id = finding.evidence.get("pattern", finding.check_id)

        h = finding_hash(repo, file_path, pattern_id, secret_value)
        s_hash = hashlib.sha256(secret_value.encode()).hexdigest() if secret_value else None
        stored_secret = secret_value if store_secret and secret_value else None
        now = datetime.now(UTC).isoformat()

        existing = self._conn.execute("SELECT id, triage_status FROM findings WHERE hash=?", (h,)).fetchone()

        if existing is not None:
            self._conn.execute(
                "UPDATE findings SET last_seen=?, scan_run_id=?, "
                "title=?, status=?, severity=?, description=?, "
                "url=?, evidence=?, metadata=?, confidence=?, confidence_score=?, "
                "secret_hash=?, secret_value=? "
                "WHERE hash=?",
                (
                    now,
                    scan_run_id,
                    finding.title,
                    finding.status.value,
                    finding.severity.value,
                    finding.description,
                    finding.url,
                    json.dumps(finding.evidence),
                    json.dumps(finding.metadata),
                    finding.metadata.get("confidence", "medium"),
                    finding.metadata.get("confidence_score", 0.0),
                    s_hash,
                    stored_secret,
                    h,
                ),
            )
            self._conn.execute(
                "INSERT OR IGNORE INTO run_findings (run_id, finding_hash) VALUES (?, ?)",
                (scan_run_id, h),
            )
            self._conn.commit()
            return str(existing["id"]), False

        fid = uuid.uuid4().hex[:8]
        self._conn.execute(
            "INSERT INTO findings "
            "(id, hash, tool, check_id, title, status, severity, "
            "description, resource, project, url, evidence, remediation, "
            "commands, metadata, confidence, confidence_score, "
            "first_seen, last_seen, scan_run_id, secret_hash, secret_value) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                fid,
                h,
                finding.tool.value,
                finding.check_id,
                finding.title,
                finding.status.value,
                finding.severity.value,
                finding.description,
                finding.resource,
                finding.project,
                finding.url,
                json.dumps(finding.evidence),
                finding.remediation,
                json.dumps(finding.commands),
                json.dumps(finding.metadata),
                finding.metadata.get("confidence", "medium"),
                finding.metadata.get("confidence_score", 0.0),
                now,
                now,
                scan_run_id,
                s_hash,
                stored_secret,
            ),
        )
        self._conn.execute(
            "INSERT OR IGNORE INTO run_findings (run_id, finding_hash) VALUES (?, ?)",
            (scan_run_id, h),
        )
        self._conn.commit()
        return fid, True

    # ------------------------------------------------------------------
    # Secret retrieval
    # ------------------------------------------------------------------

    def get_secret(self, finding_id: str) -> str | None:
        """Retrieve the stored raw credential value for a finding.

        Returns None if the finding doesn't exist or no secret was stored
        (i.e. the scan was run without --store-secrets).
        """
        row = self._conn.execute(
            "SELECT secret_value FROM findings WHERE id=?", (finding_id,)
        ).fetchone()
        if not row:
            return None
        return row["secret_value"]

    def has_stored_secrets(self) -> bool:
        """Check if any findings have stored secret values."""
        row = self._conn.execute(
            "SELECT COUNT(*) as cnt FROM findings WHERE secret_value IS NOT NULL"
        ).fetchone()
        return bool(row and row["cnt"] > 0)

    # ------------------------------------------------------------------
    # Triage
    # ------------------------------------------------------------------

    def triage(
        self,
        finding_id: str,
        status: str,
        *,
        by: str = "",
        reason: str = "",
    ) -> bool:
        """Set the triage status of a finding. Returns True if found."""
        if status not in TriageStatus.ALL:
            msg = f"Invalid triage status: {status!r}"
            raise ValueError(msg)
        now = datetime.now(UTC).isoformat()
        cur = self._conn.execute(
            "UPDATE findings SET triage_status=?, triage_by=?, triage_at=?, triage_reason=? WHERE id=?",
            (status, by, now, reason, finding_id),
        )
        self._conn.commit()
        return cur.rowcount > 0

    def bulk_triage(
        self,
        finding_ids: list[str],
        status: str,
        *,
        by: str = "",
        reason: str = "",
    ) -> int:
        """Triage multiple findings at once. Returns count updated."""
        if status not in TriageStatus.ALL:
            msg = f"Invalid triage status: {status!r}"
            raise ValueError(msg)
        now = datetime.now(UTC).isoformat()
        placeholders = ",".join("?" for _ in finding_ids)
        cur = self._conn.execute(
            f"UPDATE findings SET triage_status=?, triage_by=?, "  # noqa: S608
            f"triage_at=?, triage_reason=? "
            f"WHERE id IN ({placeholders})",
            [status, by, now, reason, *finding_ids],
        )
        self._conn.commit()
        return cur.rowcount

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def _row_to_finding(self, row: sqlite3.Row) -> UnifiedFinding:
        return UnifiedFinding(
            id=row["id"],
            tool=ToolSource(row["tool"]),
            check_id=row["check_id"],
            title=row["title"],
            status=FindingStatus(row["status"]),
            severity=Severity(row["severity"]),
            description=row["description"],
            resource=row["resource"],
            project=row["project"],
            url=row["url"],
            evidence=json.loads(row["evidence"]),
            remediation=row["remediation"],
            commands=json.loads(row["commands"]),
            metadata=json.loads(row["metadata"]),
        )

    def get_finding(self, finding_id: str) -> dict[str, Any] | None:
        row = self._conn.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
        return dict(row) if row else None

    def query_findings(
        self,
        *,
        project: str = "",
        severity: str = "",
        triage_status: str = "",
        confidence: str = "",
        tool: str = "",
        check_id: str = "",
        limit: int = 500,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Query findings with optional filters."""
        clauses: list[str] = []
        params: list[Any] = []

        if project:
            clauses.append("project = ?")
            params.append(project)
        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        if triage_status:
            clauses.append("triage_status = ?")
            params.append(triage_status)
        if confidence:
            clauses.append("confidence = ?")
            params.append(confidence)
        if tool:
            clauses.append("tool = ?")
            params.append(tool)
        if check_id:
            clauses.append("check_id = ?")
            params.append(check_id)

        where = " AND ".join(clauses) if clauses else "1=1"
        sql = f"SELECT * FROM findings WHERE {where} ORDER BY confidence_score DESC, severity ASC LIMIT ? OFFSET ?"  # noqa: S608
        params.extend([limit, offset])

        rows = self._conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    def count_findings(
        self,
        *,
        triage_status: str = "",
        project: str = "",
    ) -> int:
        clauses: list[str] = []
        params: list[Any] = []
        if triage_status:
            clauses.append("triage_status = ?")
            params.append(triage_status)
        if project:
            clauses.append("project = ?")
            params.append(project)

        where = " AND ".join(clauses) if clauses else "1=1"
        row = self._conn.execute(f"SELECT COUNT(*) as cnt FROM findings WHERE {where}", params).fetchone()  # noqa: S608
        return int(row["cnt"]) if row else 0

    def summary(self) -> dict[str, Any]:
        """Aggregate summary across all findings."""
        total = self.count_findings()
        by_triage = {}
        for status in TriageStatus.ALL:
            by_triage[status] = self.count_findings(triage_status=status)

        by_severity: dict[str, int] = {}
        rows = self._conn.execute("SELECT severity, COUNT(*) as cnt FROM findings GROUP BY severity").fetchall()
        for row in rows:
            by_severity[row["severity"]] = row["cnt"]

        by_confidence: dict[str, int] = {}
        rows = self._conn.execute("SELECT confidence, COUNT(*) as cnt FROM findings GROUP BY confidence").fetchall()
        for row in rows:
            by_confidence[row["confidence"]] = row["cnt"]

        by_project: dict[str, int] = {}
        rows = self._conn.execute(
            "SELECT project, COUNT(*) as cnt FROM findings GROUP BY project ORDER BY cnt DESC LIMIT 20"
        ).fetchall()
        for row in rows:
            by_project[row["project"]] = row["cnt"]

        runs = self.list_runs(limit=5)

        return {
            "total": total,
            "by_triage": by_triage,
            "by_severity": by_severity,
            "by_confidence": by_confidence,
            "by_project": by_project,
            "recent_runs": runs,
        }

    # ------------------------------------------------------------------
    # Baseline comparison
    # ------------------------------------------------------------------

    def baseline_hashes(self, run_id: str) -> set[str]:
        """Return the set of finding hashes that appeared in a given run."""
        rows = self._conn.execute(
            "SELECT finding_hash FROM run_findings WHERE run_id = ?",
            (run_id,),
        ).fetchall()
        return {row["finding_hash"] for row in rows}

    def baseline_diff(
        self,
        baseline_run_id: str,
        current_run_id: str,
    ) -> dict[str, Any]:
        """Compare two runs and return new, resolved, and unchanged finding counts."""
        baseline = self.baseline_hashes(baseline_run_id)
        current = self.baseline_hashes(current_run_id)

        new_hashes = current - baseline
        resolved_hashes = baseline - current
        unchanged_hashes = current & baseline

        new_findings = []
        if new_hashes:
            placeholders = ",".join("?" for _ in new_hashes)
            rows = self._conn.execute(
                f"SELECT * FROM findings WHERE hash IN ({placeholders})",  # noqa: S608
                list(new_hashes),
            ).fetchall()
            new_findings = [dict(r) for r in rows]

        resolved_findings = []
        if resolved_hashes:
            placeholders = ",".join("?" for _ in resolved_hashes)
            rows = self._conn.execute(
                f"SELECT * FROM findings WHERE hash IN ({placeholders})",  # noqa: S608
                list(resolved_hashes),
            ).fetchall()
            resolved_findings = [dict(r) for r in rows]

        return {
            "baseline_run": baseline_run_id,
            "current_run": current_run_id,
            "new_count": len(new_hashes),
            "resolved_count": len(resolved_hashes),
            "unchanged_count": len(unchanged_hashes),
            "new_findings": new_findings,
            "resolved_findings": resolved_findings,
        }

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def export_json(self, **filters: Any) -> list[dict[str, Any]]:
        """Export findings as a list of dicts (for JSON serialization)."""
        return self.query_findings(**filters, limit=100_000)

    def as_unified_findings(self, **filters: Any) -> list[UnifiedFinding]:
        """Return findings as UnifiedFinding objects."""
        rows = self._conn.execute("SELECT * FROM findings ORDER BY confidence_score DESC LIMIT 100000").fetchall()
        return [self._row_to_finding(r) for r in rows]

    # ------------------------------------------------------------------
    # Correlation — same-secret reuse detection
    # ------------------------------------------------------------------

    def secret_groups(
        self,
        *,
        min_locations: int = 2,
    ) -> list[dict[str, Any]]:
        """Group findings by secret_hash to find credentials in multiple locations."""
        base = (
            "SELECT secret_hash, COUNT(*) as location_count, "
            "MIN(severity) as worst_severity, "
            "GROUP_CONCAT(DISTINCT resource) as resources, "
            "GROUP_CONCAT(DISTINCT check_id) as patterns "
            "FROM findings WHERE secret_hash IS NOT NULL"
        )
        base += " GROUP BY secret_hash HAVING COUNT(*) >= ? ORDER BY location_count DESC"
        rows = self._conn.execute(base, (min_locations,)).fetchall()
        return [dict(r) for r in rows]

    def correlate_secret(
        self,
        secret_hash: str,
        exclude_finding_id: str | None = None,
    ) -> dict[str, Any]:
        """Find all findings sharing the same secret_hash."""
        rows = self._conn.execute(
            "SELECT id, title, resource, project, severity, triage_status, "
            "json_extract(evidence, '$.pattern') AS pattern, "
            "json_extract(evidence, '$.file_path') AS file_path "
            "FROM findings WHERE secret_hash = ? ORDER BY resource, title",
            (secret_hash,),
        ).fetchall()

        if not rows:
            return {"total": 0, "repos": [], "patterns": [], "groups": []}

        by_repo: dict[str, list[dict[str, Any]]] = {}
        patterns: set[str] = set()
        triage_counts: dict[str, int] = {"open": 0, "confirmed": 0, "fp": 0}

        for r in rows:
            d = dict(r)
            if exclude_finding_id and d["id"] == exclude_finding_id:
                continue
            repo = d["resource"] or "unknown"
            if repo not in by_repo:
                by_repo[repo] = []
            by_repo[repo].append(d)
            p = d.get("pattern") or ""
            if p:
                patterns.add(p)
            ts = d.get("triage_status") or "open"
            if ts in triage_counts:
                triage_counts[ts] += 1

        groups = []
        total = 0
        for repo, findings in sorted(by_repo.items()):
            groups.append({
                "repo": repo,
                "count": len(findings),
                "findings": findings,
            })
            total += len(findings)
        return {
            "total": total,
            "repos": sorted(by_repo.keys()),
            "repo_count": len(by_repo),
            "patterns": sorted(patterns),
            "triage": triage_counts,
            "groups": groups,
        }

    def find_reuse_clusters(
        self,
        min_repos: int = 2,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Find the top secret-hash clusters by repo spread."""
        query = (
            "SELECT secret_hash, COUNT(*) AS cnt, "
            "COUNT(DISTINCT resource) AS repo_cnt, "
            "GROUP_CONCAT(DISTINCT json_extract(evidence, '$.pattern')) AS patterns "
            "FROM findings "
            "WHERE secret_hash IS NOT NULL "
            "GROUP BY secret_hash "
            "HAVING repo_cnt >= ? "
            "ORDER BY repo_cnt DESC, cnt DESC "
            "LIMIT ?"
        )
        rows = self._conn.execute(query, (min_repos, limit)).fetchall()

        clusters = []
        for r in rows:
            sample = self._conn.execute(
                "SELECT title, resource, severity, triage_status "
                "FROM findings WHERE secret_hash = ? LIMIT 3",
                (r["secret_hash"],),
            ).fetchall()
            clusters.append({
                "secret_hash": r["secret_hash"],
                "finding_count": r["cnt"],
                "repo_count": r["repo_cnt"],
                "patterns": (r["patterns"] or "").split(","),
                "has_confirmed": any(
                    s["triage_status"] == "confirmed" for s in sample
                ),
                "samples": [dict(s) for s in sample],
            })

        return clusters
