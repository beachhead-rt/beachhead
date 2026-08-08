"""Engagement report generation — structured export of store contents.

Builds a typed ``EngagementReport`` from the store, then serializes it to
JSON or Markdown. The report is a snapshot of the engagement at export time:
findings, attack paths, audit trail, and run summary.

By default no secrets are included. Pass ``include_secrets=True`` to
:func:`build_report` (with a :class:`SecretStore`) to attach plaintext
credentials from the secure credential store. This is gated behind
``--confirm`` at the CLI layer.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from beachhead.core.secret_store import Credential, SecretStore
from beachhead.core.store.access import Store
from beachhead.core.store.rows import (
    AttackPath,
    AuditEntry,
    Engagement,
    Finding,
    Run,
    StoreSummary,
)

__all__ = ["EngagementReport", "build_report", "export_json", "export_markdown"]


def _escape_md_table(text: str) -> str:
    return text.replace("\\", "\\\\").replace("|", "\\|").replace("`", "\\`")


@dataclass(frozen=True, slots=True)
class EngagementReport:
    """Complete engagement report, ready for serialization."""

    engagement: Engagement | None
    summary: StoreSummary
    runs: list[Run]
    findings: list[Finding]
    attack_paths: list[AttackPath]
    audit_entries: list[AuditEntry]
    metadata: dict[str, Any] = field(default_factory=dict)
    credentials: list[Credential] = field(default_factory=list)


def build_report(
    store: Store,
    *,
    metadata: dict[str, Any] | None = None,
    secret_store: SecretStore | None = None,
    include_secrets: bool = False,
) -> EngagementReport:
    """Collect all exportable data from the store into an ``EngagementReport``.

    When *include_secrets* is ``True`` and a *secret_store* is provided,
    plaintext credentials are attached to the report. The caller is
    responsible for gating this behind operator confirmation.
    """
    credentials: list[Credential] = []
    if include_secrets and secret_store is not None:
        credentials = secret_store.list_credentials()

    return EngagementReport(
        engagement=store.get_engagement(),
        summary=store.summary(),
        runs=store.runs(),
        findings=store.findings(),
        attack_paths=store.attack_paths(),
        audit_entries=store.audit_entries(),
        metadata=metadata or {},
        credentials=credentials,
    )


def export_json(report: EngagementReport, path: Path) -> None:
    """Write the report as a JSON file."""
    data = _report_dict(report)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")


def export_markdown(report: EngagementReport, path: Path) -> None:
    """Write the report as a Markdown file."""
    lines: list[str] = []
    eng = report.engagement

    lines.append(f"# Engagement Report: {eng.name if eng else 'unknown'}")
    lines.append("")
    if eng:
        lines.append(f"- **Started:** {eng.started_at}")
        lines.append(f"- **Scope hash:** `{eng.scope_hash}`")
    if report.metadata:
        for k, v in report.metadata.items():
            lines.append(f"- **{k}:** {v}")
    lines.append("")

    # Summary
    s = report.summary
    lines.append("## Summary")
    lines.append("")
    lines.append("| Metric | Count |")
    lines.append("|---|---|")
    for label, count in [
        ("Runs", s.runs),
        ("Resources", s.resources),
        ("Findings", s.findings),
        ("Attack paths", s.attack_paths),
    ]:
        lines.append(f"| {label} | {count} |")
    lines.append("")

    # Findings
    if report.findings:
        lines.append("## Findings")
        lines.append("")
        lines.append("| Kind | Reference | Resource |")
        lines.append("|---|---|---|")
        for f in report.findings:
            lines.append(
                f"| {_escape_md_table(f.kind)} "
                f"| {_escape_md_table(f.reference)} "
                f"| {_escape_md_table(f.resource_id) if f.resource_id else '-'} |"
            )
        lines.append("")

    # Credentials (only present when --include-secrets was used)
    if report.credentials:
        lines.append("## Credentials")
        lines.append("")
        lines.append("> **WARNING:** This section contains plaintext secrets.")
        lines.append("")
        lines.append("| Kind | Reference | Value | Resource |")
        lines.append("|---|---|---|---|")
        for c in report.credentials:
            lines.append(
                f"| {_escape_md_table(c.kind)} "
                f"| {_escape_md_table(c.reference)} "
                f"| `{_escape_md_table(c.value)}` "
                f"| {_escape_md_table(c.resource_id) if c.resource_id else '-'} |"
            )
        lines.append("")

    # Attack paths
    if report.attack_paths:
        lines.append("## Attack Paths")
        lines.append("")
        lines.append("| Score | Source | Target | Techniques | Description |")
        lines.append("|---|---|---|---|---|")
        for ap in report.attack_paths:
            techs = ", ".join(ap.technique_ids)
            lines.append(
                f"| {ap.score:.1f} "
                f"| {_escape_md_table(ap.source_id)} "
                f"| {_escape_md_table(ap.target_id)} "
                f"| {_escape_md_table(techs)} "
                f"| {_escape_md_table(ap.description)} |"
            )
        lines.append("")

    # Runs
    if report.runs:
        lines.append("## Runs")
        lines.append("")
        lines.append("| Module | Phase | Status | Operator | Started |")
        lines.append("|---|---|---|---|---|")
        for r in report.runs:
            lines.append(
                f"| {_escape_md_table(r.module)} "
                f"| {_escape_md_table(r.phase)} "
                f"| {_escape_md_table(r.status)} "
                f"| {_escape_md_table(r.operator)} "
                f"| {r.started_at} |"
            )
        lines.append("")

    # Audit trail
    if report.audit_entries:
        lines.append("## Audit Trail")
        lines.append("")
        lines.append("| Timestamp | Operator | Action | Target | Result |")
        lines.append("|---|---|---|---|---|")
        for ae in report.audit_entries:
            lines.append(
                f"| {ae.ts} "
                f"| {_escape_md_table(ae.operator)} "
                f"| {_escape_md_table(ae.action)} "
                f"| {_escape_md_table(ae.target)} "
                f"| {_escape_md_table(ae.result)} |"
            )
        lines.append("")

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def _report_dict(report: EngagementReport) -> dict[str, Any]:
    """Convert report to a JSON-safe dict."""
    d: dict[str, Any] = {
        "engagement": asdict(report.engagement) if report.engagement else None,
        "summary": asdict(report.summary),
        "runs": [asdict(r) for r in report.runs],
        "findings": [asdict(f) for f in report.findings],
        "attack_paths": [asdict(ap) for ap in report.attack_paths],
        "audit_entries": [asdict(ae) for ae in report.audit_entries],
        "metadata": report.metadata,
    }
    if report.credentials:
        d["credentials"] = [asdict(c) for c in report.credentials]
    return d
