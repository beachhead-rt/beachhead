"""Scan Azure DevOps pipeline build logs for credential exposure."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from typing import Any

from rich.console import Console
from rich.progress import BarColumn, MofNCompleteColumn, Progress, SpinnerColumn, TextColumn

from cred_engine.ado_client import AdoClient
from cred_engine.ado_patterns import (
    CREDENTIAL_PATTERNS as _CREDENTIAL_PATTERNS,
)
from cred_engine.ado_patterns import (
    redact_match as _redact_match,
)
from cred_engine.models import FindingStatus, Severity, ToolSource, UnifiedFinding
from cred_engine.store import FindingsStore


@dataclass
class PipelineLogHit:
    project: str
    build_id: int
    build_number: str
    pipeline_name: str
    task_name: str
    log_id: int
    line_number: int
    pattern_name: str
    matched_text: str
    url: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "project": self.project,
            "build_id": self.build_id,
            "build_number": self.build_number,
            "pipeline_name": self.pipeline_name,
            "task_name": self.task_name,
            "log_id": self.log_id,
            "line_number": self.line_number,
            "pattern_name": self.pattern_name,
            "matched_text": self.matched_text,
            "url": self.url,
        }


def _scan_log_lines(
    lines: list[str],
    *,
    project: str,
    build_id: int,
    build_number: str,
    pipeline_name: str,
    task_name: str,
    log_id: int,
    org: str,
) -> list[PipelineLogHit]:
    hits: list[PipelineLogHit] = []
    build_url = (
        f"https://dev.azure.com/{org}/{project}/_build/results"
        f"?buildId={build_id}"
    )

    for line_num, line in enumerate(lines, start=1):
        for pattern_name, pattern in _CREDENTIAL_PATTERNS:
            match = pattern.search(line)
            if match:
                hits.append(PipelineLogHit(
                    project=project,
                    build_id=build_id,
                    build_number=build_number,
                    pipeline_name=pipeline_name,
                    task_name=task_name,
                    log_id=log_id,
                    line_number=line_num,
                    pattern_name=pattern_name,
                    matched_text=_redact_match(match.group()),
                    url=build_url,
                ))

    return hits


def scan_pipeline_logs(
    client: AdoClient,
    project: str,
    *,
    top: int = 20,
    console: Console | None = None,
) -> list[PipelineLogHit]:
    """Scan recent pipeline build logs for credential patterns."""
    con = console or Console(stderr=True)

    con.print(f"[bold]Listing recent builds in:[/bold] {project}")
    try:
        builds = client.list_builds(project, top=top)
    except Exception as exc:
        con.print(f"[red]Failed to list builds: {exc}[/red]")
        return []

    if not builds:
        con.print("[dim]No builds found.[/dim]")
        return []

    con.print(f"[green]{len(builds)} build(s) found[/green]")

    all_hits: list[PipelineLogHit] = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        console=con,
    ) as progress:
        task = progress.add_task("Scanning builds...", total=len(builds))

        for build in builds:
            build_id: int = build.get("id", 0)
            build_number: str = build.get("buildNumber", "")
            pipeline_name: str = build.get("definition", {}).get("name", "")
            progress.update(task, description=f"Build #{build_id} ({pipeline_name})")

            try:
                timeline = client.get_build_timeline(project, build_id)
            except Exception:
                progress.advance(task)
                continue

            records_with_logs = [
                r for r in timeline
                if isinstance(r, dict) and (r.get("log") or {}).get("id") is not None
            ]

            for record in records_with_logs:
                log_id: int = record["log"]["id"]
                task_name: str = record.get("name", "")

                try:
                    lines = client.get_build_log_lines(project, build_id, log_id)
                except Exception:
                    continue

                hits = _scan_log_lines(
                    lines,
                    project=project,
                    build_id=build_id,
                    build_number=build_number,
                    pipeline_name=pipeline_name,
                    task_name=task_name,
                    log_id=log_id,
                    org=client.org,
                )
                all_hits.extend(hits)
                time.sleep(0.03)

            progress.advance(task)

    return all_hits


def persist_hits(
    hits: list[PipelineLogHit],
    store: FindingsStore,
    run_id: str,
    *,
    store_secrets: bool = False,
) -> tuple[list[UnifiedFinding], int, int]:
    """Convert log hits to UnifiedFindings and persist them.

    Returns (findings, new_count, dedup_count).
    """
    findings: list[UnifiedFinding] = []
    new_count = 0
    for hit in hits:
        finding = UnifiedFinding(
            id=uuid.uuid4().hex[:8],
            tool=ToolSource.CRED_SCAN,
            check_id="PIPELINE-LOG-CRED",
            title=f"{hit.pattern_name} in pipeline log: {hit.pipeline_name}",
            status=FindingStatus.FAIL,
            severity=Severity.HIGH,
            description=(
                f"Credential pattern '{hit.pattern_name}' found in build log "
                f"for pipeline {hit.pipeline_name}."
            ),
            resource=hit.pipeline_name,
            project=hit.project,
            url=hit.url,
            evidence=hit.to_dict(),
            metadata={"matched_text": hit.matched_text},
        )
        _, is_new = store.upsert_finding(
            finding, run_id,
            repo=hit.pipeline_name,
            file_path=f"build/{hit.build_id}",
            pattern_id=hit.pattern_name,
            store_secret=store_secrets,
        )
        if is_new:
            new_count += 1
        findings.append(finding)
    return findings, new_count, len(findings) - new_count
