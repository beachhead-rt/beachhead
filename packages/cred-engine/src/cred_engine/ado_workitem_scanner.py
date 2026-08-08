"""Scan Azure DevOps work item fields and comments for credential exposure."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
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
from cred_engine.ado_patterns import (
    strip_html as _strip_html,
)
from cred_engine.models import FindingStatus, Severity, ToolSource, UnifiedFinding
from cred_engine.store import FindingsStore

_WI_FIELDS = [
    "System.Id",
    "System.Title",
    "System.WorkItemType",
    "System.State",
    "System.AssignedTo",
    "System.CreatedDate",
    "System.Description",
    "Microsoft.VSTS.TCM.ReproSteps",
    "System.History",
    "Microsoft.VSTS.Common.AcceptanceCriteria",
]

_BATCH_SIZE = 200

_SCANNABLE_FIELDS = [
    ("System.Description", "Description"),
    ("Microsoft.VSTS.TCM.ReproSteps", "Repro Steps"),
    ("System.History", "History"),
    ("Microsoft.VSTS.Common.AcceptanceCriteria", "Acceptance Criteria"),
]


@dataclass
class WorkItemCredentialHit:
    workitem_id: int
    title: str
    workitem_type: str
    state: str
    assigned_to: str
    created_date: str
    project: str
    url: str
    pattern_name: str
    matched_text: str
    source: str
    attachments: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "workitem_id": self.workitem_id,
            "title": self.title,
            "workitem_type": self.workitem_type,
            "state": self.state,
            "assigned_to": self.assigned_to,
            "created_date": self.created_date,
            "project": self.project,
            "url": self.url,
            "pattern_name": self.pattern_name,
            "matched_text": self.matched_text,
            "source": self.source,
        }
        if self.attachments:
            d["attachments"] = self.attachments
        return d


def _extract_attachments(workitem: dict[str, Any]) -> list[str]:
    """Pull attachment filenames from a work item's relations."""
    relations = workitem.get("relations") or []
    names: list[str] = []
    for rel in relations:
        if rel.get("rel") == "AttachedFile":
            attrs = rel.get("attributes", {})
            name = attrs.get("name", "")
            if name:
                names.append(name)
    return names


def _scan_text(
    text: str,
    *,
    workitem: dict[str, Any],
    project: str,
    org: str,
    source: str,
    attachments: list[str],
) -> list[WorkItemCredentialHit]:
    """Scan a single text blob against all credential patterns."""
    if not text:
        return []

    plain = _strip_html(text)
    hits: list[WorkItemCredentialHit] = []
    fields = workitem.get("fields", {})
    wi_id: int = fields.get("System.Id", workitem.get("id", 0))

    for pattern_name, pattern in _CREDENTIAL_PATTERNS:
        match = pattern.search(plain)
        if match:
            assigned = fields.get("System.AssignedTo", {})
            assigned_name = (
                assigned.get("displayName", "") if isinstance(assigned, dict) else str(assigned)
            )

            hits.append(
                WorkItemCredentialHit(
                    workitem_id=wi_id,
                    title=fields.get("System.Title", ""),
                    workitem_type=fields.get("System.WorkItemType", ""),
                    state=fields.get("System.State", ""),
                    assigned_to=assigned_name,
                    created_date=fields.get("System.CreatedDate", ""),
                    project=project,
                    url=f"https://dev.azure.com/{org}/{project}/_workitems/edit/{wi_id}",
                    pattern_name=pattern_name,
                    matched_text=_redact_match(match.group()),
                    source=source,
                    attachments=attachments,
                )
            )

    return hits


def scan_workitems(
    client: AdoClient,
    project: str,
    *,
    wiql: str | None = None,
    scan_comments: bool = True,
    top: int = 1000,
    console: Console | None = None,
) -> list[WorkItemCredentialHit]:
    """Scan work items in a project for credential patterns.

    Uses WIQL to discover work item IDs, fetches them in batches of
    ``_BATCH_SIZE``, and scans each scannable field.  When *scan_comments*
    is True (the default), each work item's comment thread is also checked.
    """
    con = console or Console(stderr=True)

    query = wiql or (
        f"SELECT [System.Id] FROM WorkItems WHERE [System.TeamProject] = '{project}'"
        " ORDER BY [System.CreatedDate] DESC"
    )

    con.print(f"[bold]Querying work items in:[/bold] {project}")
    try:
        wi_ids = client.query_workitems(project, query, top=top)
    except Exception as exc:
        con.print(f"[red]WIQL query failed: {exc}[/red]")
        return []

    con.print(f"[green]{len(wi_ids)} work item(s) matched[/green]")
    if not wi_ids:
        return []

    all_hits: list[WorkItemCredentialHit] = []

    batches = [wi_ids[i : i + _BATCH_SIZE] for i in range(0, len(wi_ids), _BATCH_SIZE)]

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        console=con,
    ) as progress:
        fetch_task = progress.add_task("Fetching & scanning work items...", total=len(wi_ids))

        for batch in batches:
            try:
                workitems = client.get_workitems(
                    batch,
                    fields=_WI_FIELDS,
                )
            except Exception as exc:
                con.print(
                    f"[yellow]Batch fetch error (IDs {batch[0]}-{batch[-1]}): {exc}[/yellow]"
                )
                progress.advance(fetch_task, len(batch))
                continue

            for wi in workitems:
                wi_fields = wi.get("fields", {})
                attachments = _extract_attachments(wi)

                for field_key, source_label in _SCANNABLE_FIELDS:
                    value = wi_fields.get(field_key, "")
                    if value:
                        hits = _scan_text(
                            value,
                            workitem=wi,
                            project=project,
                            org=client.org,
                            source=source_label,
                            attachments=attachments,
                        )
                        all_hits.extend(hits)

                if scan_comments:
                    wi_id = wi_fields.get("System.Id", wi.get("id", 0))
                    try:
                        comments = client.get_workitem_comments(project, wi_id)
                    except Exception:
                        comments = []

                    for comment in comments:
                        comment_text = comment.get("text", "")
                        if comment_text:
                            author = comment.get("createdBy", {}).get("displayName", "")
                            comment_source = f"Comment by {author}" if author else "Comment"
                            hits = _scan_text(
                                comment_text,
                                workitem=wi,
                                project=project,
                                org=client.org,
                                source=comment_source,
                                attachments=attachments,
                            )
                            all_hits.extend(hits)

                    if comments:
                        time.sleep(0.1)

                progress.advance(fetch_task)

    return all_hits


def persist_hits(
    hits: list[WorkItemCredentialHit],
    store: FindingsStore,
    run_id: str,
    *,
    store_secrets: bool = False,
) -> tuple[list[UnifiedFinding], int, int]:
    """Convert work item hits to UnifiedFindings and persist them.

    Returns (findings, new_count, dedup_count).
    """
    findings: list[UnifiedFinding] = []
    new_count = 0
    for hit in hits:
        finding = UnifiedFinding(
            id=uuid.uuid4().hex[:8],
            tool=ToolSource.CRED_SCAN,
            check_id="WORKITEM-CRED",
            title=f"{hit.pattern_name} in work item #{hit.workitem_id}",
            status=FindingStatus.FAIL,
            severity=Severity.MEDIUM,
            description=(
                f"Credential pattern '{hit.pattern_name}' found in work item "
                f"#{hit.workitem_id} field '{hit.source}'."
            ),
            resource=f"workitem/{hit.workitem_id}",
            project=hit.project,
            url=hit.url,
            evidence=hit.to_dict(),
            metadata={"matched_text": hit.matched_text},
        )
        _, is_new = store.upsert_finding(
            finding, run_id,
            repo=f"workitem/{hit.workitem_id}",
            file_path=hit.source,
            pattern_id=hit.pattern_name,
            store_secret=store_secrets,
        )
        if is_new:
            new_count += 1
        findings.append(finding)
    return findings, new_count, len(findings) - new_count
