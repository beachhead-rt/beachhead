"""Scan Azure DevOps pull request comments for credential exposure."""

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
from cred_engine.ado_patterns import (
    strip_html as _strip_html,
)
from cred_engine.models import FindingStatus, Severity, ToolSource, UnifiedFinding
from cred_engine.store import FindingsStore


@dataclass
class PRCredentialHit:
    project: str
    repository: str
    pr_id: int
    pr_title: str
    thread_id: int
    comment_author: str
    pattern_name: str
    matched_text: str
    url: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "project": self.project,
            "repository": self.repository,
            "pr_id": self.pr_id,
            "pr_title": self.pr_title,
            "thread_id": self.thread_id,
            "comment_author": self.comment_author,
            "pattern_name": self.pattern_name,
            "matched_text": self.matched_text,
            "url": self.url,
        }


def _scan_comment(
    content: str,
    *,
    project: str,
    repository: str,
    pr_id: int,
    pr_title: str,
    thread_id: int,
    comment_author: str,
    org: str,
) -> list[PRCredentialHit]:
    if not content:
        return []

    clean = _strip_html(content)
    hits: list[PRCredentialHit] = []
    pr_url = (
        f"https://dev.azure.com/{org}/{project}/_git/{repository}"
        f"/pullrequest/{pr_id}"
    )

    for pattern_name, pattern in _CREDENTIAL_PATTERNS:
        match = pattern.search(clean)
        if match:
            hits.append(PRCredentialHit(
                project=project,
                repository=repository,
                pr_id=pr_id,
                pr_title=pr_title,
                thread_id=thread_id,
                comment_author=comment_author,
                pattern_name=pattern_name,
                matched_text=_redact_match(match.group()),
                url=pr_url,
            ))

    return hits


def scan_pull_requests(
    client: AdoClient,
    project: str,
    *,
    status: str = "all",
    top: int = 100,
    console: Console | None = None,
) -> list[PRCredentialHit]:
    """Scan PR comment threads in all repos for credential patterns."""
    con = console or Console(stderr=True)

    con.print(f"[bold]Listing repositories in:[/bold] {project}")
    try:
        repos = client.list_repositories(project)
    except Exception as exc:
        con.print(f"[red]Failed to list repositories: {exc}[/red]")
        return []

    if not repos:
        con.print("[dim]No repositories found.[/dim]")
        return []

    con.print(f"[green]{len(repos)} repo(s) found[/green]")

    all_hits: list[PRCredentialHit] = []

    for repo in repos:
        repo_name: str = repo.get("name", "")
        repo_id: str = repo.get("id", "")
        con.print(f"  Scanning PRs in: [bold]{repo_name}[/bold]")

        try:
            prs = client.list_pull_requests(project, repo_id, status=status, top=top)
        except Exception as exc:
            con.print(f"  [yellow]Failed to list PRs: {exc}[/yellow]")
            continue

        if not prs:
            con.print("  [dim]No pull requests.[/dim]")
            continue

        con.print(f"  [green]{len(prs)} PR(s)[/green]")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            console=con,
        ) as progress:
            task = progress.add_task(f"Scanning {repo_name} PRs...", total=len(prs))

            for pr in prs:
                pr_id: int = pr.get("pullRequestId", 0)
                pr_title: str = pr.get("title", "")
                progress.update(task, description=f"PR #{pr_id}")

                try:
                    threads = client.get_pull_request_threads(project, repo_id, pr_id)
                except Exception:
                    progress.advance(task)
                    continue

                for thread in threads:
                    thread_id: int = thread.get("id", 0)
                    for comment in thread.get("comments", []):
                        content: str = comment.get("content", "")
                        author: str = comment.get("author", {}).get(
                            "displayName",
                            comment.get("author", {}).get("uniqueName", "unknown"),
                        )
                        hits = _scan_comment(
                            content,
                            project=project,
                            repository=repo_name,
                            pr_id=pr_id,
                            pr_title=pr_title,
                            thread_id=thread_id,
                            comment_author=author,
                            org=client.org,
                        )
                        all_hits.extend(hits)

                progress.advance(task)
                time.sleep(0.05)

    return all_hits


def persist_hits(
    hits: list[PRCredentialHit],
    store: FindingsStore,
    run_id: str,
    *,
    store_secrets: bool = False,
) -> tuple[list[UnifiedFinding], int, int]:
    """Convert PR hits to UnifiedFindings and persist them.

    Returns (findings, new_count, dedup_count).
    """
    findings: list[UnifiedFinding] = []
    new_count = 0
    for hit in hits:
        finding = UnifiedFinding(
            id=uuid.uuid4().hex[:8],
            tool=ToolSource.CRED_SCAN,
            check_id="PR-COMMENT-CRED",
            title=f"{hit.pattern_name} in PR comment: {hit.repository}/{hit.pr_id}",
            status=FindingStatus.FAIL,
            severity=Severity.HIGH,
            description=(
                f"Credential pattern '{hit.pattern_name}' found in PR #{hit.pr_id} "
                f"comment in {hit.repository}."
            ),
            resource=hit.repository,
            project=hit.project,
            url=hit.url,
            evidence=hit.to_dict(),
            metadata={"matched_text": hit.matched_text},
        )
        _, is_new = store.upsert_finding(
            finding, run_id,
            repo=hit.repository,
            file_path=f"pr/{hit.pr_id}",
            pattern_id=hit.pattern_name,
            store_secret=store_secrets,
        )
        if is_new:
            new_count += 1
        findings.append(finding)
    return findings, new_count, len(findings) - new_count
