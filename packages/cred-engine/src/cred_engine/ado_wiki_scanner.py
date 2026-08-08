"""Scan Azure DevOps wiki pages for credential exposure."""

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
class WikiCredentialHit:
    project: str
    wiki_name: str
    wiki_id: str
    page_path: str
    page_title: str
    url: str
    pattern_name: str
    matched_text: str
    line_number: int = 0

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "project": self.project,
            "wiki_name": self.wiki_name,
            "wiki_id": self.wiki_id,
            "page_path": self.page_path,
            "page_title": self.page_title,
            "url": self.url,
            "pattern_name": self.pattern_name,
            "matched_text": self.matched_text,
        }
        if self.line_number:
            d["line_number"] = self.line_number
        return d


def _collect_page_paths(page: dict[str, Any]) -> list[tuple[str, str]]:
    """Recursively collect (path, title) from a wiki page tree."""
    results: list[tuple[str, str]] = []
    path = page.get("path", "")
    title = page.get("path", "").rsplit("/", 1)[-1] or "/"
    if path:
        results.append((path, title))
    for sub in page.get("subPages", []):
        results.extend(_collect_page_paths(sub))
    return results


def _scan_content(
    content: str,
    *,
    project: str,
    wiki_name: str,
    wiki_id: str,
    page_path: str,
    page_title: str,
    org: str,
) -> list[WikiCredentialHit]:
    if not content:
        return []

    hits: list[WikiCredentialHit] = []
    lines = content.split("\n")
    page_url = (
        f"https://dev.azure.com/{org}/{project}/_wiki/wikis/{wiki_id}"
        f"?pagePath={page_path}"
    )

    for line_num, line in enumerate(lines, start=1):
        for pattern_name, pattern in _CREDENTIAL_PATTERNS:
            match = pattern.search(line)
            if match:
                hits.append(WikiCredentialHit(
                    project=project,
                    wiki_name=wiki_name,
                    wiki_id=wiki_id,
                    page_path=page_path,
                    page_title=page_title,
                    url=page_url,
                    pattern_name=pattern_name,
                    matched_text=_redact_match(match.group()),
                    line_number=line_num,
                ))

    return hits


def scan_wikis(
    client: AdoClient,
    project: str,
    *,
    console: Console | None = None,
) -> list[WikiCredentialHit]:
    """Scan all wiki pages in a project for credential patterns."""
    con = console or Console(stderr=True)

    con.print(f"[bold]Listing wikis in:[/bold] {project}")
    try:
        wikis = client.list_wikis(project)
    except Exception as exc:
        con.print(f"[red]Failed to list wikis: {exc}[/red]")
        return []

    if not wikis:
        con.print("[dim]No wikis found.[/dim]")
        return []

    con.print(f"[green]{len(wikis)} wiki(s) found[/green]")

    all_hits: list[WikiCredentialHit] = []

    for wiki in wikis:
        wiki_name: str = wiki.get("name", "")
        wiki_id: str = wiki.get("id", "")
        con.print(f"  Scanning wiki: [bold]{wiki_name}[/bold]")

        try:
            root = client.get_wiki_page(
                project, wiki_id, "/",
                include_content=False,
                recursion_level="full",
            )
        except Exception as exc:
            con.print(f"  [yellow]Failed to get page tree: {exc}[/yellow]")
            continue

        pages = _collect_page_paths(root)
        if not pages:
            con.print("  [dim]No pages.[/dim]")
            continue

        con.print(f"  [green]{len(pages)} page(s)[/green]")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            console=con,
        ) as progress:
            task = progress.add_task(f"Scanning {wiki_name}...", total=len(pages))

            for page_path, page_title in pages:
                progress.update(task, description=f"Scanning: {page_path}")
                try:
                    page_data = client.get_wiki_page(
                        project, wiki_id, page_path,
                        include_content=True,
                    )
                except Exception:
                    progress.advance(task)
                    continue

                content = page_data.get("content", "")
                hits = _scan_content(
                    content,
                    project=project,
                    wiki_name=wiki_name,
                    wiki_id=wiki_id,
                    page_path=page_path,
                    page_title=page_title,
                    org=client.org,
                )
                all_hits.extend(hits)
                progress.advance(task)
                time.sleep(0.05)

    return all_hits


def persist_hits(
    hits: list[WikiCredentialHit],
    store: FindingsStore,
    run_id: str,
    *,
    store_secrets: bool = False,
) -> tuple[list[UnifiedFinding], int, int]:
    """Convert wiki hits to UnifiedFindings and persist them.

    Returns (findings, new_count, dedup_count).
    """
    findings: list[UnifiedFinding] = []
    new_count = 0
    for hit in hits:
        finding = UnifiedFinding(
            id=uuid.uuid4().hex[:8],
            tool=ToolSource.CRED_SCAN,
            check_id="WIKI-CRED",
            title=f"{hit.pattern_name} in wiki: {hit.wiki_name}/{hit.page_path}",
            status=FindingStatus.FAIL,
            severity=Severity.HIGH,
            description=(
                f"Credential pattern '{hit.pattern_name}' found in wiki page "
                f"'{hit.page_path}' in {hit.wiki_name}."
            ),
            resource=hit.wiki_name,
            project=hit.project,
            url=hit.url,
            evidence=hit.to_dict(),
            metadata={"matched_text": hit.matched_text},
        )
        _, is_new = store.upsert_finding(
            finding, run_id,
            repo=hit.wiki_name,
            file_path=hit.page_path,
            pattern_id=hit.pattern_name,
            store_secret=store_secrets,
        )
        if is_new:
            new_count += 1
        findings.append(finding)
    return findings, new_count, len(findings) - new_count
