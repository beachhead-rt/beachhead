"""harvest.ado_pr_scan — ADO pull request comment credential scanner.

Scans pull request comment threads across in-scope ADO repositories for
exposed credentials.  Delegates pattern matching to cred-engine.

Read-only — never modifies ADO.

MITRE ATT&CK: T1552.001 (Unsecured Credentials: Credentials In Files)
"""

from __future__ import annotations

import asyncio
import html
import re
from typing import Any

from beachhead.core.cred_bridge import scan_and_record
from beachhead.core.errors import AuthError, ScopeError
from beachhead.core.module import Access, ModuleMeta, Phase, RunContext, RunResult
from beachhead.modules.enumerate._ado_common import (
    HTML_TAG_RE,
    ado_time_filter,
    get_orgs,
    get_pat,
    make_client,
    no_orgs_result,
    no_pat_result,
)

_MAX_PRS_PER_REPO = 100


def _strip_html(raw: str) -> str:
    text = HTML_TAG_RE.sub(" ", raw)
    text = html.unescape(text)
    return re.sub(r"\s+", " ", text).strip()


class AdoPrScan:
    meta = ModuleMeta(
        name="harvest.ado_pr_scan",
        phase=Phase.HARVEST,
        access=Access.READ,
        requires_browser=False,
        technique_ids=("T1552.001",),
        summary="Scan ADO pull request comments for exposed credentials (cred-engine).",
    )

    async def run(self, ctx: RunContext) -> RunResult:
        pat = await get_pat(ctx)
        if pat is None:
            return no_pat_result(ctx)

        orgs = get_orgs(ctx)
        if not orgs:
            return no_orgs_result(ctx)

        total_findings = 0
        prs_scanned = 0

        for org in sorted(orgs):
            ctx.console.print(f"[bold]PR comment scan: {org}[/]")
            client = make_client(org, pat, ctx)
            try:
                projects = await client.list_projects()
                proj_names = [p["name"] for p in projects if isinstance(p, dict) and "name" in p]

                for proj in proj_names:
                    n, scanned = await _scan_project_prs(ctx, client, org, proj)
                    total_findings += n
                    prs_scanned += scanned
            finally:
                await client.close()

        ctx.console.print(
            f"[green]Scanned {prs_scanned} PR(s), {total_findings} finding(s)[/]"
        )
        return RunResult(ok=True, written=total_findings)


async def _scan_project_prs(
    ctx: RunContext,
    client: Any,
    org: str,
    project: str,
) -> tuple[int, int]:
    try:
        repos = await client.list_repositories(project)
    except (ScopeError, AuthError):
        raise
    except Exception:  # noqa: BLE001
        return 0, 0

    findings = 0
    prs_scanned = 0

    valid_repos = [
        r for r in repos
        if isinstance(r, dict) and r.get("name") and r.get("id")
    ]

    async def _scan_repo(repo: dict[str, Any]) -> tuple[int, int]:
        repo_name = repo["name"]
        repo_id = repo["id"]
        try:
            prs = await client.list_pull_requests(
                project, repo_id, status="all", top=_MAX_PRS_PER_REPO,
            )
        except (ScopeError, AuthError):
            raise
        except Exception:  # noqa: BLE001
            return 0, 0

        valid_prs = [p for p in prs if isinstance(p, dict) and p.get("pullRequestId")]
        valid_prs = ado_time_filter(valid_prs, ctx.since, "creationDate", "closedDate")

        async def _fetch_threads(pr: dict[str, Any]) -> tuple[int, list[Any]]:
            pr_id = pr["pullRequestId"]
            try:
                threads = await client.get_pull_request_threads(project, repo_id, pr_id)
            except (ScopeError, AuthError):
                raise
            except Exception:  # noqa: BLE001
                threads = []
            return pr_id, threads

        thread_results = await asyncio.gather(
            *(_fetch_threads(pr) for pr in valid_prs),
            return_exceptions=True,
        )

        repo_findings = 0
        for pr, result in zip(valid_prs, thread_results):
            if isinstance(result, (ScopeError, AuthError)):
                raise result
            if isinstance(result, BaseException):
                continue
            pr_id, threads = result
            pr_title = pr.get("title", "")

            for thread in threads:
                if not isinstance(thread, dict):
                    continue
                for comment in thread.get("comments", []):
                    raw_content = comment.get("content", "")
                    if not raw_content:
                        continue
                    clean = _strip_html(raw_content)
                    if not clean:
                        continue

                    author = comment.get("author", {}).get(
                        "displayName",
                        comment.get("author", {}).get("uniqueName", "unknown"),
                    )

                    pr_url = (
                        f"https://dev.azure.com/{org}/{project}/_git/{repo_name}"
                        f"/pullrequest/{pr_id}"
                    )
                    resource = f"ado://{org}/{project}/{repo_name}/pr/{pr_id}"

                    n = scan_and_record(
                        ctx,
                        clean,
                        file_path=f"PR #{pr_id} comment",
                        repo=repo_name,
                        project=project,
                        org=org,
                        url=pr_url,
                        finding_kind="ado_pr_credential",
                        source_module="harvest.ado_pr_scan",
                        resource_id=resource,
                        extra_details={
                            "pr_id": pr_id,
                            "pr_title": pr_title[:80],
                            "comment_author": author,
                            "thread_id": thread.get("id", 0),
                        },
                    )
                    repo_findings += n
        return repo_findings, len(valid_prs)

    repo_results = await asyncio.gather(
        *(_scan_repo(r) for r in valid_repos),
        return_exceptions=True,
    )
    for r in repo_results:
        if isinstance(r, (ScopeError, AuthError)):
            raise r
        if isinstance(r, BaseException):
            continue
        findings += r[0]
        prs_scanned += r[1]

    return findings, prs_scanned
