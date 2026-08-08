"""harvest.ado_credential_scan — ADO credential scanning via cred-engine.

Scans Azure DevOps repositories and work items for exposed credentials.
Delegates all pattern matching, scoring, entropy validation, and fake
detection to the cred-engine library.  Results are written to Beachhead's
store (redacted) and secret store (plaintext).

Enumerates every repository in every project, then runs each scan query
per-repo so the result cap applies per-repo rather than per-project.

MITRE ATT&CK: T1552.001 (Unsecured Credentials: Credentials In Files)
               T1552.004 (Unsecured Credentials: Private Keys)
"""

from __future__ import annotations

import asyncio
from typing import Any
from urllib.parse import quote

from beachhead.core.clients.ado_search import CodeSearchResult
from beachhead.core.cred_bridge import (
    record_snippet_matches,
    scan_and_record,
    scan_snippet,
)
from beachhead.core.errors import AuthError, ScopeError
from beachhead.core.module import Access, ModuleMeta, Phase, RunContext, RunResult
from beachhead.modules.enumerate._ado_common import (
    HTML_TAG_RE,
    get_orgs,
    get_pat,
    make_client,
    no_orgs_result,
    no_pat_result,
)
from beachhead.modules.harvest.cred_patterns import SCAN_QUERIES, looks_like_credential

_ADO_WEB_BASE = "https://dev.azure.com"
_MAX_SNIPPET_FETCHES_PER_REPO = 50
_TREE_FETCH_BATCH = 20

_SCANNABLE_EXTENSIONS = frozenset({
    ".py", ".js", ".ts", ".jsx", ".tsx",
    ".json", ".yaml", ".yml", ".xml",
    ".config", ".cfg", ".ini", ".toml",
    ".env", ".properties",
    ".tf", ".tfvars",
    ".sh", ".bash", ".ps1", ".cmd", ".bat",
    ".cs", ".java", ".go", ".rb", ".php",
    ".bicep", ".sql",
})

_SCANNABLE_NAMES = frozenset({
    ".env", ".env.local", ".env.production", ".env.staging",
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
})


class AdoCredentialScan:
    meta = ModuleMeta(
        name="harvest.ado_credential_scan",
        phase=Phase.HARVEST,
        access=Access.READ,
        requires_browser=False,
        technique_ids=("T1552.001", "T1552.004"),
        summary="Scan ADO repos and work items for exposed credentials (cred-engine).",
    )

    async def run(self, ctx: RunContext) -> RunResult:
        pat = await get_pat(ctx)
        if pat is None:
            return no_pat_result(ctx)

        orgs = get_orgs(ctx)
        if not orgs:
            return no_orgs_result(ctx)

        total_findings = 0
        total_repos = 0

        for org in sorted(orgs):
            ctx.console.print(f"[bold]Credential scan: {org}[/]")
            client = make_client(org, pat, ctx)
            try:
                projects = await client.list_projects()
                proj_names = [
                    p["name"] for p in projects if isinstance(p, dict) and "name" in p
                ]
                if not proj_names:
                    ctx.console.print(f"  [yellow]No projects found in {org}[/]")
                    continue

                for proj in proj_names:
                    repos = await _list_repos(client, proj)
                    total_repos += len(repos)
                    ctx.console.print(f"  {proj}: {len(repos)} repo(s)")

                    for repo in repos:
                        repo_name = repo.get("name", "")
                        if not repo_name:
                            continue
                        default_branch = (
                            repo.get("defaultBranch", "refs/heads/main")
                            .removeprefix("refs/heads/")
                        )
                        total_findings += await _scan_repo(
                            ctx, client, org, proj, repo_name,
                            default_branch=default_branch,
                        )

                total_findings += await _scan_work_items(ctx, client, org, proj_names)

            finally:
                await client.close()

        actual = len(ctx.store.findings(run_id=ctx.run_id))
        ctx.console.print(
            f"[green]Credential scan complete: {total_repos} repo(s), "
            f"{total_findings} finding(s)[/]"
        )
        if actual != total_findings:
            ctx.console.print(
                f"  [yellow]Note: {actual} unique finding(s) in store "
                f"(duplicates deduplicated by ON CONFLICT)[/]"
            )
        return RunResult(
            ok=True,
            written=actual,
            details={"orgs_scanned": len(orgs), "repos_scanned": total_repos},
        )


async def _list_repos(client: Any, project: str) -> list[dict[str, Any]]:
    try:
        repos = await client.list_repositories(project)
    except (ScopeError, AuthError):
        raise
    except Exception:  # noqa: BLE001
        return []
    return [r for r in repos if isinstance(r, dict) and r.get("name")]


async def _scan_repo(
    ctx: RunContext,
    client: Any,
    org: str,
    project: str,
    repo_name: str,
    *,
    default_branch: str = "main",
) -> int:
    findings = 0

    # Primary: scan every scannable file via the repo tree.
    tree_findings, tree_fetches, tree_ok = await _scan_repo_tree(
        ctx, client, org, project, repo_name,
        branch=default_branch,
    )
    findings += tree_findings

    if tree_ok:
        ctx.console.print(
            f"    {repo_name}: {tree_fetches} file(s) scanned, "
            f"{findings} cred(s)"
        )
        return findings

    # Fallback: tree listing failed (PAT lacks Code scope) — use search.
    ctx.console.print(
        f"    {repo_name}: tree listing unavailable, falling back to search"
    )
    search_findings = await _scan_repo_via_search(
        ctx, client, org, project, repo_name,
    )
    findings += search_findings

    ctx.console.print(
        f"    {repo_name}: {findings} cred(s) (search fallback)"
    )
    return findings


async def _scan_repo_via_search(
    ctx: RunContext,
    client: Any,
    org: str,
    project: str,
    repo_name: str,
) -> int:
    """Fallback: find credentials via ALM Code Search when tree listing fails."""
    findings = 0
    snippet_fetches = 0
    covered_paths: set[str] = set()

    for query in SCAN_QUERIES:
        try:
            async for page in client.code_search_pages(
                project,
                query.search_text,
                page_size=25,
                max_results=200,
                filters={"Project": [project], "Repository": [repo_name]},
            ):
                for result in page:
                    if result.path in covered_paths:
                        continue
                    can_fetch = snippet_fetches < _MAX_SNIPPET_FETCHES_PER_REPO
                    n, fetched = await _process_code_result(
                        ctx, client, org, project, result,
                        fetch_content=can_fetch,
                    )
                    if fetched:
                        snippet_fetches += 1
                        covered_paths.add(result.path)
                    if n and n > 0:
                        covered_paths.add(result.path)
                        findings += n
        except (ScopeError, AuthError):
            raise
        except Exception:  # noqa: BLE001
            continue

    return findings


async def _process_code_result(
    ctx: RunContext,
    client: Any,
    org: str,
    project: str,
    result: CodeSearchResult,
    *,
    fetch_content: bool = True,
) -> tuple[int | None, bool]:
    """Returns (finding_count_or_None, did_fetch_file).

    A ``None`` finding count means no snippet was available (empty or
    unreadable); the caller counts these separately.
    """
    snippet_text = " ".join(result.snippets)
    clean_text = HTML_TAG_RE.sub("", snippet_text)
    fetched = False

    if not clean_text.strip():
        if not fetch_content:
            return None, False
        content = await client.get_file_content(
            project,
            result.repo_name,
            result.path,
            branch=result.branch or "main",
        )
        if not content:
            return None, True
        clean_text = content
        snippet_text = content
        fetched = True

    matches = scan_snippet(
        snippet_text,
        repo=result.repo_name,
        file_path=result.path,
        branch=result.branch or "main",
        skip_filters=True,
        find_all=True,
    )

    if not matches and not fetched and fetch_content:
        content = await client.get_file_content(
            project,
            result.repo_name,
            result.path,
            branch=result.branch or "main",
        )
        if content:
            fetched = True
            matches = scan_snippet(
                content,
                repo=result.repo_name,
                file_path=result.path,
                branch=result.branch or "main",
                skip_filters=True,
                find_all=True,
            )
            clean_text = content

    if not matches:
        return 0, fetched

    ado_url = _build_ado_url(org, project, result)
    resource = f"ado://{org}/{project}/{result.repo_name}"

    count = record_snippet_matches(
        ctx,
        matches,
        clean_text,
        finding_kind="ado_credential_exposure",
        source_module="harvest.ado_credential_scan",
        resource_id=resource,
        url=ado_url,
        org=org,
        project=project,
        repo=result.repo_name,
        file_path=result.path,
        branch=result.branch or "main",
        extra_details={
            "file_name": result.file_name,
            "content_id": result.content_id,
        },
    )
    return count, fetched


async def _scan_work_items(
    ctx: RunContext,
    client: Any,
    org: str,
    projects: list[str],
) -> int:
    findings = 0
    seen_wi: set[str] = set()
    wi_search_terms = [
        "password",
        "connection string",
        "secret key",
        "access key",
        "api key",
    ]

    for proj in projects:
        for search_text in wi_search_terms:
            try:
                _total, results = await client.work_item_search(proj, search_text, top=25)
                for wi in results:
                    wi_key = f"{proj}/{wi.work_item_id}"
                    if wi_key in seen_wi:
                        continue

                    snippet_text = " ".join(wi.snippets)
                    clean_text = HTML_TAG_RE.sub("", snippet_text)

                    if not looks_like_credential(clean_text):
                        continue

                    wi_url = f"{_ADO_WEB_BASE}/{org}/{proj}/_workitems/edit/{wi.work_item_id}"
                    resource = f"ado://{org}/{proj}/wi/{wi.work_item_id}"

                    ctx.store.insert_finding(
                        kind="ado_workitem_credential",
                        resource_id=resource,
                        reference=f"Work item #{wi.work_item_id}: {wi.title[:80]}",
                        run_id=ctx.run_id,
                        redacted=True,
                        details={
                            "work_item_id": wi.work_item_id,
                            "work_item_label": f"WI #{wi.work_item_id}",
                            "title": wi.title,
                            "type": wi.work_item_type,
                            "state": wi.state,
                            "project": proj,
                            "org": org,
                            "ado_url": wi_url,
                        },
                    )
                    if ctx.secrets is not None:
                        ctx.secrets.store_credential(
                            kind="ado_workitem_credential",
                            resource_id=resource,
                            reference=f"Work item #{wi.work_item_id}: {wi.title[:80]}",
                            run_id=ctx.run_id,
                            value=clean_text,
                            details={
                                "source_module": "harvest.ado_credential_scan",
                                "credential_type": "work_item_credential",
                                "context": f"WI #{wi.work_item_id}: {wi.title[:80]}",
                                "org": org,
                                "project": proj,
                                "work_item_id": wi.work_item_id,
                            },
                        )
                    seen_wi.add(wi_key)
                    findings += 1
            except (ScopeError, AuthError):
                raise
            except Exception:  # noqa: BLE001, S112
                continue

    return findings


def _is_scannable(path: str) -> bool:
    """Check if a file path has an extension worth scanning for credentials."""
    name = path.rsplit("/", 1)[-1] if "/" in path else path
    if name in _SCANNABLE_NAMES:
        return True
    dot = name.rfind(".")
    if dot == -1:
        return False
    return name[dot:].lower() in _SCANNABLE_EXTENSIONS


def _file_priority(path: str) -> int:
    """Lower = higher priority for credential scanning."""
    lower = path.lower()
    name = lower.rsplit("/", 1)[-1] if "/" in lower else lower
    if name.startswith(".env"):
        return 0
    if any(k in name for k in ("secret", "credential", "password")):
        return 0
    if any(k in name for k in ("config", "setting", "appsetting")):
        return 1
    dot = name.rfind(".")
    ext = name[dot:] if dot != -1 else ""
    if ext in (".json", ".yaml", ".yml", ".xml", ".properties", ".toml", ".ini", ".cfg"):
        return 2
    return 3


async def _scan_repo_tree(
    ctx: RunContext,
    client: Any,
    org: str,
    project: str,
    repo_name: str,
    *,
    branch: str = "main",
) -> tuple[int, int, bool]:
    """Scan all scannable files in the repo tree.

    Returns (findings_count, files_fetched, tree_ok).
    ``tree_ok`` is False when the tree listing itself failed (e.g. PAT
    lacks Code scope), signalling the caller to fall back to search.
    """
    try:
        all_paths = await client.list_repo_items(project, repo_name, branch=branch)
    except (ScopeError, AuthError):
        raise
    except Exception:  # noqa: BLE001
        return 0, 0, False

    scannable = [p for p in all_paths if _is_scannable(p)]
    scannable.sort(key=_file_priority)

    if not scannable:
        return 0, 0, True

    findings = 0
    fetches = 0

    for i in range(0, len(scannable), _TREE_FETCH_BATCH):
        batch = scannable[i : i + _TREE_FETCH_BATCH]
        results = await asyncio.gather(
            *(
                client.get_file_content(project, repo_name, p, branch=branch)
                for p in batch
            ),
            return_exceptions=True,
        )
        fetches += len(batch)

        for path, content in zip(batch, results):
            if isinstance(content, BaseException) or not content:
                continue

            count = scan_and_record(
                ctx,
                content,
                file_path=path,
                branch=branch,
                repo=repo_name,
                project=project,
                org=org,
                url=(
                    f"{_ADO_WEB_BASE}/{org}/{project}/_git/{repo_name}"
                    f"?path={quote(path, safe='/')}&version=GB{quote(branch, safe='')}"
                ),
                finding_kind="ado_credential_exposure",
                source_module="harvest.ado_credential_scan",
                resource_id=f"ado://{org}/{project}/{repo_name}",
                skip_filters=True,
                find_all=True,
            )
            findings += count

    return findings, fetches, True


def _build_ado_url(org: str, project: str, result: CodeSearchResult) -> str:
    branch = result.branch or "main"
    path = result.path
    return (
        f"{_ADO_WEB_BASE}/{org}/{project}/_git/{result.repo_name}"
        f"?path={quote(path, safe='/')}&version=GB{quote(branch, safe='')}"
    )
