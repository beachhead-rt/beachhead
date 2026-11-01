"""harvest.ado_wiki_scan — ADO wiki credential scanner via cred-engine.

Searches Azure DevOps wiki pages for exposed credentials using the ALM
Wiki Search API to identify candidate pages, then fetches the full page
content via the Wiki Pages API for accurate credential extraction.
Falls back to search snippets when full-page fetch is unavailable.

Read-only — never modifies ADO.

MITRE ATT&CK: T1552.001 (Unsecured Credentials: Credentials In Files)
"""

from __future__ import annotations

import asyncio
import re
from typing import Any
from urllib.parse import quote, unquote

from cred_engine.patterns import PATTERNS as _CE_PATTERNS

from beachhead.core.cred_bridge import record_snippet_matches, scan_text
from beachhead.modules.harvest.cred_patterns import build_custom_patterns
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

_WIKI_SEARCH_QUERIES = [
    "password",
    "connection string",
    "secret key",
    "access key",
    "api key",
    "credentials",
    "private key",
    "token",
    "login",
]

_PATTERN_TERMS: dict[str, list[list[str]]] = {}
for _p in _CE_PATTERNS:
    _PATTERN_TERMS[_p.name] = [
        re.sub(r"\s+ext:\S+", "", t).strip().lower().split()
        for t in _p.search_terms
    ]


def _pattern_relevance(pattern_name: str, content_lower: str) -> float:
    """Score how well a pattern's search terms match the content (0.0–1.0)."""
    terms_lists = _PATTERN_TERMS.get(pattern_name)
    if not terms_lists:
        return 0.0
    best = 0.0
    for words in terms_lists:
        if not words:
            continue
        hits = sum(1 for w in words if w in content_lower)
        best = max(best, hits / len(words))
    return best


def _sort_by_relevance(
    matches: list[dict[str, Any]], content: str
) -> list[dict[str, Any]]:
    """Sort matches so contextually-relevant patterns come before generic ones."""
    cl = content.lower()
    return sorted(matches, key=lambda m: -_pattern_relevance(m.get("pattern", ""), cl))


class AdoWikiScan:
    meta = ModuleMeta(
        name="harvest.ado_wiki_scan",
        phase=Phase.HARVEST,
        access=Access.READ,
        requires_browser=False,
        technique_ids=("T1552.001",),
        summary="Scan ADO wiki pages for exposed credentials (cred-engine).",
    )

    async def run(self, ctx: RunContext) -> RunResult:
        pat = await get_pat(ctx)
        if pat is None:
            return no_pat_result(ctx)

        orgs = get_orgs(ctx)
        if not orgs:
            return no_orgs_result(ctx)

        custom_terms: tuple[str, ...] = getattr(ctx.config, "custom_search_terms", ())
        custom_pats = build_custom_patterns(custom_terms) if custom_terms else None
        extra_search = list(custom_terms)
        if custom_terms:
            ctx.console.print(
                f"[dim]Custom search terms active: {len(custom_terms)} term(s)[/]"
            )

        total_findings = 0
        total_pages_scanned = 0

        if ctx.since:
            ctx.console.print(
                "[dim]Time filter active — limiting to recently updated projects[/]"
            )

        for org in sorted(orgs):
            ctx.console.print(f"[bold]Wiki scan: {org}[/]")
            client = make_client(org, pat, ctx)
            try:
                projects = await client.list_projects()
                projects = ado_time_filter(projects, ctx.since, "lastUpdateTime")
                proj_names = [
                    p["name"] for p in projects if isinstance(p, dict) and "name" in p
                ]
                for proj in proj_names:
                    page_map = await _discover_all_pages(
                        ctx, client, proj, extra_search=extra_search,
                    )

                    total_pages_scanned += len(page_map)
                    scan_results = await asyncio.gather(
                        *(_scan_wiki_page(
                            ctx, client, org, proj, info,
                            extra_patterns=custom_pats,
                          )
                          for info in page_map.values()),
                        return_exceptions=True,
                    )
                    for r in scan_results:
                        if isinstance(r, (ScopeError, AuthError)):
                            raise r
                        if isinstance(r, BaseException):
                            continue
                        total_findings += r
            finally:
                await client.close()

        ctx.console.print(
            f"[green]Scanned {total_pages_scanned} wiki page(s), "
            f"{total_findings} finding(s)[/]"
        )
        return RunResult(ok=True, written=total_findings)


async def _discover_all_pages(
    ctx: RunContext, client: Any, project: str,
    *, extra_search: list[str] | None = None,
) -> dict[str, "_PageInfo"]:
    """Discover wiki pages — enumerate directly, fall back to search."""
    page_map: dict[str, _PageInfo] = {}

    try:
        wikis = await client.list_wikis(project)
    except (ScopeError, AuthError):
        raise
    except Exception:  # noqa: BLE001
        wikis = []

    if wikis:
        for wiki in wikis:
            if not isinstance(wiki, dict):
                continue
            wiki_name = wiki.get("name", "")
            if not wiki_name:
                continue
            try:
                paths = await client.list_wiki_pages(project, wiki_name)
            except (ScopeError, AuthError):
                raise
            except Exception:  # noqa: BLE001
                paths = []

            ctx.console.print(
                f"  [dim]wiki[/] {wiki_name}: {len(paths)} page(s)"
            )
            for path in paths:
                key = f"{wiki_name}/{path}"
                if key not in page_map:
                    page_map[key] = _PageInfo(
                        wiki_name=wiki_name,
                        page_path=path,
                        project_name=project,
                        dedup_key=key,
                    )

    if not page_map:
        ctx.console.print(
            f"  [dim]No wikis enumerated for {project} — "
            f"falling back to search-based discovery[/]"
        )
        search_queries = list(_WIKI_SEARCH_QUERIES)
        if extra_search:
            for t in extra_search:
                if t not in search_queries:
                    search_queries.append(t)
        pages = _collect_pages(client, project, search_queries)
        async for info in pages:
            page_map.setdefault(info.dedup_key, info).snippets.update(
                info.snippets
            )

    return page_map


class _PageInfo:
    """Accumulated info for a single wiki page across search queries."""

    __slots__ = ("wiki_name", "page_path", "project_name", "dedup_key", "snippets")

    def __init__(
        self, wiki_name: str, page_path: str, project_name: str, dedup_key: str
    ) -> None:
        self.wiki_name = wiki_name
        self.page_path = page_path
        self.project_name = project_name
        self.dedup_key = dedup_key
        self.snippets: set[str] = set()


async def _collect_pages(
    client: Any, project: str, queries: list[str]
) -> Any:
    """Yield _PageInfo for every search hit, accumulating snippets."""
    for query in queries:
        try:
            _total, results = await client.wiki_search(project, query, top=25)
        except (ScopeError, AuthError):
            raise
        except Exception:  # noqa: BLE001, S112
            continue
        for result in results:
            path = unquote(result.page_path)
            wiki = unquote(result.wiki_name)
            key = f"{wiki}/{path}"
            info = _PageInfo(
                wiki_name=wiki,
                page_path=path,
                project_name=result.project_name,
                dedup_key=key,
            )
            info.snippets.update(result.snippets)
            yield info


_MAX_WIKI_PAGE_SIZE = 500_000


async def _try_get_wiki_page(
    client: Any, project: str, wiki_name: str, page_path: str
) -> str | None:
    """Try fetching wiki page content, attempting path variations on failure.

    Wiki search returns paths with ``.md`` but the Pages API uses bare paths,
    so try the stripped version first to avoid a needless 404.
    Pages exceeding ``_MAX_WIKI_PAGE_SIZE`` are skipped.
    """
    if page_path.endswith(".md"):
        bare = page_path[:-3]
        content = await client.get_wiki_page(project, wiki_name, bare)
        if content and content.strip() and len(content) <= _MAX_WIKI_PAGE_SIZE:
            return content
        content = await client.get_wiki_page(project, wiki_name, page_path)
        if content and content.strip() and len(content) <= _MAX_WIKI_PAGE_SIZE:
            return content
    else:
        content = await client.get_wiki_page(project, wiki_name, page_path)
        if content and content.strip() and len(content) <= _MAX_WIKI_PAGE_SIZE:
            return content
        content = await client.get_wiki_page(project, wiki_name, page_path + ".md")
        if content and content.strip() and len(content) <= _MAX_WIKI_PAGE_SIZE:
            return content

    return None


async def _scan_wiki_page(
    ctx: RunContext,
    client: Any,
    org: str,
    project: str,
    info: _PageInfo,
    *,
    extra_patterns: list[Any] | None = None,
) -> int:
    """Fetch full wiki page content and scan it; fall back to snippets."""
    page_url = (
        f"https://dev.azure.com/{org}/{project}/_wiki/wikis/{info.wiki_name}"
        f"?pagePath={quote(info.page_path, safe='')}"
    )
    resource = f"ado://{org}/{project}/wiki/{info.wiki_name}"

    content = await _try_get_wiki_page(
        client, project, info.wiki_name, info.page_path
    )
    if content:
        matches = scan_text(
            content,
            file_path=info.page_path,
            repo=info.wiki_name,
            skip_filters=True,
            find_all=True,
            extra_patterns=extra_patterns,
        )
        if matches:
            matches = _sort_by_relevance(matches, content)
            unique_secrets = {m.get("_raw_secret", "") for m in matches} - {""}
            ctx.console.print(
                f"  [dim]page[/] {info.page_path} — full-page ({len(content)} chars), "
                f"{len(matches)} match(es), {len(unique_secrets)} unique secret(s)"
            )
            return record_snippet_matches(
                ctx,
                matches,
                content,
                finding_kind="ado_wiki_credential",
                source_module="harvest.ado_wiki_scan",
                resource_id=resource,
                url=page_url,
                org=org,
                project=project,
                repo=info.wiki_name,
                file_path=info.page_path,
                extra_details={
                    "wiki_name": info.wiki_name,
                    "page_path": info.page_path,
                },
            )
        ctx.console.print(
            f"  [dim]page[/] {info.page_path} — full-page ({len(content)} chars), "
            f"0 matches"
        )
        return 0

    ctx.console.print(
        f"  [yellow]page[/] {info.page_path} — full-page fetch failed, "
        f"falling back to snippets ({len(info.snippets)})"
    )

    if not info.snippets:
        return 0

    clean_text = HTML_TAG_RE.sub("", "\n".join(info.snippets))
    if not clean_text.strip():
        return 0

    matches = scan_text(
        clean_text,
        file_path=info.page_path,
        repo=info.wiki_name,
        skip_filters=True,
        find_all=True,
        extra_patterns=extra_patterns,
    )
    if not matches:
        return 0

    matches = _sort_by_relevance(matches, clean_text)
    unique_secrets = {m.get("_raw_secret", "") for m in matches} - {""}
    ctx.console.print(
        f"  [dim]page[/] {info.page_path} — snippets, "
        f"{len(matches)} match(es), {len(unique_secrets)} unique secret(s)"
    )

    return record_snippet_matches(
        ctx,
        matches,
        clean_text,
        finding_kind="ado_wiki_credential",
        source_module="harvest.ado_wiki_scan",
        resource_id=resource,
        url=page_url,
        org=org,
        project=project,
        repo=info.wiki_name,
        file_path=info.page_path,
        extra_details={
            "wiki_name": info.wiki_name,
            "page_path": info.page_path,
        },
    )
