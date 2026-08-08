"""Azure DevOps Code Search adapter for the credential scanner.

Uses AdoClient to search code across an ADO organization and return
SearchHit objects compatible with cred_engine.pipeline.process_hit().

The search uses the ADO Code Search REST API (almsearch.dev.azure.com)
and fetches full file content for each match via the Git Items API.
All calls are read-only.
"""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import quote

from cred_engine.ado_client import AdoClient
from cred_engine.patterns import CredPattern
from cred_engine.search import SearchHit

logger = logging.getLogger(__name__)

# ADO Code Search caps $top at 1000 and returns at most 1000 results total.
_PAGE_SIZE = 200
_MAX_RESULTS = 1000


def _build_web_url(org: str, project: str, repo: str, path: str, branch: str) -> str:
    """Build the ADO web URL for a file in a repository."""
    encoded_path = quote(path, safe="/")
    return (
        f"https://dev.azure.com/{org}/{quote(project, safe='')}"
        f"/_git/{quote(repo, safe='')}?path={encoded_path}&version=GB{quote(branch, safe='')}"
    )


def _normalize_path(path: str) -> str:
    """Strip the leading slash ADO returns on file paths."""
    return path.lstrip("/")


def search_ado_code(
    client: AdoClient,
    pattern: CredPattern,
    *,
    project: str = "",
) -> list[SearchHit]:
    """Search ADO code for a credential pattern and return SearchHit objects.

    For each search term in *pattern*, calls the ADO Code Search API via
    *client*.  For every result that matches, fetches the full file content
    so the pipeline can run regex extraction and entropy checks.

    Args:
        client: An authenticated AdoClient instance.
        pattern: The credential pattern whose search_terms to query.
        project: Optional project filter. When empty, searches the full org.

    Returns:
        A list of SearchHit objects ready for process_hit().
    """
    hits: list[SearchHit] = []
    seen: set[tuple[str, str, str]] = set()  # (project, repo, path) dedup

    for term in pattern.search_terms:
        results = _search_all_pages(client, term, project=project)

        for result in results:
            proj = result.get("project", {}).get("name", "")
            repo = result.get("repository", {}).get("name", "")
            raw_path = result.get("path", "")
            path = _normalize_path(raw_path)

            versions = result.get("versions") or []
            branch = versions[0].get("branchName", "main") if versions else "main"

            # Deduplicate: same file may appear for multiple search terms
            key = (proj, repo, path)
            if key in seen:
                continue
            seen.add(key)

            # Fetch full file content for regex/entropy analysis
            try:
                content = client.get_file_content(proj, repo, path, branch)
            except Exception:
                logger.debug(
                    "Could not fetch content for %s/%s/%s@%s — skipping",
                    proj,
                    repo,
                    path,
                    branch,
                )
                continue

            if not content:
                continue

            url = _build_web_url(client.org, proj, repo, path, branch)

            hits.append(
                SearchHit(
                    repo=repo,
                    file_path=path,
                    branch=branch,
                    content=content,
                    url=url,
                    project=proj,
                )
            )

    return hits


def _search_all_pages(
    client: AdoClient,
    search_text: str,
    *,
    project: str = "",
) -> list[dict[str, Any]]:
    """Paginate through ADO Code Search results for a single query.

    ADO Code Search supports ``$skip`` / ``$top`` pagination up to 1000
    total results.  We fetch pages of ``_PAGE_SIZE`` until we have all
    results or hit the cap.
    """
    all_results: list[dict[str, Any]] = []
    skip = 0

    while skip < _MAX_RESULTS:
        try:
            data = client.search_code(search_text, project=project, skip=skip, top=_PAGE_SIZE)
        except Exception:
            logger.warning(
                "Code search request failed for '%s' (skip=%d) — stopping pagination",
                search_text,
                skip,
            )
            break

        results = data.get("results", [])
        all_results.extend(results)

        total_count = data.get("count", 0)
        skip += len(results)

        # Stop when we have all results or an empty page
        if not results or skip >= total_count or skip >= _MAX_RESULTS:
            break

    return all_results
