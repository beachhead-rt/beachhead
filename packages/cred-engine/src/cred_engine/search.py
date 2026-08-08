"""Search adapter protocol — implement for your target platform.

This module defines the SearchHit protocol and provides a local filesystem
scanner as the default adapter. To scan a remote platform (GitHub, GitLab,
Bitbucket, ADO), implement a search function that returns SearchHit objects.

Example adapters are included as commented-out reference implementations.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path

from cred_engine.patterns import CredPattern

logger = logging.getLogger(__name__)


@dataclass
class SearchHit:
    """A single file that matched a credential search term."""

    repo: str
    file_path: str
    branch: str
    content: str
    url: str
    project: str = ""


def search_local(
    root: Path,
    pattern: CredPattern,
    *,
    repo_name: str = "",
) -> list[SearchHit]:
    """Scan local files under root for a credential pattern.

    Walks the directory tree, filters by extension, and checks each file
    for search term matches. This is the default adapter for scanning
    local checkouts or filesystem targets.
    """
    if not root.is_dir():
        return []

    name = repo_name or root.name
    hits: list[SearchHit] = []
    skip_dirs = {".git", "node_modules", "vendor", "__pycache__", ".venv", "venv", ".tox"}

    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in skip_dirs for part in path.parts):
            continue

        if pattern.extensions:
            ext = path.suffix.lstrip(".")
            if ext not in pattern.extensions:
                continue

        try:
            content = path.read_text(errors="replace")
        except OSError:
            continue

        if len(content) > 5_000_000:
            continue

        for term in pattern.search_terms:
            clean_term = re.sub(r"\s+ext:\S+", "", term).strip()
            if clean_term.lower() in content.lower():
                rel = str(path.relative_to(root))
                hits.append(SearchHit(
                    repo=name,
                    file_path=rel,
                    branch="local",
                    content=content,
                    url=str(path),
                ))
                break

    return hits


# ---------------------------------------------------------------------------
# Example: GitHub Code Search adapter (requires httpx)
# ---------------------------------------------------------------------------
#
# import httpx
#
# def search_github(
#     org: str,
#     token: str,
#     pattern: CredPattern,
# ) -> list[SearchHit]:
#     """Search code via GitHub Code Search API."""
#     hits: list[SearchHit] = []
#     for term in pattern.search_terms:
#         ext_filter = " ".join(f"path:*.{e}" for e in pattern.extensions)
#         q = f"org:{org} {term} {ext_filter}".strip()
#         resp = httpx.get(
#             "https://api.github.com/search/code",
#             params={"q": q, "per_page": 100},
#             headers={"Authorization": f"Bearer {token}"},
#         )
#         resp.raise_for_status()
#         for item in resp.json()["items"]:
#             content_resp = httpx.get(
#                 item["url"],
#                 headers={"Authorization": f"Bearer {token}"},
#             )
#             hits.append(SearchHit(
#                 repo=item["repository"]["full_name"],
#                 file_path=item["path"],
#                 branch=item["repository"]["default_branch"],
#                 content=content_resp.text,
#                 url=item["html_url"],
#             ))
#     return hits

# ---------------------------------------------------------------------------
# Example: Azure DevOps Code Search adapter
# ---------------------------------------------------------------------------
#
# import base64
# import json
# import urllib.request
#
# def search_ado(
#     org: str,
#     pat: str,
#     pattern: CredPattern,
#     project: str = "",
# ) -> list[SearchHit]:
#     """Search code via ADO Code Search API."""
#     creds = base64.b64encode(f":{pat}".encode()).decode()
#     headers = {
#         "Authorization": f"Basic {creds}",
#         "Content-Type": "application/json",
#     }
#     hits: list[SearchHit] = []
#     for term in pattern.search_terms:
#         body = json.dumps({
#             "searchText": term,
#             "$top": 200,
#             "filters": {"Project": [project]} if project else {},
#         }).encode()
#         url = f"https://almsearch.dev.azure.com/{org}/_apis/search/codesearchresults?api-version=7.1"
#         req = urllib.request.Request(url, data=body, headers=headers, method="POST")
#         with urllib.request.urlopen(req, timeout=30) as resp:
#             data = json.loads(resp.read())
#         for result in data.get("results", []):
#             repo_name = result["repository"]["name"]
#             file_path = result["path"].lstrip("/")
#             branch = result.get("versions", [{}])[0].get("branchName", "main")
#             # Fetch file content via Items API
#             content = _fetch_ado_file(org, pat, result["project"]["name"], repo_name, file_path, branch)
#             hits.append(SearchHit(
#                 repo=repo_name,
#                 file_path=file_path,
#                 branch=branch,
#                 content=content,
#                 url=result.get("url", ""),
#                 project=result["project"]["name"],
#             ))
#     return hits
