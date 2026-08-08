"""Thin Azure DevOps REST API client shared by all surface scanners.

Consolidates the ADO API calls needed by the 5 credential-scanning surfaces
(code search, work items, wikis, PRs, pipeline logs) behind a single
rate-limited httpx client. All calls are **read-only**.

Usage::

    with AdoClient(org="myorg", pat=os.environ["ADO_PAT"]) as ado:
        repos = ado.list_repositories("MyProject")
        results = ado.search_code("AccountKey=")
"""

from __future__ import annotations

import logging
import threading
import time
import urllib.parse
from typing import Any

import httpx

logger = logging.getLogger(__name__)

_API_VERSION = "7.1"


# ---------------------------------------------------------------------------
# Adaptive rate limiter (ported from dashboard/runner.py)
# ---------------------------------------------------------------------------


class AdaptiveRateLimiter:
    """Adaptive delay based on ADO rate-limit response headers.

    Adjusts the inter-request delay based on ``Retry-After``,
    ``X-RateLimit-Delay``, and ``X-RateLimit-Remaining``/``Limit`` headers
    that Azure DevOps returns on every response.
    """

    def __init__(self, base_delay: float = 0.1) -> None:
        self._base = base_delay
        self._delay = base_delay
        self._lock = threading.Lock()

    def process_headers(self, headers: Any) -> None:
        """Adjust delay based on response headers (works on 200s too)."""
        with self._lock:
            retry = headers.get("Retry-After")
            if retry:
                time.sleep(float(retry))
                self._delay = max(self._delay, 2.0)
                return

            x_delay = headers.get("X-RateLimit-Delay")
            if x_delay and float(x_delay) > 0:
                self._delay = max(self._delay, 1.0)
                return

            remaining = headers.get("X-RateLimit-Remaining")
            limit = headers.get("X-RateLimit-Limit")
            if remaining and limit:
                ratio = float(remaining) / max(float(limit), 1)
                if ratio < 0.20:
                    self._delay = 3.0
                elif ratio < 0.40:
                    self._delay = 1.0
                elif ratio < 0.60:
                    self._delay = 0.3
                else:
                    self._delay = self._base
            else:
                self._delay = max(self._delay * 0.9, self._base)

    def wait(self) -> None:
        """Sleep for the current adaptive delay."""
        time.sleep(self._delay)

    @property
    def current_delay(self) -> float:
        return self._delay


# ---------------------------------------------------------------------------
# ADO REST client
# ---------------------------------------------------------------------------


class AdoClient:
    """Read-only Azure DevOps REST client with adaptive rate limiting.

    Creates two ``httpx.Client`` instances -- one for the standard
    ``dev.azure.com`` host and one for ``vsrm.dev.azure.com`` (release
    management).  A third host, ``almsearch.dev.azure.com``, is used for
    code search via an explicit URL.

    Parameters
    ----------
    org:
        Azure DevOps organization name.
    pat:
        Personal Access Token for authentication.
    timeout:
        HTTP request timeout in seconds.
    base_delay:
        Starting inter-request delay for the adaptive rate limiter.
    """

    def __init__(
        self,
        org: str,
        pat: str,
        *,
        timeout: float = 30.0,
        base_delay: float = 0.1,
    ) -> None:
        self._org = org
        self._client = httpx.Client(
            base_url=f"https://dev.azure.com/{org}",
            auth=("", pat),
            timeout=timeout,
            headers={"Accept": "application/json"},
        )
        self._vsrm_client = httpx.Client(
            base_url=f"https://vsrm.dev.azure.com/{org}",
            auth=("", pat),
            timeout=timeout,
            headers={"Accept": "application/json"},
        )
        # Code-search requests are POSTed to almsearch.dev.azure.com and
        # need an explicit Content-Type header.
        self._search_client = httpx.Client(
            base_url=f"https://almsearch.dev.azure.com/{org}",
            auth=("", pat),
            timeout=timeout,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
        )
        self._rate_limiter = AdaptiveRateLimiter(base_delay=base_delay)

    # -- context manager / lifecycle ----------------------------------------

    def close(self) -> None:
        self._client.close()
        self._vsrm_client.close()
        self._search_client.close()

    def __enter__(self) -> AdoClient:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    @property
    def org(self) -> str:
        return self._org

    @property
    def rate_limiter(self) -> AdaptiveRateLimiter:
        """Expose the rate limiter for callers that need to inspect delay."""
        return self._rate_limiter

    # -- internal helpers ---------------------------------------------------

    def _get(
        self,
        path: str,
        *,
        params: dict[str, str] | None = None,
        client: httpx.Client | None = None,
    ) -> httpx.Response:
        """Rate-limited GET request."""
        c = client or self._client
        merged_params = {"api-version": _API_VERSION}
        if params:
            merged_params.update(params)
        self._rate_limiter.wait()
        try:
            resp = c.get(path, params=merged_params)
            self._rate_limiter.process_headers(resp.headers)
            resp.raise_for_status()
            return resp
        except httpx.HTTPError:
            logger.warning("GET %s failed", path, exc_info=True)
            raise

    def _post(
        self,
        path: str,
        *,
        json_body: Any = None,
        params: dict[str, str] | None = None,
        client: httpx.Client | None = None,
    ) -> httpx.Response:
        """Rate-limited POST request."""
        c = client or self._client
        merged_params = {"api-version": _API_VERSION}
        if params:
            merged_params.update(params)
        self._rate_limiter.wait()
        try:
            resp = c.post(path, json=json_body, params=merged_params)
            self._rate_limiter.process_headers(resp.headers)
            resp.raise_for_status()
            return resp
        except httpx.HTTPError:
            logger.warning("POST %s failed", path, exc_info=True)
            raise

    @staticmethod
    def _enc(value: str) -> str:
        """URL-encode a path segment (project name, repo name, etc.)."""
        return urllib.parse.quote(value, safe="")

    # ======================================================================
    # Code Search (almsearch.dev.azure.com)
    # ======================================================================

    def search_code(
        self,
        search_text: str,
        *,
        project: str = "",
        top: int = 1000,
        skip: int = 0,
    ) -> dict[str, Any]:
        """Search code across the organization (or within *project*).

        POST to ``almsearch.dev.azure.com/{org}/_apis/search/codesearchresults``.
        """
        base_path = ""
        if project:
            base_path = f"/{self._enc(project)}"
        path = f"{base_path}/_apis/search/codesearchresults"
        body: dict[str, Any] = {
            "searchText": search_text,
            "$top": top,
            "$skip": skip,
        }
        resp = self._post(
            path,
            json_body=body,
            params={"api-version": "7.1-preview.1"},
            client=self._search_client,
        )
        return resp.json()  # type: ignore[no-any-return]

    # ======================================================================
    # Git — repositories & file content
    # ======================================================================

    def list_repositories(self, project: str) -> list[dict[str, Any]]:
        """List Git repositories in *project*."""
        path = f"/{self._enc(project)}/_apis/git/repositories"
        try:
            resp = self._get(path)
            return resp.json().get("value", [])  # type: ignore[no-any-return]
        except httpx.HTTPError:
            return []

    def get_file_content(
        self,
        project: str,
        repo: str,
        path: str,
        *,
        branch: str = "",
    ) -> str:
        """Fetch raw file content from a Git repository.

        GET ``git/repositories/{repo}/items?path=...&includeContent=true``.
        Returns the file text, or an empty string on failure.
        """
        api_path = f"/{self._enc(project)}/_apis/git/repositories/{self._enc(repo)}/items"
        params: dict[str, str] = {
            "path": path,
            "includeContent": "true",
        }
        if branch:
            params["versionDescriptor.version"] = branch
            params["versionDescriptor.versionType"] = "branch"
        try:
            resp = self._get(api_path, params=params)
            return resp.text
        except httpx.HTTPError:
            return ""

    # ======================================================================
    # Builds & pipeline logs
    # ======================================================================

    def list_builds(
        self,
        project: str,
        *,
        top: int = 20,
    ) -> list[dict[str, Any]]:
        """List recent builds in *project*."""
        path = f"/{self._enc(project)}/_apis/build/builds"
        try:
            resp = self._get(path, params={"$top": str(top)})
            return resp.json().get("value", [])  # type: ignore[no-any-return]
        except httpx.HTTPError:
            return []

    def get_build_timeline(
        self,
        project: str,
        build_id: int,
    ) -> list[dict[str, Any]]:
        """Get timeline records for a build.

        GET ``build/builds/{id}/timeline``, returning the ``records`` array.
        """
        path = f"/{self._enc(project)}/_apis/build/builds/{build_id}/timeline"
        try:
            resp = self._get(path)
            return resp.json().get("records", [])  # type: ignore[no-any-return]
        except httpx.HTTPError:
            return []

    def get_build_log_lines(
        self,
        project: str,
        build_id: int,
        log_id: int,
    ) -> list[str]:
        """Fetch individual build log content as a list of lines.

        GET ``build/builds/{id}/logs/{logId}``.
        """
        path = f"/{self._enc(project)}/_apis/build/builds/{build_id}/logs/{log_id}"
        try:
            resp = self._get(path)
            return resp.text.split("\n")
        except httpx.HTTPError:
            return []

    # ======================================================================
    # Pull requests
    # ======================================================================

    def list_pull_requests(
        self,
        project: str,
        repo_id: str,
        *,
        status: str = "all",
        top: int = 100,
    ) -> list[dict[str, Any]]:
        """List pull requests for a repository.

        GET ``git/repositories/{repoId}/pullrequests``.
        """
        path = f"/{self._enc(project)}/_apis/git/repositories/{self._enc(repo_id)}/pullrequests"
        try:
            resp = self._get(
                path,
                params={
                    "searchCriteria.status": status,
                    "$top": str(top),
                },
            )
            return resp.json().get("value", [])  # type: ignore[no-any-return]
        except httpx.HTTPError:
            return []

    def get_pull_request_threads(
        self,
        project: str,
        repo_id: str,
        pr_id: int,
    ) -> list[dict[str, Any]]:
        """Get comment threads for a pull request.

        GET ``git/repositories/{repoId}/pullRequests/{prId}/threads``.
        """
        path = f"/{self._enc(project)}/_apis/git/repositories/{self._enc(repo_id)}/pullRequests/{pr_id}/threads"
        try:
            resp = self._get(path)
            return resp.json().get("value", [])  # type: ignore[no-any-return]
        except httpx.HTTPError:
            return []

    # ======================================================================
    # Work items
    # ======================================================================

    def query_workitems(
        self,
        project: str,
        wiql: str,
        *,
        top: int = 1000,
    ) -> list[int]:
        """Execute a WIQL query and return matching work-item IDs.

        POST ``wit/wiql``.
        """
        path = f"/{self._enc(project)}/_apis/wit/wiql"
        body = {"query": wiql}
        try:
            resp = self._post(
                path,
                json_body=body,
                params={"$top": str(top)},
            )
            rows = resp.json().get("workItems", [])
            return [int(row["id"]) for row in rows]
        except httpx.HTTPError:
            return []

    def get_workitems(
        self,
        ids: list[int],
        *,
        fields: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Fetch work items by ID (batched).

        GET ``wit/workitems?ids=1,2,3``.  The ADO API accepts up to 200 IDs
        per request; this method transparently batches larger lists.
        """
        if not ids:
            return []

        all_items: list[dict[str, Any]] = []
        batch_size = 200
        for start in range(0, len(ids), batch_size):
            batch = ids[start : start + batch_size]
            params: dict[str, str] = {"ids": ",".join(str(i) for i in batch)}
            if fields:
                params["fields"] = ",".join(fields)
            try:
                resp = self._get("/_apis/wit/workitems", params=params)
                all_items.extend(resp.json().get("value", []))
            except httpx.HTTPError:
                continue
        return all_items

    def get_workitem_comments(
        self,
        project: str,
        wi_id: int,
    ) -> list[dict[str, Any]]:
        """Fetch comments on a work item.

        GET ``wit/workItems/{id}/comments``.
        """
        path = f"/{self._enc(project)}/_apis/wit/workItems/{wi_id}/comments"
        try:
            resp = self._get(path)
            return resp.json().get("comments", [])  # type: ignore[no-any-return]
        except httpx.HTTPError:
            return []

    # ======================================================================
    # Wikis
    # ======================================================================

    def list_wikis(self, project: str) -> list[dict[str, Any]]:
        """List wikis in *project*."""
        path = f"/{self._enc(project)}/_apis/wiki/wikis"
        try:
            resp = self._get(path)
            return resp.json().get("value", [])  # type: ignore[no-any-return]
        except httpx.HTTPError:
            return []

    def get_wiki_page(
        self,
        project: str,
        wiki_id: str,
        path: str,
        *,
        include_content: bool = True,
        recursion_level: str = "none",
    ) -> dict[str, Any]:
        """Fetch a wiki page (optionally with content).

        GET ``wiki/wikis/{wikiId}/pages?path=...``.
        Returns an empty dict on failure.
        """
        api_path = f"/{self._enc(project)}/_apis/wiki/wikis/{self._enc(wiki_id)}/pages"
        params: dict[str, str] = {
            "path": path,
            "includeContent": str(include_content).lower(),
            "recursionLevel": recursion_level,
        }
        try:
            resp = self._get(api_path, params=params)
            return resp.json()  # type: ignore[no-any-return]
        except httpx.HTTPError:
            return {}
