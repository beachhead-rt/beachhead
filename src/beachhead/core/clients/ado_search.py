"""Azure DevOps ALM Search + REST API client — PAT-auth, TSTU-rate-limited.

Uses PAT-based Basic auth (base64-encoded
``:PAT``). Rate limiting tracks TSTUs (200 per sliding 5-min window) and
honors ``Retry-After`` / ``X-RateLimit-*`` response headers.

Two API surfaces share one client:
  - Regular ADO REST API (``dev.azure.com/{org}/_apis/...``)
  - ALM Search API (``almsearch.dev.azure.com/{org}/{project}/_apis/search/...``)

All calls are scope-checked (kind="ado") and audited (command shape only).
"""

from __future__ import annotations

import asyncio
import base64
import logging
import random
import re
import time
from collections import deque
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import Any

import httpx

from beachhead.core.errors import ApiError, AuthError, Throttled, Transient
from beachhead.core.module import AuditLog, ScopeGuard

logger = logging.getLogger(__name__)

__all__ = [
    "AdoSearchClient",
    "CodeSearchResult",
    "WikiSearchResult",
    "WorkItemSearchResult",
]

_REST_BASE = "https://dev.azure.com"
_EXTMGMT_BASE = "https://extmgmt.dev.azure.com"
_SEARCH_BASE = "https://almsearch.dev.azure.com"
_API_VERSION = "7.1"
_USER_AGENT = "Beachhead/0.1"

_MAX_RETRIES = 5
_BACKOFF_BASE = 1.0
_BACKOFF_CAP = 60.0
_DEFAULT_CONCURRENCY = 5

_UNSAFE_PATH_CHARS = re.compile(r"[/\\?#%\x00-\x1f]")


def _parse_permission_response(data: Any) -> bool:
    """Parse the response from GET /_apis/permissions.

    The API may return:
      - a bare boolean: ``True`` / ``False``
      - a string: ``"true"`` / ``"false"``
      - a dict with a value array: ``{"count": 1, "value": [true]}``
    """
    if isinstance(data, bool):
        return data
    if isinstance(data, dict):
        values = data.get("value", [])
        if isinstance(values, list) and values:
            return bool(values[0])
        return False
    if isinstance(data, str):
        return data.strip().lower() == "true"
    return bool(data)


def _check_path_safe(value: str, label: str) -> None:
    if _UNSAFE_PATH_CHARS.search(value):
        raise ValueError(f"{label} contains unsafe URL path characters: {value!r}")

_TSTU_WINDOW_SECS = 300
_TSTU_BUDGET = 200


@dataclass(frozen=True, slots=True)
class CodeSearchResult:
    """One file match from ALM code search."""

    file_name: str
    path: str
    repo_name: str
    repo_url: str
    project_name: str
    branch: str
    content_id: str
    snippets: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class WorkItemSearchResult:
    """One work item match from ALM work-item search."""

    work_item_id: int
    title: str
    work_item_type: str
    state: str
    project_name: str
    snippets: tuple[str, ...]
    url: str


@dataclass(frozen=True, slots=True)
class WikiSearchResult:
    """One wiki page match from ALM wiki search."""

    wiki_name: str
    page_path: str
    project_name: str
    snippets: tuple[str, ...]


@dataclass
class _TstuTracker:
    """Sliding-window TSTU budget tracker (200 TSTUs per 5-min window)."""

    budget: int = _TSTU_BUDGET
    window_secs: float = _TSTU_WINDOW_SECS
    _ledger: deque[tuple[float, int]] = field(default_factory=deque)

    def _prune(self, now: float) -> None:
        cutoff = now - self.window_secs
        while self._ledger and self._ledger[0][0] <= cutoff:
            self._ledger.popleft()

    def remaining(self) -> int:
        self._prune(time.monotonic())
        spent = sum(c for _, c in self._ledger)
        return max(0, self.budget - spent)

    def record(self, cost: int) -> None:
        self._ledger.append((time.monotonic(), cost))

    async def wait_if_needed(self, cost: int) -> None:
        while self.remaining() < cost:
            self._prune(time.monotonic())
            if not self._ledger:
                break
            oldest = self._ledger[0][0]
            wait = (oldest + self.window_secs) - time.monotonic() + 0.5
            if wait > 0:
                await asyncio.sleep(wait)
            self._prune(time.monotonic())


class AdoSearchClient:
    """Async ADO ALM Search + REST API client.

    Not on RunContext — modules construct from ``ctx.auth.get("ado")`` or an
    injected PAT. The client handles scope checks, auditing, rate limiting, and
    retries so modules don't reinvent them.
    """

    def __init__(
        self,
        *,
        org: str,
        pat: str,
        scope: ScopeGuard,
        audit: AuditLog,
        run_id: str,
        max_concurrency: int = _DEFAULT_CONCURRENCY,
    ) -> None:
        _check_path_safe(org, "org")
        self._org = org
        self._scope = scope
        self._audit = audit
        self._run_id = run_id
        self._sem = asyncio.Semaphore(max_concurrency)
        self._tstu = _TstuTracker()

        encoded = base64.b64encode(f":{pat}".encode()).decode()
        self._auth_header = f"Basic {encoded}"
        self._client: httpx.AsyncClient | None = None
        self._client_lock = asyncio.Lock()

    async def _ensure_client(self) -> httpx.AsyncClient:
        async with self._client_lock:
            if self._client is None or self._client.is_closed:
                self._client = httpx.AsyncClient(
                    headers={
                        "User-Agent": _USER_AGENT,
                        "Authorization": self._auth_header,
                    },
                    timeout=httpx.Timeout(30.0, connect=10.0),
                )
            return self._client

    async def close(self) -> None:
        if self._client is not None and not self._client.is_closed:
            await self._client.aclose()

    async def __aenter__(self) -> AdoSearchClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()

    @property
    def tstu_remaining(self) -> int:
        return self._tstu.remaining()

    # ------------------------------------------------------------------
    # Public API: REST
    # ------------------------------------------------------------------
    def _safe(self, value: str, label: str) -> str:
        """Validate a path-interpolated parameter and return it."""
        _check_path_safe(value, label)
        return value

    async def list_projects(self) -> list[dict[str, Any]]:
        """GET all projects in the org via the ADO Core API."""
        self._scope.check(self._org, kind="ado")
        url = f"{_REST_BASE}/{self._org}/_apis/projects"
        data = await self._get(url, params={"api-version": _API_VERSION})
        return data.get("value", []) if isinstance(data, dict) else []

    async def list_pipelines(self, project: str) -> list[dict[str, Any]]:
        """GET YAML pipelines in a project."""
        self._scope.check(self._org, kind="ado")
        self._safe(project, "project")
        url = f"{_REST_BASE}/{self._org}/{project}/_apis/pipelines"
        data = await self._get(url, params={"api-version": _API_VERSION})
        return data.get("value", []) if isinstance(data, dict) else []

    async def list_build_definitions(self, project: str) -> list[dict[str, Any]]:
        """GET build definitions in a project (includes process metadata)."""
        self._scope.check(self._org, kind="ado")
        self._safe(project, "project")
        url = f"{_REST_BASE}/{self._org}/{project}/_apis/build/definitions"
        data = await self._get(
            url,
            params={"api-version": _API_VERSION, "includeAllProperties": "true"},
        )
        return data.get("value", []) if isinstance(data, dict) else []

    async def get_build_definition(self, project: str, definition_id: int) -> dict[str, Any]:
        """GET a specific build definition (includes variables, tasks)."""
        self._scope.check(self._org, kind="ado")
        self._safe(project, "project")
        url = f"{_REST_BASE}/{self._org}/{project}/_apis/build/definitions/{definition_id}"
        data = await self._get(url, params={"api-version": _API_VERSION})
        return data if isinstance(data, dict) else {}

    async def list_release_definitions(self, project: str) -> list[dict[str, Any]]:
        """GET classic release definitions (vsrm host)."""
        self._scope.check(self._org, kind="ado")
        self._safe(project, "project")
        url = f"https://vsrm.dev.azure.com/{self._org}/{project}/_apis/release/definitions"
        data = await self._get(
            url,
            params={"api-version": _API_VERSION},
            audit_action="ado.release_definitions",
        )
        return data.get("value", []) if isinstance(data, dict) else []

    async def list_service_connections(self, project: str) -> list[dict[str, Any]]:
        """GET service endpoints in a project."""
        self._scope.check(self._org, kind="ado")
        self._safe(project, "project")
        url = f"{_REST_BASE}/{self._org}/{project}/_apis/serviceendpoint/endpoints"
        data = await self._get(
            url,
            params={"api-version": _API_VERSION},
            audit_action="ado.service_connections",
        )
        return data.get("value", []) if isinstance(data, dict) else []

    async def list_agent_pools(self) -> list[dict[str, Any]]:
        """GET agent pools (org-level)."""
        self._scope.check(self._org, kind="ado")
        url = f"{_REST_BASE}/{self._org}/_apis/distributedtask/pools"
        data = await self._get(
            url,
            params={"api-version": _API_VERSION},
            audit_action="ado.agent_pools",
        )
        return data.get("value", []) if isinstance(data, dict) else []

    async def list_pool_agents(
        self, pool_id: int, *, include_capabilities: bool = True
    ) -> list[dict[str, Any]]:
        """GET agents in a pool."""
        self._scope.check(self._org, kind="ado")
        params: dict[str, str] = {"api-version": _API_VERSION}
        if include_capabilities:
            params["includeCapabilities"] = "true"
        url = f"{_REST_BASE}/{self._org}/_apis/distributedtask/pools/{pool_id}/agents"
        data = await self._get(url, params=params, audit_action="ado.pool_agents")
        return data.get("value", []) if isinstance(data, dict) else []

    async def list_variable_groups(self, project: str) -> list[dict[str, Any]]:
        """GET variable groups in a project."""
        self._scope.check(self._org, kind="ado")
        self._safe(project, "project")
        url = f"{_REST_BASE}/{self._org}/{project}/_apis/distributedtask/variablegroups"
        data = await self._get(
            url,
            params={"api-version": _API_VERSION},
            audit_action="ado.variable_groups",
        )
        return data.get("value", []) if isinstance(data, dict) else []

    # ------------------------------------------------------------------
    # Public API: Repos
    # ------------------------------------------------------------------
    async def list_repositories(self, project: str) -> list[dict[str, Any]]:
        """GET Git repositories in a project."""
        self._scope.check(self._org, kind="ado")
        self._safe(project, "project")
        url = f"{_REST_BASE}/{self._org}/{project}/_apis/git/repositories"
        data = await self._get(
            url, params={"api-version": _API_VERSION}, audit_action="ado.repositories"
        )
        return data.get("value", []) if isinstance(data, dict) else []

    async def list_refs(self, project: str, repository_id: str) -> list[dict[str, Any]]:
        """GET refs (branches/tags) for a repository."""
        self._scope.check(self._org, kind="ado")
        self._safe(project, "project")
        self._safe(repository_id, "repository_id")
        url = f"{_REST_BASE}/{self._org}/{project}/_apis/git/repositories/{repository_id}/refs"
        data = await self._get(url, params={"api-version": _API_VERSION}, audit_action="ado.refs")
        return data.get("value", []) if isinstance(data, dict) else []

    async def update_refs(
        self, project: str, repository_id: str, ref_updates: list[dict[str, str]],
    ) -> list[dict[str, Any]]:
        """POST to create, update, or delete refs (branches/tags)."""
        self._scope.check(self._org, kind="ado")
        self._safe(project, "project")
        self._safe(repository_id, "repository_id")
        url = (
            f"{_REST_BASE}/{self._org}/{project}"
            f"/_apis/git/repositories/{repository_id}/refs"
        )
        data = await self._post(
            url,
            json=ref_updates,
            params={"api-version": _API_VERSION},
            audit_action="ado.update_refs",
        )
        return data.get("value", []) if isinstance(data, dict) else []

    async def create_push(
        self,
        project: str,
        repository_id: str,
        *,
        ref_name: str,
        old_object_id: str,
        path: str,
        content: str,
        comment: str,
    ) -> dict[str, Any]:
        """POST a push (single-file edit commit) to a repo branch."""
        self._scope.check(self._org, kind="ado")
        self._safe(project, "project")
        self._safe(repository_id, "repository_id")
        url = (
            f"{_REST_BASE}/{self._org}/{project}"
            f"/_apis/git/repositories/{repository_id}/pushes"
        )
        body = {
            "refUpdates": [{"name": ref_name, "oldObjectId": old_object_id}],
            "commits": [{
                "comment": comment,
                "changes": [{
                    "changeType": "edit",
                    "item": {"path": path},
                    "newContent": {"content": content, "contentType": "rawtext"},
                }],
            }],
        }
        data = await self._post(
            url,
            json=body,
            params={"api-version": _API_VERSION},
            audit_action="ado.create_push",
        )
        return data if isinstance(data, dict) else {}

    async def list_policy_configurations(self, project: str) -> list[dict[str, Any]]:
        """GET branch policy configurations in a project."""
        self._scope.check(self._org, kind="ado")
        self._safe(project, "project")
        url = f"{_REST_BASE}/{self._org}/{project}/_apis/policy/configurations"
        data = await self._get(
            url, params={"api-version": _API_VERSION}, audit_action="ado.policy_configurations"
        )
        return data.get("value", []) if isinstance(data, dict) else []

    async def list_pull_requests(
        self,
        project: str,
        repository_id: str,
        *,
        top: int = 50,
        status: str = "completed",
    ) -> list[dict[str, Any]]:
        """GET recent pull requests for a repository."""
        self._scope.check(self._org, kind="ado")
        self._safe(project, "project")
        self._safe(repository_id, "repository_id")
        url = (
            f"{_REST_BASE}/{self._org}/{project}"
            f"/_apis/git/repositories/{repository_id}/pullrequests"
        )
        data = await self._get(
            url,
            params={
                "api-version": _API_VERSION,
                "searchCriteria.status": status,
                "$top": str(top),
            },
            audit_action="ado.pull_requests",
        )
        return data.get("value", []) if isinstance(data, dict) else []

    async def get_pull_request_threads(
        self,
        project: str,
        repository_id: str,
        pull_request_id: int,
    ) -> list[dict[str, Any]]:
        """GET comment threads for a pull request."""
        self._scope.check(self._org, kind="ado")
        self._safe(project, "project")
        self._safe(repository_id, "repository_id")
        url = (
            f"{_REST_BASE}/{self._org}/{project}"
            f"/_apis/git/repositories/{repository_id}"
            f"/pullRequests/{pull_request_id}/threads"
        )
        data = await self._get(
            url,
            params={"api-version": _API_VERSION},
            audit_action="ado.pr_threads",
        )
        return data.get("value", []) if isinstance(data, dict) else []

    # ------------------------------------------------------------------
    # Public API: Feeds
    # ------------------------------------------------------------------
    async def list_feeds(self, project: str | None = None) -> list[dict[str, Any]]:
        """GET packaging feeds (project-scoped if project given, else org-scoped)."""
        self._scope.check(self._org, kind="ado")
        if project is not None:
            self._safe(project, "project")
            url = f"{_REST_BASE}/{self._org}/{project}/_apis/packaging/feeds"
        else:
            url = f"{_REST_BASE}/{self._org}/_apis/packaging/feeds"
        data = await self._get(url, params={"api-version": _API_VERSION}, audit_action="ado.feeds")
        return data.get("value", []) if isinstance(data, dict) else []

    async def list_feed_packages(
        self, feed_id: str, project: str | None = None, *, top: int = 100
    ) -> list[dict[str, Any]]:
        """GET packages in a feed."""
        self._scope.check(self._org, kind="ado")
        self._safe(feed_id, "feed_id")
        if project is not None:
            self._safe(project, "project")
            url = f"{_REST_BASE}/{self._org}/{project}/_apis/packaging/feeds/{feed_id}/packages"
        else:
            url = f"{_REST_BASE}/{self._org}/_apis/packaging/feeds/{feed_id}/packages"
        data = await self._get(
            url,
            params={"api-version": _API_VERSION, "$top": str(top)},
            audit_action="ado.feed_packages",
        )
        return data.get("value", []) if isinstance(data, dict) else []

    # ------------------------------------------------------------------
    # Public API: Permissions
    # ------------------------------------------------------------------
    async def list_security_namespaces(self) -> list[dict[str, Any]]:
        """GET all security namespaces in the org."""
        self._scope.check(self._org, kind="ado")
        url = f"{_REST_BASE}/{self._org}/_apis/securitynamespaces"
        data = await self._get(
            url, params={"api-version": _API_VERSION}, audit_action="ado.security_namespaces"
        )
        return data.get("value", []) if isinstance(data, dict) else []

    async def list_access_control_lists(
        self,
        namespace_id: str,
        *,
        token: str | None = None,
        recurse: bool = False,
        include_extended_info: bool = False,
    ) -> list[dict[str, Any]]:
        """GET access control lists for a security namespace."""
        self._scope.check(self._org, kind="ado")
        self._safe(namespace_id, "namespace_id")
        url = f"{_REST_BASE}/{self._org}/_apis/accesscontrollists/{namespace_id}"
        params: dict[str, str] = {"api-version": _API_VERSION}
        if token is not None:
            params["token"] = token
        if recurse:
            params["recurse"] = "true"
        if include_extended_info:
            params["includeExtendedInfo"] = "true"
        data = await self._get(url, params=params, audit_action="ado.access_control_lists")
        return data.get("value", []) if isinstance(data, dict) else []

    async def evaluate_permissions_batch(
        self,
        evaluations: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Check the current caller's effective permissions.

        Each evaluation dict must contain:
          - ``securityNamespaceId`` — the namespace GUID
          - ``token`` — the ACL token (e.g. ``endpoints/{project_id}/{endpoint_id}``)
          - ``permissions`` — integer bitmask to check

        Returns the list with ``value`` (bool) populated per evaluation.

        Tries the batch POST first; falls back to per-permission GET
        (``/_apis/permissions``) if the batch endpoint fails.
        """
        self._scope.check(self._org, kind="ado")

        # Try batch POST first — most reliable when the endpoint works
        url = (
            f"{_REST_BASE}/{self._org}"
            "/_apis/security/permissionevaluationbatch"
        )
        body = {
            "alwaysAllowAdministrators": True,
            "evaluations": evaluations,
        }
        try:
            data = await self._post(
                url,
                json=body,
                params={"api-version": _API_VERSION},
                audit_action="ado.permission_evaluation_batch",
            )
            if isinstance(data, dict):
                results = data.get("value", data.get("evaluations", []))
                if results and len(results) == len(evaluations):
                    return results
        except Exception:  # noqa: BLE001, S110
            pass

        # Fall back to per-permission GET
        return await self._evaluate_permissions_individually(evaluations)

    async def _evaluate_permissions_individually(
        self,
        evaluations: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Check each permission via the GET has-permission API.

        Falls back to ACL lookup when the permissions endpoint 500s.
        """

        async def _check_one(ev: dict[str, Any]) -> dict[str, Any]:
            ns_id = ev.get("securityNamespaceId", "")
            token = ev.get("token", "")
            perms = ev.get("permissions", 0)
            url = (
                f"{_REST_BASE}/{self._org}"
                f"/_apis/permissions/{ns_id}/{perms}"
            )
            try:
                data = await self._get(
                    url,
                    params={
                        "api-version": _API_VERSION,
                        "token": token,
                        "alwaysAllowAdministrators": "true",
                    },
                    audit_action="ado.has_permission",
                )
                has_perm = _parse_permission_response(data)
                return {**ev, "value": has_perm}
            except Exception as exc:  # noqa: BLE001
                return {**ev, "value": None, "_error": exc}

        results = list(await asyncio.gather(*[_check_one(ev) for ev in evaluations]))

        # If all results are None (API 500s), fall back to ACL lookup
        if all(r.get("value") is None for r in results):
            acl_results = await self._evaluate_via_acls(evaluations)
            if acl_results is not None:
                return acl_results

        return results

    async def _evaluate_via_acls(
        self,
        evaluations: list[dict[str, Any]],
    ) -> list[dict[str, Any]] | None:
        """Fallback: check permissions by reading ACL entries directly."""
        by_key: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for ev in evaluations:
            key = (ev.get("securityNamespaceId", ""), ev.get("token", ""))
            by_key.setdefault(key, []).append(ev)

        async def _check_group(
            key: tuple[str, str], evs: list[dict[str, Any]],
        ) -> list[dict[str, Any]] | None:
            ns_id, token = key
            try:
                acls = await self.list_access_control_lists(
                    ns_id, token=token, include_extended_info=True,
                )
            except Exception:  # noqa: BLE001
                return None

            results: list[dict[str, Any]] = []
            for ev in evs:
                bit = ev.get("permissions", 0)
                granted = False
                for acl in acls:
                    aces = acl.get("acesDictionary", {})
                    for ace in aces.values():
                        ext = ace.get("extendedInfo", {})
                        allow = ext.get("effectiveAllow", 0) or ace.get("allow", 0)
                        deny = ext.get("effectiveDeny", 0) or ace.get("deny", 0)
                        if (allow & bit) == bit and not (deny & bit):
                            granted = True
                            break
                    if granted:
                        break
                results.append({**ev, "value": granted})
            return results

        all_results: list[dict[str, Any]] = []
        for key, evs in by_key.items():
            grp = await _check_group(key, evs)
            if grp is None:
                return None
            all_results.extend(grp)
        return all_results

    # ------------------------------------------------------------------
    # Public API: Pipeline checks & branch policies
    # ------------------------------------------------------------------
    async def list_pipeline_check_configurations(
        self,
        project: str,
        resource_type: str,
        resource_id: str,
    ) -> list[dict[str, Any]]:
        """GET check configurations (approvals, etc.) on a pipeline resource."""
        self._scope.check(self._org, kind="ado")
        self._safe(project, "project")
        url = (
            f"{_REST_BASE}/{self._org}/{project}"
            "/_apis/pipelines/checks/configurations"
        )
        params: dict[str, str] = {
            "api-version": f"{_API_VERSION}-preview",
            "resourceType": resource_type,
            "resourceId": resource_id,
        }
        data = await self._get(
            url, params=params,
            audit_action="ado.pipeline_checks",
        )
        return (
            data.get("value", [])
            if isinstance(data, dict)
            else (data if isinstance(data, list) else [])
        )

    async def list_branch_policy_configurations(
        self,
        project: str,
        repository_id: str,
        ref_name: str,
    ) -> list[dict[str, Any]]:
        """GET branch policy configurations for a repo + branch."""
        self._scope.check(self._org, kind="ado")
        self._safe(project, "project")
        url = (
            f"{_REST_BASE}/{self._org}/{project}"
            "/_apis/policy/configurations"
        )
        params: dict[str, str] = {
            "api-version": _API_VERSION,
            "scope.repositoryId": repository_id,
            "scope.refName": ref_name,
        }
        data = await self._get(
            url, params=params,
            audit_action="ado.branch_policies",
        )
        return (
            data.get("value", [])
            if isinstance(data, dict)
            else []
        )

    # ------------------------------------------------------------------
    # ------------------------------------------------------------------
    # Public API: Service hooks
    # ------------------------------------------------------------------
    async def list_service_hook_subscriptions(self) -> list[dict[str, Any]]:
        """GET service hook subscriptions in the org."""
        self._scope.check(self._org, kind="ado")
        url = f"{_REST_BASE}/{self._org}/_apis/hooks/subscriptions"
        data = await self._get(
            url, params={"api-version": _API_VERSION}, audit_action="ado.service_hooks"
        )
        return data.get("value", []) if isinstance(data, dict) else []

    # ------------------------------------------------------------------
    # Public API: Extensions
    # ------------------------------------------------------------------
    async def list_installed_extensions(self) -> list[dict[str, Any]]:
        """GET installed extensions in the org."""
        self._scope.check(self._org, kind="ado")
        url = f"{_EXTMGMT_BASE}/{self._org}/_apis/extensionmanagement/installedextensions"
        data = await self._get(
            url, params={"api-version": f"{_API_VERSION}-preview"}, audit_action="ado.extensions"
        )
        return data.get("value", []) if isinstance(data, dict) else []

    # ------------------------------------------------------------------
    # Public API: ALM Search
    # ------------------------------------------------------------------
    async def code_search(
        self,
        project: str,
        search_text: str,
        *,
        top: int = 25,
        skip: int = 0,
        filters: dict[str, list[str]] | None = None,
    ) -> tuple[int, list[CodeSearchResult]]:
        """Run an ALM code search query. Returns (total_count, results)."""
        self._scope.check(self._org, kind="ado")
        self._safe(project, "project")
        url = f"{_SEARCH_BASE}/{self._org}/{project}/_apis/search/codesearchresults"
        body: dict[str, Any] = {
            "searchText": search_text,
            "$skip": skip,
            "$top": top,
            "includeSnippet": True,
        }
        if filters:
            body["filters"] = filters

        data = await self._post(
            url,
            json=body,
            params={"api-version": _API_VERSION},
            audit_action="ado.code_search",
        )
        total = data.get("count", 0) if isinstance(data, dict) else 0
        raw = data.get("results", []) if isinstance(data, dict) else []
        results = [_parse_code_result(r) for r in raw if isinstance(r, dict)]
        return total, results

    def code_search_pages(
        self,
        project: str,
        search_text: str,
        *,
        page_size: int = 25,
        max_results: int = 1000,
        filters: dict[str, list[str]] | None = None,
    ) -> AsyncIterator[list[CodeSearchResult]]:
        """Paginate code search results as an async iterator of pages."""
        return _CodeSearchPager(
            client=self,
            project=project,
            search_text=search_text,
            page_size=page_size,
            max_results=max_results,
            filters=filters,
        )

    async def work_item_search(
        self,
        project: str,
        search_text: str,
        *,
        top: int = 25,
        skip: int = 0,
        filters: dict[str, list[str]] | None = None,
    ) -> tuple[int, list[WorkItemSearchResult]]:
        """Run an ALM work-item search query. Returns (total_count, results)."""
        self._scope.check(self._org, kind="ado")
        self._safe(project, "project")
        url = f"{_SEARCH_BASE}/{self._org}/{project}/_apis/search/workitemsearchresults"
        body: dict[str, Any] = {
            "searchText": search_text,
            "$skip": skip,
            "$top": top,
        }
        if filters:
            body["filters"] = filters

        data = await self._post(
            url,
            json=body,
            params={"api-version": _API_VERSION},
            audit_action="ado.workitem_search",
        )
        total = data.get("count", 0) if isinstance(data, dict) else 0
        raw = data.get("results", []) if isinstance(data, dict) else []
        results = [_parse_wi_result(r) for r in raw if isinstance(r, dict)]
        return total, results

    async def list_wikis(self, project: str) -> list[dict[str, Any]]:
        """GET all wikis in a project."""
        self._scope.check(self._org, kind="ado")
        self._safe(project, "project")
        url = f"{_REST_BASE}/{self._org}/{project}/_apis/wiki/wikis"
        data = await self._get(
            url, params={"api-version": _API_VERSION}, audit_action="ado.wikis"
        )
        return data.get("value", []) if isinstance(data, dict) else []

    async def list_wiki_pages(
        self, project: str, wiki_name: str
    ) -> list[str]:
        """GET the full page tree for a wiki; returns a flat list of page paths."""
        self._scope.check(self._org, kind="ado")
        self._safe(project, "project")
        self._safe(wiki_name, "wiki_name")
        url = (
            f"{_REST_BASE}/{self._org}/{project}"
            f"/_apis/wiki/wikis/{wiki_name}/pages"
        )
        try:
            data = await self._request(
                "GET",
                url,
                params={
                    "path": "/",
                    "recursionLevel": "full",
                    "api-version": "7.1-preview.1",
                },
                audit_action="ado.wiki_pages",
            )
        except (ApiError, Transient, Throttled):
            return []
        if not isinstance(data, dict):
            return []
        paths: list[str] = []
        _walk_page_tree(data, paths)
        return paths

    async def wiki_search(
        self,
        project: str,
        search_text: str,
        *,
        top: int = 25,
        skip: int = 0,
    ) -> tuple[int, list[WikiSearchResult]]:
        """Run an ALM wiki search query. Returns (total_count, results)."""
        self._scope.check(self._org, kind="ado")
        self._safe(project, "project")
        url = f"{_SEARCH_BASE}/{self._org}/{project}/_apis/search/wikisearchresults"
        body: dict[str, Any] = {
            "searchText": search_text,
            "$skip": skip,
            "$top": top,
        }

        data = await self._post(
            url,
            json=body,
            params={"api-version": _API_VERSION},
            audit_action="ado.wiki_search",
        )
        total = data.get("count", 0) if isinstance(data, dict) else 0
        raw = data.get("results", []) if isinstance(data, dict) else []
        results = [_parse_wiki_result(r) for r in raw if isinstance(r, dict)]
        return total, results

    async def get_wiki_page(
        self,
        project: str,
        wiki_name: str,
        page_path: str,
    ) -> str | None:
        """GET the full markdown content of a wiki page. Returns None on error."""
        self._scope.check(self._org, kind="ado")
        self._safe(project, "project")
        self._safe(wiki_name, "wiki_name")
        url = (
            f"{_REST_BASE}/{self._org}/{project}"
            f"/_apis/wiki/wikis/{wiki_name}/pages"
        )
        try:
            data = await self._request(
                "GET",
                url,
                params={
                    "path": page_path,
                    "includeContent": "true",
                    "api-version": "7.1-preview.1",
                },
                audit_action="ado.wiki_page",
            )
            return data.get("content") if isinstance(data, dict) else None
        except (ApiError, Transient, Throttled):
            logger.warning(
                "wiki page fetch failed for %s/%s", wiki_name, page_path, exc_info=True
            )
            return None

    # ------------------------------------------------------------------
    # Public API: Build logs
    # ------------------------------------------------------------------
    async def list_build_logs(self, project: str, build_id: int) -> list[dict[str, Any]]:
        """GET log entries for a build."""
        self._scope.check(self._org, kind="ado")
        self._safe(project, "project")
        url = f"{_REST_BASE}/{self._org}/{project}/_apis/build/builds/{build_id}/logs"
        data = await self._get(
            url,
            params={"api-version": _API_VERSION},
            audit_action="ado.build_logs",
        )
        return data.get("value", []) if isinstance(data, dict) else []

    async def get_build_log(self, project: str, build_id: int, log_id: int) -> str:
        """GET the text content of a single build log."""
        self._scope.check(self._org, kind="ado")
        self._safe(project, "project")
        url = f"{_REST_BASE}/{self._org}/{project}/_apis/build/builds/{build_id}/logs/{log_id}"
        try:
            data = await self._request(
                "GET",
                url,
                params={"api-version": _API_VERSION},
                headers={"Accept": "text/plain"},
                audit_action="ado.build_log_content",
            )
            return data if isinstance(data, str) else ""
        except (ApiError, Transient, Throttled):
            return ""

    async def list_recent_builds(self, project: str, *, top: int = 25) -> list[dict[str, Any]]:
        """GET recent builds in a project."""
        self._scope.check(self._org, kind="ado")
        self._safe(project, "project")
        url = f"{_REST_BASE}/{self._org}/{project}/_apis/build/builds"
        data = await self._get(
            url,
            params={
                "api-version": _API_VERSION,
                "$top": str(top),
                "queryOrder": "finishTimeDescending",
            },
            audit_action="ado.builds",
        )
        return data.get("value", []) if isinstance(data, dict) else []

    async def has_recent_pushes(
        self, project: str, repository_id: str, *, since: str,
    ) -> bool:
        """Return True if the repo has at least one push since *since* (ISO 8601)."""
        self._scope.check(self._org, kind="ado")
        self._safe(project, "project")
        url = (
            f"{_REST_BASE}/{self._org}/{project}"
            f"/_apis/git/repositories/{repository_id}/pushes"
        )
        try:
            data = await self._get(
                url,
                params={
                    "api-version": _API_VERSION,
                    "searchCriteria.fromDate": since,
                    "$top": "1",
                },
                audit_action="ado.pushes",
            )
        except Exception:  # noqa: BLE001
            return True
        items = data.get("value", []) if isinstance(data, dict) else []
        return len(items) > 0

    async def get_variable_group(self, project: str, group_id: int) -> dict[str, Any]:
        """GET a specific variable group by ID."""
        self._scope.check(self._org, kind="ado")
        self._safe(project, "project")
        url = f"{_REST_BASE}/{self._org}/{project}/_apis/distributedtask/variablegroups/{group_id}"
        data = await self._get(
            url,
            params={"api-version": _API_VERSION},
            audit_action="ado.variable_group",
        )
        return data if isinstance(data, dict) else {}

    async def list_repo_items(
        self,
        project: str,
        repo_name: str,
        *,
        branch: str = "main",
    ) -> list[str]:
        """List all file paths in a repo tree. Returns non-folder paths."""
        self._scope.check(self._org, kind="ado")
        self._safe(project, "project")
        self._safe(repo_name, "repo_name")
        url = (
            f"{_REST_BASE}/{self._org}/{project}"
            f"/_apis/git/repositories/{repo_name}/items"
        )
        data = await self._get(
            url,
            params={
                "scopePath": "/",
                "recursionLevel": "full",
                "versionDescriptor.version": branch.removeprefix("refs/heads/"),
                "versionDescriptor.versionType": "branch",
                "api-version": _API_VERSION,
            },
            audit_action="ado.repo_items",
        )
        items = data.get("value", []) if isinstance(data, dict) else []
        return [
            item["path"]
            for item in items
            if isinstance(item, dict)
            and not item.get("isFolder", False)
            and item.get("path")
        ]

    async def get_file_content(
        self, project: str, repo_name: str, path: str, *, branch: str = "main"
    ) -> str | None:
        """GET raw text content of a file from a Git repo. Returns None on error."""
        self._scope.check(self._org, kind="ado")
        self._safe(project, "project")
        self._safe(repo_name, "repo_name")
        url = (
            f"{_REST_BASE}/{self._org}/{project}"
            f"/_apis/git/repositories/{repo_name}/items"
        )
        try:
            data = await self._request(
                "GET",
                url,
                params={
                    "path": path,
                    "includeContent": "true",
                    "versionDescriptor.version": branch.removeprefix("refs/heads/"),
                    "versionDescriptor.versionType": "branch",
                    "api-version": _API_VERSION,
                    "$format": "json",
                },
                audit_action="ado.file_content",
            )
            return data.get("content") if isinstance(data, dict) else None
        except (ApiError, Transient, Throttled):
            return None

    async def create_build_definition(
        self, project: str, definition: dict[str, Any]
    ) -> dict[str, Any]:
        """POST a new build definition."""
        self._scope.check(self._org, kind="ado")
        self._safe(project, "project")
        url = f"{_REST_BASE}/{self._org}/{project}/_apis/build/definitions"
        data = await self._post(
            url,
            json=definition,
            params={"api-version": _API_VERSION},
            audit_action="ado.create_build_definition",
        )
        return data if isinstance(data, dict) else {}

    async def delete_build_definition(self, project: str, definition_id: int) -> None:
        """DELETE a build definition."""
        self._scope.check(self._org, kind="ado")
        self._safe(project, "project")
        url = (
            f"{_REST_BASE}/{self._org}/{project}"
            f"/_apis/build/definitions/{definition_id}"
        )
        await self._request(
            "DELETE", url,
            params={"api-version": _API_VERSION},
            audit_action="ado.delete_build_definition",
        )

    async def queue_build(self, project: str, definition_id: int) -> dict[str, Any]:
        """POST to queue a build for a definition."""
        self._scope.check(self._org, kind="ado")
        self._safe(project, "project")
        url = f"{_REST_BASE}/{self._org}/{project}/_apis/build/builds"
        data = await self._post(
            url,
            json={"definition": {"id": definition_id}},
            params={"api-version": _API_VERSION},
            audit_action="ado.queue_build",
        )
        return data if isinstance(data, dict) else {}

    async def get_build(self, project: str, build_id: int) -> dict[str, Any]:
        """GET build status."""
        self._scope.check(self._org, kind="ado")
        self._safe(project, "project")
        url = f"{_REST_BASE}/{self._org}/{project}/_apis/build/builds/{build_id}"
        data = await self._get(
            url,
            params={"api-version": _API_VERSION},
            audit_action="ado.build_status",
        )
        return data if isinstance(data, dict) else {}

    async def get_build_retention_leases(
        self, project: str, build_id: int, definition_id: int,
    ) -> list[dict[str, Any]]:
        """GET retention leases for a build run."""
        self._scope.check(self._org, kind="ado")
        self._safe(project, "project")
        url = (
            f"{_REST_BASE}/{self._org}/{project}"
            f"/_apis/build/retention/leases"
        )
        data = await self._get(
            url,
            params={
                "api-version": _API_VERSION,
                "runId": str(build_id),
                "definitionId": str(definition_id),
            },
            audit_action="ado.build_retention_leases",
        )
        if isinstance(data, dict):
            return data.get("value", [])
        return data if isinstance(data, list) else []

    async def delete_retention_leases(
        self, project: str, lease_ids: list[int],
    ) -> None:
        """DELETE retention leases by ID."""
        if not lease_ids:
            return
        self._scope.check(self._org, kind="ado")
        self._safe(project, "project")
        url = (
            f"{_REST_BASE}/{self._org}/{project}"
            f"/_apis/build/retention/leases"
        )
        await self._request(
            "DELETE", url,
            params={
                "api-version": _API_VERSION,
                "ids": ",".join(str(i) for i in lease_ids),
            },
            audit_action="ado.delete_retention_leases",
        )

    async def delete_build(
        self, project: str, build_id: int, definition_id: int,
    ) -> None:
        """DELETE a build record, releasing retention leases first.

        Lease deletion is best-effort — if the PAT lacks the
        "Retain indefinitely" permission, we skip it and attempt the
        build DELETE directly (which often succeeds regardless).
        """
        self._scope.check(self._org, kind="ado")
        self._safe(project, "project")
        try:
            leases = await self.get_build_retention_leases(
                project, build_id, definition_id,
            )
            lease_ids = [
                le["leaseId"] for le in leases
                if isinstance(le, dict) and "leaseId" in le
            ]
            if lease_ids:
                await self.delete_retention_leases(project, lease_ids)
        except Exception:  # noqa: BLE001, S110
            pass  # best-effort; proceed to build delete
        url = (
            f"{_REST_BASE}/{self._org}/{project}"
            f"/_apis/build/builds/{build_id}"
        )
        await self._request(
            "DELETE", url,
            params={"api-version": _API_VERSION},
            audit_action="ado.delete_build",
        )

    async def get_build_timeline(self, project: str, build_id: int) -> dict[str, Any]:
        """GET build timeline (task records with log URLs)."""
        self._scope.check(self._org, kind="ado")
        self._safe(project, "project")
        url = f"{_REST_BASE}/{self._org}/{project}/_apis/build/builds/{build_id}/timeline"
        data = await self._get(
            url,
            params={"api-version": _API_VERSION},
            audit_action="ado.build_timeline",
        )
        return data if isinstance(data, dict) else {}

    async def queue_pipeline_run(
        self, project: str, pipeline_id: int, ref_name: str,
    ) -> dict[str, Any]:
        """POST to queue a YAML pipeline run on a specific branch."""
        self._scope.check(self._org, kind="ado")
        self._safe(project, "project")
        url = f"{_REST_BASE}/{self._org}/{project}/_apis/pipelines/{pipeline_id}/runs"
        body: dict[str, Any] = {
            "resources": {
                "repositories": {
                    "self": {"refName": ref_name},
                },
            },
        }
        data = await self._post(
            url,
            json=body,
            params={"api-version": _API_VERSION},
            audit_action="ado.queue_pipeline_run",
        )
        return data if isinstance(data, dict) else {}

    # ------------------------------------------------------------------
    # Internal HTTP
    # ------------------------------------------------------------------
    async def _get(
        self,
        url: str,
        *,
        params: dict[str, str] | None = None,
        audit_action: str = "ado.get",
    ) -> Any:
        return await self._request("GET", url, params=params, audit_action=audit_action)

    async def _post(
        self,
        url: str,
        *,
        json: Any = None,
        params: dict[str, str] | None = None,
        audit_action: str = "ado.post",
        retryable: bool = False,
    ) -> Any:
        return await self._request(
            "POST", url, json=json, params=params,
            audit_action=audit_action, retryable_override=retryable,
        )

    async def _request(
        self,
        method: str,
        url: str,
        *,
        json: Any = None,
        params: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        audit_action: str = "ado.request",
        retryable_override: bool | None = None,
    ) -> Any:
        client = await self._ensure_client()
        retryable = (
            retryable_override
            if retryable_override is not None
            else method.upper() in ("GET", "DELETE")
        )

        for attempt in range(_MAX_RETRIES + 1):
            try:
                async with self._sem:
                    await self._tstu.wait_if_needed(1)
                    resp = await client.request(
                        method, url, json=json, params=params, headers=headers,
                    )
            except httpx.TransportError as exc:
                if retryable and attempt < _MAX_RETRIES:
                    await self._backoff(attempt)
                    continue
                self._audit.record(
                    action=audit_action, target=self._org, result="error",
                )
                raise Transient(
                    f"ADO transport error on {method} {url}"
                    f"{f' after {_MAX_RETRIES} retries' if attempt else ''}: {exc}"
                ) from exc

            self._track_tstu(resp)

            if resp.status_code == 401:
                self._audit.record(
                    action=audit_action, target=self._org, result="error",
                )
                raise AuthError(f"ADO 401 on {method} {url} — PAT may be invalid or expired")

            if resp.status_code == 403:
                self._audit.record(
                    action=audit_action, target=self._org, result="error",
                )
                detail = ""
                try:
                    body = resp.json()
                    detail = body.get("message", "") or body.get("Message", "")
                except Exception:  # noqa: BLE001
                    detail = resp.text[:500] if resp.text else ""
                msg = f"ADO 403 on {method} {url}"
                if detail:
                    msg = f"{msg}: {detail}"
                raise ApiError(msg, status=403)

            if resp.status_code == 429:
                if retryable and attempt < _MAX_RETRIES:
                    retry_after = self._parse_retry_after(resp)
                    await self._backoff(attempt, retry_after)
                    continue
                self._audit.record(
                    action=audit_action, target=self._org, result="error",
                )
                raise Throttled(f"ADO 429 on {method} {url}")

            if resp.status_code >= 500:
                if retryable and attempt < _MAX_RETRIES:
                    await self._backoff(attempt)
                    continue
                self._audit.record(
                    action=audit_action, target=self._org, result="error",
                )
                raise Transient(f"ADO {resp.status_code} on {method} {url}")

            if resp.status_code >= 400:
                self._audit.record(
                    action=audit_action, target=self._org, result="error",
                )
                raise ApiError(
                    f"ADO {resp.status_code} on {method} {url}: {resp.text[:200]}",
                    status=resp.status_code,
                )

            self._audit.record(
                action=audit_action,
                target=self._org,
                result="ok",
            )
            if resp.status_code == 204:
                return {}
            content_type = resp.headers.get("content-type", "")
            if "text/plain" in content_type:
                return resp.text
            try:
                return resp.json()
            except (ValueError, UnicodeDecodeError) as exc:
                raise ApiError(
                    f"ADO returned non-JSON on {method} {url}: {exc}",
                    status=resp.status_code,
                ) from exc

        raise Transient("unreachable")  # pragma: no cover

    def _track_tstu(self, resp: httpx.Response) -> None:
        cost_raw = resp.headers.get("X-RateLimit-Cost")
        cost = int(cost_raw) if cost_raw and cost_raw.isdigit() else 1
        self._tstu.record(cost)

    @staticmethod
    async def _backoff(attempt: int, retry_after: float | None = None) -> None:
        if retry_after is not None:
            delay = retry_after
        else:
            delay = random.uniform(  # noqa: S311
                0, min(_BACKOFF_CAP, _BACKOFF_BASE * (2**attempt))
            )
        await asyncio.sleep(delay)

    @staticmethod
    def _parse_retry_after(resp: httpx.Response) -> float | None:
        raw = resp.headers.get("Retry-After")
        if raw is None:
            return None
        try:
            return float(raw)
        except ValueError:
            return None


class _CodeSearchPager:
    """Async iterator that pages through code search results."""

    def __init__(
        self,
        *,
        client: AdoSearchClient,
        project: str,
        search_text: str,
        page_size: int,
        max_results: int,
        filters: dict[str, list[str]] | None,
    ) -> None:
        self._client = client
        self._project = project
        self._search_text = search_text
        self._page_size = page_size
        self._max_results = max_results
        self._filters = filters
        self._skip = 0
        self._done = False

    def __aiter__(self) -> _CodeSearchPager:
        return self

    async def __anext__(self) -> list[CodeSearchResult]:
        if self._done or self._skip >= self._max_results:
            raise StopAsyncIteration
        total, page = await self._client.code_search(
            self._project,
            self._search_text,
            top=self._page_size,
            skip=self._skip,
            filters=self._filters,
        )
        if not page:
            raise StopAsyncIteration
        self._skip += len(page)
        if self._skip >= total or self._skip >= self._max_results:
            self._done = True
        return page


# ------------------------------------------------------------------
# Parsers
# ------------------------------------------------------------------
def _parse_code_result(raw: dict[str, Any]) -> CodeSearchResult:
    repo = raw.get("repository", {})
    project = repo.get("project", {})
    versions = raw.get("versions", [])
    branch = versions[0].get("branchName", "") if versions else ""
    snippets = _extract_code_snippets(raw)
    return CodeSearchResult(
        file_name=raw.get("fileName", ""),
        path=raw.get("path", ""),
        repo_name=repo.get("name", ""),
        repo_url=repo.get("url", ""),
        project_name=project.get("name", ""),
        branch=branch,
        content_id=raw.get("contentId", ""),
        snippets=snippets,
    )


def _extract_code_snippets(raw: dict[str, Any]) -> tuple[str, ...]:
    """Extract snippet text from a code search result.

    ADO API v7.1 returns highlights in ``hits[].highlights``; older responses
    may use ``matches.content`` with plain strings.  Position-only objects
    (``{charOffset, length}``) in ``matches.content`` are skipped.
    """
    hits = raw.get("hits", [])
    if hits:
        out: list[str] = []
        for hit in hits:
            if not isinstance(hit, dict):
                continue
            for hl in (hit.get("highlights") or []):
                if isinstance(hl, str):
                    out.append(hl)
        if out:
            return tuple(out)

    matches = raw.get("matches")
    if isinstance(matches, dict):
        content = matches.get("content", [])
        if content and all(isinstance(c, str) for c in content):
            return tuple(content)

    return ()


def _parse_wi_result(raw: dict[str, Any]) -> WorkItemSearchResult:
    fields = raw.get("fields", {})
    project = raw.get("project", {})
    hits = raw.get("hits", [])
    snippets = []
    for hit in hits:
        for hl in hit.get("highlights", []):
            snippets.append(hl)
    url = raw.get("url", "")
    return WorkItemSearchResult(
        work_item_id=int(fields.get("system.id", 0)),
        title=fields.get("system.title", ""),
        work_item_type=fields.get("system.workitemtype", ""),
        state=fields.get("system.state", ""),
        project_name=project.get("name", ""),
        snippets=tuple(snippets),
        url=url,
    )


def _walk_page_tree(node: dict[str, Any], out: list[str]) -> None:
    """Recursively extract page paths from the wiki page tree response."""
    path = node.get("path", "")
    if path and path != "/":
        out.append(path)
    for sub in node.get("subPages", []):
        if isinstance(sub, dict):
            _walk_page_tree(sub, out)


def _parse_wiki_result(raw: dict[str, Any]) -> WikiSearchResult:
    wiki = raw.get("wiki", {})
    project = raw.get("project", {})
    hits = raw.get("hits", [])
    snippets = []
    for hit in hits:
        for hl in hit.get("highlights", []):
            snippets.append(hl)
    return WikiSearchResult(
        wiki_name=wiki.get("name", ""),
        page_path=raw.get("path", ""),
        project_name=project.get("name", ""),
        snippets=tuple(snippets),
    )
