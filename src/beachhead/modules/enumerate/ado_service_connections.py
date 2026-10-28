"""enumerate.ado_service_connections — ADO service endpoints.

Enumerates service connections (endpoints) across all in-scope ADO
organizations and projects. Records connection type, URL, authorization
scheme, and flags overly-broad configurations.

For each endpoint the module also uses ADO's permission evaluation batch
API to check whether the current PAT identity has effective Administrator
permission on the connection. The result is stored in the
resource's ``properties_summary`` (``pat_can_admin``) and, when admin
access is confirmed on a supported connection type, a dedicated finding
(``ado_service_connection_admin_access``) is created so that
``analyze.ado_attack_paths`` can score the path appropriately.

MITRE ATT&CK: T1078.004 (Valid Accounts: Cloud Accounts)
"""

from __future__ import annotations

import asyncio
from typing import Any

from beachhead.core.errors import AuthError, ScopeError
from beachhead.core.module import Access, ModuleMeta, Phase, RunContext, RunResult
from beachhead.modules.enumerate._ado_common import (
    ado_time_filter,
    get_orgs,
    get_pat,
    make_client,
    no_orgs_result,
    no_pat_result,
)

# ServiceEndpoints security namespace GUID (stable across ADO instances).
_SVC_ENDPOINT_NS = "49b48001-ca20-4adc-8111-5b60c903a50c"

# ServiceEndpoints namespace permission bits:
#   1 = Use, 2 = Administer, 4 = Create,
#   8 = ViewAuthorization, 16 = ViewEndpoint
_ADMINISTER_BIT = 2

# Connection types the exploit module can extract credentials from.
_EXPLOITABLE_TYPES = frozenset({"azurerm", "dockerregistry"})


class AdoServiceConnections:
    meta = ModuleMeta(
        name="enumerate.ado_service_connections",
        phase=Phase.ENUMERATE,
        access=Access.READ,
        requires_browser=False,
        technique_ids=("T1078.004",),
        summary="Enumerate ADO service connections (endpoints).",
    )

    async def run(self, ctx: RunContext) -> RunResult:  # noqa: C901
        pat = await get_pat(ctx)
        if pat is None:
            return no_pat_result(ctx)

        orgs = get_orgs(ctx)
        if not orgs:
            return no_orgs_result(ctx)

        results = await asyncio.gather(
            *(_enum_svc_org(ctx, org, pat) for org in sorted(orgs)),
            return_exceptions=True,
        )

        total = 0
        findings = 0
        for r in results:
            if isinstance(r, (ScopeError, AuthError)):
                raise r
            if isinstance(r, BaseException):
                continue
            total += r[0]
            findings += r[1]

        ctx.console.print(
            f"[green]Recorded {total} service connection(s), "
            f"{findings} finding(s)[/]"
        )
        return RunResult(ok=True, written=total + findings)


async def _enum_svc_org(  # noqa: C901
    ctx: RunContext, org: str, pat: str,
) -> tuple[int, int]:
    ctx.console.print(
        f"[bold]Enumerating service connections: {org}[/]",
    )
    client = make_client(org, pat, ctx)
    total = 0
    findings = 0
    try:
        projects = await client.list_projects()
        projects = ado_time_filter(projects, ctx.since, "lastUpdateTime")
        proj_list = [
            (p["name"], p.get("id", ""))
            for p in projects
            if isinstance(p, dict) and "name" in p
        ]

        ep_results = await asyncio.gather(
            *(_get_endpoints(client, name) for name, _ in proj_list),
            return_exceptions=True,
        )

        proj_id_map = {name: pid for name, pid in proj_list}

        endpoints_by_project: dict[str, list[str]] = {}
        for result in ep_results:
            if isinstance(result, BaseException):
                continue
            proj_name, endpoints = result
            pid = proj_id_map.get(proj_name, "")
            if pid:
                endpoints_by_project[pid] = [
                    ep.get("id", "")
                    for ep in endpoints
                    if isinstance(ep, dict) and ep.get("id")
                ]

        admin_ep_ids, admin_proj_ids = (
            await _fetch_admin_endpoints(
                client, proj_id_map, endpoints_by_project,
            )
        )

        for result in ep_results:
            if isinstance(result, (ScopeError, AuthError)):
                raise result
            if isinstance(result, BaseException):
                continue
            proj, endpoints = result
            proj_guid = proj_id_map.get(proj, "")
            for ep in endpoints:
                if not isinstance(ep, dict):
                    continue

                ep_id = ep.get("id", "")
                name = ep.get("name", "")
                ep_type = ep.get("type", "")
                url = ep.get("url", "")
                auth = ep.get("authorization", {})
                scheme = (
                    auth.get("scheme", "")
                    if isinstance(auth, dict)
                    else ""
                )
                is_shared = ep.get("isShared", False)
                can_admin = (
                    ep_id in admin_ep_ids
                    or proj_guid in admin_proj_ids
                )

                ctx.store.upsert_resource(
                    resource_id=(
                        f"ado://{org}/{proj}/endpoint/{ep_id}"
                    ),
                    type="ado_service_connection",
                    run_id=ctx.run_id,
                    name=name,
                    properties_summary={
                        "org": org,
                        "project": proj,
                        "endpoint_id": ep_id,
                        "endpoint_type": ep_type,
                        "url": url,
                        "auth_scheme": scheme,
                        "is_shared": is_shared,
                        "pat_can_admin": can_admin,
                    },
                )
                total += 1

                f = _check_connection(
                    ctx, org, proj, ep, can_admin=can_admin,
                )
                findings += f
    finally:
        await client.close()

    return total, findings


async def _get_endpoints(
    client: Any, proj_name: str,
) -> tuple[str, list[Any]]:
    try:
        eps = await client.list_service_connections(proj_name)
    except (ScopeError, AuthError):
        raise
    except Exception:  # noqa: BLE001
        eps = []
    return proj_name, eps


async def _fetch_admin_endpoints(
    client: Any,
    proj_id_map: dict[str, str],
    endpoints_by_project: dict[str, list[str]],
) -> tuple[set[str], set[str]]:
    """Check which endpoints the *current* PAT can Administer.

    Uses ADO's permission evaluation batch API which resolves the
    caller's effective permissions (including group membership),
    avoiding false positives from other identities' ACEs.

    Returns ``(admin_endpoint_ids, admin_project_ids)``.
    """
    admin_ep_ids: set[str] = set()
    admin_proj_ids: set[str] = set()

    project_ids = [pid for pid in proj_id_map.values() if pid]
    if not project_ids:
        return admin_ep_ids, admin_proj_ids

    evaluations: list[dict[str, Any]] = []
    eval_tokens: list[tuple[str, str]] = []

    for pid in project_ids:
        proj_token = f"endpoints/{pid}"
        evaluations.append({
            "securityNamespaceId": _SVC_ENDPOINT_NS,
            "token": proj_token,
            "permissions": _ADMINISTER_BIT,
        })
        eval_tokens.append(("project", pid))

        for ep_id in endpoints_by_project.get(pid, []):
            ep_token = f"endpoints/{pid}/{ep_id}"
            evaluations.append({
                "securityNamespaceId": _SVC_ENDPOINT_NS,
                "token": ep_token,
                "permissions": _ADMINISTER_BIT,
            })
            eval_tokens.append(("endpoint", ep_id))

    if not evaluations:
        return admin_ep_ids, admin_proj_ids

    _BATCH_SIZE = 25
    batches = [
        evaluations[i : i + _BATCH_SIZE]
        for i in range(0, len(evaluations), _BATCH_SIZE)
    ]

    async def _eval_batch(
        batch: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        try:
            return await client.evaluate_permissions_batch(batch)
        except (ScopeError, AuthError):
            raise
        except Exception:  # noqa: BLE001
            return [{}] * len(batch)

    batch_results = await asyncio.gather(
        *(_eval_batch(b) for b in batches),
    )
    all_results: list[dict[str, Any]] = []
    for br in batch_results:
        all_results.extend(br)

    for (kind, obj_id), result in zip(
        eval_tokens, all_results, strict=True,
    ):
        if not isinstance(result, dict):
            continue
        if result.get("value") is True:
            if kind == "project":
                admin_proj_ids.add(obj_id)
            else:
                admin_ep_ids.add(obj_id)

    return admin_ep_ids, admin_proj_ids


def _check_connection(
    ctx: RunContext,
    org: str,
    project: str,
    ep: dict[str, Any],
    *,
    can_admin: bool,
) -> int:
    findings = 0
    ep_id = ep.get("id", "")
    name = ep.get("name", "")
    ep_type = ep.get("type", "")

    if ep_type == "azurerm":
        data = ep.get("data", {}) or {}
        scope_level = data.get("scopeLevel", "")
        if scope_level == "Subscription":
            sub_id = data.get("subscriptionId", "")
            ctx.store.insert_finding(
                kind="ado_service_connection_azure",
                resource_id=f"ado://{org}/{project}/endpoint/{ep_id}",
                reference=(
                    f"Azure RM connection '{name}' has "
                    f"subscription-level scope ({sub_id})"
                ),
                run_id=ctx.run_id,
                details={
                    "org": org,
                    "project": project,
                    "endpoint_name": name,
                    "subscription_id": sub_id,
                    "scope_level": scope_level,
                },
            )
            findings += 1

    if ep.get("isShared"):
        ctx.store.insert_finding(
            kind="ado_service_connection_shared",
            resource_id=f"ado://{org}/{project}/endpoint/{ep_id}",
            reference=(
                f"Service connection '{name}' ({ep_type}) "
                f"is shared across projects"
            ),
            run_id=ctx.run_id,
            details={
                "org": org,
                "project": project,
                "endpoint_name": name,
                "endpoint_type": ep_type,
            },
        )
        findings += 1

    if can_admin and (ep_type or "").lower() in _EXPLOITABLE_TYPES:
        ctx.store.insert_finding(
            kind="ado_service_connection_admin_access",
            resource_id=f"ado://{org}/{project}/endpoint/{ep_id}",
            reference=(
                f"PAT has Administrator access on "
                f"'{name}' ({ep_type}) "
                f"— credential extraction possible"
            ),
            run_id=ctx.run_id,
            details={
                "org": org,
                "project": project,
                "endpoint_name": name,
                "endpoint_id": ep_id,
                "endpoint_type": ep_type,
            },
        )
        findings += 1

    return findings
