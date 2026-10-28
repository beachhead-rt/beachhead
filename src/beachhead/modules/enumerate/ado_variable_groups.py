"""enumerate.ado_variable_groups — ADO variable groups.

Enumerates variable groups across all in-scope ADO organizations and
projects. Records variable names (not secret values), Key Vault links,
and variable counts as resources.

Credential analysis of variable values is handled by
``harvest.ado_variable_scan``.

MITRE ATT&CK: T1552.001 (Unsecured Credentials: Credentials In Files)
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


class AdoVariableGroups:
    meta = ModuleMeta(
        name="enumerate.ado_variable_groups",
        phase=Phase.ENUMERATE,
        access=Access.READ,
        requires_browser=False,
        technique_ids=("T1552.001",),
        summary="Enumerate ADO variable groups (names, Key Vault links).",
    )

    async def run(self, ctx: RunContext) -> RunResult:
        pat = await get_pat(ctx)
        if pat is None:
            return no_pat_result(ctx)

        orgs = get_orgs(ctx)
        if not orgs:
            return no_orgs_result(ctx)

        total = 0

        for org in sorted(orgs):
            ctx.console.print(f"[bold]Enumerating variable groups: {org}[/]")
            client = make_client(org, pat, ctx)
            try:
                projects = await client.list_projects()
                proj_names = [p["name"] for p in projects if isinstance(p, dict) and "name" in p]
                async def _get_groups(proj: str) -> tuple[str, list[Any]]:
                    try:
                        grps = await client.list_variable_groups(proj)
                    except (ScopeError, AuthError):
                        raise
                    except Exception:  # noqa: BLE001
                        grps = []
                    return proj, grps

                grp_results = await asyncio.gather(
                    *(_get_groups(p) for p in proj_names),
                    return_exceptions=True,
                )

                for result in grp_results:
                    if isinstance(result, (ScopeError, AuthError)):
                        raise result
                    if isinstance(result, BaseException):
                        continue
                    proj, groups = result
                    groups = ado_time_filter(groups, ctx.since, "modifiedOn", "createdOn")
                    for vg in groups:
                        if not isinstance(vg, dict):
                            continue
                        _record_variable_group(ctx, org, proj, vg)
                        total += 1
            finally:
                await client.close()

        ctx.console.print(f"[green]Recorded {total} variable group(s)[/]")
        return RunResult(ok=True, written=total)


def _record_variable_group(
    ctx: RunContext,
    org: str,
    project: str,
    vg: dict[str, Any],
) -> None:
    vg_id = vg.get("id", "")
    name = vg.get("name", "")
    vg_type = vg.get("type", "")
    variables = vg.get("variables", {}) or {}
    provider_data = vg.get("providerData", {}) or {}

    variable_names = list(variables.keys())
    secret_count = sum(1 for v in variables.values() if isinstance(v, dict) and v.get("isSecret"))
    plaintext_count = len(variables) - secret_count

    vault_name = provider_data.get("vaultName", "")
    service_endpoint_id = provider_data.get("serviceEndpointId", "")

    props: dict[str, object] = {
        "org": org,
        "project": project,
        "group_id": vg_id,
        "group_type": vg_type,
        "variable_count": len(variables),
        "secret_count": secret_count,
        "plaintext_count": plaintext_count,
        "variable_names": variable_names[:50],
    }
    if vault_name:
        props["vault_name"] = vault_name
        props["service_endpoint_id"] = service_endpoint_id

    ctx.store.upsert_resource(
        resource_id=f"ado://{org}/{project}/vargroup/{vg_id}",
        type="ado_variable_group",
        run_id=ctx.run_id,
        name=name,
        properties_summary=props,
    )
