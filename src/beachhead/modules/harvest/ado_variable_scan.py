"""harvest.ado_variable_scan — ADO pipeline variable credential scanner.

Fetches pipeline variables from build definitions, release definitions,
and variable groups, then classifies each using cred-engine's variable
classifier.  Non-secret (unmasked) variables whose values look like
credentials are recorded as findings.

Read-only — never modifies ADO.

MITRE ATT&CK: T1552.001 (Unsecured Credentials: Credentials In Files)
"""

from __future__ import annotations

import asyncio
from typing import Any

from beachhead.core.cred_bridge import classify_variable
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


class AdoVariableScan:
    meta = ModuleMeta(
        name="harvest.ado_variable_scan",
        phase=Phase.HARVEST,
        access=Access.READ,
        requires_browser=False,
        technique_ids=("T1552.001",),
        summary="Classify ADO pipeline variables as credentials (cred-engine).",
    )

    async def run(self, ctx: RunContext) -> RunResult:
        pat = await get_pat(ctx)
        if pat is None:
            return no_pat_result(ctx)

        orgs = get_orgs(ctx)
        if not orgs:
            return no_orgs_result(ctx)

        total_findings = 0
        total_vars = 0

        for org in sorted(orgs):
            ctx.console.print(f"[bold]Variable scan: {org}[/]")
            client = make_client(org, pat, ctx)
            try:
                projects = await client.list_projects()
                proj_names = [
                    p["name"] for p in projects if isinstance(p, dict) and "name" in p
                ]

                for proj in proj_names:
                    n, v = await _scan_project_variables(ctx, client, org, proj)
                    total_findings += n
                    total_vars += v
            finally:
                await client.close()

        ctx.console.print(
            f"[green]Scanned {total_vars} variable(s), {total_findings} credential(s) found[/]"
        )
        return RunResult(ok=True, written=total_findings)


async def _scan_project_variables(
    ctx: RunContext,
    client: Any,
    org: str,
    project: str,
) -> tuple[int, int]:
    findings = 0
    var_count = 0

    async def _list_groups() -> list[Any]:
        try:
            return await client.list_variable_groups(project)
        except (ScopeError, AuthError):
            raise
        except Exception:  # noqa: BLE001
            return []

    async def _list_builds() -> list[Any]:
        try:
            return await client.list_build_definitions(project)
        except (ScopeError, AuthError):
            raise
        except Exception:  # noqa: BLE001
            return []

    async def _list_releases() -> list[Any]:
        try:
            return await client.list_release_definitions(project)
        except (ScopeError, AuthError):
            raise
        except Exception:  # noqa: BLE001
            return []

    results = await asyncio.gather(
        _list_groups(), _list_builds(), _list_releases(),
        return_exceptions=True,
    )
    for r in results:
        if isinstance(r, (ScopeError, AuthError)):
            raise r

    groups = results[0] if isinstance(results[0], list) else []
    build_defs = results[1] if isinstance(results[1], list) else []
    release_defs = results[2] if isinstance(results[2], list) else []

    groups = ado_time_filter(groups, ctx.since, "modifiedOn", "createdOn")
    build_defs = ado_time_filter(build_defs, ctx.since, "createdDate")
    release_defs = ado_time_filter(release_defs, ctx.since, "createdOn", "modifiedOn")

    # --- Variable groups ---
    for group in groups:
        if not isinstance(group, dict):
            continue
        group_name = group.get("name", "")
        variables = group.get("variables", {})
        if not isinstance(variables, dict):
            continue

        for var_name, var_obj in variables.items():
            if not isinstance(var_obj, dict):
                continue
            if var_obj.get("isSecret", False):
                continue
            value = var_obj.get("value", "")
            if not value or not isinstance(value, str):
                continue

            var_count += 1
            resource = f"variable_group/{group_name}"
            recorded = classify_variable(
                ctx,
                variable_name=var_name,
                value=value,
                resource=resource,
                project=project,
                org=org,
                source_group=group_name,
            )
            if recorded:
                findings += 1

    # --- Build definitions (fetch full defs in parallel) ---
    valid_bd = [
        bd for bd in build_defs
        if isinstance(bd, dict) and bd.get("id") is not None
    ]

    async def _get_full_def(bd: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        def_id = bd["id"]
        def_name = bd.get("name", "")
        try:
            full = await client.get_build_definition(project, def_id)
        except (ScopeError, AuthError):
            raise
        except Exception:  # noqa: BLE001
            full = {}
        return def_name, full

    def_results = await asyncio.gather(
        *(_get_full_def(bd) for bd in valid_bd),
        return_exceptions=True,
    )

    for result in def_results:
        if isinstance(result, (ScopeError, AuthError)):
            raise result
        if isinstance(result, BaseException):
            continue
        def_name, full_def = result
        variables = full_def.get("variables", {})
        if not isinstance(variables, dict):
            continue

        for var_name, var_obj in variables.items():
            if not isinstance(var_obj, dict):
                continue
            if var_obj.get("isSecret", False):
                continue
            value = var_obj.get("value", "")
            if not value or not isinstance(value, str):
                continue

            var_count += 1
            resource = f"pipeline/{def_name}"
            recorded = classify_variable(
                ctx,
                variable_name=var_name,
                value=value,
                resource=resource,
                project=project,
                org=org,
                source_pipeline=def_name,
            )
            if recorded:
                findings += 1

    # --- Release definitions ---
    for rd in release_defs:
        if not isinstance(rd, dict):
            continue
        rd_name = rd.get("name", "")
        variables = rd.get("variables", {})
        if not isinstance(variables, dict):
            continue

        for var_name, var_obj in variables.items():
            if not isinstance(var_obj, dict):
                continue
            if var_obj.get("isSecret", False):
                continue
            value = var_obj.get("value", "")
            if not value or not isinstance(value, str):
                continue

            var_count += 1
            resource = f"release/{rd_name}"
            recorded = classify_variable(
                ctx,
                variable_name=var_name,
                value=value,
                resource=resource,
                project=project,
                org=org,
                source_pipeline=rd_name,
            )
            if recorded:
                findings += 1

    return findings, var_count
