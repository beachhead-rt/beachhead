"""enumerate.ado_pipelines — ADO pipeline definitions (YAML + classic build + release).

Enumerates YAML pipelines, classic build definitions, and classic release
definitions across all in-scope ADO organizations and projects. Records
pipeline metadata as resources.

Credential analysis of pipeline variables is handled by
``harvest.ado_variable_scan``.

MITRE ATT&CK: T1059.009 (Command and Scripting Interpreter: Cloud API)
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


class AdoPipelines:
    meta = ModuleMeta(
        name="enumerate.ado_pipelines",
        phase=Phase.ENUMERATE,
        access=Access.READ,
        requires_browser=False,
        technique_ids=("T1059.009",),
        summary="Enumerate ADO pipelines (YAML, classic build, classic release).",
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
            ctx.console.print(f"[bold]Enumerating pipelines: {org}[/]")
            client = make_client(org, pat, ctx)
            try:
                projects = await client.list_projects()
                proj_names = [p["name"] for p in projects if isinstance(p, dict) and "name" in p]
                for proj in proj_names:
                    total += await _enum_project(ctx, client, org, proj)
            finally:
                await client.close()

        ctx.console.print(f"[green]Recorded {total} pipeline(s)[/]")
        return RunResult(ok=True, written=total)


async def _enum_project(ctx: RunContext, client: Any, org: str, project: str) -> int:
    count = 0

    async def _list_yaml() -> list[Any]:
        try:
            return await client.list_pipelines(project)
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

    results = await asyncio.gather(_list_yaml(), _list_builds(), _list_releases(), return_exceptions=True)
    for r in results:
        if isinstance(r, (ScopeError, AuthError)):
            raise r

    yaml_pipelines = results[0] if isinstance(results[0], list) else []
    build_defs = results[1] if isinstance(results[1], list) else []
    release_defs = results[2] if isinstance(results[2], list) else []

    yaml_pipelines = ado_time_filter(yaml_pipelines, ctx.since, "createdDate")
    build_defs = ado_time_filter(build_defs, ctx.since, "createdDate")
    release_defs = ado_time_filter(release_defs, ctx.since, "createdOn", "modifiedOn")

    for p in yaml_pipelines:
        if not isinstance(p, dict):
            continue
        pid = p.get("id", "")
        name = p.get("name", "")
        ctx.store.upsert_resource(
            resource_id=f"ado://{org}/{project}/pipeline/{pid}",
            type="ado_pipeline_yaml",
            run_id=ctx.run_id,
            name=name,
            properties_summary={
                "org": org,
                "project": project,
                "pipeline_id": pid,
                "folder": p.get("folder", ""),
                "revision": p.get("revision"),
            },
        )
        count += 1

    for bd in build_defs:
        if not isinstance(bd, dict):
            continue
        bd_id = bd.get("id", "")
        name = bd.get("name", "")
        bd_type = bd.get("type", "")
        variables = bd.get("variables", {})

        ctx.store.upsert_resource(
            resource_id=f"ado://{org}/{project}/build/{bd_id}",
            type="ado_pipeline_classic_build",
            run_id=ctx.run_id,
            name=name,
            properties_summary={
                "org": org,
                "project": project,
                "definition_id": bd_id,
                "type": bd_type,
                "variable_count": len(variables),
                "secret_variable_count": sum(
                    1 for v in variables.values() if isinstance(v, dict) and v.get("isSecret")
                ),
                "queue_name": (bd.get("queue") or {}).get("name", ""),
            },
        )
        count += 1

    for rd in release_defs:
        if not isinstance(rd, dict):
            continue
        rd_id = rd.get("id", "")
        name = rd.get("name", "")
        envs = rd.get("environments", [])

        ctx.store.upsert_resource(
            resource_id=f"ado://{org}/{project}/release/{rd_id}",
            type="ado_pipeline_classic_release",
            run_id=ctx.run_id,
            name=name,
            properties_summary={
                "org": org,
                "project": project,
                "definition_id": rd_id,
                "environment_count": len(envs),
                "environment_names": [e.get("name", "") for e in envs if isinstance(e, dict)][:10],
            },
        )
        count += 1

    return count
