"""harvest.ado_pipeline_log_scan — ADO pipeline log credential detector.

Scans recent build logs for secret scrubbing failures. ADO replaces known
secret values with ``***`` in logs, but base64-encoded, URL-encoded, or
substring secrets bypass scrubbing. This module fetches recent build logs
and applies cred-engine's patterns to detect leaked secrets.

Read-only — never modifies ADO.

MITRE ATT&CK: T1552.001 (Unsecured Credentials: Credentials In Files)
"""

from __future__ import annotations

import asyncio
import re
from typing import Any

from beachhead.core.cred_bridge import scan_and_record
from beachhead.core.errors import AuthError, ScopeError
from beachhead.core.module import Access, ModuleMeta, Phase, RunContext, RunResult
from beachhead.modules.enumerate._ado_common import (
    get_orgs,
    get_pat,
    make_client,
    no_orgs_result,
    no_pat_result,
)

_MAX_BUILDS_PER_PROJECT = 10
_MAX_LOG_SIZE = 50_000
_SCRUB_MARKER = re.compile(r"\*{3,}")


class AdoPipelineLogScan:
    meta = ModuleMeta(
        name="harvest.ado_pipeline_log_scan",
        phase=Phase.HARVEST,
        access=Access.READ,
        requires_browser=False,
        technique_ids=("T1552.001",),
        summary="Scan ADO pipeline build logs for secret scrubbing failures (cred-engine).",
    )

    async def run(self, ctx: RunContext) -> RunResult:
        pat = await get_pat(ctx)
        if pat is None:
            return no_pat_result(ctx)

        orgs = get_orgs(ctx)
        if not orgs:
            return no_orgs_result(ctx)

        total_findings = 0
        builds_scanned = 0

        for org in sorted(orgs):
            ctx.console.print(f"[bold]Pipeline log scan: {org}[/]")
            client = make_client(org, pat, ctx)
            try:
                projects = await client.list_projects()
                proj_names = [p["name"] for p in projects if isinstance(p, dict) and "name" in p]
                for proj in proj_names:
                    try:
                        builds = await client.list_recent_builds(proj, top=_MAX_BUILDS_PER_PROJECT)
                    except (ScopeError, AuthError):
                        raise
                    except Exception:  # noqa: BLE001, S112
                        continue

                    valid = [
                        b for b in builds
                        if isinstance(b, dict) and b.get("id") is not None
                    ]
                    results = await asyncio.gather(
                        *(_scan_build(ctx, client, org, proj, b) for b in valid),
                        return_exceptions=True,
                    )
                    for r in results:
                        if isinstance(r, (ScopeError, AuthError)):
                            raise r
                        if isinstance(r, BaseException):
                            continue
                        total_findings += r
                    builds_scanned += len(valid)
            finally:
                await client.close()

        ctx.console.print(
            f"[green]Scanned {builds_scanned} build(s), {total_findings} finding(s)[/]"
        )
        return RunResult(ok=True, written=total_findings)


async def _scan_build(
    ctx: RunContext,
    client: Any,
    org: str,
    project: str,
    build: dict[str, Any],
) -> int:
    build_id = build["id"]
    build_number = build.get("buildNumber", str(build_id))

    try:
        logs = await client.list_build_logs(project, build_id)
    except (ScopeError, AuthError):
        raise
    except Exception:  # noqa: BLE001
        return 0

    valid_logs = [
        e for e in logs
        if isinstance(e, dict) and e.get("id") is not None
    ]
    if not valid_logs:
        return 0

    log_ids = [e["id"] for e in valid_logs]
    contents = await asyncio.gather(
        *(client.get_build_log(project, build_id, lid) for lid in log_ids),
        return_exceptions=True,
    )

    findings = 0
    build_url = f"https://dev.azure.com/{org}/{project}/_build/results?buildId={build_id}"

    for log_id, content in zip(log_ids, contents):
        if isinstance(content, (ScopeError, AuthError)):
            raise content
        if isinstance(content, BaseException) or not content:
            continue
        if len(content) > _MAX_LOG_SIZE:
            continue

        filtered_lines = [
            line for line in content.splitlines()
            if not _SCRUB_MARKER.search(line)
        ]
        filtered_content = "\n".join(filtered_lines)
        if not filtered_content.strip():
            continue

        resource = f"ado://{org}/{project}/build/{build_id}/log/{log_id}"
        n = scan_and_record(
            ctx,
            filtered_content,
            file_path=f"build-{build_id}/log-{log_id}",
            repo=f"build/{build_number}",
            project=project,
            org=org,
            url=build_url,
            finding_kind="ado_pipeline_log_secret",
            source_module="harvest.ado_pipeline_log_scan",
            resource_id=resource,
            extra_details={
                "build_id": build_id,
                "build_number": build_number,
                "log_id": log_id,
            },
        )
        findings += n

    return findings
