"""enumerate.ado_extensions — installed ADO marketplace extensions.

Enumerates installed extensions across all in-scope ADO organizations.
Records extension scopes and flags high-privilege third-party extensions.

MITRE ATT&CK: T1176 (Browser Extensions)
"""

from __future__ import annotations

from typing import Any

from beachhead.core.errors import ApiError
from beachhead.core.module import Access, ModuleMeta, Phase, RunContext, RunResult
from beachhead.modules.enumerate._ado_common import (
    ado_time_filter,
    get_orgs,
    get_pat,
    make_client,
    no_orgs_result,
    no_pat_result,
)

_HIGH_PRIVILEGE_SCOPES = frozenset({
    "vso.code_write",
    "vso.build_execute",
    "vso.release_execute",
    "vso.security_manage",
    "vso.serviceendpoint_manage",
    "vso.tokens",
    "vso.identity_manage",
})


class AdoExtensions:
    meta = ModuleMeta(
        name="enumerate.ado_extensions",
        phase=Phase.ENUMERATE,
        access=Access.READ,
        requires_browser=False,
        technique_ids=("T1176",),
        summary="Enumerate installed ADO marketplace extensions and their scopes.",
    )

    async def run(self, ctx: RunContext) -> RunResult:
        pat = await get_pat(ctx)
        if pat is None:
            return no_pat_result(ctx)

        orgs = get_orgs(ctx)
        if not orgs:
            return no_orgs_result(ctx)

        total = 0
        findings = 0

        for org in sorted(orgs):
            ctx.console.print(f"[bold]Enumerating extensions: {org}[/]")
            client = make_client(org, pat, ctx)
            try:
                try:
                    extensions = await client.list_installed_extensions()
                except ApiError as exc:
                    if exc.status in (400, 403, 404):
                        ctx.console.print(
                            f"[yellow]Extension API unavailable for {org}"
                            f" ({exc.status}) — skipping[/]"
                        )
                        continue
                    raise
                extensions = ado_time_filter(extensions, ctx.since, "lastPublished")
                for ext in extensions:
                    if not isinstance(ext, dict):
                        continue
                    n, f = _record_extension(ctx, org, ext)
                    total += n
                    findings += f
            finally:
                await client.close()

        ctx.console.print(f"[green]Recorded {total} extension(s), {findings} finding(s)[/]")
        return RunResult(ok=True, written=total + findings)


def _record_extension(
    ctx: RunContext,
    org: str,
    ext: dict[str, Any],
) -> tuple[int, int]:
    publisher_id = ext.get("publisherId", "")
    extension_id = ext.get("extensionId", "")
    extension_name = ext.get("extensionName", "")
    publisher_name = ext.get("publisherName", "")
    version = ext.get("version", "")
    flags = ext.get("flags", []) or []
    if isinstance(flags, str):
        flags = [flags]
    raw_scopes = ext.get("scopes", []) or []
    scopes = [s if isinstance(s, str) else s.get("name", "") for s in raw_scopes]
    install_state = (ext.get("installState", {}) or {}).get("flags", "")
    last_updated = ext.get("lastPublished", "")

    ctx.store.upsert_resource(
        resource_id=f"ado://{org}/extension/{publisher_id}.{extension_id}",
        type="ado_extension",
        run_id=ctx.run_id,
        name=extension_name,
        properties_summary={
            "org": org,
            "publisher_id": publisher_id,
            "extension_id": extension_id,
            "extension_name": extension_name,
            "publisher_name": publisher_name,
            "version": version,
            "flags": flags,
            "scopes": scopes,
            "install_state": install_state,
            "last_updated": last_updated,
        },
    )

    findings = 0

    is_builtin = "builtIn" in flags
    if not is_builtin:
        high_scopes = [s for s in scopes if s in _HIGH_PRIVILEGE_SCOPES]
        if high_scopes:
            ctx.store.insert_finding(
                kind="ado_extension_high_privilege",
                resource_id=f"ado://{org}/extension/{publisher_id}.{extension_id}",
                reference=(
                    f"Extension '{extension_name}' by {publisher_name} "
                    f"has high-privilege scopes: {', '.join(high_scopes)}"
                ),
                run_id=ctx.run_id,
                details={
                    "org": org,
                    "publisher_id": publisher_id,
                    "extension_id": extension_id,
                    "extension_name": extension_name,
                    "publisher_name": publisher_name,
                    "high_scopes": high_scopes,
                },
            )
            findings += 1

    return 1, findings
