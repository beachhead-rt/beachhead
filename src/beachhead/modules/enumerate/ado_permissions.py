"""enumerate.ado_permissions — ADO security namespaces and ACLs.

Enumerates security namespaces and access control lists across all
in-scope ADO organizations. Decodes permission bitmasks to human-readable
action names and flags identities with security-critical permissions on
key namespaces (Git Repositories, Build, ReleaseManagement, Project).

Findings are structured with decoded permissions and risk classification
so analyze.ado_attack_paths can generate specific privilege-escalation
and lateral-movement paths.

MITRE ATT&CK: T1069.003 (Permission Groups Discovery: Cloud Groups)
"""

from __future__ import annotations

import asyncio
import hashlib
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

# ------------------------------------------------------------------ #
# Well-known ADO security namespaces and their action bitmasks.
# These are stable across ADO instances — used as fallback when the
# API response doesn't include full action metadata.
# ------------------------------------------------------------------ #
_KEY_NAMESPACES: dict[str, str] = {
    "2e9eb7ed-3c0a-47d4-87c1-0ffdd275fd87": "Git Repositories",
    "33344d9c-fc72-4d6f-aba5-fa317101a7e9": "Build",
    "c788c23e-1b46-4162-8f5e-d7585343b5de": "ReleaseManagement",
    "52d39943-cb85-4d7f-8fa8-c6baac873819": "Project",
    "5a27515b-ccd7-42c9-84f1-54c998f03866": "Identity",
}

_KNOWN_ACTIONS: dict[str, dict[int, str]] = {
    "2e9eb7ed-3c0a-47d4-87c1-0ffdd275fd87": {
        1: "Read",
        2: "Contribute",
        4: "CreateBranch",
        8: "CreateTag",
        16: "ManageNote",
        32: "PolicyExempt",
        64: "CreateRepository",
        128: "DeleteRepository",
        256: "RenameRepository",
        512: "EditPolicies",
        1024: "RemoveOthersLocks",
        2048: "ManagePermissions",
        4096: "PullRequestContribute",
        8192: "PullRequestBypassPolicy",
        16384: "ForcePush",
    },
    "33344d9c-fc72-4d6f-aba5-fa317101a7e9": {
        1: "ViewBuilds",
        2: "EditBuildQuality",
        4: "RetainIndefinitely",
        8: "DeleteBuilds",
        16: "ManageBuildQualities",
        32: "DestroyBuilds",
        64: "UpdateBuildInformation",
        128: "QueueBuilds",
        256: "ManageBuildQueue",
        512: "StopBuilds",
        1024: "ViewBuildDefinition",
        2048: "EditBuildDefinition",
        4096: "DeleteBuildDefinition",
        8192: "OverrideBuildCheckInValidation",
        16384: "AdministerBuildPermissions",
    },
    "c788c23e-1b46-4162-8f5e-d7585343b5de": {
        1: "ViewReleaseDefinition",
        2: "EditReleaseDefinition",
        4: "DeleteReleaseDefinition",
        8: "ManageReleaseApprovers",
        16: "ManageReleases",
        32: "ViewReleases",
        64: "CreateReleases",
        128: "EditReleaseEnvironment",
        256: "DeleteReleaseEnvironment",
        512: "AdministerReleasePermissions",
        1024: "DeleteReleases",
        2048: "ManageDeployments",
        4096: "ManageReleaseSettings",
    },
    "52d39943-cb85-4d7f-8fa8-c6baac873819": {
        1: "ViewProjectInfo",
        2: "EditProjectInfo",
        4: "DeleteProject",
        8: "PublishTestResults",
        16: "AdministerBuild",
        32: "StartBuild",
        64: "EditBuildStatus",
        128: "UpdateBuild",
        256: "DeleteTestRuns",
        512: "ViewTestRuns",
        1024: "ManageTestEnvironments",
        2048: "ManageTestConfigurations",
        4096: "DeleteWorkItems",
        8192: "MoveWorkItemsOut",
        16384: "MoveWorkItemsIn",
    },
    "5a27515b-ccd7-42c9-84f1-54c998f03866": {
        1: "Read",
        2: "Write",
        4: "Delete",
        8: "ManageMembership",
        16: "CreateScope",
        32: "RestoreScope",
    },
}

_DANGEROUS_ACTIONS: frozenset[str] = frozenset({
    "ManagePermissions",
    "AdministerBuildPermissions",
    "AdministerReleasePermissions",
    "ForcePush",
    "PullRequestBypassPolicy",
    "PolicyExempt",
    "DeleteRepository",
    "EditPolicies",
    "EditBuildDefinition",
    "DeleteBuildDefinition",
    "QueueBuilds",
    "EditReleaseDefinition",
    "DeleteReleaseDefinition",
    "ManageReleaseApprovers",
    "CreateReleases",
    "ManageDeployments",
    "DeleteProject",
    "AdministerBuild",
    "ManageMembership",
    "CreateScope",
    "OverrideBuildCheckInValidation",
})

_MAX_FINDINGS_PER_NAMESPACE = 25


class AdoPermissions:
    meta = ModuleMeta(
        name="enumerate.ado_permissions",
        phase=Phase.ENUMERATE,
        access=Access.READ,
        requires_browser=False,
        technique_ids=("T1069.003",),
        summary="Enumerate ADO security namespaces and access control lists.",
    )

    async def run(self, ctx: RunContext) -> RunResult:
        pat = await get_pat(ctx)
        if pat is None:
            return no_pat_result(ctx)

        orgs = get_orgs(ctx)
        if not orgs:
            return no_orgs_result(ctx)

        results = await asyncio.gather(
            *(_run_org(ctx, org, pat) for org in sorted(orgs)),
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
            f"[green]Recorded {total} permission resource(s), "
            f"{findings} finding(s)[/]"
        )
        return RunResult(ok=True, written=total + findings)


async def _run_org(
    ctx: RunContext, org: str, pat: str,
) -> tuple[int, int]:
    ctx.console.print(f"[bold]Enumerating permissions: {org}[/]")
    client = make_client(org, pat, ctx)
    try:
        if ctx.since:
            projects = await client.list_projects()
            active = ado_time_filter(projects, ctx.since, "lastUpdateTime")
            if not active:
                ctx.console.print(f"  [dim]No recently updated projects in {org} — skipping[/]")
                return 0, 0
        return await _enum_org(ctx, client, org)
    finally:
        await client.close()


async def _enum_org(ctx: RunContext, client: Any, org: str) -> tuple[int, int]:
    count = 0
    findings = 0

    ctx.console.print("  [dim]GET security namespaces...[/]")
    try:
        namespaces = await client.list_security_namespaces()
    except (ScopeError, AuthError):
        raise
    except Exception as exc:  # noqa: BLE001
        ctx.console.print(f"  [red]FAIL list_security_namespaces: {exc}[/]")
        return 0, 0
    ctx.console.print(f"  [green]OK[/] {len(namespaces)} namespace(s) returned")

    action_maps: dict[str, dict[int, str]] = {}

    for ns in namespaces:
        if not isinstance(ns, dict):
            continue
        ns_id = ns.get("namespaceId", "") or ns.get("id", "")
        if not ns_id:
            continue
        name = ns.get("name", "")
        display_name = ns.get("displayName", name)
        actions = ns.get("actions", [])

        api_action_map: dict[int, str] = {}
        action_names: list[str] = []
        for a in actions:
            if not isinstance(a, dict):
                continue
            bit = a.get("bit", 0)
            action_name = a.get("displayName", a.get("name", ""))
            if bit and action_name:
                api_action_map[bit] = action_name
            action_names.append(action_name)

        if api_action_map:
            action_maps[ns_id] = api_action_map
        elif ns_id in _KNOWN_ACTIONS:
            action_maps[ns_id] = _KNOWN_ACTIONS[ns_id]

        ctx.store.upsert_resource(
            resource_id=f"ado://{org}/namespace/{ns_id}",
            type="ado_security_namespace",
            run_id=ctx.run_id,
            name=name,
            properties_summary={
                "org": org,
                "namespace_id": ns_id,
                "name": name,
                "display_name": display_name,
                "actions": action_names[:30],
            },
        )
        count += 1

    async def _fetch_acls(ns_id: str, ns_name: str) -> list[dict[str, Any]]:
        ctx.console.print(f"  [dim]GET ACLs for {ns_name} ({ns_id[:8]}...)...[/]")
        try:
            result = await client.list_access_control_lists(ns_id)
        except (ScopeError, AuthError):
            raise
        except Exception as exc:  # noqa: BLE001
            ctx.console.print(
                f"  [yellow]SKIP[/] {ns_name} — ACL endpoint returned error: {exc}"
            )
            return []
        ctx.console.print(f"  [green]OK[/] {ns_name}: {len(result)} ACL(s)")
        return result

    fetchable = [
        (ns_id, ns_name) for ns_id, ns_name in _KEY_NAMESPACES.items()
        if action_maps.get(ns_id, _KNOWN_ACTIONS.get(ns_id, {}))
    ]
    ctx.console.print(f"  [bold]Fetching ACLs for {len(fetchable)} key namespace(s)...[/]")
    acl_results = await asyncio.gather(
        *(_fetch_acls(ns_id, ns_name) for ns_id, ns_name in fetchable),
        return_exceptions=True,
    )

    for (ns_id, ns_name), acls_or_exc in zip(fetchable, acl_results, strict=True):
        if isinstance(acls_or_exc, BaseException):
            if isinstance(acls_or_exc, (ScopeError, AuthError)):
                raise acls_or_exc
            ctx.console.print(f"  [red]FAIL {ns_name}: {acls_or_exc}[/]")
            continue
        acls: list[dict[str, Any]] = acls_or_exc
        ns_action_map = action_maps.get(ns_id, _KNOWN_ACTIONS.get(ns_id, {}))

        ns_findings = 0
        for acl in acls:
            if not isinstance(acl, dict):
                continue
            token = acl.get("token", "")
            inherit = acl.get("inheritPermissions", True)
            aces = acl.get("acesDictionary", {}) or {}

            token_hash = hashlib.sha256(token.encode()).hexdigest()[:12]
            ctx.store.upsert_resource(
                resource_id=f"ado://{org}/acl/{ns_id}/{token_hash}",
                type="ado_access_control",
                run_id=ctx.run_id,
                name=f"{ns_name}: {token[:60]}",
                properties_summary={
                    "org": org,
                    "namespace_id": ns_id,
                    "namespace_name": ns_name,
                    "token": token,
                    "inherit_permissions": inherit,
                    "aces_count": len(aces),
                },
            )
            count += 1

            for descriptor, ace in aces.items():
                if ns_findings >= _MAX_FINDINGS_PER_NAMESPACE:
                    break
                if not isinstance(ace, dict):
                    continue
                allow = ace.get("allow", 0)
                deny = ace.get("deny", 0)
                if not isinstance(allow, int) or allow == 0:
                    continue

                allowed_actions = _decode_bitmask(allow, ns_action_map)
                denied_actions = (
                    _decode_bitmask(deny, ns_action_map) if isinstance(deny, int) else []
                )
                effective_actions = [a for a in allowed_actions if a not in denied_actions]

                dangerous = [a for a in effective_actions if a in _DANGEROUS_ACTIONS]
                if not dangerous:
                    continue

                identity_label = _clean_descriptor(descriptor)

                target_context = _parse_token_context(token, ns_name)

                ctx.store.insert_finding(
                    kind="ado_broad_permissions",
                    resource_id=f"ado://{org}/acl/{ns_id}/{token_hash}",
                    reference=(
                        f"{identity_label} has dangerous permissions on "
                        f"{ns_name} ({target_context}): "
                        f"{', '.join(dangerous[:5])}"
                        + (f" (+{len(dangerous)-5} more)" if len(dangerous) > 5 else "")
                    ),
                    run_id=ctx.run_id,
                    details={
                        "org": org,
                        "namespace_id": ns_id,
                        "namespace_name": ns_name,
                        "descriptor": descriptor,
                        "identity_label": identity_label,
                        "allow_bits": allow,
                        "deny_bits": ace.get("deny", 0),
                        "allowed_actions": effective_actions,
                        "dangerous_actions": dangerous,
                        "token": token,
                        "target_context": target_context,
                    },
                )
                ns_findings += 1
                findings += 1

        total_aces = sum(len(a.get("acesDictionary", {}) or {}) for a in acls if isinstance(a, dict))
        ctx.console.print(
            f"  [dim]{ns_name}:[/] {len(acls)} ACL(s), "
            f"{total_aces} ACE(s), {ns_findings} finding(s)"
        )

    return count, findings


def _decode_bitmask(mask: int, action_map: dict[int, str]) -> list[str]:
    """Decode a permission bitmask into human-readable action names."""
    actions = []
    for bit, name in sorted(action_map.items()):
        if mask & bit:
            actions.append(name)
    return actions


def _clean_descriptor(descriptor: str) -> str:
    """Extract a readable label from an ADO identity descriptor."""
    prefixes = [
        ("Microsoft.TeamFoundation.Identity;", "TF Identity", 20),
        ("Microsoft.IdentityModel.Claims.ClaimsIdentity;", "Claims Identity", 30),
        ("Microsoft.TeamFoundation.ServiceIdentity;", "Service Identity", 30),
    ]
    for prefix, label, trim in prefixes:
        if descriptor.startswith(prefix):
            val = descriptor.split(";", 1)[1]
            if len(val) > trim:
                return f"{label} ({val[:trim]}...)"
            return f"{label} ({val})"
    short_prefixes = [("vssgp.", "VSS Group"), ("aad.", "AAD Identity")]
    for prefix, label in short_prefixes:
        if descriptor.startswith(prefix):
            if len(descriptor) > 25:
                return f"{label} ({descriptor[:25]}...)"
            return f"{label} ({descriptor})"
    return descriptor[:50]


def _parse_token_context(token: str, ns_name: str) -> str:
    """Parse a security token into a human-readable scope description."""
    if not token:
        return "org-level"

    parts = token.split("/")
    if ns_name == "Git Repositories":
        if len(parts) >= 3:
            return f"repo scope: {'/'.join(parts[-2:])}"
        if len(parts) >= 2:
            return f"project scope: {parts[-1]}"
    elif ns_name == "Build":
        if len(parts) >= 2:
            return f"build scope: {'/'.join(parts[-2:])}"
    elif ns_name == "ReleaseManagement":
        if len(parts) >= 2:
            return f"release scope: {'/'.join(parts[-2:])}"
    elif ns_name == "Project":
        if len(parts) >= 1 and parts[-1]:
            return f"project: {parts[-1]}"

    return f"scope: {token[:40]}" if len(token) > 40 else f"scope: {token}"
