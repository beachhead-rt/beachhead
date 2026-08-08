"""analyze.ado_attack_paths — ADO pipeline lateral movement analysis.

Reads ADO resources and findings from the store to derive attack paths:
  - Pipeline → service connection → Azure subscription (lateral movement)
  - Variable group → Key Vault (secret access)
  - Self-hosted agent pool → pipeline (code execution on agent host)
  - Plaintext credentials → direct access
  - Unprotected repos → code injection into pipelines
  - Public-upstream feeds → dependency confusion
  - Broad permissions → privilege escalation
  - External/insecure service hooks → exfiltration / interception
  - High-privilege extensions → compromised extension abuse

Makes **no** API calls — purely offline store analysis.

MITRE ATT&CK: T1078.004 (Valid Accounts: Cloud Accounts)
               T1021.007 (Remote Services: Cloud Services Dashboard)
               T1195.002 (Supply Chain Compromise: Compromise Software Supply Chain)
               T1557     (Adversary-in-the-Middle)
               T1176     (Browser Extensions)
               T1102.002 (Web Service: Bidirectional Communication)
"""

from __future__ import annotations

import json
from typing import Any

from beachhead.core.module import Access, ModuleMeta, Phase, RunContext, RunResult


class AdoAttackPaths:
    meta = ModuleMeta(
        name="analyze.ado_attack_paths",
        phase=Phase.ANALYZE,
        access=Access.READ,
        requires_browser=False,
        technique_ids=("T1078.004", "T1021.007", "T1195.002", "T1557", "T1176", "T1102.002"),
        summary="Derive ADO lateral movement paths from enumerated data (offline).",
    )

    async def run(self, ctx: RunContext) -> RunResult:
        ado_resources = _get_ado_resources(ctx)
        count = 0
        count += _service_connection_paths(ctx, ado_resources)
        count += _keyvault_variable_group_paths(ctx)
        count += _self_hosted_agent_paths(ctx, ado_resources)
        count += _credential_exposure_paths(ctx)
        count += _branch_policy_bypass_paths(ctx, ado_resources)
        count += _feed_poisoning_paths(ctx)
        count += _permission_escalation_paths(ctx)
        count += _service_hook_exfil_paths(ctx)
        count += _extension_privilege_paths(ctx)

        ctx.console.print(f"[green]Derived {count} ADO attack path(s)[/]")
        return RunResult(ok=True, written=count)


def _get_ado_resources(ctx: RunContext) -> dict[str, list[Any]]:
    """Group ADO resources by type."""
    resources = ctx.store.resources()
    by_type: dict[str, list[Any]] = {}
    for r in resources:
        if r.type.startswith("ado_"):
            by_type.setdefault(r.type, []).append(r)
    return by_type


def _props(resource: Any) -> dict[str, Any]:
    """Extract properties_summary as a dict."""
    ps = resource.properties_summary
    if isinstance(ps, str):
        try:
            loaded: Any = json.loads(ps)
            return dict(loaded) if isinstance(loaded, dict) else {}
        except (json.JSONDecodeError, TypeError):
            return {}
    return dict(ps) if isinstance(ps, dict) else {}


def _service_connection_paths(ctx: RunContext, ado_resources: dict[str, list[Any]]) -> int:
    findings = ctx.store.findings(kind="ado_service_connection_azure")
    if not findings:
        return 0

    pipelines = ado_resources.get("ado_pipeline_yaml", []) + ado_resources.get(
        "ado_pipeline_classic_build", []
    )

    admin_findings = ctx.store.findings(
        kind="ado_service_connection_admin_access",
    )
    admin_resource_ids = {
        f.resource_id for f in admin_findings if f.resource_id
    }

    count = 0
    for finding in findings:
        details = finding.details or {}
        endpoint_name = details.get("endpoint_name", "")
        sub_id = details.get("subscription_id", "")
        org = details.get("org", "")
        project = details.get("project", "")

        has_admin = finding.resource_id in admin_resource_ids

        proj_pipelines = [
            p for p in pipelines if _props(p).get("project") == project
        ]

        for pipeline in proj_pipelines:
            pipe_name = (
                pipeline.name
                or _props(pipeline).get("pipeline_id", "")
            )
            edges: list[dict[str, object]] = [
                {
                    "from": pipeline.resource_id,
                    "to": finding.resource_id or "",
                    "via": "service_connection",
                },
                {
                    "from": finding.resource_id or "",
                    "to": f"subscription:{sub_id}",
                    "via": "azure_rm_scope",
                },
            ]

            if has_admin:
                score = 8.5
                desc = (
                    f"Pipeline '{pipe_name}' in {org}/{project} "
                    f"can reach Azure subscription {sub_id} via "
                    f"service connection '{endpoint_name}' "
                    f"[PAT has Administrator — extraction viable]"
                )
            else:
                score = 5.0
                desc = (
                    f"Pipeline '{pipe_name}' in {org}/{project} "
                    f"can reach Azure subscription {sub_id} via "
                    f"service connection '{endpoint_name}' "
                    f"[PAT lacks Administrator — extraction "
                    f"requires elevated permissions]"
                )

            ctx.store.insert_attack_path(
                source_id=pipeline.resource_id,
                target_id=f"subscription:{sub_id}",
                edges=edges,
                technique_ids=["T1078.004"],
                score=score,
                description=desc,
                run_id=ctx.run_id,
            )
            count += 1
    return count


def _keyvault_variable_group_paths(ctx: RunContext) -> int:
    findings = ctx.store.findings(kind="ado_variable_group_keyvault")
    count = 0
    for finding in findings:
        details = finding.details or {}
        vault_name = details.get("vault_name", "")
        group_name = details.get("group_name", "")
        org = details.get("org", "")
        project = details.get("project", "")

        edges: list[dict[str, object]] = [
            {
                "from": finding.resource_id or "",
                "to": f"keyvault:{vault_name}",
                "via": "variable_group_link",
            },
        ]
        ctx.store.insert_attack_path(
            source_id=finding.resource_id or "",
            target_id=f"keyvault:{vault_name}",
            edges=edges,
            technique_ids=["T1552.001"],
            score=6.0,
            description=(
                f"Variable group '{group_name}' in {org}/{project} "
                f"links to Key Vault '{vault_name}'"
            ),
            run_id=ctx.run_id,
        )
        count += 1
    return count


def _self_hosted_agent_paths(ctx: RunContext, ado_resources: dict[str, list[Any]]) -> int:
    findings = ctx.store.findings(kind="ado_self_hosted_pool")
    pipelines = ado_resources.get("ado_pipeline_yaml", []) + ado_resources.get(
        "ado_pipeline_classic_build", []
    )

    count = 0
    for finding in findings:
        details = finding.details or {}
        pool_name = details.get("pool_name", "")
        org = details.get("org", "")

        org_pipelines = [p for p in pipelines if _props(p).get("org") == org]
        if not org_pipelines:
            edges: list[dict[str, object]] = [
                {
                    "from": "any_pipeline",
                    "to": finding.resource_id or "",
                    "via": "self_hosted_pool",
                },
            ]
            ctx.store.insert_attack_path(
                source_id="any_pipeline",
                target_id=finding.resource_id or "",
                edges=edges,
                technique_ids=["T1021.007"],
                score=5.0,
                description=(
                    f"Self-hosted agent pool '{pool_name}' in {org} — "
                    f"pipeline code executes on operator-managed hosts"
                ),
                run_id=ctx.run_id,
            )
            count += 1
        else:
            for pipeline in org_pipelines[:5]:
                pipe_name = pipeline.name or ""
                edges = [
                    {
                        "from": pipeline.resource_id,
                        "to": finding.resource_id or "",
                        "via": "self_hosted_pool",
                    },
                ]
                ctx.store.insert_attack_path(
                    source_id=pipeline.resource_id,
                    target_id=finding.resource_id or "",
                    edges=edges,
                    technique_ids=["T1021.007"],
                    score=5.5,
                    description=(
                        f"Pipeline '{pipe_name}' may execute on self-hosted "
                        f"pool '{pool_name}' in {org}"
                    ),
                    run_id=ctx.run_id,
                )
                count += 1
    return count


def _credential_exposure_paths(ctx: RunContext) -> int:
    credential_kinds = (
        "ado_credential_exposure",
        "ado_pipeline_plaintext_variable",
        "ado_variable_group_plaintext_secret",
        "ado_pipeline_log_secret",
        "ado_wiki_credential",
    )
    count = 0
    for kind in credential_kinds:
        findings = ctx.store.findings(kind=kind)
        for finding in findings:
            details = finding.details or {}
            org = details.get("org", "")
            project = details.get("project", "")

            edges: list[dict[str, object]] = [
                {
                    "from": finding.resource_id or kind,
                    "to": "credential_access",
                    "via": kind,
                },
            ]
            sev = finding.details.get("severity", "medium") if finding.details else "medium"
            score = _severity_to_score(sev)
            ctx.store.insert_attack_path(
                source_id=finding.resource_id or kind,
                target_id="credential_access",
                edges=edges,
                technique_ids=["T1552.001"],
                score=score,
                description=(
                    f"Credential exposure ({kind}) in {org}/{project}: {finding.reference[:80]}"
                ),
                run_id=ctx.run_id,
            )
            count += 1
    return count


def _severity_to_score(severity: str) -> float:
    return {
        "critical": 9.0,
        "high": 7.5,
        "medium": 5.0,
        "low": 3.0,
    }.get(severity, 5.0)


def _branch_policy_bypass_paths(ctx: RunContext, ado_resources: dict[str, list[Any]]) -> int:
    count = 0
    pipelines = ado_resources.get("ado_pipeline_yaml", []) + ado_resources.get(
        "ado_pipeline_classic_build", []
    )

    for finding in ctx.store.findings(kind="ado_repo_no_branch_policy"):
        details = finding.details or {}
        org = details.get("org", "")
        project = details.get("project", "")
        repo_name = details.get("repo_name", "")
        edges: list[dict[str, object]] = [
            {
                "from": finding.resource_id or "",
                "to": "code_execution",
                "via": "no_branch_policy",
            },
        ]
        ctx.store.insert_attack_path(
            source_id=finding.resource_id or "",
            target_id="code_execution",
            edges=edges,
            technique_ids=["T1195.002"],
            score=6.5,
            description=(
                f"Repository '{repo_name}' in {org}/{project} has no branch policy "
                f"— direct push to default branch enables code injection into pipelines"
            ),
            run_id=ctx.run_id,
        )
        count += 1

    for finding in ctx.store.findings(kind="ado_pr_no_reviewer"):
        details = finding.details or {}
        org = details.get("org", "")
        project = details.get("project", "")
        repo_name = details.get("repo_name", "")
        proj_pipelines = [p for p in pipelines if _props(p).get("project") == project]
        for pipeline in proj_pipelines[:5]:
            pipe_name = pipeline.name or _props(pipeline).get("pipeline_id", "")
            edges = [
                {
                    "from": finding.resource_id or "",
                    "to": pipeline.resource_id,
                    "via": "pr_no_reviewer",
                },
            ]
            ctx.store.insert_attack_path(
                source_id=finding.resource_id or "",
                target_id=pipeline.resource_id,
                edges=edges,
                technique_ids=["T1195.002"],
                score=5.5,
                description=(
                    f"PRs in '{repo_name}' can merge without review "
                    f"→ pipeline '{pipe_name}' executes that code"
                ),
                run_id=ctx.run_id,
            )
            count += 1

    return count


def _feed_poisoning_paths(ctx: RunContext) -> int:
    count = 0
    for finding in ctx.store.findings(kind="ado_feed_upstream_public"):
        details = finding.details or {}
        org = details.get("org", "")
        feed_name = details.get("feed_name", "")
        edges: list[dict[str, object]] = [
            {
                "from": finding.resource_id or "",
                "to": "supply_chain_compromise",
                "via": "public_upstream",
            },
        ]
        ctx.store.insert_attack_path(
            source_id=finding.resource_id or "",
            target_id="supply_chain_compromise",
            edges=edges,
            technique_ids=["T1195.002"],
            score=7.0,
            description=(
                f"Feed '{feed_name}' in {org} has public upstream sources "
                f"— dependency confusion attack possible"
            ),
            run_id=ctx.run_id,
        )
        count += 1
    return count


def _permission_escalation_paths(ctx: RunContext) -> int:
    count = 0
    for finding in ctx.store.findings(kind="ado_broad_permissions"):
        details = finding.details or {}
        org = details.get("org", "")
        ns_name = details.get("namespace_name", "")
        identity_label = details.get("identity_label", "")
        dangerous = details.get("dangerous_actions", [])
        target_ctx = details.get("target_context", "")

        attack_target, technique, score = _classify_permission_attack(ns_name, dangerous)

        perm_summary = ", ".join(dangerous[:4])
        if len(dangerous) > 4:
            perm_summary += f" (+{len(dangerous) - 4} more)"

        edges: list[dict[str, object]] = [
            {
                "from": finding.resource_id or "",
                "to": attack_target,
                "via": f"permissions:{ns_name}",
            },
        ]
        ctx.store.insert_attack_path(
            source_id=finding.resource_id or "",
            target_id=attack_target,
            edges=edges,
            technique_ids=[technique],
            score=score,
            description=(
                f"{identity_label} has [{perm_summary}] on {ns_name} "
                f"({target_ctx}) in {org} — {_attack_narrative(ns_name, dangerous)}"
            ),
            run_id=ctx.run_id,
        )
        count += 1
    return count


def _classify_permission_attack(
    ns_name: str, dangerous_actions: list[str],
) -> tuple[str, str, float]:
    """Map permission findings to attack target, technique, and score."""
    admin_perms = {
        "ManagePermissions", "AdministerBuildPermissions",
        "AdministerReleasePermissions", "ManageMembership", "CreateScope",
    }
    code_inject_perms = {
        "ForcePush", "PullRequestBypassPolicy", "PolicyExempt", "EditPolicies",
    }
    build_perms = {
        "EditBuildDefinition", "QueueBuilds", "OverrideBuildCheckInValidation",
        "DeleteBuildDefinition",
    }
    release_perms = {
        "EditReleaseDefinition", "ManageDeployments", "CreateReleases",
        "ManageReleaseApprovers", "DeleteReleaseDefinition",
    }

    has_admin = any(a in admin_perms for a in dangerous_actions)
    has_code = any(a in code_inject_perms for a in dangerous_actions)
    has_build = any(a in build_perms for a in dangerous_actions)
    has_release = any(a in release_perms for a in dangerous_actions)

    if has_admin:
        return "privilege_escalation", "T1078.004", 8.5
    if has_code and (has_build or has_release):
        return "code_execution_via_pipeline", "T1195.002", 8.0
    if has_code:
        return "code_injection", "T1195.002", 7.0
    if has_build:
        return "pipeline_manipulation", "T1059.009", 7.0
    if has_release:
        return "deployment_hijack", "T1059.009", 7.0
    return "privilege_escalation", "T1078.004", 6.0


def _attack_narrative(ns_name: str, dangerous_actions: list[str]) -> str:
    """One-line narrative of what the permissions enable."""
    admin_set = {"ManagePermissions", "AdministerBuildPermissions"}
    if admin_set & set(dangerous_actions):
        return "can grant arbitrary permissions to any identity"
    if "ForcePush" in dangerous_actions:
        return "can force-push to protected branches, bypassing all branch policies"
    if "PullRequestBypassPolicy" in dangerous_actions:
        return "can merge PRs bypassing required reviews and build validation"
    if "EditBuildDefinition" in dangerous_actions and "QueueBuilds" in dangerous_actions:
        return "can modify pipeline definitions and trigger builds (code execution)"
    if "EditBuildDefinition" in dangerous_actions:
        return "can modify pipeline definitions to inject malicious steps"
    if "QueueBuilds" in dangerous_actions:
        return "can trigger pipeline runs (code execution on agents)"
    if "EditReleaseDefinition" in dangerous_actions:
        return "can modify release pipelines to inject into deployments"
    if "CreateReleases" in dangerous_actions:
        return "can create releases to deploy arbitrary code"
    if "ManageMembership" in dangerous_actions:
        return "can add/remove group members for privilege escalation"
    if "PolicyExempt" in dangerous_actions:
        return "exempt from branch policies — can push directly to protected branches"
    if "EditPolicies" in dangerous_actions:
        return "can weaken or remove branch protection policies"
    return "has elevated permissions enabling lateral movement"


def _service_hook_exfil_paths(ctx: RunContext) -> int:
    count = 0
    for finding in ctx.store.findings(kind="ado_hook_external_target"):
        edges: list[dict[str, object]] = [
            {
                "from": finding.resource_id or "",
                "to": "data_exfiltration",
                "via": "external_webhook",
            },
        ]
        ctx.store.insert_attack_path(
            source_id=finding.resource_id or "",
            target_id="data_exfiltration",
            edges=edges,
            technique_ids=["T1102.002"],
            score=5.0,
            description=(
                "Service hook sends events to external target "
                "— potential data exfiltration or injection point"
            ),
            run_id=ctx.run_id,
        )
        count += 1

    for finding in ctx.store.findings(kind="ado_hook_insecure_url"):
        edges = [
            {
                "from": finding.resource_id or "",
                "to": "credential_interception",
                "via": "insecure_webhook",
            },
        ]
        ctx.store.insert_attack_path(
            source_id=finding.resource_id or "",
            target_id="credential_interception",
            edges=edges,
            technique_ids=["T1557"],
            score=6.0,
            description=(
                "Service hook uses non-HTTPS URL — webhook payloads "
                "(including tokens/secrets in events) transmitted in cleartext"
            ),
            run_id=ctx.run_id,
        )
        count += 1

    return count


def _extension_privilege_paths(ctx: RunContext) -> int:
    count = 0
    for finding in ctx.store.findings(kind="ado_extension_high_privilege"):
        details = finding.details or {}
        ext_name = details.get("extension_name", "unknown")
        edges: list[dict[str, object]] = [
            {
                "from": finding.resource_id or "",
                "to": "privilege_escalation",
                "via": "high_privilege_extension",
            },
        ]
        ctx.store.insert_attack_path(
            source_id=finding.resource_id or "",
            target_id="privilege_escalation",
            edges=edges,
            technique_ids=["T1176"],
            score=5.0,
            description=(
                f"Extension '{ext_name}' has high-privilege scopes "
                f"— compromised extension could access code/builds/releases/secrets"
            ),
            run_id=ctx.run_id,
        )
        count += 1
    return count
