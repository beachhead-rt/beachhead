"""Tests for analyze.ado_attack_paths — offline ADO lateral-movement analysis."""

from __future__ import annotations

from typing import Any

import pytest
from conftest import FakeClock, FakeIds
from rich.console import Console

from beachhead.core.runner import RunEnv, run_module
from beachhead.core.store.engine import open_store
from beachhead.modules.analyze.ado_attack_paths import AdoAttackPaths


class FakeAz:
    async def run(self, args: list[str], **kw: Any) -> Any:
        return {}


class FakeScope:
    def check(self, target: str, *, kind: str = "target") -> None:
        pass


class FakeConfig:
    @property
    def engagement(self) -> str:
        return "ACME"

    @property
    def allow_write(self) -> bool:
        return False

    @property
    def ado_organizations(self) -> frozenset[str]:
        return frozenset({"test-org"})


@pytest.fixture
def store(tmp_path: Any) -> Any:
    s = open_store(str(tmp_path / "test.db"), clock=FakeClock(), id_factory=FakeIds())
    s.ensure_engagement(name="ACME", scope_hash="h")
    return s


def _env(store: Any) -> RunEnv:
    return RunEnv(
        store=store,
        az=FakeAz(),
        auth=None,
        config=FakeConfig(),
        scope=FakeScope(),
        console=Console(quiet=True),
        operator="op",
    )


def test_meta() -> None:
    m = AdoAttackPaths()
    assert m.meta.name == "analyze.ado_attack_paths"
    assert m.meta.phase.value == "analyze"
    assert m.meta.access.value == "read"
    assert m.meta.gated is False


@pytest.mark.asyncio
async def test_service_connection_to_subscription(store: Any) -> None:
    """Pipeline + service connection finding → attack path to subscription."""
    seed_run = store.start_run(
        module="enumerate.ado_service_connections",
        phase="enumerate",
        operator="op",
    )

    store.upsert_resource(
        resource_id="ado://test-org/proj1/pipeline/42",
        type="ado_pipeline_yaml",
        name="deploy-pipeline",
        run_id=seed_run,
        properties_summary={"project": "proj1", "org": "test-org", "pipeline_id": "42"},
    )

    store.insert_finding(
        kind="ado_service_connection_azure",
        resource_id="ado://test-org/proj1/endpoint/sc-1",
        reference="Service connection sc-1 -> subscription",
        run_id=seed_run,
        details={
            "endpoint_name": "azure-prod",
            "subscription_id": "sub-1111",
            "org": "test-org",
            "project": "proj1",
        },
    )
    store.finish_run(seed_run, status="ok")

    env = _env(store)
    result = await run_module(AdoAttackPaths(), env)  # type: ignore[arg-type]

    assert result.ok is True
    assert result.written >= 1

    paths = store.attack_paths()
    assert len(paths) >= 1
    p = paths[0]
    assert "subscription" in p.target_id.lower() or "sub-1111" in p.target_id
    assert p.score >= 5.0
    assert "deploy-pipeline" in p.description or "azure-prod" in p.description


@pytest.mark.asyncio
async def test_keyvault_variable_group_path(store: Any) -> None:
    """Variable group linked to Key Vault → attack path."""
    seed_run = store.start_run(
        module="enumerate.ado_variable_groups",
        phase="enumerate",
        operator="op",
    )

    store.insert_finding(
        kind="ado_variable_group_keyvault",
        resource_id="ado://test-org/proj1/variablegroup/5",
        reference="Variable group secrets-vg linked to Key Vault prod-kv",
        run_id=seed_run,
        details={
            "vault_name": "prod-kv",
            "group_name": "secrets-vg",
            "org": "test-org",
            "project": "proj1",
        },
    )
    store.finish_run(seed_run, status="ok")

    env = _env(store)
    result = await run_module(AdoAttackPaths(), env)  # type: ignore[arg-type]

    assert result.ok is True
    assert result.written >= 1

    paths = store.attack_paths()
    assert len(paths) >= 1
    p = paths[0]
    assert "keyvault:prod-kv" in p.target_id
    assert "secrets-vg" in p.description


@pytest.mark.asyncio
async def test_empty_store_no_paths(store: Any) -> None:
    """Empty store produces zero attack paths."""
    env = _env(store)
    result = await run_module(AdoAttackPaths(), env)  # type: ignore[arg-type]

    assert result.ok is True
    assert result.written == 0
    assert len(store.attack_paths()) == 0


@pytest.mark.asyncio
async def test_self_hosted_agent_path(store: Any) -> None:
    """Self-hosted pool finding → attack path."""
    seed_run = store.start_run(
        module="enumerate.ado_agent_pools",
        phase="enumerate",
        operator="op",
    )

    store.insert_finding(
        kind="ado_self_hosted_pool",
        resource_id="ado://test-org/pool/99",
        reference="Self-hosted pool build-agents",
        run_id=seed_run,
        details={
            "pool_name": "build-agents",
            "org": "test-org",
        },
    )
    store.finish_run(seed_run, status="ok")

    env = _env(store)
    result = await run_module(AdoAttackPaths(), env)  # type: ignore[arg-type]

    assert result.ok is True
    assert result.written >= 1

    paths = store.attack_paths()
    assert any("build-agents" in p.description for p in paths)


@pytest.mark.asyncio
async def test_branch_policy_bypass_paths(store: Any) -> None:
    """Repo with no branch policy → attack path to code_execution."""
    seed_run = store.start_run(
        module="enumerate.ado_repos",
        phase="enumerate",
        operator="op",
    )

    store.upsert_resource(
        resource_id="ado://test-org/proj1/repo/r-1",
        type="ado_repo",
        name="my-app",
        run_id=seed_run,
        properties_summary={"org": "test-org", "project": "proj1"},
    )

    store.insert_finding(
        kind="ado_repo_no_branch_policy",
        resource_id="ado://test-org/proj1/repo/r-1",
        reference="Repository 'my-app' in test-org/proj1 has no branch policy",
        run_id=seed_run,
        details={
            "org": "test-org",
            "project": "proj1",
            "repo_name": "my-app",
        },
    )
    store.finish_run(seed_run, status="ok")

    env = _env(store)
    result = await run_module(AdoAttackPaths(), env)  # type: ignore[arg-type]

    assert result.ok is True
    assert result.written >= 1

    paths = store.attack_paths()
    bp_paths = [p for p in paths if p.target_id == "code_execution"]
    assert len(bp_paths) >= 1
    assert "my-app" in bp_paths[0].description
    assert bp_paths[0].score == 6.5


@pytest.mark.asyncio
async def test_feed_poisoning_paths(store: Any) -> None:
    """Feed with public upstream → attack path to supply_chain_compromise."""
    seed_run = store.start_run(
        module="enumerate.ado_feeds",
        phase="enumerate",
        operator="op",
    )

    store.upsert_resource(
        resource_id="ado://test-org/feed/f-1",
        type="ado_feed",
        name="internal-nuget",
        run_id=seed_run,
        properties_summary={"org": "test-org"},
    )

    store.insert_finding(
        kind="ado_feed_upstream_public",
        resource_id="ado://test-org/feed/f-1",
        reference="Feed 'internal-nuget' has public upstream nuget.org",
        run_id=seed_run,
        details={
            "org": "test-org",
            "feed_name": "internal-nuget",
        },
    )
    store.finish_run(seed_run, status="ok")

    env = _env(store)
    result = await run_module(AdoAttackPaths(), env)  # type: ignore[arg-type]

    assert result.ok is True
    assert result.written >= 1

    paths = store.attack_paths()
    fp_paths = [p for p in paths if p.target_id == "supply_chain_compromise"]
    assert len(fp_paths) >= 1
    assert "internal-nuget" in fp_paths[0].description
    assert fp_paths[0].score == 7.0


@pytest.mark.asyncio
async def test_permission_escalation_paths(store: Any) -> None:
    """Enriched permission finding → attack path with decoded permission names."""
    seed_run = store.start_run(
        module="enumerate.ado_permissions",
        phase="enumerate",
        operator="op",
    )

    store.insert_finding(
        kind="ado_broad_permissions",
        resource_id="ado://test-org/acl/ns-1/tok-abc",
        reference=(
            "TF Identity (user1) has dangerous permissions on "
            "Git Repositories (repo scope: proj1/my-repo): "
            "ManagePermissions, ForcePush"
        ),
        run_id=seed_run,
        details={
            "org": "test-org",
            "namespace_id": "2e9eb7ed-3c0a-47d4-87c1-0ffdd275fd87",
            "namespace_name": "Git Repositories",
            "identity_label": "TF Identity (user1)",
            "dangerous_actions": ["ManagePermissions", "ForcePush"],
            "allowed_actions": ["Read", "Contribute", "ManagePermissions", "ForcePush"],
            "target_context": "repo scope: proj1/my-repo",
            "token": "repoV2/proj-guid/repo-guid",
        },
    )
    store.finish_run(seed_run, status="ok")

    env = _env(store)
    result = await run_module(AdoAttackPaths(), env)  # type: ignore[arg-type]

    assert result.ok is True
    assert result.written >= 1

    paths = store.attack_paths()
    pe_paths = [p for p in paths if "privilege_escalation" in p.target_id]
    assert len(pe_paths) >= 1
    assert "ManagePermissions" in pe_paths[0].description
    assert "can grant arbitrary permissions" in pe_paths[0].description
    assert pe_paths[0].score >= 8.0


@pytest.mark.asyncio
async def test_permission_build_manipulation_path(store: Any) -> None:
    """Build namespace permissions → pipeline_manipulation attack path."""
    seed_run = store.start_run(
        module="enumerate.ado_permissions",
        phase="enumerate",
        operator="op",
    )

    store.insert_finding(
        kind="ado_broad_permissions",
        resource_id="ado://test-org/acl/build-ns/tok-xyz",
        reference=(
            "VSS Group (builders) has dangerous permissions on Build: "
            "EditBuildDefinition, QueueBuilds"
        ),
        run_id=seed_run,
        details={
            "org": "test-org",
            "namespace_name": "Build",
            "identity_label": "VSS Group (builders)",
            "dangerous_actions": ["EditBuildDefinition", "QueueBuilds"],
            "target_context": "build scope: proj1",
        },
    )
    store.finish_run(seed_run, status="ok")

    env = _env(store)
    result = await run_module(AdoAttackPaths(), env)  # type: ignore[arg-type]

    assert result.ok is True
    paths = store.attack_paths()
    build_paths = [p for p in paths if "pipeline" in p.target_id]
    assert len(build_paths) >= 1
    assert "code execution" in build_paths[0].description.lower()
    assert build_paths[0].score >= 7.0


@pytest.mark.asyncio
async def test_service_hook_paths(store: Any) -> None:
    """External-target and insecure-URL hooks → two distinct attack paths."""
    seed_run = store.start_run(
        module="enumerate.ado_service_hooks",
        phase="enumerate",
        operator="op",
    )

    store.insert_finding(
        kind="ado_hook_external_target",
        resource_id="ado://test-org/hook/h-1",
        reference="Service hook 'build.complete' sends to external target: evil.com",
        run_id=seed_run,
        details={"org": "test-org"},
    )

    store.insert_finding(
        kind="ado_hook_insecure_url",
        resource_id="ado://test-org/hook/h-2",
        reference="Service hook sends to non-HTTPS URL: http://internal/webhook",
        run_id=seed_run,
        details={"org": "test-org"},
    )
    store.finish_run(seed_run, status="ok")

    env = _env(store)
    result = await run_module(AdoAttackPaths(), env)  # type: ignore[arg-type]

    assert result.ok is True
    assert result.written >= 2

    paths = store.attack_paths()
    exfil = [p for p in paths if p.target_id == "data_exfiltration"]
    intercept = [p for p in paths if p.target_id == "credential_interception"]
    assert len(exfil) >= 1
    assert exfil[0].score == 5.0
    assert len(intercept) >= 1
    assert intercept[0].score == 6.0


@pytest.mark.asyncio
async def test_extension_privilege_paths(store: Any) -> None:
    """High-privilege extension → attack path to privilege_escalation."""
    seed_run = store.start_run(
        module="enumerate.ado_extensions",
        phase="enumerate",
        operator="op",
    )

    store.insert_finding(
        kind="ado_extension_high_privilege",
        resource_id="ado://test-org/extension/shady-pub.mega-tool",
        reference="Extension 'MegaTool' by shady-pub has high-privilege scopes",
        run_id=seed_run,
        details={
            "org": "test-org",
            "extension_name": "MegaTool",
            "publisher_name": "shady-pub",
        },
    )
    store.finish_run(seed_run, status="ok")

    env = _env(store)
    result = await run_module(AdoAttackPaths(), env)  # type: ignore[arg-type]

    assert result.ok is True
    assert result.written >= 1

    paths = store.attack_paths()
    ext_paths = [p for p in paths if "MegaTool" in p.description]
    assert len(ext_paths) >= 1
    assert ext_paths[0].score == 5.0
    assert ext_paths[0].target_id == "privilege_escalation"
