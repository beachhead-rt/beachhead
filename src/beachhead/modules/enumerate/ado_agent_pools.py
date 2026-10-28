"""enumerate.ado_agent_pools — ADO agent pools and agents.

Enumerates agent pools (org-level) and agents within each pool,
recording capabilities, status, and version. Flags self-hosted pools
and agents with potentially sensitive capabilities.

MITRE ATT&CK: T1526 (Cloud Service Discovery)
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

_SENSITIVE_CAPABILITY_KEYWORDS = frozenset(
    {
        "password",
        "secret",
        "key",
        "token",
        "credential",
        "connection_string",
        "pat",
        "api_key",
    }
)


class AdoAgentPools:
    meta = ModuleMeta(
        name="enumerate.ado_agent_pools",
        phase=Phase.ENUMERATE,
        access=Access.READ,
        requires_browser=False,
        technique_ids=("T1526",),
        summary="Enumerate ADO agent pools and agents with capabilities.",
    )

    async def run(self, ctx: RunContext) -> RunResult:
        pat = await get_pat(ctx)
        if pat is None:
            return no_pat_result(ctx)

        orgs = get_orgs(ctx)
        if not orgs:
            return no_orgs_result(ctx)

        total_pools = 0
        total_agents = 0
        findings = 0

        for org in sorted(orgs):
            ctx.console.print(f"[bold]Enumerating agent pools: {org}[/]")
            client = make_client(org, pat, ctx)
            try:
                pools = await client.list_agent_pools()
                pools = ado_time_filter(pools, ctx.since, "createdOn")

                for pool in pools:
                    if not isinstance(pool, dict):
                        continue

                    pool_id = pool.get("id", "")
                    name = pool.get("name", "")
                    is_hosted = pool.get("isHosted", True)
                    pool_type = pool.get("poolType", "")
                    size = pool.get("size", 0)

                    ctx.store.upsert_resource(
                        resource_id=f"ado://{org}/pool/{pool_id}",
                        type="ado_agent_pool",
                        run_id=ctx.run_id,
                        name=name,
                        properties_summary={
                            "org": org,
                            "pool_id": pool_id,
                            "is_hosted": is_hosted,
                            "pool_type": pool_type,
                            "size": size,
                            "auto_provision": pool.get("autoProvision", False),
                            "auto_update": pool.get("autoUpdate", True),
                        },
                    )
                    total_pools += 1

                    if not is_hosted:
                        ctx.store.insert_finding(
                            kind="ado_self_hosted_pool",
                            resource_id=f"ado://{org}/pool/{pool_id}",
                            reference=(f"Self-hosted agent pool '{name}' ({size} agent(s))"),
                            run_id=ctx.run_id,
                            details={
                                "org": org,
                                "pool_name": name,
                                "pool_id": pool_id,
                                "size": size,
                            },
                        )
                        findings += 1

                self_hosted = [
                    p for p in pools
                    if isinstance(p, dict) and not p.get("isHosted", True) and p.get("size", 0) > 0
                ]

                async def _get_agents(p: dict[str, Any]) -> tuple[Any, str, list[Any]]:
                    pid = p.get("id", "")
                    pname = p.get("name", "")
                    try:
                        agts = await client.list_pool_agents(pid)
                    except (ScopeError, AuthError):
                        raise
                    except Exception:  # noqa: BLE001
                        agts = []
                    return pid, pname, agts

                agent_results = await asyncio.gather(
                    *(_get_agents(p) for p in self_hosted),
                    return_exceptions=True,
                )

                for result in agent_results:
                    if isinstance(result, (ScopeError, AuthError)):
                        raise result
                    if isinstance(result, BaseException):
                        continue
                    pid, pname, agents = result
                    for agent in agents:
                        if not isinstance(agent, dict):
                            continue
                        a, f = _record_agent(ctx, org, pid, pname, agent)
                        total_agents += a
                        findings += f

            finally:
                await client.close()

        ctx.console.print(
            f"[green]Recorded {total_pools} pool(s), {total_agents} agent(s), "
            f"{findings} finding(s)[/]"
        )
        return RunResult(ok=True, written=total_pools + total_agents + findings)


def _record_agent(
    ctx: RunContext,
    org: str,
    pool_id: object,
    pool_name: str,
    agent: dict[str, Any],
) -> tuple[int, int]:
    agent_id = agent.get("id", "")
    agent_name = agent.get("name", "")
    status = agent.get("status", "")
    version = agent.get("version", "")
    os_desc = agent.get("osDescription", "")

    sys_caps = agent.get("systemCapabilities", {}) or {}
    user_caps = agent.get("userCapabilities", {}) or {}

    ctx.store.upsert_resource(
        resource_id=f"ado://{org}/pool/{pool_id}/agent/{agent_id}",
        type="ado_agent",
        run_id=ctx.run_id,
        name=agent_name,
        properties_summary={
            "org": org,
            "pool_id": pool_id,
            "pool_name": pool_name,
            "agent_id": agent_id,
            "status": status,
            "version": version,
            "os": os_desc,
            "system_capability_count": len(sys_caps),
            "user_capability_count": len(user_caps),
        },
    )

    findings = 0
    sensitive_caps = []
    for cap_name in list(sys_caps) + list(user_caps):
        lower = cap_name.lower()
        if any(kw in lower for kw in _SENSITIVE_CAPABILITY_KEYWORDS):
            sensitive_caps.append(cap_name)

    if sensitive_caps:
        ctx.store.insert_finding(
            kind="ado_agent_sensitive_capability",
            resource_id=f"ado://{org}/pool/{pool_id}/agent/{agent_id}",
            reference=(
                f"Agent '{agent_name}' in pool '{pool_name}' has "
                f"sensitive capabilities: {', '.join(sensitive_caps[:5])}"
            ),
            run_id=ctx.run_id,
            details={
                "org": org,
                "pool_name": pool_name,
                "agent_name": agent_name,
                "sensitive_capabilities": sensitive_caps[:20],
            },
        )
        findings += 1

    return 1, findings
