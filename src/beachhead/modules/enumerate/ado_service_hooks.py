"""enumerate.ado_service_hooks — ADO service hook subscriptions (webhooks).

Enumerates service hook subscriptions across all in-scope ADO organizations.
Records webhook targets, event types, and flags insecure or external targets.

MITRE ATT&CK: T1102.002 (Web Service: Bidirectional Communication)
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from beachhead.core.module import Access, ModuleMeta, Phase, RunContext, RunResult
from beachhead.modules.enumerate._ado_common import (
    ado_time_filter,
    get_orgs,
    get_pat,
    make_client,
    no_orgs_result,
    no_pat_result,
)

_INTERNAL_DOMAINS = (".azure.com", ".visualstudio.com", ".microsoft.com")


class AdoServiceHooks:
    meta = ModuleMeta(
        name="enumerate.ado_service_hooks",
        phase=Phase.ENUMERATE,
        access=Access.READ,
        requires_browser=False,
        technique_ids=("T1102.002",),
        summary="Enumerate ADO service hook subscriptions (webhooks).",
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
            ctx.console.print(f"[bold]Enumerating service hooks: {org}[/]")
            client = make_client(org, pat, ctx)
            try:
                hooks = await client.list_service_hook_subscriptions()
                hooks = ado_time_filter(hooks, ctx.since, "createdDate", "modifiedDate")
                for hook in hooks:
                    if not isinstance(hook, dict):
                        continue
                    n, f = _record_hook(ctx, org, hook)
                    total += n
                    findings += f
            finally:
                await client.close()

        ctx.console.print(f"[green]Recorded {total} service hook(s), {findings} finding(s)[/]")
        return RunResult(ok=True, written=total + findings)


def _redact_url(raw_url: str) -> str:
    parsed = urlparse(raw_url)
    if not parsed.scheme:
        return raw_url
    host = parsed.hostname or ""
    port_suffix = f":{parsed.port}" if parsed.port else ""
    return f"{parsed.scheme}://{host}{port_suffix}{parsed.path}"


def _record_hook(
    ctx: RunContext,
    org: str,
    hook: dict[str, Any],
) -> tuple[int, int]:
    sub_id = hook.get("id", "")
    event_type = hook.get("eventType", "")
    consumer_id = hook.get("consumerId", "")
    consumer_action_id = hook.get("consumerActionId", "")
    publisher_id = hook.get("publisherId", "")
    status = hook.get("status", "")
    consumer_inputs = hook.get("consumerInputs", {}) or {}
    raw_url = consumer_inputs.get("url", "")
    redacted_url = _redact_url(raw_url) if raw_url else ""

    ctx.store.upsert_resource(
        resource_id=f"ado://{org}/hook/{sub_id}",
        type="ado_service_hook",
        run_id=ctx.run_id,
        name=event_type,
        properties_summary={
            "org": org,
            "subscription_id": sub_id,
            "event_type": event_type,
            "consumer_id": consumer_id,
            "consumer_action_id": consumer_action_id,
            "publisher_id": publisher_id,
            "status": status,
            "consumer_inputs_url": redacted_url,
        },
    )

    findings = 0

    if consumer_id == "webHooks" and raw_url:
        parsed = urlparse(raw_url)

        if parsed.scheme == "http":
            ctx.store.insert_finding(
                kind="ado_hook_insecure_url",
                resource_id=f"ado://{org}/hook/{sub_id}",
                reference=f"Service hook sends to non-HTTPS URL: {redacted_url}",
                run_id=ctx.run_id,
                details={
                    "org": org,
                    "subscription_id": sub_id,
                    "event_type": event_type,
                    "url": redacted_url,
                },
            )
            findings += 1

        host = parsed.hostname or ""
        if host and not any(host.endswith(d) for d in _INTERNAL_DOMAINS):
            ctx.store.insert_finding(
                kind="ado_hook_external_target",
                resource_id=f"ado://{org}/hook/{sub_id}",
                reference=f"Service hook '{event_type}' sends to external target: {host}",
                run_id=ctx.run_id,
                details={
                    "org": org,
                    "subscription_id": sub_id,
                    "event_type": event_type,
                    "external_host": host,
                },
            )
            findings += 1

    if status in ("disabledBySystem", "disabledByInactivity"):
        ctx.store.insert_finding(
            kind="ado_hook_disabled",
            resource_id=f"ado://{org}/hook/{sub_id}",
            reference=f"Service hook '{event_type}' is disabled ({status})",
            run_id=ctx.run_id,
            details={
                "org": org,
                "subscription_id": sub_id,
                "event_type": event_type,
                "status": status,
            },
        )
        findings += 1

    return 1, findings
