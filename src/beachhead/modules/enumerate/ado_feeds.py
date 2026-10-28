"""enumerate.ado_feeds — ADO packaging feeds and packages.

Enumerates packaging feeds (org- and project-scoped), upstream sources,
and packages across all in-scope ADO organizations. Flags feeds with
public upstream sources (dependency confusion risk) and overly broad
org-scoped feeds.

MITRE ATT&CK: T1195.002 (Supply Chain Compromise: Compromise Software Supply Chain)
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

_PUBLIC_REGISTRIES = frozenset({
    "nuget.org",
    "npmjs.org",
    "registry.npmjs.org",
    "pypi.org",
    "repo.maven.apache.org",
    "registry.yarnpkg.com",
    "pub.dev",
    "rubygems.org",
    "crates.io",
})


class AdoFeeds:
    meta = ModuleMeta(
        name="enumerate.ado_feeds",
        phase=Phase.ENUMERATE,
        access=Access.READ,
        requires_browser=False,
        technique_ids=("T1195.002",),
        summary="Enumerate ADO packaging feeds, upstream sources, and packages.",
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
            ctx.console.print(f"[bold]Enumerating feeds: {org}[/]")
            client = make_client(org, pat, ctx)
            try:
                n, f = await _enum_org_feeds(ctx, client, org)
                total += n
                findings += f
            finally:
                await client.close()

        ctx.console.print(
            f"[green]Recorded {total} feed/package resource(s), {findings} finding(s)[/]"
        )
        return RunResult(ok=True, written=total + findings)


async def _enum_org_feeds(
    ctx: RunContext, client: Any, org: str
) -> tuple[int, int]:
    total = 0
    findings = 0
    seen_feed_ids: set[str] = set()

    try:
        org_feeds = await client.list_feeds(project=None)
    except (ScopeError, AuthError):
        raise
    except Exception:  # noqa: BLE001
        org_feeds = []

    for feed in org_feeds:
        if not isinstance(feed, dict):
            continue
        feed_id = str(feed.get("id", ""))
        if feed_id in seen_feed_ids:
            continue
        seen_feed_ids.add(feed_id)
        n, f = await _record_feed(ctx, client, org, None, feed)
        total += n
        findings += f

    try:
        projects = await client.list_projects()
    except (ScopeError, AuthError):
        raise
    except Exception:  # noqa: BLE001
        projects = []

    projects = ado_time_filter(projects, ctx.since, "lastUpdateTime")
    proj_names = [p["name"] for p in projects if isinstance(p, dict) and "name" in p]

    async def _get_proj_feeds(proj: str) -> tuple[str, list[Any]]:
        try:
            feeds = await client.list_feeds(project=proj)
        except (ScopeError, AuthError):
            raise
        except Exception:  # noqa: BLE001
            feeds = []
        return proj, feeds

    proj_results = await asyncio.gather(
        *(_get_proj_feeds(p) for p in proj_names),
        return_exceptions=True,
    )

    for result in proj_results:
        if isinstance(result, (ScopeError, AuthError)):
            raise result
        if isinstance(result, BaseException):
            continue
        proj, proj_feeds = result
        for feed in proj_feeds:
            if not isinstance(feed, dict):
                continue
            feed_id = str(feed.get("id", ""))
            if feed_id in seen_feed_ids:
                continue
            seen_feed_ids.add(feed_id)
            n, f = await _record_feed(ctx, client, org, proj, feed)
            total += n
            findings += f

    return total, findings


async def _record_feed(
    ctx: RunContext,
    client: Any,
    org: str,
    project: str | None,
    feed: dict[str, Any],
) -> tuple[int, int]:
    count = 0
    findings = 0

    feed_id = str(feed.get("id", ""))
    name = feed.get("name", "")
    upstream_enabled = feed.get("upstreamEnabled", False)
    upstream_sources = feed.get("upstreamSources", []) or []
    upstream_names = [
        s.get("name", "") for s in upstream_sources if isinstance(s, dict)
    ]
    fqn = feed.get("fullyQualifiedName", "")

    if project:
        resource_id = f"ado://{org}/{project}/feed/{feed_id}"
    else:
        resource_id = f"ado://{org}/feed/{feed_id}"

    props: dict[str, object] = {
        "org": org,
        "project": project,
        "feed_id": feed_id,
        "name": name,
        "feed_url": feed.get("url", ""),
        "upstream_enabled": upstream_enabled,
        "upstream_sources": upstream_names,
        "fully_qualified_name": fqn,
    }

    try:
        packages = await client.list_feed_packages(feed_id, project=project, top=100)
    except (ScopeError, AuthError):
        raise
    except Exception:  # noqa: BLE001
        packages = []

    props["package_count"] = len(packages)

    ctx.store.upsert_resource(
        resource_id=resource_id,
        type="ado_feed",
        run_id=ctx.run_id,
        name=name,
        properties_summary=props,
    )
    count += 1

    for pkg in packages:
        if not isinstance(pkg, dict):
            continue
        pkg_id = str(pkg.get("id", ""))
        pkg_name = pkg.get("name", "")
        protocol_type = pkg.get("protocolType", "")
        versions = pkg.get("versions", []) or []
        latest_version = ""
        if versions and isinstance(versions[0], dict):
            latest_version = versions[0].get("version", "")

        pkg_resource_id = f"{resource_id}/package/{pkg_id}"
        ctx.store.upsert_resource(
            resource_id=pkg_resource_id,
            type="ado_feed_package",
            run_id=ctx.run_id,
            name=pkg_name,
            properties_summary={
                "org": org,
                "project": project,
                "feed_id": feed_id,
                "feed_name": name,
                "package_id": pkg_id,
                "name": pkg_name,
                "protocol_type": protocol_type,
                "latest_version": latest_version,
            },
        )
        count += 1

    findings += _check_feed_findings(
        ctx, org, project, feed, resource_id, name, upstream_enabled, upstream_sources
    )

    return count, findings


def _check_feed_findings(
    ctx: RunContext,
    org: str,
    project: str | None,
    feed: dict[str, Any],
    resource_id: str,
    name: str,
    upstream_enabled: bool,
    upstream_sources: list[Any],
) -> int:
    findings = 0

    if upstream_enabled and upstream_sources:
        public_upstreams = []
        for src in upstream_sources:
            if not isinstance(src, dict):
                continue
            location = (src.get("location", "") or "").lower()
            src_name = (src.get("name", "") or "").lower()
            if any(reg in location or reg in src_name for reg in _PUBLIC_REGISTRIES):
                public_upstreams.append(src.get("name", ""))

        if public_upstreams:
            ctx.store.insert_finding(
                kind="ado_feed_upstream_public",
                resource_id=resource_id,
                reference=(
                    f"Feed '{name}' in {org} has public upstream source(s): "
                    f"{', '.join(public_upstreams[:5])} — dependency confusion risk"
                ),
                run_id=ctx.run_id,
                details={
                    "org": org,
                    "project": project,
                    "feed_name": name,
                    "public_upstreams": public_upstreams[:10],
                },
            )
            findings += 1

    if project is None:
        has_upstream = bool(upstream_sources)
        if not has_upstream:
            ctx.store.insert_finding(
                kind="ado_feed_org_scoped",
                resource_id=resource_id,
                reference=(
                    f"Feed '{name}' is org-scoped (accessible to all projects in {org})"
                ),
                run_id=ctx.run_id,
                details={
                    "org": org,
                    "feed_name": name,
                },
            )
            findings += 1

    return findings
