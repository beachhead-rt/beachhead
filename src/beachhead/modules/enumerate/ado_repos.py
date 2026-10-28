"""enumerate.ado_repos — ADO Git repositories, branches, policies, PRs.

Enumerates Git repositories across all in-scope ADO organizations and
projects. Records repo metadata, branch counts, branch policy coverage,
and flags repos without branch policies and PRs merged without reviewers.

MITRE ATT&CK: T1213.003 (Data from Information Repositories: Code Repositories)
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


class AdoRepos:
    meta = ModuleMeta(
        name="enumerate.ado_repos",
        phase=Phase.ENUMERATE,
        access=Access.READ,
        requires_browser=False,
        technique_ids=("T1213.003",),
        summary="Enumerate ADO Git repositories, branches, policies, and PR reviewers.",
    )

    async def run(self, ctx: RunContext) -> RunResult:
        pat = await get_pat(ctx)
        if pat is None:
            return no_pat_result(ctx)

        orgs = get_orgs(ctx)
        if not orgs:
            return no_orgs_result(ctx)

        total_repos = 0
        total_policies = 0
        findings = 0

        for org in sorted(orgs):
            ctx.console.print(f"[bold]Enumerating repositories: {org}[/]")
            client = make_client(org, pat, ctx)
            try:
                projects = await client.list_projects()
                proj_names = [p["name"] for p in projects if isinstance(p, dict) and "name" in p]
                for proj in proj_names:
                    r, p, f = await _enum_project(ctx, client, org, proj)
                    total_repos += r
                    total_policies += p
                    findings += f
            finally:
                await client.close()

        ctx.console.print(
            f"[green]Recorded {total_repos} repo(s), {total_policies} policy/policies, "
            f"{findings} finding(s)[/]"
        )
        return RunResult(ok=True, written=total_repos + total_policies + findings)


async def _enum_project(
    ctx: RunContext, client: Any, org: str, project: str
) -> tuple[int, int, int]:
    """Returns (repo_count, policy_count, findings)."""
    repo_count = 0
    policy_count = 0
    findings = 0

    ctx.console.print(f"  [bold]{project}[/]")

    try:
        repos = await client.list_repositories(project)
    except (ScopeError, AuthError):
        raise
    except Exception as exc:  # noqa: BLE001
        ctx.console.print(
            f"    [yellow]Could not list repos ({type(exc).__name__}: {exc})[/]"
        )
        return 0, 0, 0

    if not repos:
        ctx.console.print(
            "    [yellow]No repositories returned — PAT may lack Code (Read) scope "
            "(vso.code). ADO returns an empty list instead of 403 when the "
            "token cannot read repos.[/]"
        )

    repo_index: dict[str, dict[str, Any]] = {}

    valid_repos = [r for r in repos if isinstance(r, dict) and r.get("id")]

    async def _get_refs(repo_id: str) -> int:
        try:
            refs = await client.list_refs(project, repo_id)
            return len(refs)
        except (ScopeError, AuthError):
            raise
        except Exception:  # noqa: BLE001
            return 0

    ref_counts = await asyncio.gather(
        *(_get_refs(r["id"]) for r in valid_repos),
        return_exceptions=True,
    )

    for repo, branch_count_or_exc in zip(valid_repos, ref_counts):
        if isinstance(branch_count_or_exc, (ScopeError, AuthError)):
            raise branch_count_or_exc
        branch_count = branch_count_or_exc if isinstance(branch_count_or_exc, int) else 0

        repo_id = repo.get("id", "")
        name = repo.get("name", "")
        default_branch = repo.get("defaultBranch", "")

        props: dict[str, object] = {
            "org": org,
            "project": project,
            "repo_id": repo_id,
            "name": name,
            "default_branch": default_branch,
            "size": repo.get("size", 0),
            "is_fork": repo.get("isFork", False),
            "is_disabled": repo.get("isDisabled", False),
            "branch_count": branch_count,
        }

        ctx.store.upsert_resource(
            resource_id=f"ado://{org}/{project}/repo/{repo_id}",
            type="ado_repo",
            run_id=ctx.run_id,
            name=name,
            properties_summary=props,
        )
        repo_count += 1
        repo_index[repo_id] = {"name": name, "default_branch": default_branch}

        fork_tag = " [dim](fork)[/]" if repo.get("isFork") else ""
        disabled_tag = " [dim](disabled)[/]" if repo.get("isDisabled") else ""
        ctx.console.print(
            f"    [cyan]{name}[/]{fork_tag}{disabled_tag}"
            f"  [dim]{branch_count} branch(es), {default_branch or 'no default'}[/]"
        )

    policies = []
    try:
        policies = await client.list_policy_configurations(project)
    except (ScopeError, AuthError):
        raise
    except Exception:  # noqa: BLE001, S110
        pass

    protected_repos: set[str] = set()
    for pc in policies:
        if not isinstance(pc, dict):
            continue
        config_id = pc.get("id", "")
        ptype = pc.get("type", {}) or {}
        settings = pc.get("settings", {}) or {}
        scopes = settings.get("scope", [])

        ctx.store.upsert_resource(
            resource_id=f"ado://{org}/{project}/policy/{config_id}",
            type="ado_branch_policy",
            run_id=ctx.run_id,
            name=ptype.get("displayName", ""),
            properties_summary={
                "org": org,
                "project": project,
                "policy_id": config_id,
                "type_display_name": ptype.get("displayName", ""),
                "is_enabled": pc.get("isEnabled", False),
                "is_blocking": pc.get("isBlocking", False),
                "scope": scopes[:10],
            },
        )
        policy_count += 1

        for scope_entry in scopes:
            if isinstance(scope_entry, dict):
                rid = scope_entry.get("repositoryId")
                if rid:
                    protected_repos.add(rid)

    for repo_id, info in repo_index.items():
        if repo_id not in protected_repos and info["default_branch"]:
            ctx.store.insert_finding(
                kind="ado_repo_no_branch_policy",
                resource_id=f"ado://{org}/{project}/repo/{repo_id}",
                reference=(
                    f"Repository '{info['name']}' in {org}/{project} "
                    f"has no branch policy on its default branch"
                ),
                run_id=ctx.run_id,
                details={
                    "org": org,
                    "project": project,
                    "repo_name": info["name"],
                    "default_branch": info["default_branch"],
                },
            )
            findings += 1

    async def _check_prs(repo_id: str) -> list[dict[str, Any]]:
        try:
            prs = await client.list_pull_requests(project, repo_id, top=25)
        except (ScopeError, AuthError):
            raise
        except Exception:  # noqa: BLE001
            return []
        prs = ado_time_filter(prs, ctx.since, "creationDate", "closedDate")
        no_review: list[dict[str, Any]] = []
        for pr in prs:
            if not isinstance(pr, dict):
                continue
            if len(no_review) >= 3:
                break
            if not pr.get("reviewers", []):
                no_review.append(pr)
        return no_review

    repo_items = list(repo_index.items())
    pr_results = await asyncio.gather(
        *(_check_prs(rid) for rid, _ in repo_items),
        return_exceptions=True,
    )

    for (repo_id, info), result in zip(repo_items, pr_results):
        if isinstance(result, (ScopeError, AuthError)):
            raise result
        if isinstance(result, BaseException):
            continue
        for pr in result:
            pr_id = pr.get("pullRequestId", "")
            title = pr.get("title", "")
            ctx.store.insert_finding(
                kind="ado_pr_no_reviewer",
                resource_id=f"ado://{org}/{project}/repo/{repo_id}",
                reference=(
                    f"PR #{pr_id} '{title}' in {org}/{project}/{info['name']} "
                    f"completed with no reviewers"
                ),
                run_id=ctx.run_id,
                details={
                    "org": org,
                    "project": project,
                    "repo_name": info["name"],
                    "pr_id": pr_id,
                    "pr_title": title,
                },
            )
            findings += 1

    return repo_count, policy_count, findings
