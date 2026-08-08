"""Tests for enumerate.ado_repos — ADO repository enumeration."""

from __future__ import annotations

from typing import Any

import httpx
import pytest
import respx
from conftest import FakeClock, FakeIds
from rich.console import Console

from beachhead.core.errors import AuthError
from beachhead.core.runner import RunEnv, run_module
from beachhead.core.store.engine import open_store
from beachhead.modules.enumerate.ado_repos import AdoRepos



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


class FakeAuth:
    async def get(self, audience: str) -> str:
        if audience == "ado":
            return "fake-ado-pat"
        return "fake-token"


@pytest.fixture
def store(tmp_path: Any) -> Any:
    s = open_store(str(tmp_path / "test.db"), clock=FakeClock(), id_factory=FakeIds())
    s.ensure_engagement(name="ACME", scope_hash="h")
    return s


def _env(store: Any) -> RunEnv:
    return RunEnv(
        store=store,
        az=FakeAz(),
        auth=FakeAuth(),
        config=FakeConfig(),
        scope=FakeScope(),
        console=Console(quiet=True),
        operator="op",
    )


def test_meta() -> None:
    m = AdoRepos()
    assert m.meta.name == "enumerate.ado_repos"
    assert m.meta.phase.value == "enumerate"
    assert m.meta.access.value == "read"
    assert m.meta.gated is False


@respx.mock
@pytest.mark.asyncio
async def test_enumerates_repos_and_policies(store: Any) -> None:
    """Enumerates repos, branches, policies, and PRs."""
    respx.get("https://dev.azure.com/test-org/_apis/projects").mock(
        return_value=httpx.Response(200, json={"value": [{"name": "proj1"}]})
    )
    respx.get("https://dev.azure.com/test-org/proj1/_apis/git/repositories").mock(
        return_value=httpx.Response(
            200,
            json={
                "value": [
                    {
                        "id": "repo-1",
                        "name": "MainApp",
                        "defaultBranch": "refs/heads/main",
                        "size": 50000,
                        "isFork": False,
                        "isDisabled": False,
                    },
                    {
                        "id": "repo-2",
                        "name": "Lib",
                        "defaultBranch": "refs/heads/main",
                        "size": 1000,
                        "isFork": False,
                        "isDisabled": False,
                    },
                ]
            },
        )
    )
    respx.get(
        "https://dev.azure.com/test-org/proj1/_apis/git/repositories/repo-1/refs"
    ).mock(
        return_value=httpx.Response(
            200,
            json={"value": [{"name": "refs/heads/main"}, {"name": "refs/heads/dev"}]},
        )
    )
    respx.get(
        "https://dev.azure.com/test-org/proj1/_apis/git/repositories/repo-2/refs"
    ).mock(
        return_value=httpx.Response(
            200, json={"value": [{"name": "refs/heads/main"}]}
        )
    )
    respx.get("https://dev.azure.com/test-org/proj1/_apis/policy/configurations").mock(
        return_value=httpx.Response(
            200,
            json={
                "value": [
                    {
                        "id": 101,
                        "type": {"displayName": "Minimum number of reviewers"},
                        "isEnabled": True,
                        "isBlocking": True,
                        "settings": {
                            "scope": [
                                {
                                    "repositoryId": "repo-1",
                                    "refName": "refs/heads/main",
                                    "matchKind": "exact",
                                }
                            ]
                        },
                    }
                ]
            },
        )
    )
    respx.get(
        "https://dev.azure.com/test-org/proj1/_apis/git/repositories/repo-1/pullrequests"
    ).mock(
        return_value=httpx.Response(
            200,
            json={
                "value": [
                    {
                        "pullRequestId": 42,
                        "title": "Add feature",
                        "status": "completed",
                        "reviewers": [{"uniqueName": "alice@acme.test", "vote": 10}],
                    }
                ]
            },
        )
    )
    respx.get(
        "https://dev.azure.com/test-org/proj1/_apis/git/repositories/repo-2/pullrequests"
    ).mock(return_value=httpx.Response(200, json={"value": []}))

    env = _env(store)
    result = await run_module(AdoRepos(), env)  # type: ignore[arg-type]

    assert result.ok is True
    assert result.written >= 3  # 2 repos + 1 policy + findings

    resources = store.resources()
    repos = [r for r in resources if r.type == "ado_repo"]
    policies = [r for r in resources if r.type == "ado_branch_policy"]
    assert len(repos) == 2
    assert len(policies) == 1


@respx.mock
@pytest.mark.asyncio
async def test_flags_no_branch_policy(store: Any) -> None:
    """Repos with no branch policy on default branch produce a finding."""
    respx.get("https://dev.azure.com/test-org/_apis/projects").mock(
        return_value=httpx.Response(200, json={"value": [{"name": "proj1"}]})
    )
    respx.get("https://dev.azure.com/test-org/proj1/_apis/git/repositories").mock(
        return_value=httpx.Response(
            200,
            json={
                "value": [
                    {
                        "id": "repo-1",
                        "name": "Unprotected",
                        "defaultBranch": "refs/heads/main",
                        "size": 1000,
                    }
                ]
            },
        )
    )
    respx.get(
        "https://dev.azure.com/test-org/proj1/_apis/git/repositories/repo-1/refs"
    ).mock(
        return_value=httpx.Response(
            200, json={"value": [{"name": "refs/heads/main"}]}
        )
    )
    respx.get("https://dev.azure.com/test-org/proj1/_apis/policy/configurations").mock(
        return_value=httpx.Response(200, json={"value": []})
    )
    respx.get(
        "https://dev.azure.com/test-org/proj1/_apis/git/repositories/repo-1/pullrequests"
    ).mock(return_value=httpx.Response(200, json={"value": []}))

    env = _env(store)
    result = await run_module(AdoRepos(), env)  # type: ignore[arg-type]

    assert result.ok is True
    findings = store.findings(kind="ado_repo_no_branch_policy")
    assert len(findings) >= 1
    assert "Unprotected" in findings[0].reference


@respx.mock
@pytest.mark.asyncio
async def test_flags_pr_no_reviewer(store: Any) -> None:
    """PRs completed with no reviewers produce a finding."""
    respx.get("https://dev.azure.com/test-org/_apis/projects").mock(
        return_value=httpx.Response(200, json={"value": [{"name": "proj1"}]})
    )
    respx.get("https://dev.azure.com/test-org/proj1/_apis/git/repositories").mock(
        return_value=httpx.Response(
            200,
            json={
                "value": [
                    {
                        "id": "repo-1",
                        "name": "LeakyRepo",
                        "defaultBranch": "refs/heads/main",
                        "size": 1000,
                    }
                ]
            },
        )
    )
    respx.get(
        "https://dev.azure.com/test-org/proj1/_apis/git/repositories/repo-1/refs"
    ).mock(
        return_value=httpx.Response(
            200, json={"value": [{"name": "refs/heads/main"}]}
        )
    )
    respx.get("https://dev.azure.com/test-org/proj1/_apis/policy/configurations").mock(
        return_value=httpx.Response(200, json={"value": []})
    )
    respx.get(
        "https://dev.azure.com/test-org/proj1/_apis/git/repositories/repo-1/pullrequests"
    ).mock(
        return_value=httpx.Response(
            200,
            json={
                "value": [
                    {
                        "pullRequestId": 99,
                        "title": "Quick fix no review",
                        "status": "completed",
                        "reviewers": [],
                    }
                ]
            },
        )
    )

    env = _env(store)
    result = await run_module(AdoRepos(), env)  # type: ignore[arg-type]

    assert result.ok is True
    findings = store.findings(kind="ado_pr_no_reviewer")
    assert len(findings) >= 1
    assert "99" in findings[0].reference
    assert "LeakyRepo" in findings[0].reference


@pytest.mark.asyncio
async def test_no_pat_fails(store: Any) -> None:
    """Without a PAT, the module fails gracefully."""
    import os
    from unittest.mock import patch

    class NoAuth:
        async def get(self, audience: str) -> str:
            raise AuthError("no token")

    env = _env(store)
    env.auth = NoAuth()  # type: ignore[assignment]

    with patch.dict(os.environ, {}, clear=True):
        clean_env = {k: v for k, v in os.environ.items() if k != "BEACHHEAD_ADO_PAT"}
        with patch.dict(os.environ, clean_env, clear=True):
            result = await run_module(AdoRepos(), env)  # type: ignore[arg-type]

    assert result.ok is False
    assert "PAT" in result.message
