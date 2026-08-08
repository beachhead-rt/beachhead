"""Tests for collect.ado_credential_scan — ADO credential scanner module."""

from __future__ import annotations

import os
import sqlite3
from typing import Any
from unittest.mock import patch

import httpx
import pytest
import respx
from conftest import FakeClock, FakeIds
from rich.console import Console

from beachhead.core.errors import AuthError
from beachhead.core.runner import RunEnv, run_module
from beachhead.core.secret_store import SecretStore
from beachhead.core.store.engine import open_store
from beachhead.modules.harvest.ado_credential_scan import AdoCredentialScan


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
    sec_conn = sqlite3.connect(":memory:", isolation_level=None)
    return RunEnv(
        store=store,
        az=FakeAz(),
        auth=FakeAuth(),
        config=FakeConfig(),
        scope=FakeScope(),
        console=Console(quiet=True),
        operator="op",
        secrets=SecretStore(sec_conn),
    )


def test_meta() -> None:
    m = AdoCredentialScan()
    assert m.meta.name == "harvest.ado_credential_scan"
    assert m.meta.phase.value == "harvest"
    assert m.meta.access.value == "read"
    assert m.meta.gated is False
    assert "T1552.001" in m.meta.technique_ids


_CONN_STRING = (
    "DefaultEndpointsProtocol=https;"
    "AccountName=mystorage;"
    "AccountKey=abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMN==;"
    "EndpointSuffix=core.windows.net"
)


def _items_handler_for_repo(repo_slug: str, files: dict[str, str]):
    """Return a respx side_effect that serves tree listing and file content."""
    def handler(request: httpx.Request) -> httpx.Response:
        params = dict(request.url.params)
        if "recursionLevel" in params:
            items = [{"path": "/", "isFolder": True}]
            items += [{"path": p, "isFolder": False} for p in files]
            return httpx.Response(200, json={"count": len(items), "value": items})
        path = params.get("path", "")
        content = files.get(path, "")
        return httpx.Response(200, json={"content": content})
    return handler


@respx.mock
@pytest.mark.asyncio
async def test_finds_credential_in_repo(store: Any, tmp_path: Any) -> None:
    """Tree scan finds an Azure Storage connection string in a config file."""
    respx.get("https://dev.azure.com/test-org/_apis/projects").mock(
        return_value=httpx.Response(200, json={"value": [{"name": "proj1"}]})
    )

    respx.get("https://dev.azure.com/test-org/proj1/_apis/git/repositories").mock(
        return_value=httpx.Response(
            200, json={"value": [{"name": "my-repo", "id": "repo-1"}]}
        )
    )

    respx.get(
        "https://dev.azure.com/test-org/proj1/_apis/git/repositories/my-repo/items"
    ).mock(side_effect=_items_handler_for_repo("my-repo", {
        "/src/config.json": _CONN_STRING,
    }))

    respx.post(
        "https://almsearch.dev.azure.com/test-org/proj1/_apis/search/workitemsearchresults"
    ).mock(return_value=httpx.Response(200, json={"count": 0, "results": []}))

    env = _env(store)
    result = await run_module(AdoCredentialScan(), env)  # type: ignore[arg-type]

    assert result.ok is True
    assert result.written >= 1

    findings = store.findings(kind="ado_credential_exposure")
    assert len(findings) >= 1
    f = findings[0]
    assert f.redacted is True
    details = f.details
    assert "ado_url" in details
    assert "test-org" in str(details["ado_url"])
    assert details["repo_name"] == "my-repo"
    assert details["project"] == "proj1"


@respx.mock
@pytest.mark.asyncio
async def test_search_fallback_when_tree_fails(store: Any) -> None:
    """When tree listing fails, falls back to code search."""
    respx.get("https://dev.azure.com/test-org/_apis/projects").mock(
        return_value=httpx.Response(200, json={"value": [{"name": "proj1"}]})
    )
    respx.get("https://dev.azure.com/test-org/proj1/_apis/git/repositories").mock(
        return_value=httpx.Response(
            200, json={"value": [{"name": "my-repo", "id": "repo-1"}]}
        )
    )
    # Tree listing fails
    respx.get(
        "https://dev.azure.com/test-org/proj1/_apis/git/repositories/my-repo/items"
    ).mock(return_value=httpx.Response(404))
    # Search finds a credential
    respx.post(
        "https://almsearch.dev.azure.com/test-org/proj1/_apis/search/codesearchresults"
    ).mock(
        return_value=httpx.Response(200, json={
            "count": 1,
            "results": [{
                "fileName": "config.json",
                "path": "/src/config.json",
                "repository": {
                    "name": "my-repo",
                    "url": "https://dev.azure.com/test-org/proj1/_git/my-repo",
                    "project": {"name": "proj1"},
                },
                "versions": [{"branchName": "main", "changeId": "abc"}],
                "contentId": "hash123",
                "matches": {"content": [_CONN_STRING]},
            }],
        })
    )
    respx.post(
        "https://almsearch.dev.azure.com/test-org/proj1/_apis/search/workitemsearchresults"
    ).mock(return_value=httpx.Response(200, json={"count": 0, "results": []}))

    env = _env(store)
    result = await run_module(AdoCredentialScan(), env)  # type: ignore[arg-type]

    assert result.ok is True
    assert result.written >= 1


@respx.mock
@pytest.mark.asyncio
async def test_no_ado_orgs(store: Any) -> None:
    """If config has no ADO orgs, skip gracefully."""

    class EmptyConfig:
        @property
        def engagement(self) -> str:
            return "ACME"

        @property
        def allow_write(self) -> bool:
            return False

        @property
        def ado_organizations(self) -> frozenset[str]:
            return frozenset()

    env = _env(store)
    env.config = EmptyConfig()
    result = await run_module(AdoCredentialScan(), env)  # type: ignore[arg-type]
    assert result.ok is True
    assert result.written == 0


@pytest.mark.asyncio
async def test_no_pat_fails(store: Any) -> None:
    """Without a PAT, the module fails gracefully."""

    class NoAuth:
        async def get(self, audience: str) -> str:
            raise AuthError("no token")

    env = _env(store)
    env.auth = NoAuth()  # type: ignore[assignment]

    with patch.dict(os.environ, {}, clear=True):
        clean_env = {k: v for k, v in os.environ.items() if k != "BEACHHEAD_ADO_PAT"}
        with patch.dict(os.environ, clean_env, clear=True):
            result = await run_module(AdoCredentialScan(), env)  # type: ignore[arg-type]

    assert result.ok is False
    assert "PAT" in result.message


@respx.mock
@pytest.mark.asyncio
async def test_work_item_credential_found(store: Any, tmp_path: Any) -> None:
    """Work item search finds a credential reference."""
    respx.get("https://dev.azure.com/test-org/_apis/projects").mock(
        return_value=httpx.Response(200, json={"value": [{"name": "proj1"}]})
    )

    respx.get("https://dev.azure.com/test-org/proj1/_apis/git/repositories").mock(
        return_value=httpx.Response(200, json={"value": []})
    )

    respx.post(
        "https://almsearch.dev.azure.com/test-org/proj1/_apis/search/codesearchresults"
    ).mock(return_value=httpx.Response(200, json={"count": 0, "results": []}))

    respx.post(
        "https://almsearch.dev.azure.com/test-org/proj1/_apis/search/workitemsearchresults"
    ).mock(
        return_value=httpx.Response(
            200,
            json={
                "count": 1,
                "results": [
                    {
                        "fields": {
                            "system.id": "99",
                            "system.title": "Update password for prod DB",
                            "system.workitemtype": "Task",
                            "system.state": "Active",
                        },
                        "project": {"name": "proj1"},
                        "hits": [{"highlights": ["password=SuperSecret123 for production"]}],
                        "url": ("https://dev.azure.com/test-org/proj1/_workitems/edit/99"),
                    }
                ],
            },
        )
    )

    env = _env(store)
    result = await run_module(AdoCredentialScan(), env)  # type: ignore[arg-type]

    assert result.ok is True

    wi_findings = store.findings(kind="ado_workitem_credential")
    assert len(wi_findings) >= 1
    assert wi_findings[0].details["work_item_id"] == 99


@respx.mock
@pytest.mark.asyncio
async def test_scan_handles_api_error(store: Any, tmp_path: Any) -> None:
    """Tree listing error + search error don't crash the scan."""
    respx.get("https://dev.azure.com/test-org/_apis/projects").mock(
        return_value=httpx.Response(200, json={"value": [{"name": "proj1"}]})
    )

    respx.get("https://dev.azure.com/test-org/proj1/_apis/git/repositories").mock(
        return_value=httpx.Response(
            200, json={"value": [{"name": "some-repo", "id": "r1"}]}
        )
    )

    # Tree listing fails
    respx.get(
        "https://dev.azure.com/test-org/proj1/_apis/git/repositories/some-repo/items"
    ).mock(return_value=httpx.Response(500, text="Internal Server Error"))

    # Search fallback also fails
    respx.post(
        "https://almsearch.dev.azure.com/test-org/proj1/_apis/search/codesearchresults"
    ).mock(return_value=httpx.Response(500, text="Internal Server Error"))

    respx.post(
        "https://almsearch.dev.azure.com/test-org/proj1/_apis/search/workitemsearchresults"
    ).mock(return_value=httpx.Response(200, json={"count": 0, "results": []}))

    env = _env(store)
    result = await run_module(AdoCredentialScan(), env)  # type: ignore[arg-type]

    assert result.ok is True


@respx.mock
@pytest.mark.asyncio
async def test_tree_scan_finds_missed_credential(store: Any) -> None:
    """Tree scan finds credentials in files that code search missed."""
    respx.get("https://dev.azure.com/test-org/_apis/projects").mock(
        return_value=httpx.Response(200, json={"value": [{"name": "proj1"}]})
    )

    respx.get("https://dev.azure.com/test-org/proj1/_apis/git/repositories").mock(
        return_value=httpx.Response(
            200,
            json={
                "value": [
                    {
                        "name": "data-repo",
                        "id": "repo-1",
                        "defaultBranch": "refs/heads/main",
                    }
                ]
            },
        )
    )

    respx.post(
        "https://almsearch.dev.azure.com/test-org/proj1/_apis/search/codesearchresults"
    ).mock(return_value=httpx.Response(200, json={"count": 0, "results": []}))

    respx.post(
        "https://almsearch.dev.azure.com/test-org/proj1/_apis/search/workitemsearchresults"
    ).mock(return_value=httpx.Response(200, json={"count": 0, "results": []}))

    conn_string = (
        "DefaultEndpointsProtocol=https;"
        "AccountName=mystorage;"
        "AccountKey=abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMN==;"
        "EndpointSuffix=core.windows.net"
    )

    def items_handler(request: httpx.Request) -> httpx.Response:
        params = dict(request.url.params)
        if "recursionLevel" in params:
            return httpx.Response(
                200,
                json={
                    "count": 3,
                    "value": [
                        {"path": "/", "isFolder": True},
                        {"path": "/src/config.json", "isFolder": False},
                        {"path": "/README.md", "isFolder": False},
                    ],
                },
            )
        if params.get("path") == "/src/config.json":
            return httpx.Response(200, json={"content": conn_string})
        return httpx.Response(200, json={"content": ""})

    respx.get(
        "https://dev.azure.com/test-org/proj1/_apis/git/repositories/data-repo/items"
    ).mock(side_effect=items_handler)

    env = _env(store)
    result = await run_module(AdoCredentialScan(), env)  # type: ignore[arg-type]

    assert result.ok is True
    assert result.written >= 1

    findings = store.findings(kind="ado_credential_exposure")
    assert len(findings) >= 1
    assert any("config.json" in f.reference for f in findings)
