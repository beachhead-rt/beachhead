"""Tests for the ADO ALM Search client."""

from __future__ import annotations

from typing import Any

import httpx
import pytest
import respx

from beachhead.core.clients.ado_search import (
    AdoSearchClient,
    CodeSearchResult,
    WorkItemSearchResult,
)
from beachhead.core.errors import AuthError, Throttled


class FakeScope:
    def check(self, target: str, *, kind: str = "target") -> None:
        pass


class FakeAudit:
    def __init__(self) -> None:
        self.records: list[dict[str, str]] = []

    def record(
        self, action: str, target: str, *, result: str = "ok", **extra: Any
    ) -> None:
        self.records.append({"action": action, "target": target, "result": result})


def _client(pat: str = "faketoken") -> tuple[AdoSearchClient, FakeAudit]:
    audit = FakeAudit()
    c = AdoSearchClient(
        org="test-org",
        pat=pat,
        scope=FakeScope(),
        audit=audit,
        run_id="run-1",
    )
    return c, audit


@respx.mock
@pytest.mark.asyncio
async def test_list_projects() -> None:
    respx.get("https://dev.azure.com/test-org/_apis/projects").mock(
        return_value=httpx.Response(200, json={"value": [{"name": "proj1"}, {"name": "proj2"}]})
    )
    client, audit = _client()
    try:
        projects = await client.list_projects()
        assert len(projects) == 2
        assert projects[0]["name"] == "proj1"
        assert len(audit.records) == 1
        assert audit.records[0]["action"] == "ado.get"
    finally:
        await client.close()


@respx.mock
@pytest.mark.asyncio
async def test_code_search_returns_results() -> None:
    respx.post(
        "https://almsearch.dev.azure.com/test-org/proj1/_apis/search/codesearchresults"
    ).mock(
        return_value=httpx.Response(
            200,
            json={
                "count": 1,
                "results": [
                    {
                        "fileName": "config.json",
                        "path": "/src/config.json",
                        "repository": {
                            "name": "my-repo",
                            "url": "https://dev.azure.com/test-org/proj1/_git/my-repo",
                            "project": {"name": "proj1"},
                        },
                        "versions": [{"branchName": "main", "changeId": "abc"}],
                        "contentId": "hash123",
                        "matches": {"content": ["AccountKey=abc123def456"]},
                    }
                ],
            },
        )
    )
    client, _ = _client()
    try:
        total, results = await client.code_search("proj1", "AccountKey")
        assert total == 1
        assert len(results) == 1
        assert isinstance(results[0], CodeSearchResult)
        assert results[0].file_name == "config.json"
        assert results[0].repo_name == "my-repo"
        assert results[0].snippets == ("AccountKey=abc123def456",)
    finally:
        await client.close()


@respx.mock
@pytest.mark.asyncio
async def test_code_search_pages_iterates() -> None:
    call_count = 0

    def side_effect(request: httpx.Request) -> httpx.Response:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return httpx.Response(
                200,
                json={
                    "count": 3,
                    "results": [
                        {
                            "fileName": f"f{i}.txt",
                            "path": f"/f{i}.txt",
                            "repository": {
                                "name": "repo",
                                "url": "",
                                "project": {"name": "p"},
                            },
                            "versions": [],
                            "contentId": f"c{i}",
                            "matches": {"content": [f"match{i}"]},
                        }
                        for i in range(2)
                    ],
                },
            )
        return httpx.Response(
            200,
            json={
                "count": 3,
                "results": [
                    {
                        "fileName": "f2.txt",
                        "path": "/f2.txt",
                        "repository": {
                            "name": "repo",
                            "url": "",
                            "project": {"name": "p"},
                        },
                        "versions": [],
                        "contentId": "c2",
                        "matches": {"content": ["match2"]},
                    }
                ],
            },
        )

    respx.post(
        "https://almsearch.dev.azure.com/test-org/proj1/_apis/search/codesearchresults"
    ).mock(side_effect=side_effect)

    client, _ = _client()
    try:
        all_results: list[CodeSearchResult] = []
        async for page in client.code_search_pages("proj1", "test", page_size=2, max_results=10):
            all_results.extend(page)
        assert len(all_results) == 3
    finally:
        await client.close()


@respx.mock
@pytest.mark.asyncio
async def test_work_item_search() -> None:
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
                            "system.id": "42",
                            "system.title": "Fix password leak",
                            "system.workitemtype": "Bug",
                            "system.state": "Active",
                        },
                        "project": {"name": "proj1"},
                        "hits": [{"highlights": ["password=s3cret"]}],
                        "url": "https://dev.azure.com/test-org/proj1/_workitems/edit/42",
                    }
                ],
            },
        )
    )
    client, _ = _client()
    try:
        total, results = await client.work_item_search("proj1", "password")
        assert total == 1
        assert len(results) == 1
        assert isinstance(results[0], WorkItemSearchResult)
        assert results[0].work_item_id == 42
        assert results[0].title == "Fix password leak"
    finally:
        await client.close()


@respx.mock
@pytest.mark.asyncio
async def test_401_raises_auth_error() -> None:
    respx.get("https://dev.azure.com/test-org/_apis/projects").mock(
        return_value=httpx.Response(401, json={"message": "unauthorized"})
    )
    client, _ = _client()
    try:
        with pytest.raises(AuthError, match="PAT may be invalid"):
            await client.list_projects()
    finally:
        await client.close()


@respx.mock
@pytest.mark.asyncio
async def test_429_retries_then_raises_throttled() -> None:
    respx.get("https://dev.azure.com/test-org/_apis/projects").mock(
        return_value=httpx.Response(
            429,
            headers={"Retry-After": "0.01"},
            json={"message": "rate limited"},
        )
    )
    client, _ = _client()
    try:
        with pytest.raises(Throttled):
            await client.list_projects()
    finally:
        await client.close()


@respx.mock
@pytest.mark.asyncio
async def test_tstu_tracking() -> None:
    respx.get("https://dev.azure.com/test-org/_apis/projects").mock(
        return_value=httpx.Response(
            200,
            headers={"X-RateLimit-Cost": "3"},
            json={"value": []},
        )
    )
    client, _ = _client()
    try:
        initial = client.tstu_remaining
        await client.list_projects()
        assert client.tstu_remaining == initial - 3
    finally:
        await client.close()


@respx.mock
@pytest.mark.asyncio
async def test_code_search_hits_format() -> None:
    """ADO API v7.1 returns snippets in hits[].highlights, not matches.content."""
    respx.post(
        "https://almsearch.dev.azure.com/test-org/proj1/_apis/search/codesearchresults"
    ).mock(
        return_value=httpx.Response(
            200,
            json={
                "count": 1,
                "results": [
                    {
                        "fileName": "config.json",
                        "path": "/src/config.json",
                        "repository": {
                            "name": "my-repo",
                            "url": "",
                            "project": {"name": "proj1"},
                        },
                        "versions": [{"branchName": "main", "changeId": "abc"}],
                        "contentId": "hash123",
                        "hits": [
                            {
                                "fieldReferenceName": "content",
                                "highlights": [
                                    "<highlighthit>AccountKey</highlighthit>=abc123"
                                ],
                            }
                        ],
                        "matches": {
                            "content": [{"charOffset": 10, "length": 10}],
                        },
                    }
                ],
            },
        )
    )
    client, _ = _client()
    try:
        total, results = await client.code_search("proj1", "AccountKey")
        assert total == 1
        assert len(results) == 1
        assert results[0].snippets == ("<highlighthit>AccountKey</highlighthit>=abc123",)
    finally:
        await client.close()


@respx.mock
@pytest.mark.asyncio
async def test_code_search_position_only_matches() -> None:
    """When matches.content has position objects and no hits, snippets are empty."""
    respx.post(
        "https://almsearch.dev.azure.com/test-org/proj1/_apis/search/codesearchresults"
    ).mock(
        return_value=httpx.Response(
            200,
            json={
                "count": 1,
                "results": [
                    {
                        "fileName": "f.txt",
                        "path": "/f.txt",
                        "repository": {
                            "name": "repo",
                            "url": "",
                            "project": {"name": "p"},
                        },
                        "versions": [],
                        "contentId": "c1",
                        "matches": {
                            "content": [{"charOffset": 5, "length": 8}],
                        },
                    }
                ],
            },
        )
    )
    client, _ = _client()
    try:
        total, results = await client.code_search("proj1", "test")
        assert total == 1
        assert results[0].snippets == ()
    finally:
        await client.close()


@respx.mock
@pytest.mark.asyncio
async def test_empty_code_search() -> None:
    respx.post(
        "https://almsearch.dev.azure.com/test-org/proj1/_apis/search/codesearchresults"
    ).mock(return_value=httpx.Response(200, json={"count": 0, "results": []}))
    client, _ = _client()
    try:
        total, results = await client.code_search("proj1", "nothing")
        assert total == 0
        assert results == []
    finally:
        await client.close()
