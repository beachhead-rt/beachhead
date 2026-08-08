"""Tests for collect.ado_wiki_scan — ADO wiki credential scanner."""

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
from beachhead.modules.harvest.ado_wiki_scan import AdoWikiScan


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
    m = AdoWikiScan()
    assert m.meta.name == "harvest.ado_wiki_scan"
    assert m.meta.phase.value == "harvest"
    assert m.meta.access.value == "read"
    assert m.meta.gated is False


def _mock_no_wikis() -> None:
    """Mock list_wikis returning empty so the scanner falls back to search."""
    respx.get("https://dev.azure.com/test-org/proj1/_apis/wiki/wikis").mock(
        return_value=httpx.Response(200, json={"value": []})
    )


@respx.mock
@pytest.mark.asyncio
async def test_finds_wiki_credential(store: Any) -> None:
    """Wiki page with credential-like content generates a finding."""
    respx.get("https://dev.azure.com/test-org/_apis/projects").mock(
        return_value=httpx.Response(200, json={"value": [{"name": "proj1"}]})
    )
    _mock_no_wikis()
    respx.post(
        "https://almsearch.dev.azure.com/test-org/proj1/_apis/search/wikisearchresults"
    ).mock(
        return_value=httpx.Response(
            200,
            json={
                "count": 1,
                "results": [
                    {
                        "wiki": {"name": "project-wiki"},
                        "path": "/Setup/Database-Config",
                        "project": {"name": "proj1"},
                        "hits": [
                            {
                                "highlights": [
                                    "connection string: <b>password</b>=SuperSecret123"
                                ]
                            }
                        ],
                    }
                ],
            },
        )
    )
    respx.get(
        "https://dev.azure.com/test-org/proj1/_apis/wiki/wikis/project-wiki/pages"
    ).mock(
        return_value=httpx.Response(
            200,
            json={
                "content": "## Database Config\n"
                "connection string: password=SuperSecret123; Server=prod.db",
            },
        )
    )

    env = _env(store)
    result = await run_module(AdoWikiScan(), env)  # type: ignore[arg-type]

    assert result.ok is True
    assert result.written >= 1

    findings = store.findings(kind="ado_wiki_credential")
    assert len(findings) >= 1
    f = findings[0]
    assert f.redacted is True
    assert "project-wiki" in f.reference
    assert f.details["ado_url"] == (
        "https://dev.azure.com/test-org/proj1/_wiki/wikis/project-wiki"
        "?pagePath=%2FSetup%2FDatabase-Config"
    )


@respx.mock
@pytest.mark.asyncio
async def test_skips_non_credential_wiki(store: Any) -> None:
    """Wiki page that mentions 'password' without a value is not flagged."""
    respx.get("https://dev.azure.com/test-org/_apis/projects").mock(
        return_value=httpx.Response(200, json={"value": [{"name": "proj1"}]})
    )
    _mock_no_wikis()
    respx.post(
        "https://almsearch.dev.azure.com/test-org/proj1/_apis/search/wikisearchresults"
    ).mock(
        return_value=httpx.Response(
            200,
            json={
                "count": 1,
                "results": [
                    {
                        "wiki": {"name": "project-wiki"},
                        "path": "/FAQ",
                        "project": {"name": "proj1"},
                        "hits": [
                            {"highlights": ["How to reset your <b>password</b> using the portal"]}
                        ],
                    }
                ],
            },
        )
    )
    respx.get(
        "https://dev.azure.com/test-org/proj1/_apis/wiki/wikis/project-wiki/pages"
    ).mock(
        return_value=httpx.Response(
            200,
            json={
                "content": "# FAQ\nHow to reset your password using the portal.",
            },
        )
    )

    env = _env(store)
    result = await run_module(AdoWikiScan(), env)  # type: ignore[arg-type]

    assert result.ok is True
    findings = store.findings(kind="ado_wiki_credential")
    assert len(findings) == 0


@respx.mock
@pytest.mark.asyncio
async def test_falls_back_to_snippets(store: Any) -> None:
    """When the Wiki Pages API fails, fall back to search snippets."""
    respx.get("https://dev.azure.com/test-org/_apis/projects").mock(
        return_value=httpx.Response(200, json={"value": [{"name": "proj1"}]})
    )
    _mock_no_wikis()
    respx.post(
        "https://almsearch.dev.azure.com/test-org/proj1/_apis/search/wikisearchresults"
    ).mock(
        return_value=httpx.Response(
            200,
            json={
                "count": 1,
                "results": [
                    {
                        "wiki": {"name": "project-wiki"},
                        "path": "/Setup/Creds",
                        "project": {"name": "proj1"},
                        "hits": [
                            {
                                "highlights": [
                                    "connection string: password=FallbackSecret99; Server=db"
                                ]
                            }
                        ],
                    }
                ],
            },
        )
    )
    respx.get(
        "https://dev.azure.com/test-org/proj1/_apis/wiki/wikis/project-wiki/pages"
    ).mock(return_value=httpx.Response(404))

    env = _env(store)
    result = await run_module(AdoWikiScan(), env)  # type: ignore[arg-type]

    assert result.ok is True
    assert result.written >= 1
    findings = store.findings(kind="ado_wiki_credential")
    assert len(findings) >= 1


@respx.mock
@pytest.mark.asyncio
async def test_direct_wiki_enumeration(store: Any) -> None:
    """When list_wikis works, enumerate all pages without search."""
    respx.get("https://dev.azure.com/test-org/_apis/projects").mock(
        return_value=httpx.Response(200, json={"value": [{"name": "proj1"}]})
    )
    respx.get("https://dev.azure.com/test-org/proj1/_apis/wiki/wikis").mock(
        return_value=httpx.Response(200, json={
            "value": [{"name": "project-wiki", "id": "wiki-1"}],
        })
    )

    _page_contents = {
        "/Environment-Setup": "## Setup\nDB_PASSWORD=hunter2\nAPI_KEY=sk-abc123secret",
        "/Architecture": "# Architecture\nStandard microservices layout.",
        "/Runbook": "# Runbook\nCheck dashboards first.",
    }

    def _wiki_pages_handler(request: httpx.Request) -> httpx.Response:
        params = dict(request.url.params)
        if "recursionLevel" in params:
            return httpx.Response(200, json={
                "path": "/",
                "subPages": [{"path": p} for p in _page_contents],
            })
        path = params.get("path", "")
        content = _page_contents.get(path, "")
        return httpx.Response(200, json={"content": content})

    respx.get(
        "https://dev.azure.com/test-org/proj1/_apis/wiki/wikis/project-wiki/pages"
    ).mock(side_effect=_wiki_pages_handler)

    env = _env(store)
    result = await run_module(AdoWikiScan(), env)  # type: ignore[arg-type]

    assert result.ok is True
    assert result.written >= 1
    findings = store.findings(kind="ado_wiki_credential")
    assert len(findings) >= 1


@respx.mock
@pytest.mark.asyncio
async def test_no_ado_orgs(store: Any) -> None:
    """No ADO orgs in scope -> skip gracefully."""

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
    result = await run_module(AdoWikiScan(), env)  # type: ignore[arg-type]
    assert result.ok is True
    assert result.written == 0


@pytest.mark.asyncio
async def test_no_pat(store: Any) -> None:
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
            result = await run_module(AdoWikiScan(), env)  # type: ignore[arg-type]

    assert result.ok is False
    assert "PAT" in result.message
