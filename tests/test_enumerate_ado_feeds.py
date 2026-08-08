"""Tests for enumerate.ado_feeds — ADO packaging feeds enumeration."""

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
from beachhead.modules.enumerate.ado_feeds import AdoFeeds



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
    m = AdoFeeds()
    assert m.meta.name == "enumerate.ado_feeds"
    assert m.meta.phase.value == "enumerate"
    assert m.meta.access.value == "read"
    assert m.meta.gated is False


@respx.mock
@pytest.mark.asyncio
async def test_enumerates_feeds_and_packages(store: Any) -> None:
    """Enumerates org and project feeds plus their packages."""
    # org-scoped feeds
    respx.get("https://dev.azure.com/test-org/_apis/packaging/feeds").mock(
        return_value=httpx.Response(
            200,
            json={
                "value": [
                    {
                        "id": "feed-1",
                        "name": "org-feed",
                        "url": "https://feeds.dev.azure.com/test-org/_apis/packaging/feeds/feed-1",
                        "upstreamEnabled": False,
                        "upstreamSources": [],
                        "fullyQualifiedName": "org-feed",
                    }
                ]
            },
        )
    )
    # project list
    respx.get("https://dev.azure.com/test-org/_apis/projects").mock(
        return_value=httpx.Response(200, json={"value": [{"name": "proj1"}]})
    )
    # project-scoped feeds
    respx.get("https://dev.azure.com/test-org/proj1/_apis/packaging/feeds").mock(
        return_value=httpx.Response(
            200,
            json={
                "value": [
                    {
                        "id": "feed-2",
                        "name": "proj-feed",
                        "url": "https://feeds.dev.azure.com/test-org/_apis/packaging/feeds/feed-2",
                        "upstreamEnabled": True,
                        "upstreamSources": [
                            {"name": "NuGet Gallery", "location": "https://api.nuget.org/v3/index.json"}
                        ],
                        "fullyQualifiedName": "proj1/proj-feed",
                    }
                ]
            },
        )
    )
    # packages for org-feed
    respx.get("https://dev.azure.com/test-org/_apis/packaging/feeds/feed-1/packages").mock(
        return_value=httpx.Response(
            200,
            json={
                "value": [
                    {
                        "id": "pkg-1",
                        "name": "MyLib",
                        "protocolType": "NuGet",
                        "versions": [{"version": "1.2.3"}],
                    },
                    {
                        "id": "pkg-2",
                        "name": "MyOtherLib",
                        "protocolType": "NuGet",
                        "versions": [{"version": "2.0.0"}],
                    },
                ]
            },
        )
    )
    # packages for proj-feed
    respx.get("https://dev.azure.com/test-org/proj1/_apis/packaging/feeds/feed-2/packages").mock(
        return_value=httpx.Response(
            200,
            json={
                "value": [
                    {
                        "id": "pkg-3",
                        "name": "FrontendKit",
                        "protocolType": "npm",
                        "versions": [{"version": "0.9.1"}],
                    },
                ]
            },
        )
    )

    env = _env(store)
    result = await run_module(AdoFeeds(), env)  # type: ignore[arg-type]

    assert result.ok is True
    # 2 feeds + 3 packages = 5 resources, plus findings
    assert result.written >= 5

    resources = store.resources()
    types = {r.type for r in resources}
    assert "ado_feed" in types
    assert "ado_feed_package" in types

    feed_resources = [r for r in resources if r.type == "ado_feed"]
    assert len(feed_resources) == 2

    pkg_resources = [r for r in resources if r.type == "ado_feed_package"]
    assert len(pkg_resources) == 3


@respx.mock
@pytest.mark.asyncio
async def test_flags_public_upstream(store: Any) -> None:
    """Flags feeds with public registry upstream sources."""
    respx.get("https://dev.azure.com/test-org/_apis/packaging/feeds").mock(
        return_value=httpx.Response(200, json={"value": []})
    )
    respx.get("https://dev.azure.com/test-org/_apis/projects").mock(
        return_value=httpx.Response(200, json={"value": [{"name": "proj1"}]})
    )
    respx.get("https://dev.azure.com/test-org/proj1/_apis/packaging/feeds").mock(
        return_value=httpx.Response(
            200,
            json={
                "value": [
                    {
                        "id": "feed-up",
                        "name": "upstream-feed",
                        "upstreamEnabled": True,
                        "upstreamSources": [
                            {"name": "NuGet Gallery", "location": "https://api.nuget.org/v3/index.json"},
                            {"name": "npmjs", "location": "https://registry.npmjs.org"},
                        ],
                        "fullyQualifiedName": "proj1/upstream-feed",
                    }
                ]
            },
        )
    )
    respx.get("https://dev.azure.com/test-org/proj1/_apis/packaging/feeds/feed-up/packages").mock(
        return_value=httpx.Response(200, json={"value": []})
    )

    env = _env(store)
    result = await run_module(AdoFeeds(), env)  # type: ignore[arg-type]

    assert result.ok is True
    findings = store.findings(kind="ado_feed_upstream_public")
    assert len(findings) >= 1
    assert "upstream-feed" in findings[0].reference
    assert "dependency confusion" in findings[0].reference


@respx.mock
@pytest.mark.asyncio
async def test_flags_org_scoped_feed(store: Any) -> None:
    """Flags org-scoped feeds with no upstream sources."""
    respx.get("https://dev.azure.com/test-org/_apis/packaging/feeds").mock(
        return_value=httpx.Response(
            200,
            json={
                "value": [
                    {
                        "id": "feed-org",
                        "name": "shared-feed",
                        "upstreamEnabled": False,
                        "upstreamSources": [],
                        "fullyQualifiedName": "shared-feed",
                    }
                ]
            },
        )
    )
    respx.get("https://dev.azure.com/test-org/_apis/projects").mock(
        return_value=httpx.Response(200, json={"value": []})
    )
    respx.get("https://dev.azure.com/test-org/_apis/packaging/feeds/feed-org/packages").mock(
        return_value=httpx.Response(200, json={"value": []})
    )

    env = _env(store)
    result = await run_module(AdoFeeds(), env)  # type: ignore[arg-type]

    assert result.ok is True
    findings = store.findings(kind="ado_feed_org_scoped")
    assert len(findings) >= 1
    assert "shared-feed" in findings[0].reference


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
            result = await run_module(AdoFeeds(), env)  # type: ignore[arg-type]

    assert result.ok is False
    assert "PAT" in result.message


@respx.mock
@pytest.mark.asyncio
async def test_deduplicates_feeds(store: Any) -> None:
    """Feeds seen at org level are not duplicated when seen at project level."""
    respx.get("https://dev.azure.com/test-org/_apis/packaging/feeds").mock(
        return_value=httpx.Response(
            200,
            json={
                "value": [
                    {
                        "id": "feed-dup",
                        "name": "dup-feed",
                        "upstreamEnabled": False,
                        "upstreamSources": [],
                    }
                ]
            },
        )
    )
    respx.get("https://dev.azure.com/test-org/_apis/projects").mock(
        return_value=httpx.Response(200, json={"value": [{"name": "proj1"}]})
    )
    respx.get("https://dev.azure.com/test-org/proj1/_apis/packaging/feeds").mock(
        return_value=httpx.Response(
            200,
            json={
                "value": [
                    {
                        "id": "feed-dup",
                        "name": "dup-feed",
                        "upstreamEnabled": False,
                        "upstreamSources": [],
                    }
                ]
            },
        )
    )
    respx.get("https://dev.azure.com/test-org/_apis/packaging/feeds/feed-dup/packages").mock(
        return_value=httpx.Response(200, json={"value": []})
    )

    env = _env(store)
    result = await run_module(AdoFeeds(), env)  # type: ignore[arg-type]

    assert result.ok is True
    feed_resources = [r for r in store.resources() if r.type == "ado_feed"]
    assert len(feed_resources) == 1


@respx.mock
@pytest.mark.asyncio
async def test_no_ado_orgs(store: Any) -> None:
    """No ADO orgs in scope → skip gracefully."""

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
    result = await run_module(AdoFeeds(), env)  # type: ignore[arg-type]
    assert result.ok is True
    assert result.written == 0
