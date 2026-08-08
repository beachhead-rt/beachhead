"""Tests for enumerate.ado_permissions — ADO security namespace + ACL enumeration."""

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
from beachhead.modules.enumerate.ado_permissions import AdoPermissions



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
    m = AdoPermissions()
    assert m.meta.name == "enumerate.ado_permissions"
    assert m.meta.phase.value == "enumerate"
    assert m.meta.access.value == "read"
    assert m.meta.gated is False


@respx.mock
@pytest.mark.asyncio
async def test_enumerates_namespaces_and_acls(store: Any) -> None:
    """Enumerates security namespaces and ACLs for key namespaces."""
    git_ns_id = "2e9eb7ed-3c0a-47d4-87c1-0ffdd275fd87"
    other_ns_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

    respx.get("https://dev.azure.com/test-org/_apis/securitynamespaces").mock(
        return_value=httpx.Response(
            200,
            json={
                "value": [
                    {
                        "namespaceId": git_ns_id,
                        "name": "Git Repositories",
                        "displayName": "Git Repositories",
                        "actions": [
                            {"name": "Read", "displayName": "Read", "bit": 1},
                            {"name": "Contribute", "displayName": "Contribute", "bit": 2},
                        ],
                    },
                    {
                        "namespaceId": other_ns_id,
                        "name": "Analytics",
                        "displayName": "Analytics",
                        "actions": [],
                    },
                ]
            },
        )
    )

    respx.get(
        f"https://dev.azure.com/test-org/_apis/accesscontrollists/{git_ns_id}"
    ).mock(
        return_value=httpx.Response(
            200,
            json={
                "value": [
                    {
                        "token": "repoV2/proj-guid/repo-guid",
                        "inheritPermissions": True,
                        "acesDictionary": {
                            "Microsoft.TeamFoundation.Identity;user1": {
                                "allow": 3,
                                "deny": 0,
                            }
                        },
                    }
                ]
            },
        )
    )

    env = _env(store)
    result = await run_module(AdoPermissions(), env)  # type: ignore[arg-type]

    assert result.ok is True
    assert result.written >= 3  # 2 namespaces + 1 ACL

    resources = store.resources()
    types = {r.type for r in resources}
    assert "ado_security_namespace" in types
    assert "ado_access_control" in types

    ns_resources = [r for r in resources if r.type == "ado_security_namespace"]
    assert len(ns_resources) == 2


@respx.mock
@pytest.mark.asyncio
async def test_flags_dangerous_permissions_with_decoded_names(store: Any) -> None:
    """Flags identities with dangerous permissions and decodes bitmask to action names."""
    git_ns_id = "2e9eb7ed-3c0a-47d4-87c1-0ffdd275fd87"

    respx.get("https://dev.azure.com/test-org/_apis/securitynamespaces").mock(
        return_value=httpx.Response(
            200,
            json={
                "value": [
                    {
                        "namespaceId": git_ns_id,
                        "name": "Git Repositories",
                        "displayName": "Git Repositories",
                        "actions": [
                            {"name": "Read", "displayName": "Read", "bit": 1},
                            {"name": "Contribute", "displayName": "Contribute", "bit": 2},
                            {"name": "ForcePush", "displayName": "ForcePush", "bit": 16384},
                            {
                                "name": "ManagePermissions",
                                "displayName": "ManagePermissions",
                                "bit": 2048,
                            },
                        ],
                    }
                ]
            },
        )
    )

    # allow=18435 = 1 (Read) + 2 (Contribute) + 2048 (ManagePermissions) + 16384 (ForcePush)
    respx.get(
        f"https://dev.azure.com/test-org/_apis/accesscontrollists/{git_ns_id}"
    ).mock(
        return_value=httpx.Response(
            200,
            json={
                "value": [
                    {
                        "token": "repoV2/proj-guid",
                        "inheritPermissions": False,
                        "acesDictionary": {
                            "Microsoft.TeamFoundation.Identity;overprivileged-user": {
                                "allow": 18435,
                                "deny": 0,
                            }
                        },
                    }
                ]
            },
        )
    )

    env = _env(store)
    result = await run_module(AdoPermissions(), env)  # type: ignore[arg-type]

    assert result.ok is True
    findings = store.findings(kind="ado_broad_permissions")
    assert len(findings) >= 1

    f = findings[0]
    assert "ManagePermissions" in f.reference or "ForcePush" in f.reference
    details = f.details
    assert "dangerous_actions" in details
    assert "ManagePermissions" in details["dangerous_actions"]
    assert "ForcePush" in details["dangerous_actions"]
    assert "allowed_actions" in details
    assert "identity_label" in details
    assert "target_context" in details


@respx.mock
@pytest.mark.asyncio
async def test_skips_read_only_permissions(store: Any) -> None:
    """Does not flag identities that only have read permissions."""
    git_ns_id = "2e9eb7ed-3c0a-47d4-87c1-0ffdd275fd87"

    respx.get("https://dev.azure.com/test-org/_apis/securitynamespaces").mock(
        return_value=httpx.Response(
            200,
            json={
                "value": [
                    {
                        "namespaceId": git_ns_id,
                        "name": "Git Repositories",
                        "displayName": "Git Repositories",
                        "actions": [
                            {"name": "Read", "displayName": "Read", "bit": 1},
                        ],
                    }
                ]
            },
        )
    )

    respx.get(
        f"https://dev.azure.com/test-org/_apis/accesscontrollists/{git_ns_id}"
    ).mock(
        return_value=httpx.Response(
            200,
            json={
                "value": [
                    {
                        "token": "repoV2/proj-guid",
                        "inheritPermissions": True,
                        "acesDictionary": {
                            "Microsoft.TeamFoundation.Identity;reader": {
                                "allow": 1,
                                "deny": 0,
                            }
                        },
                    }
                ]
            },
        )
    )

    env = _env(store)
    result = await run_module(AdoPermissions(), env)  # type: ignore[arg-type]

    assert result.ok is True
    findings = store.findings(kind="ado_broad_permissions")
    assert len(findings) == 0


@respx.mock
@pytest.mark.asyncio
async def test_uses_known_actions_fallback(store: Any) -> None:
    """Uses built-in action maps when API doesn't return action metadata."""
    build_ns_id = "33344d9c-fc72-4d6f-aba5-fa317101a7e9"

    respx.get("https://dev.azure.com/test-org/_apis/securitynamespaces").mock(
        return_value=httpx.Response(
            200,
            json={
                "value": [
                    {
                        "namespaceId": build_ns_id,
                        "name": "Build",
                        "displayName": "Build",
                        "actions": [],
                    }
                ]
            },
        )
    )

    # allow=2176 = 128 (QueueBuilds) + 2048 (EditBuildDefinition)
    respx.get(
        f"https://dev.azure.com/test-org/_apis/accesscontrollists/{build_ns_id}"
    ).mock(
        return_value=httpx.Response(
            200,
            json={
                "value": [
                    {
                        "token": "proj-guid",
                        "inheritPermissions": True,
                        "acesDictionary": {
                            "vssgp.Uy0xLTktaWQtMQ": {
                                "allow": 2176,
                                "deny": 0,
                            }
                        },
                    }
                ]
            },
        )
    )

    env = _env(store)
    result = await run_module(AdoPermissions(), env)  # type: ignore[arg-type]

    assert result.ok is True
    findings = store.findings(kind="ado_broad_permissions")
    assert len(findings) >= 1

    details = findings[0].details
    assert "QueueBuilds" in details["dangerous_actions"]
    assert "EditBuildDefinition" in details["dangerous_actions"]
    assert "VSS Group" in details["identity_label"]


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
            result = await run_module(AdoPermissions(), env)  # type: ignore[arg-type]

    assert result.ok is False
    assert "PAT" in result.message
