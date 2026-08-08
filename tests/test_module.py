"""Contract tests for the module interface (core/module.py).

This is the keystone contract every capability builds against, so its metadata
validation, input coercion, gating logic, and run-context surface are locked here.
"""

from __future__ import annotations

import dataclasses

import pytest

from beachhead.core.module import (
    Access,
    ModuleMeta,
    Phase,
    RunContext,
    StoreAccess,
    TokenProvider,
)


# --------------------------------------------------------------------------- #
# ModuleMeta: input coercion
# --------------------------------------------------------------------------- #
def test_meta_coerces_string_phase_and_access_to_enums() -> None:
    meta = ModuleMeta(
        name="enumerate.role_assignments",
        phase="enumerate",
        access="read",
        summary="List assignments.",
    )
    assert meta.phase is Phase.ENUMERATE
    assert meta.access is Access.READ


def test_meta_coerces_technique_ids_iterable_to_tuple() -> None:
    meta = ModuleMeta(
        name="enumerate.x",
        phase=Phase.ENUMERATE,
        access=Access.READ,
        summary="x",
        technique_ids=["T1069.003", "T1078"],
    )
    assert meta.technique_ids == ("T1069.003", "T1078")
    assert isinstance(meta.technique_ids, tuple)


def test_meta_technique_ids_default_is_empty_tuple() -> None:
    meta = ModuleMeta(name="enumerate.x", phase="enumerate", access="read", summary="x")
    assert meta.technique_ids == ()


def test_meta_is_frozen() -> None:
    meta = ModuleMeta(name="enumerate.x", phase="enumerate", access="read", summary="x")
    with pytest.raises(dataclasses.FrozenInstanceError):
        meta.summary = "changed"  # type: ignore[misc]


# --------------------------------------------------------------------------- #
# ModuleMeta: validation
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("bad_name", ["", "enumerate", "noseparator"])
def test_meta_rejects_non_dotted_name(bad_name: str) -> None:
    with pytest.raises(ValueError, match="dotted"):
        ModuleMeta(name=bad_name, phase="enumerate", access="read", summary="x")


def test_meta_rejects_missing_summary() -> None:
    with pytest.raises(ValueError, match="summary"):
        ModuleMeta(name="enumerate.x", phase="enumerate", access="read", summary="")


def test_meta_rejects_analyze_write_module() -> None:
    # analyze modules read the store and make no API calls (architecture.md).
    with pytest.raises(ValueError, match="analyze modules must be access='read'"):
        ModuleMeta(name="analyze.x", phase="analyze", access="write", summary="x")


def test_meta_allows_analyze_read_module() -> None:
    meta = ModuleMeta(name="analyze.paths", phase="analyze", access="read", summary="x")
    assert meta.phase is Phase.ANALYZE


def test_meta_rejects_unknown_phase() -> None:
    with pytest.raises(ValueError):
        ModuleMeta(name="bogus.x", phase="bogus", access="read", summary="x")


# --------------------------------------------------------------------------- #
# ModuleMeta.gated
# --------------------------------------------------------------------------- #
def test_read_module_is_not_gated() -> None:
    meta = ModuleMeta(name="enumerate.x", phase="enumerate", access="read", summary="x")
    assert meta.gated is False


def test_write_module_is_gated() -> None:
    meta = ModuleMeta(name="persist.x", phase="persist", access="write", summary="x")
    assert meta.gated is True


def test_browser_required_read_module_is_gated() -> None:
    # A manual/browser step is gated even when it only reads.
    meta = ModuleMeta(
        name="collect.ado_pat",
        phase="collect",
        access="read",
        summary="x",
        requires_browser=True,
    )
    assert meta.gated is True


# --------------------------------------------------------------------------- #
# RunContext surface
# --------------------------------------------------------------------------- #
def test_run_context_carries_expected_collaborators() -> None:
    fields = {f.name for f in dataclasses.fields(RunContext)}
    assert {
        "az",
        "store",
        "scope",
        "audit",
        "config",
        "console",
        "confirm",
        "run_id",
        "operator",
        "auth",
    } <= fields


# --------------------------------------------------------------------------- #
# StoreAccess conformance
# --------------------------------------------------------------------------- #
def test_store_access_requires_collection_methods() -> None:
    # A store exposing ONLY begin() must NOT satisfy the tightened protocol.
    # (With the old begin()-only protocol this assertion fails — that's the RED state.)
    class OnlyBegin:
        def begin(self) -> object: ...

    assert not isinstance(OnlyBegin(), StoreAccess)


def test_full_fake_satisfies_store_access() -> None:
    from collections.abc import Iterator
    from contextlib import contextmanager

    class FakeStore:
        @contextmanager
        def begin(self) -> Iterator[None]:
            yield

        def upsert_resource(self, **kwargs: object) -> None: ...
        def insert_finding(self, **kwargs: object) -> str:
            return "f-1"

        def insert_attack_path(self, **kwargs: object) -> str:
            return "ap-1"

        def resources(self) -> list[object]:
            return []

        def findings(self, *, kind: str | None = None) -> list[object]:
            return []

        def attack_paths(self) -> list[object]:
            return []

        def runs(self) -> list[object]:
            return []

    assert isinstance(FakeStore(), StoreAccess)


def test_concrete_store_satisfies_store_access() -> None:
    from beachhead.core.store.access import Store

    assert issubclass(Store, StoreAccess)


def test_token_provider_is_runtime_checkable() -> None:
    class FakeAuth:
        async def get(self, audience: str) -> str:
            return "tok"

    assert isinstance(FakeAuth(), TokenProvider)


def test_run_context_auth_defaults_to_none() -> None:
    default = next(f for f in dataclasses.fields(RunContext) if f.name == "auth").default
    assert default is None
