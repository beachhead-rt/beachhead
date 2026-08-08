"""Tests for the module loader and registry (core/loader.py)."""

from __future__ import annotations

import pytest

from beachhead.core.loader import LoadError, ModuleRegistry, load_modules, register_inline
from beachhead.core.module import ModuleMeta, Phase, RunContext, RunResult


# ---------------------------------------------------------------------------
# Minimal fake module
# ---------------------------------------------------------------------------
class FakeModule:
    meta = ModuleMeta(
        name="enumerate.test_mod",
        phase="enumerate",
        access="read",
        summary="Test module",
        technique_ids=["T9999"],
    )

    async def run(self, ctx: RunContext) -> RunResult:
        return RunResult(ok=True)


class AnalyzeModule:
    meta = ModuleMeta(
        name="analyze.paths",
        phase="analyze",
        access="read",
        summary="Analyze attack paths",
    )

    async def run(self, ctx: RunContext) -> RunResult:
        return RunResult(ok=True)


# ---------------------------------------------------------------------------
# ModuleRegistry
# ---------------------------------------------------------------------------
def test_empty_registry() -> None:
    reg = ModuleRegistry({}, [])
    assert len(reg) == 0
    assert reg.list_all() == []
    assert reg.names() == []
    assert reg.get("anything") is None
    assert "anything" not in reg


def test_registry_with_one_module() -> None:
    m = FakeModule()
    reg = ModuleRegistry({"enumerate.test_mod": m}, [])  # type: ignore[dict-item]
    assert len(reg) == 1
    assert reg.get("enumerate.test_mod") is m
    assert "enumerate.test_mod" in reg
    assert reg.names() == ["enumerate.test_mod"]


def test_registry_list_phase() -> None:
    m1 = FakeModule()
    m2 = AnalyzeModule()
    reg = ModuleRegistry(  # type: ignore[dict-item]
        {"enumerate.test_mod": m1, "analyze.paths": m2}, []
    )
    enum_mods = reg.list_phase("enumerate")
    assert len(enum_mods) == 1
    assert enum_mods[0].meta.name == "enumerate.test_mod"

    analyze_mods = reg.list_phase(Phase.ANALYZE)
    assert len(analyze_mods) == 1
    assert analyze_mods[0].meta.name == "analyze.paths"


def test_registry_list_all_sorted() -> None:
    m1 = FakeModule()
    m2 = AnalyzeModule()
    reg = ModuleRegistry(  # type: ignore[dict-item]
        {"enumerate.test_mod": m1, "analyze.paths": m2}, []
    )
    all_mods = reg.list_all()
    names = [m.meta.name for m in all_mods]
    assert names == ["analyze.paths", "enumerate.test_mod"]


def test_registry_errors_preserved() -> None:
    err = LoadError("broken.mod", "import failed")
    reg = ModuleRegistry({}, [err])
    assert len(reg.errors) == 1
    assert reg.errors[0].module_name == "broken.mod"
    assert "import failed" in reg.errors[0].reason


# ---------------------------------------------------------------------------
# load_modules (empty group — no modules registered in test env)
# ---------------------------------------------------------------------------
def test_load_modules_empty_group() -> None:
    reg = load_modules(group="beachhead.test.nonexistent")
    assert len(reg) == 0
    assert reg.errors == []


def test_load_modules_default_group() -> None:
    reg = load_modules()
    assert len(reg) >= 1
    assert "enumerate.ado_pipelines" in reg


# ---------------------------------------------------------------------------
# register_inline (testing helper)
# ---------------------------------------------------------------------------
def test_register_inline_adds_module() -> None:
    reg = ModuleRegistry({}, [])
    m = FakeModule()
    reg2 = register_inline(reg, m)
    assert len(reg2) == 1
    assert reg2.get("enumerate.test_mod") is m
    assert len(reg) == 0  # original unchanged


def test_register_inline_rejects_bad_meta() -> None:
    reg = ModuleRegistry({}, [])

    class BadMod:
        meta = "not a ModuleMeta"

    with pytest.raises(TypeError, match="valid ModuleMeta"):
        register_inline(reg, BadMod())


# ---------------------------------------------------------------------------
# LoadError
# ---------------------------------------------------------------------------
def test_load_error_str() -> None:
    e = LoadError("enumerate.x", "import failed: ModuleNotFoundError")
    assert "enumerate.x" in str(e)
    assert "import failed" in str(e)
    assert e.module_name == "enumerate.x"
