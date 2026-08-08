"""Module discovery, validation, and registry.

Discovers modules via ``beachhead.modules`` entry points (pyproject.toml),
validates their ``meta`` on first load, and exposes a :class:`ModuleRegistry`
the CLI and TUI use to list and look up modules by name or phase.

Modules are never imported eagerly — entry-point loading is deferred until
``load_modules()`` is called so startup stays fast and import errors surface
cleanly rather than aborting the CLI.
"""

from __future__ import annotations

import logging
from importlib.metadata import entry_points
from typing import Any

from beachhead.core.module import Module, ModuleMeta, Phase

__all__ = ["ModuleRegistry", "load_modules", "LoadError"]

log = logging.getLogger(__name__)


class LoadError(Exception):
    """A module entry point could not be loaded or validated."""

    def __init__(self, name: str, reason: str) -> None:
        super().__init__(f"{name}: {reason}")
        self.module_name = name
        self.reason = reason


class ModuleRegistry:
    """Validated collection of discovered modules.

    The registry is immutable after construction; the CLI/TUI reads it
    to populate catalogs, and the runner looks up modules by name.
    """

    def __init__(
        self,
        modules: dict[str, Module],
        errors: list[LoadError],
    ) -> None:
        self._modules = dict(modules)
        self._errors = list(errors)

    def get(self, name: str) -> Module | None:
        return self._modules.get(name)

    def list_all(self) -> list[Module]:
        return sorted(self._modules.values(), key=lambda m: m.meta.name)

    def list_phase(self, phase: Phase | str) -> list[Module]:
        p = Phase(phase)
        return [m for m in self.list_all() if m.meta.phase is p]

    def names(self) -> list[str]:
        return sorted(self._modules)

    @property
    def errors(self) -> list[LoadError]:
        return list(self._errors)

    def __len__(self) -> int:
        return len(self._modules)

    def __contains__(self, name: str) -> bool:
        return name in self._modules


def load_modules(*, group: str = "beachhead.modules") -> ModuleRegistry:
    """Discover and validate all modules from entry points.

    Every entry point is loaded, its class instantiated, and ``meta``
    validated.  Failures are collected (not raised) so one broken module
    doesn't prevent all others from loading.
    """
    modules: dict[str, Module] = {}
    errors: list[LoadError] = []

    eps = entry_points(group=group)
    for ep in eps:
        name = ep.name
        try:
            cls = ep.load()
        except Exception as exc:  # noqa: BLE001
            err = LoadError(name, f"import failed: {exc}")
            errors.append(err)
            log.warning("module %s: %s", name, err.reason)
            continue

        try:
            instance = cls()
        except Exception as exc:  # noqa: BLE001
            err = LoadError(name, f"instantiation failed: {exc}")
            errors.append(err)
            log.warning("module %s: %s", name, err.reason)
            continue

        if not hasattr(instance, "meta") or not isinstance(instance.meta, ModuleMeta):
            err = LoadError(name, "missing or invalid 'meta' attribute")
            errors.append(err)
            log.warning("module %s: %s", name, err.reason)
            continue

        if not hasattr(instance, "run") or not callable(instance.run):
            err = LoadError(name, "missing or non-callable 'run' method")
            errors.append(err)
            log.warning("module %s: %s", name, err.reason)
            continue

        if instance.meta.name != name:
            err = LoadError(
                name,
                f"meta.name {instance.meta.name!r} does not match entry-point name {name!r}",
            )
            errors.append(err)
            log.warning("module %s: %s", name, err.reason)
            continue

        if name in modules:
            err = LoadError(name, "duplicate entry-point name")
            errors.append(err)
            log.warning("module %s: %s", name, err.reason)
            continue

        modules[name] = instance
        log.debug("loaded module %s (%s/%s)", name, instance.meta.phase, instance.meta.access)

    return ModuleRegistry(modules, errors)


def register_inline(registry: ModuleRegistry, module: Any) -> ModuleRegistry:
    """Add a module to a registry without entry points (testing helper)."""
    if not isinstance(module.meta, ModuleMeta):
        msg = "module must have a valid ModuleMeta"
        raise TypeError(msg)
    new_modules = {n: registry.get(n) for n in registry.names()}
    new_modules[module.meta.name] = module
    return ModuleRegistry(
        {k: v for k, v in new_modules.items() if v is not None},
        registry.errors,
    )
