"""Beachhead module interface — the keystone contract.

Every post-exploitation capability is a module implementing :class:`Module`:
a declarative :class:`ModuleMeta` plus an async ``run(ctx)``. ``ctx`` (a
:class:`RunContext`) is the module's only door to the outside world — it carries
the clients, store, scope guard, audit log, config, console, and confirm gate.
Modules never import clients or open store connections directly.

See docs/module-authoring.md for the authoring guide and docs/architecture.md
for how this fits the data flow.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

if TYPE_CHECKING:
    from contextlib import AbstractContextManager

    from rich.console import Console

    from beachhead.core.secret_store import Credential
    from beachhead.core.store.rows import (
        AttackPath,
        Finding,
        Resource,
        Run,
    )

__all__ = [
    "Phase",
    "Access",
    "ModuleMeta",
    "RunResult",
    "RunContext",
    "Module",
    "AzClient",
    "StoreAccess",
    "SecretStoreAccess",
    "ScopeGuard",
    "AuditLog",
    "EngagementConfig",
    "ConfirmGate",
    "TokenProvider",
]


# --------------------------------------------------------------------------- #
# Enums
# --------------------------------------------------------------------------- #
class Phase(StrEnum):
    """Post-exploitation phase a module belongs to."""

    ENUMERATE = "enumerate"
    HARVEST = "harvest"
    ANALYZE = "analyze"
    EXPLOIT = "exploit"


class Access(StrEnum):
    """Whether a module mutates the target."""

    READ = "read"
    WRITE = "write"


# --------------------------------------------------------------------------- #
# Metadata
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class ModuleMeta:
    """Declarative metadata that drives discovery, gating, and reporting.

    Accepts plain strings for ``phase``/``access`` (coerced to enums) and any
    iterable for ``technique_ids`` (stored as a tuple). ``name`` must be a
    dotted ``phase.module`` identifier, e.g. ``"enumerate.role_assignments"``.
    """

    name: str
    phase: Phase
    access: Access
    summary: str
    technique_ids: tuple[str, ...] = ()
    requires_browser: bool = False
    needs_secrets: bool = False

    def __post_init__(self) -> None:
        # Coerce inputs so call sites can pass strings/lists (see docs examples).
        object.__setattr__(self, "phase", Phase(self.phase))
        object.__setattr__(self, "access", Access(self.access))
        object.__setattr__(self, "technique_ids", tuple(self.technique_ids))

        # Harvest and exploit modules always write to the secret store.
        if self.phase in (Phase.HARVEST, Phase.EXPLOIT):
            object.__setattr__(self, "needs_secrets", True)

        if not self.name or "." not in self.name:
            raise ValueError(f"module name must be a dotted 'phase.module' id, got {self.name!r}")
        if not self.summary:
            raise ValueError(f"module {self.name!r} is missing a summary")
        if self.phase is Phase.ANALYZE and self.access is Access.WRITE:
            # analyze modules read the store and make no API calls (architecture.md)
            raise ValueError("analyze modules must be access='read'")

    @property
    def gated(self) -> bool:
        """True if a run requires the confirmation gate + audit + artifact record.

        Write modules and any browser-required (manual) module are gated.
        """
        return self.access is Access.WRITE or self.requires_browser


# --------------------------------------------------------------------------- #
# Result
# --------------------------------------------------------------------------- #
@dataclass(slots=True)
class RunResult:
    """Structured outcome of a module run, surfaced in the TUI and report."""

    ok: bool
    written: int = 0
    message: str = ""
    details: dict[str, Any] = field(default_factory=dict)


# --------------------------------------------------------------------------- #
# Collaborator protocols
#
# These describe the *surface* modules may call. Concrete implementations live
# in core/clients, core/store, core/scope, core/audit, core/config. Defining
# them as Protocols keeps this interface module self-contained and lets modules
# be type-checked and unit-tested against fakes.
# --------------------------------------------------------------------------- #
@runtime_checkable
class AzClient(Protocol):
    """Wrapper around the ``az`` / ``az devops`` CLI.

    Routes the target through the scope guard, runs with ``--output json``,
    audits the invocation, and never accepts secrets on the command line.
    See ``core/clients/az_client.py`` for the concrete implementation.
    """

    async def run(
        self,
        args: list[str],
        *,
        scope_targets: Sequence[str] = (),
        subscription: str | None = None,
        organization: str | None = None,
        parse_json: bool = True,
        timeout: float | None = None,  # noqa: ASYNC109
    ) -> Any: ...


@runtime_checkable
class StoreAccess(Protocol):
    """Normalized read/write access layer over the SQLite store (module-facing).

    The tight surface modules legitimately touch: collection upserts/reads + a batched
    transaction. The concrete Store (core/store/access.py) also carries the runner /
    audit methods, which modules reach via ctx.audit, not here.
    """

    def begin(self) -> AbstractContextManager[None]:
        """Return a transaction context manager for batched writes."""
        ...

    def insert_finding(
        self,
        *,
        kind: str,
        reference: str,
        run_id: str,
        resource_id: str | None = None,
        redacted: bool = False,
        details: dict[str, object] | None = None,
    ) -> str: ...

    def insert_attack_path(
        self,
        *,
        source_id: str,
        target_id: str,
        edges: list[dict[str, object]],
        technique_ids: list[str],
        score: float,
        description: str,
        run_id: str,
    ) -> str: ...

    def upsert_resource(
        self,
        *,
        resource_id: str,
        type: str,
        name: str,
        run_id: str,
        properties_summary: str | dict[str, object] = "",
    ) -> None: ...

    def resources(self, *, type: str | None = None) -> list[Resource]: ...
    def findings(self, *, kind: str | None = None, run_id: str | None = None) -> list[Finding]: ...
    def attack_paths(self) -> list[AttackPath]: ...
    def runs(self) -> list[Run]: ...


@runtime_checkable
class ScopeGuard(Protocol):
    """Authorization boundary. ``check`` raises ScopeError if out of scope."""

    def check(self, target: str, *, kind: str = "target") -> None: ...


@runtime_checkable
class AuditLog(Protocol):
    """Append-only operator-action log."""

    def record(
        self,
        action: str,
        target: str,
        *,
        result: str = "ok",
        **extra: Any,
    ) -> None: ...


@runtime_checkable
class EngagementConfig(Protocol):
    """Loaded engagement/scope config (core/config.py)."""

    @property
    def engagement(self) -> str: ...
    @property
    def allow_write(self) -> bool: ...


@runtime_checkable
class ConfirmGate(Protocol):
    """Confirmation gate for gated (write/manual) operations.

    Returns True only when the operator has authorized the action.
    """

    async def __call__(self, prompt: str, *, dangerous: bool = False) -> bool: ...


@runtime_checkable
class PromptFn(Protocol):
    """Text-input prompt that works in both CLI (stdin) and TUI (returns default)."""

    async def __call__(self, message: str, *, default: str = "") -> str: ...


@runtime_checkable
class TokenProvider(Protocol):
    """Async token retrieval — the module-facing auth interface.

    Clients and modules call ``await ctx.auth.get("graph")`` to obtain a valid
    access token; the broker handles expiry and refresh transparently.  See
    ``core/auth/broker.py``.
    """

    async def get(self, audience: str) -> str: ...


@runtime_checkable
class SecretStoreAccess(Protocol):
    """Read/write access to the plaintext credential store.

    Mirrors :class:`StoreAccess.insert_finding` with the addition of a
    ``value`` field for the plaintext secret.  Harvest and exploit modules
    call ``store_credential`` to persist discovered secrets alongside the
    redacted finding in the main store.  The analyze ``discovered_credentials``
    module calls ``list_credentials`` to display them offline.
    """

    def store_credential(
        self,
        *,
        kind: str,
        reference: str,
        run_id: str,
        value: str,
        resource_id: str | None = None,
        redacted: bool = False,
        details: dict[str, object] | None = None,
    ) -> str: ...

    def list_credentials(
        self,
        *,
        kind: str | None = None,
    ) -> list[Credential]: ...

    def credential_count(self) -> int: ...

    def close(self) -> None: ...


# --------------------------------------------------------------------------- #
# Run context
# --------------------------------------------------------------------------- #
@dataclass(slots=True)
class RunContext:
    """Everything a module is allowed to touch during a run."""

    az: AzClient
    store: StoreAccess
    scope: ScopeGuard
    audit: AuditLog
    config: EngagementConfig
    console: Console
    confirm: ConfirmGate
    prompt: PromptFn
    run_id: str
    operator: str
    auth: TokenProvider | None = None
    secrets: SecretStoreAccess | None = None


# --------------------------------------------------------------------------- #
# Module protocol + optional base
# --------------------------------------------------------------------------- #
@runtime_checkable
class Module(Protocol):
    """A post-exploitation capability. Implementations need ``meta`` + ``run``."""

    meta: ModuleMeta

    async def run(self, ctx: RunContext) -> RunResult: ...


