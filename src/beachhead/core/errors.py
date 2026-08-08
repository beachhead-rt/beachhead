"""Shared client error taxonomy.

All clients in ``core/clients`` raise these typed errors so modules and the TUI
react consistently regardless of which surface (Graph, ARM, ``az``, ``pwsh``) a
call went through. See docs/api-clients.md ("Error taxonomy").

  - ``AuthError``        — 401-equivalent after one refresh; bad/expired/wrong-audience token.
  - ``ScopeError``       — target rejected by core/scope. **Never retried, never suppressed.**
  - ``Throttled``        — 429/503-equivalent after retries exhausted.
  - ``Transient``        — network/5xx/timeout; safe to surface as retryable.
  - ``ApiError``         — any other client/tool failure; carries status/exit code + detail.
  - ``StoreError``       — local SQLite store failure (integrity/operational).
  - ``StoreMissingError`` — store file absent / no module has run yet.
  - ``MigrationError``   — schema migration failed/malformed/version skew.
"""

from __future__ import annotations

__all__ = [
    "BeachheadError",
    "AuthError",
    "ScopeError",
    "ConfigError",
    "ConfigMissingError",
    "AuditError",
    "Throttled",
    "Transient",
    "ApiError",
    "StoreError",
    "StoreMissingError",
    "MigrationError",
]


class BeachheadError(Exception):
    """Base for all Beachhead client errors."""


class AuthError(BeachheadError):
    """Authentication/authorization failure (401-equivalent, wrong audience)."""


class ScopeError(BeachheadError):
    """Target outside the engagement scope. Hard fail — never retried/suppressed."""


class ConfigError(BeachheadError):
    """Engagement config unreadable, invalid, or empty (no scope). Refuse to run."""


class ConfigMissingError(ConfigError):
    """Engagement config file does not exist yet. Callers can offer guided creation."""

    def __init__(self, path: str) -> None:
        super().__init__(f"engagement config not found: {path}")
        self.config_path = path


class AuditError(BeachheadError):
    """Audit record rejected: bad result vocabulary, empty action/target, or
    unsupported extra fields. Fail loud — never write a malformed audit row."""


class Throttled(BeachheadError):
    """Rate limited (429/503-equivalent) after retries were exhausted."""


class Transient(BeachheadError):
    """Network error, 5xx, or timeout — retryable."""


class ApiError(BeachheadError):
    """A client/tool failure that isn't one of the above.

    ``status`` is the HTTP status for the HTTP clients; ``exit_code`` is the process
    exit code for the subprocess clients (``az``/``pwsh``). Either may be ``None``.
    """

    def __init__(
        self,
        message: str,
        *,
        status: int | None = None,
        exit_code: int | None = None,
        correlation_id: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.exit_code = exit_code
        self.correlation_id = correlation_id


class StoreError(BeachheadError):
    """Local SQLite store failure (integrity/operational). Wraps sqlite3 errors."""


class StoreMissingError(BeachheadError):
    """The store file does not exist yet (no module has run). Refuse to read."""


class MigrationError(StoreError):
    """A schema migration failed, the migration set is malformed, or versions skew."""
