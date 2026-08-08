"""Shared CLI/TUI bootstrap.

Loads the engagement config (refuse if absent — unset scope must never run), opens the
store read-only, and compares the config's scope_hash against the store's engagement row so
a boundary change is surfaced. No Azure calls; no writes. See
docs/superpowers/specs/2026-06-04-cli-tui-read-console-design.md.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Protocol

from beachhead.core.config import EngagementConfig, load_config
from beachhead.core.store.access import Store
from beachhead.core.store.engine import open_store, open_store_readonly
from beachhead.core.store.rows import Engagement


@dataclass(frozen=True, slots=True)
class SurfaceContext:
    """Everything a read-only operator surface needs after bootstrap."""

    config: EngagementConfig
    store: Store
    engagement: Engagement | None
    scope_match: bool


def open_surface(store_path: str, config_path: str | None = None) -> SurfaceContext:
    """Load config + open the store read-only + compute scope-hash match.

    Raises ConfigError (missing/invalid config).
    Caller is responsible for calling ``sc.store.close()`` when done.
    """
    config = load_config(config_path)
    if not Path(store_path).exists():
        # Create an empty store so the TUI can render views in their "empty"
        # state and the operator can launch the first module run from there.
        seed = open_store(store_path)
        seed.ensure_engagement(name=config.engagement, scope_hash=config.scope_hash)
        seed.close()
    store = open_store_readonly(store_path)
    try:
        engagement = store.get_engagement()
        scope_match = engagement is not None and engagement.scope_hash == config.scope_hash
    except Exception:  # noqa: BLE001 - close the store on any post-open failure, then re-raise
        store.close()
        raise
    return SurfaceContext(
        config=config, store=store, engagement=engagement, scope_match=scope_match
    )


class _HasTimes(Protocol):
    @property
    def started_at(self) -> str: ...
    @property
    def finished_at(self) -> str | None: ...


def format_duration(run: _HasTimes) -> str:
    """Human duration for a run; '—' while still running."""
    if not run.finished_at:
        return "—"
    started = datetime.fromisoformat(run.started_at)
    finished = datetime.fromisoformat(run.finished_at)
    return f"{(finished - started).total_seconds():.1f}s"
