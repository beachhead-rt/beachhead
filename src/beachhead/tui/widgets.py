"""Shared TUI widgets: engagement bar, status indicators."""

from __future__ import annotations

import logging

from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.reactive import reactive
from textual.widgets import Static

_log = logging.getLogger(__name__)


class EngagementBar(Horizontal):
    """Persistent bar showing engagement context — always visible at top."""

    DEFAULT_CSS = """
    EngagementBar {
        dock: top;
        height: 1;
        background: $panel;
        padding: 0 1;
    }
    EngagementBar .bar-label { width: auto; }
    EngagementBar .bar-sep { width: 3; color: $text-muted; }
    EngagementBar .bar-warn { color: $warning; }
    EngagementBar .bar-ok { color: $success; }
    EngagementBar .bar-error { color: $error; }
    EngagementBar.scope-mismatch { background: $error; color: $text; }
    """

    engagement_name: reactive[str] = reactive("")
    scope_info: reactive[str] = reactive("")
    window_status: reactive[str] = reactive("OK")
    run_count: reactive[int] = reactive(0)
    active_runs: reactive[int] = reactive(0)
    scope_match: reactive[bool] = reactive(True)

    def compose(self) -> ComposeResult:
        yield Static("Beachhead", id="bar-name", classes="bar-label")
        yield Static(" · ", classes="bar-sep")
        yield Static("", id="bar-engagement", classes="bar-label")
        yield Static(" · ", classes="bar-sep")
        yield Static("", id="bar-scope", classes="bar-label")
        yield Static(" · ", classes="bar-sep")
        yield Static("", id="bar-window", classes="bar-label")
        yield Static(" · ", classes="bar-sep")
        yield Static("", id="bar-runs", classes="bar-label")

    def watch_engagement_name(self, value: str) -> None:
        try:
            self.query_one("#bar-engagement", Static).update(value)
        except Exception:  # noqa: BLE001
            _log.debug("engagement bar update failed", exc_info=True)

    def watch_scope_info(self, value: str) -> None:
        try:
            self.query_one("#bar-scope", Static).update(f"scope: {value}")
        except Exception:  # noqa: BLE001
            _log.debug("engagement bar update failed", exc_info=True)

    def watch_window_status(self, value: str) -> None:
        try:
            w = self.query_one("#bar-window", Static)
            w.update(f"window: {value}")
            w.set_class(value != "OK", "bar-warn")
        except Exception:  # noqa: BLE001
            _log.debug("engagement bar update failed", exc_info=True)

    def watch_run_count(self, value: int) -> None:
        self._update_runs()

    def watch_active_runs(self, value: int) -> None:
        self._update_runs()

    def _update_runs(self) -> None:
        try:
            label = f"runs: {self.run_count}"
            if self.active_runs > 0:
                label += f" ({self.active_runs} active)"
            self.query_one("#bar-runs", Static).update(label)
        except Exception:  # noqa: BLE001
            _log.debug("engagement bar update failed", exc_info=True)

    def watch_scope_match(self, value: bool) -> None:
        self.set_class(not value, "scope-mismatch")
        try:
            name = self.query_one("#bar-name", Static)
            if not value:
                name.update("⚠ SCOPE MISMATCH")
                name.set_class(True, "bar-error")
            else:
                name.update("Beachhead")
                name.set_class(False, "bar-error")
        except Exception:  # noqa: BLE001
            _log.debug("engagement bar update failed", exc_info=True)
