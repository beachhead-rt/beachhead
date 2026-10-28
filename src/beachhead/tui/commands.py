"""Command palette provider: Ctrl+P fuzzy search for views, actions, and filters."""

from __future__ import annotations

from typing import TYPE_CHECKING

from textual.command import DiscoveryHit, Hit, Hits, Provider

if TYPE_CHECKING:
    from beachhead.tui.app import BeachheadTUI

_VIEW_COMMANDS: list[tuple[str, str, str]] = [
    ("dashboard", "Go to Dashboard", "Overview counts and recent runs"),
    ("modules", "Go to Modules", "Module catalog, run modules"),
    ("runs", "Go to Runs", "Run history with audit drill-down"),
    ("resources", "Go to Resources", "Collected ADO resources"),
    ("paths", "Go to Attack Paths", "Derived privilege-escalation paths"),
    ("findings", "Go to Findings", "Collection results, credential exposures"),
    ("credentials", "Go to Credentials", "Discovered credentials from harvest/exploit"),
    ("audit", "Go to Audit Log", "Operator action history"),
]

_ACTION_COMMANDS: list[tuple[str, str, str]] = [
    ("refresh", "Refresh Current View", "Reload data from the store"),
]

_TIME_FILTER_VIEWS = frozenset({"modules"})

_TIME_FILTER_COMMANDS: list[tuple[str, str]] = [
    ("time_filter_24h", "Time Filter: Last 24 hours"),
    ("time_filter_7d", "Time Filter: Last 7 days"),
    ("time_filter_30d", "Time Filter: Last 30 days"),
    ("time_filter_this_month", "Time Filter: This month"),
    ("time_filter_this_year", "Time Filter: This year"),
    ("time_filter_clear", "Time Filter: All time"),
]

_FILTER_COMMANDS: dict[str, list[tuple[str, str]]] = {
    "findings": [
        ("filter_findings_clear", "Filter Findings: Clear filter"),
    ],
    "paths": [
        ("filter_paths_high_score", "Filter Attack Paths: Score >= 7"),
        ("filter_paths_clear", "Filter Attack Paths: Clear filter"),
    ],
}


class BeachheadCommandProvider(Provider):
    """Global command provider for Beachhead TUI navigation and actions."""

    @property
    def _app(self) -> BeachheadTUI:
        return self.screen.app  # type: ignore[return-value]

    async def discover(self) -> Hits:
        for view_id, label, help_text in _VIEW_COMMANDS:
            yield DiscoveryHit(label, self._make_navigate(view_id), help=help_text)
        for action_id, label, help_text in _ACTION_COMMANDS:
            yield DiscoveryHit(label, self._make_action(action_id), help=help_text)
        current = self._current_view()
        if current in _FILTER_COMMANDS:
            for action_id, label in _FILTER_COMMANDS[current]:
                yield DiscoveryHit(label, self._make_action(action_id))
        if current in _TIME_FILTER_VIEWS:
            for action_id, label in _TIME_FILTER_COMMANDS:
                yield DiscoveryHit(label, self._make_action(action_id))

    async def search(self, query: str) -> Hits:
        query_lower = query.lower()
        for view_id, label, help_text in _VIEW_COMMANDS:
            score = _fuzzy_score(query_lower, label.lower())
            if score > 0:
                yield Hit(score, label, self._make_navigate(view_id), help=help_text)
        for action_id, label, help_text in _ACTION_COMMANDS:
            score = _fuzzy_score(query_lower, label.lower())
            if score > 0:
                yield Hit(score, label, self._make_action(action_id), help=help_text)
        current = self._current_view()
        if current in _FILTER_COMMANDS:
            for action_id, label in _FILTER_COMMANDS[current]:
                score = _fuzzy_score(query_lower, label.lower())
                if score > 0:
                    yield Hit(score, label, self._make_action(action_id))
        if current in _TIME_FILTER_VIEWS:
            for action_id, label in _TIME_FILTER_COMMANDS:
                score = _fuzzy_score(query_lower, label.lower())
                if score > 0:
                    yield Hit(score, label, self._make_action(action_id))

    def _current_view(self) -> str:
        from textual.widgets import ContentSwitcher

        try:
            switcher = self._app.query_one("#main", ContentSwitcher)
            return switcher.current or ""
        except Exception:  # noqa: BLE001
            return ""

    def _make_navigate(self, view_id: str):  # noqa: ANN202
        def callback() -> None:
            self._app.action_show(view_id)

        return callback

    def _make_action(self, action_id: str):  # noqa: ANN202
        def callback() -> None:
            self._app.handle_command_action(action_id)

        return callback


def _fuzzy_score(query: str, target: str) -> float:
    if query in target:
        return 1.0
    qi = 0
    for char in target:
        if qi < len(query) and char == query[qi]:
            qi += 1
    if qi == len(query):
        return 0.5 + (len(query) / len(target)) * 0.4
    return 0.0
