"""The Beachhead TUI app shell.

Integrates: engagement bar (reactive), command palette (Ctrl+P), tab bar
navigation, content switcher of read-only views, drill-down navigation,
and module runner.

Bootstrap (load config, open store read-only, compare scope hash) runs in
on_mount so refuse (no config) and empty (no store) states render inside
the app.

API note (Textual 8.2.7): Static.renderable does not exist; the equivalent
is Static.content. All view content is set via Static.update().
"""

from __future__ import annotations

import logging
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import ClassVar

from textual.app import App, ComposeResult
from textual.binding import Binding, BindingType
from textual.containers import Horizontal, Vertical
from textual.reactive import reactive
from textual.screen import ModalScreen
from textual.widgets import Button, ContentSwitcher, Footer, Input, Select, Static, Tab, Tabs

from beachhead.core.errors import ConfigError, ConfigMissingError, StoreMissingError
from beachhead.surface import SurfaceContext, open_surface
from beachhead.tui.commands import BeachheadCommandProvider
from beachhead.tui.views import (
    AttackPathsView,
    AuditView,
    CredentialsView,
    DashboardView,
    FindingsView,
    ModulesView,
    ResourcesView,
    RunsView,
)
from beachhead.tui.widgets import EngagementBar

_log = logging.getLogger(__name__)

_VIEWS: list[tuple[str, str]] = [
    ("dashboard", "Dashboard"),
    ("modules", "Modules"),
    ("runs", "Runs"),
    ("resources", "Resources"),
    ("paths", "Paths"),
    ("findings", "Findings"),
    ("credentials", "Creds"),
    ("audit", "Audit"),
]


class PassphraseScreen(ModalScreen[str]):
    """Modal prompt for the secret store passphrase."""

    CSS = """
    PassphraseScreen {
        align: center middle;
    }
    #pp-dialog {
        width: 64;
        height: auto;
        max-height: 20;
        border: thick $accent;
        padding: 1 2;
    }
    #pp-dialog Static {
        height: auto;
    }
    #pp-buttons {
        height: 3;
        margin-top: 1;
    }
    #pp-buttons Button {
        margin-right: 1;
    }
    """

    def __init__(self, message: str = "", *, exists: bool = True) -> None:
        super().__init__()
        self._message = message
        self._exists = exists

    def compose(self) -> ComposeResult:
        with Vertical(id="pp-dialog"):
            yield Static("Secret store passphrase")
            if self._message:
                yield Static(f"[red]{self._message}[/]")
            yield Static("[dim]Set BH_SECRETS_KEY to skip this prompt.[/]")
            yield Input(placeholder="passphrase", password=True, id="pp-input")
            with Horizontal(id="pp-buttons"):
                yield Button(
                    "Unlock" if self._exists else "Set",
                    variant="primary",
                    id="pp-ok",
                    disabled=True,
                )
                yield Button("Skip", id="pp-skip")

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "pp-input":
            self.query_one("#pp-ok", Button).disabled = not event.value.strip()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "pp-ok":
            self.dismiss(self.query_one("#pp-input", Input).value)
        else:
            self.dismiss("")

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "pp-input" and event.value.strip():
            self.dismiss(event.value)


class BeachheadTUI(App[None]):
    CSS = """
    #tab-bar {
        dock: top;
        height: 3;
    }
    #main { padding: 0 1; }
    .mismatch { color: $error; }
    .view-title { text-style: bold; }
    """

    COMMANDS: ClassVar[set[type]] = {BeachheadCommandProvider}

    BINDINGS: ClassVar[list[BindingType]] = [
        ("q", "quit", "Quit"),
        Binding("r", "refresh", "Refresh", show=False),
        ("t", "toggle_tabs", "Tabs"),
        ("1", "show('dashboard')", "Dash"),
        ("2", "show('modules')", "Modules"),
        ("3", "show('runs')", "Runs"),
        ("4", "show('resources')", "Rsrc"),
        ("5", "show('paths')", "Paths"),
        ("6", "show('findings')", "Finds"),
        ("7", "show('credentials')", "Creds"),
        ("8", "show('audit')", "Audit"),
    ]

    active_runs: reactive[int] = reactive(0)
    last_run_status: reactive[str] = reactive("")

    def __init__(self, *, store_path: str, config_path: str | None = None) -> None:
        super().__init__()
        self._store_path = store_path
        self._config_path = config_path
        self.surface: SurfaceContext | None = None
        self.load_error: str | None = None
        self._passphrase: str | None = os.environ.get("BH_SECRETS_KEY")

    def compose(self) -> ComposeResult:
        yield EngagementBar(id="engagement-bar")
        yield Tabs(
            *[Tab(label, id=f"tab-{view_id}") for view_id, label in _VIEWS],
            id="tab-bar",
        )
        yield ContentSwitcher(initial="dashboard", id="main")
        yield Footer()

    async def on_mount(self) -> None:
        try:
            self.surface = open_surface(self._store_path, self._config_path)
        except ConfigMissingError:
            await self._enter_no_config()
            return
        except ConfigError as exc:
            await self._enter_state(
                "refuse", f"Config error — refusing to run.\n{exc}", mismatch=True
            )
            return
        except StoreMissingError as exc:
            await self._enter_state("empty", str(exc), mismatch=False)
            return
        except Exception as exc:  # noqa: BLE001
            await self._enter_state("refuse", f"Failed to open store — {exc}", mismatch=True)
            return

        self._populate_engagement_bar()

        if self._passphrase:
            await self._build_views()
        else:
            from beachhead.core.secret_store import secret_store_path

            ss_exists = Path(secret_store_path(self._store_path)).exists()
            self.push_screen(PassphraseScreen(exists=ss_exists), callback=self._on_passphrase)

    def _on_passphrase(self, passphrase: str) -> None:
        """Callback from PassphraseScreen — validate and build views."""
        if not passphrase:
            self._passphrase = None
            self.run_worker(self._build_views())
            return

        from beachhead.core.secret_store import open_secret_store, secret_store_path

        sec_path = secret_store_path(self._store_path)
        if Path(sec_path).exists():
            try:
                ss = open_secret_store(sec_path, passphrase)
                ss.close()
            except Exception:  # noqa: BLE001
                self.push_screen(
                    PassphraseScreen("Wrong passphrase — try again."),
                    callback=self._on_passphrase,
                )
                return

        self._passphrase = passphrase
        self.run_worker(self._build_views())

    # ------------------------------------------------------------------ #

    async def _enter_state(self, state_id: str, message: str, *, mismatch: bool) -> None:
        self.load_error = message
        ebar = self.query_one(EngagementBar)
        ebar.engagement_name = f"Beachhead — {state_id.upper()}"
        ebar.scope_match = not mismatch
        switcher = self.query_one("#main", ContentSwitcher)
        await switcher.mount(Static(message, id=state_id))
        switcher.current = state_id

    async def _enter_no_config(self) -> None:
        ebar = self.query_one(EngagementBar)
        ebar.engagement_name = "Beachhead — NO CONFIG"
        ebar.scope_match = False
        switcher = self.query_one("#main", ContentSwitcher)
        container = Vertical(
            Static(
                "No engagement config found.\n\n"
                "Create one here or run [bold]bh engage status[/] in the CLI.",
            ),
            Button(
                "Create New Engagement",
                id="create-engagement-btn",
                variant="primary",
            ),
            id="no-config",
        )
        await switcher.mount(container)
        switcher.current = "no-config"

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "create-engagement-btn":
            from beachhead.tui.views.engage import EngagementSetupScreen

            self.push_screen(
                EngagementSetupScreen(config_path=self._config_path),
                callback=self._on_engagement_created,
            )

    def _on_engagement_created(self, saved: bool | None) -> None:
        if saved:
            self.run_worker(self._reload_after_setup())

    async def _reload_after_setup(self) -> None:
        """Re-open the surface after engagement config was created and build views."""
        try:
            self.surface = open_surface(self._store_path, self._config_path)
        except Exception as exc:  # noqa: BLE001
            _log.debug("reload after setup failed", exc_info=True)
            await self._enter_state(
                "refuse", f"Config created but failed to load: {exc}", mismatch=True
            )
            return

        try:
            no_config = self.query_one("#no-config")
            await no_config.remove()
        except Exception:  # noqa: BLE001
            _log.debug("no-config container not found during reload", exc_info=True)

        self._populate_engagement_bar()

        if self._passphrase:
            await self._build_views()
        else:
            from beachhead.core.secret_store import secret_store_path

            ss_exists = Path(secret_store_path(self._store_path)).exists()  # noqa: ASYNC240
            self.push_screen(PassphraseScreen(exists=ss_exists), callback=self._on_passphrase)

    def _populate_engagement_bar(self) -> None:
        if self.surface is None:  # pragma: no cover
            return
        try:
            cfg = self.surface.config
            now = datetime.now(UTC)
            window_ok = cfg.window_start <= now <= cfg.window_end
            summary = self.surface.store.summary()

            ebar = self.query_one(EngagementBar)
            ebar.engagement_name = cfg.engagement
            ado_orgs = ", ".join(cfg.ado_organizations) if cfg.ado_organizations else "none"
            ebar.scope_info = f"ADO: {ado_orgs}"
            ebar.window_status = "OK" if window_ok else "OUTSIDE"
            ebar.run_count = summary.runs
            ebar.scope_match = self.surface.scope_match
        except Exception:  # noqa: BLE001
            _log.debug("engagement bar population failed", exc_info=True)

    async def _build_views(self) -> None:
        if self.surface is None:  # pragma: no cover
            return
        store = self.surface.store
        switcher = self.query_one("#main", ContentSwitcher)
        views = [
            DashboardView(
                self.surface,
                store_path=self._store_path,
                config_path=self._config_path,
                id="dashboard",
            ),
            ModulesView(
                store_path=self._store_path,
                config_path=self._config_path,
                id="modules",
            ),
            RunsView(self.surface.store, id="runs"),
            ResourcesView(store, id="resources"),
            AttackPathsView(store, id="paths"),
            FindingsView(store, id="findings"),
            CredentialsView(self._store_path, id="credentials"),
            AuditView(store, id="audit"),
        ]
        for v in views:
            if v.id != "dashboard":
                v.display = False
        await switcher.mount(*views)
        switcher.current = "dashboard"

    # ------------------------------------------------------------------ #

    _syncing_tab: bool = False

    def on_tabs_tab_activated(self, event: Tabs.TabActivated) -> None:
        if self._syncing_tab:
            return
        tab_id = event.tab.id or ""
        if tab_id.startswith("tab-"):
            view_id = tab_id[4:]
            self._switch_view(view_id)

    def action_show(self, view: str) -> None:
        if self.surface is None:
            return
        self._switch_view(view)
        self._syncing_tab = True
        try:
            self.query_one("#tab-bar", Tabs).active = f"tab-{view}"
        except Exception:  # noqa: BLE001
            _log.debug("tab sync failed for %s", view, exc_info=True)
        finally:
            self._syncing_tab = False

    def action_toggle_tabs(self) -> None:
        try:
            tabs = self.query_one("#tab-bar", Tabs)
            tabs.display = not tabs.display
        except Exception:  # noqa: BLE001
            _log.debug("toggle tabs failed", exc_info=True)

    def _switch_view(self, view: str) -> None:
        if self.surface is None:
            return
        switcher = self.query_one("#main", ContentSwitcher)
        try:
            node = self.query_one(f"#{view}")
        except Exception:  # noqa: BLE001
            _log.debug("view %s not found", view, exc_info=True)
            return
        if switcher.current == view and view != "modules":
            reload = getattr(node, "reload", None)
            if callable(reload):
                try:
                    reload()
                except Exception:  # noqa: BLE001
                    _log.debug("reload failed for %s", view, exc_info=True)
            return
        switcher.current = view

    async def action_refresh(self) -> None:
        if self.surface is None:
            return
        self._refresh_engagement_bar()
        switcher = self.query_one("#main", ContentSwitcher)
        current = switcher.current
        if current is None:
            return
        node = self.query_one(f"#{current}")
        reload = getattr(node, "reload", None)
        if callable(reload):
            result = reload()
            if result is not None:
                await result

    def _refresh_engagement_bar(self) -> None:
        if self.surface is None:
            return
        try:
            summary = self.surface.store.summary()
            ebar = self.query_one(EngagementBar)
            ebar.run_count = summary.runs
        except Exception:  # noqa: BLE001
            _log.debug("engagement bar refresh failed", exc_info=True)

    # ------------------------------------------------------------------ #
    # Command palette action dispatch
    # ------------------------------------------------------------------ #

    _TIME_ACTION_MAP: dict[str, str] = {
        "time_filter_24h": "24h",
        "time_filter_7d": "7d",
        "time_filter_30d": "30d",
        "time_filter_this_month": "this-month",
        "time_filter_this_year": "this-year",
        "time_filter_clear": "all",
    }

    def handle_command_action(self, action_id: str) -> None:
        if action_id == "refresh":
            self.action_refresh()
            return

        if action_id in self._TIME_ACTION_MAP:
            self._apply_time_filter(self._TIME_ACTION_MAP[action_id])
            return

        if action_id == "filter_findings_clear":
            self._apply_view_filter("findings", "")
        elif action_id == "filter_paths_high_score":
            self._set_attack_path_filter(min_score=7.0)
        elif action_id == "filter_paths_clear":
            self._set_attack_path_filter(min_score=0.0)

    def _apply_time_filter(self, value: str) -> None:
        from textual.widgets import ContentSwitcher

        try:
            switcher = self.query_one("#main", ContentSwitcher)
            current = switcher.current
            if not current:
                return
            view = self.query_one(f"#{current}")
            select = view.query_one("#time-filter", Select)
            select.value = value
        except Exception:  # noqa: BLE001
            _log.debug("time filter failed", exc_info=True)

    def _apply_view_filter(self, view_id: str, value: str) -> None:
        self.action_show(view_id)
        try:
            view = self.query_one(f"#{view_id}")
            filter_input = view.query_one("#filter", Input)
            filter_input.value = value
        except Exception:  # noqa: BLE001
            _log.debug("apply filter failed for %s", view_id, exc_info=True)

    def _set_attack_path_filter(self, *, min_score: float) -> None:
        self.action_show("paths")
        try:
            view = self.query_one("#paths", AttackPathsView)
            view.min_score_filter = min_score
            view.reload()
        except Exception:  # noqa: BLE001
            _log.debug("attack path filter failed", exc_info=True)

    # ------------------------------------------------------------------ #
    # Drill-down: views post DrillDown messages
    # ------------------------------------------------------------------ #

    def drill_to_attack_path(self, path_id: str) -> None:
        if self.surface is None:
            return
        from beachhead.tui.views.detail import AttackPathDetailScreen

        self.push_screen(AttackPathDetailScreen(self.surface.store, path_id))

    def drill_to_finding(self, finding_data: dict) -> None:
        from beachhead.tui.views.detail import FindingDetailScreen

        self.push_screen(FindingDetailScreen(finding_data))

    def on_unmount(self) -> None:
        from beachhead.tui.urls import stop_spyglass

        stop_spyglass()
