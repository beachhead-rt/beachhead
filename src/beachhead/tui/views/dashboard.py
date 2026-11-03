"""Dashboard: stats panel, recent runs, report export, search term editor.

Renders a two-column stats grid using Rich Table inside a Static widget —
avoids Textual card-layout sizing issues and gives clean, aligned output
that reads well in any terminal width.  Hotkey hints next to each stat
tell the operator how to jump to the detail view.

The Report section at the bottom provides an Export button that opens a
modal for filename, format, and optional credential inclusion with a
confirmation gate.  The Search Terms button opens an editor for the
operator's custom credential search terms (persisted to the config YAML).
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml
from rich.table import Table
from rich.text import Text
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Checkbox, DataTable, Input, Static

from beachhead import __version__
from beachhead.core.store.rows import StoreSummary
from beachhead.surface import SurfaceContext

_log = logging.getLogger(__name__)

_LEFT_STATS: list[tuple[str, str, str]] = [
    ("Resources", "resources", "4"),
    ("Findings", "findings", "6"),
]

_RIGHT_STATS: list[tuple[str, str, str, str]] = [
    ("", "Attack Paths", "attack_paths", "5"),
    ("OPS", "", "", ""),
    ("", "Runs", "runs", "3"),
]


def _val_style(count: int) -> str:
    return "bold green" if count > 0 else "dim"


def _build_stats(summary: StoreSummary) -> Table:
    grid = Table(
        show_header=False,
        show_edge=False,
        pad_edge=False,
        box=None,
        expand=True,
        padding=(0, 1),
    )
    grid.add_column("lbl_l", min_width=22, no_wrap=True)
    grid.add_column("val_l", min_width=5, justify="right", no_wrap=True)
    grid.add_column("key_l", min_width=4, no_wrap=True)
    grid.add_column("sep", width=3)
    grid.add_column("lbl_r", min_width=18, no_wrap=True)
    grid.add_column("val_r", min_width=5, justify="right", no_wrap=True)
    grid.add_column("key_r", min_width=4, no_wrap=True)

    grid.add_row(
        Text("DATA", style="bold underline"),
        "",
        "",
        "",
        Text("ANALYSIS", style="bold underline"),
        "",
        "",
    )

    left_rows: list[tuple[Text, Text, Text]] = []
    for label, field, key in _LEFT_STATS:
        count = getattr(summary, field, 0)
        style = _val_style(count)
        left_rows.append(
            (
                Text(f"  {label}", style="white" if count > 0 else "dim"),
                Text(str(count), style=style),
                Text(f" [{key}]", style="dim italic") if key else Text(""),
            )
        )

    right_rows: list[tuple[Text, Text, Text]] = []
    for header, label, field, key in _RIGHT_STATS:
        if header:
            right_rows.append(
                (
                    Text(header, style="bold underline"),
                    Text(""),
                    Text(""),
                )
            )
            continue
        if not label:
            right_rows.append((Text(""), Text(""), Text("")))
            continue
        count = getattr(summary, field, 0)
        style = _val_style(count)
        right_rows.append(
            (
                Text(f"  {label}", style="white" if count > 0 else "dim"),
                Text(str(count), style=style),
                Text(f" [{key}]", style="dim italic") if key else Text(""),
            )
        )

    max_rows = max(len(left_rows), len(right_rows))
    for i in range(max_rows):
        if i < len(left_rows):
            l_lbl, l_val, l_key = left_rows[i]
        else:
            l_lbl, l_val, l_key = Text(""), Text(""), Text("")

        if i < len(right_rows):
            r_lbl, r_val, r_key = right_rows[i]
        else:
            r_lbl, r_val, r_key = Text(""), Text(""), Text("")

        grid.add_row(l_lbl, l_val, l_key, Text(""), r_lbl, r_val, r_key)

    return grid


class ExportScreen(ModalScreen[dict[str, Any] | None]):
    """Modal for engagement report export options."""

    CSS = """
    ExportScreen {
        align: center middle;
    }
    #export-dialog {
        width: 64;
        height: auto;
        max-height: 24;
        border: thick $accent;
        padding: 1 2;
    }
    #export-dialog Static {
        height: auto;
    }
    #export-buttons {
        height: 3;
        margin-top: 1;
    }
    #export-buttons Button {
        margin-right: 1;
    }
    #export-confirm-row {
        height: 3;
        margin-top: 1;
    }
    #export-confirm-row Button {
        margin-right: 1;
    }
    #export-status {
        height: auto;
        margin-top: 1;
    }
    """

    def __init__(self) -> None:
        super().__init__()
        self._confirmed = False

    def compose(self) -> ComposeResult:
        with Vertical(id="export-dialog"):
            yield Static("[bold]Export engagement report[/]")
            yield Static("Filename [dim](.json or .md)[/]")
            yield Input(
                placeholder="report.json",
                id="export-filename",
            )
            yield Checkbox(
                "Include plaintext credentials",
                id="export-secrets",
            )
            with Horizontal(id="export-buttons"):
                yield Button(
                    "Confirm",
                    id="export-confirm",
                    variant="warning",
                    disabled=True,
                )
                yield Button(
                    "Export",
                    id="export-run",
                    variant="primary",
                    disabled=True,
                )
                yield Button("Cancel", id="export-cancel")
            yield Static("", id="export-status")

    def on_mount(self) -> None:
        self.query_one("#export-confirm", Button).display = False

    @property
    def _has_valid_filename(self) -> bool:
        name = self.query_one("#export-filename", Input).value.strip()
        return name.endswith(".json") or name.endswith(".md")

    @property
    def _needs_confirm(self) -> bool:
        return self.query_one("#export-secrets", Checkbox).value

    def _sync_buttons(self) -> None:
        valid = self._has_valid_filename
        needs_confirm = self._needs_confirm
        confirm_btn = self.query_one("#export-confirm", Button)
        export_btn = self.query_one("#export-run", Button)

        confirm_btn.display = needs_confirm
        if needs_confirm:
            confirm_btn.disabled = not valid or self._confirmed
            export_btn.disabled = not valid or not self._confirmed
        else:
            self._confirmed = False
            export_btn.disabled = not valid

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id != "export-filename":
            return
        self._confirmed = False
        self._sync_buttons()
        self.query_one("#export-status", Static).update("")

    def on_checkbox_changed(self, event: Checkbox.Changed) -> None:
        if event.checkbox.id != "export-secrets":
            return
        self._confirmed = False
        self._sync_buttons()
        self.query_one("#export-status", Static).update("")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "export-cancel":
            self.dismiss(None)
        elif event.button.id == "export-confirm":
            self._confirmed = True
            self._sync_buttons()
            self.query_one("#export-status", Static).update(
                "[yellow]Ready to export. Press Export to write the file.[/]"
            )
        elif event.button.id == "export-run":
            filename = self.query_one("#export-filename", Input).value.strip()
            include_secrets = self.query_one("#export-secrets", Checkbox).value
            self.dismiss({"filename": filename, "include_secrets": include_secrets})


class SearchTermsScreen(ModalScreen[list[str] | None]):
    """Modal for editing custom credential search terms."""

    CSS = """
    SearchTermsScreen {
        align: center middle;
    }
    #terms-dialog {
        width: 72;
        height: auto;
        max-height: 24;
        border: thick $accent;
        padding: 1 2;
    }
    #terms-dialog Static {
        height: auto;
    }
    #terms-buttons {
        height: 3;
        margin-top: 1;
    }
    #terms-buttons Button {
        margin-right: 1;
    }
    #terms-status {
        height: auto;
        margin-top: 1;
    }
    """

    def __init__(self, current_terms: tuple[str, ...] = ()) -> None:
        super().__init__()
        self._current = current_terms

    def compose(self) -> ComposeResult:
        with Vertical(id="terms-dialog"):
            yield Static("[bold]Custom Search Terms[/]")
            yield Static(
                "[dim]Comma-separated terms fed to the cred-engine. "
                "Matches compound names (e.g. 'PROD' catches PROD_API_KEY).[/]"
            )
            yield Input(
                value=", ".join(self._current),
                placeholder="e.g. [known-secret-value], sqladmin, api-key, prod-key",
                id="terms-input",
            )
            with Horizontal(id="terms-buttons"):
                yield Button("Save", id="terms-save", variant="primary")
                yield Button("Cancel", id="terms-cancel")
            yield Static("", id="terms-status")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "terms-cancel":
            self.dismiss(None)
        elif event.button.id == "terms-save":
            raw = self.query_one("#terms-input", Input).value
            terms = [t.strip() for t in raw.split(",") if t.strip()]
            self.dismiss(terms)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "terms-input":
            raw = event.value
            terms = [t.strip() for t in raw.split(",") if t.strip()]
            self.dismiss(terms)


class DashboardView(Vertical):
    DEFAULT_CSS = """
    DashboardView {
        padding: 1 2;
    }
    #dash-header {
        height: 1;
        margin-bottom: 1;
    }
    #stats-panel {
        height: auto;
    }
    #recent-label {
        margin-top: 1;
    }
    #actions-row {
        margin-top: 1;
        height: auto;
    }
    #report-section {
        width: 1fr;
    }
    #config-section {
        width: 1fr;
    }
    #teardown-section {
        width: auto;
        align: right top;
    }
    #export-result {
        height: auto;
        margin-top: 1;
    }
    """

    def __init__(
        self,
        surface: SurfaceContext,
        *,
        store_path: str,
        config_path: str | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self._surface: SurfaceContext = surface
        self._store_path = store_path
        self._config_path = config_path
        self._custom_terms: tuple[str, ...] = tuple(
            getattr(surface.config, "custom_search_terms", ()) or ()
        )

    def compose(self) -> ComposeResult:
        yield Static(
            Text.from_markup(
                f"[bold red]BEACHHEAD[/]  [dim]v{__version__}  ·  "
                "Azure DevOps post-exploitation framework[/]"
            ),
            id="dash-header",
        )
        yield Static("", id="stats-panel")
        yield Static("Recent runs", id="recent-label", classes="view-title")
        yield DataTable(id="recent", cursor_type="row")
        with Horizontal(id="actions-row"):
            with Vertical(id="report-section"):
                yield Static("Report", classes="view-title")
                yield Button("Export", id="export-btn", variant="primary", disabled=True)
            with Vertical(id="config-section"):
                yield Static("Config", classes="view-title")
                yield Button("Search Terms", id="search-terms-btn", variant="default")
            with Vertical(id="teardown-section"):
                yield Static("Teardown", classes="view-title")
                yield Button("Start", id="teardown-btn", variant="error")
        yield Static("", id="export-result")

    def on_mount(self) -> None:
        self.query_one("#recent", DataTable).add_columns(
            "module", "phase", "status", "started"
        )
        self._columns_ready = True

    def on_show(self) -> None:
        if getattr(self, "_columns_ready", False):
            self.reload()
        self.refresh(layout=True)

    def reload(self) -> None:
        store = self._surface.store
        summary = store.summary()

        self.query_one("#stats-panel", Static).update(_build_stats(summary))
        self.query_one("#export-btn", Button).disabled = summary.runs == 0

        btn = self.query_one("#search-terms-btn", Button)
        btn.label = f"Search Terms ({len(self._custom_terms)})" if self._custom_terms else "Search Terms"

        table = self.query_one("#recent", DataTable)
        table.clear()
        for run in store.runs()[:10]:
            table.add_row(run.module, run.phase, run.status, run.started_at)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "export-btn":
            self.app.push_screen(ExportScreen(), callback=self._on_export_result)
        elif event.button.id == "search-terms-btn":
            self.app.push_screen(
                SearchTermsScreen(current_terms=self._custom_terms),
                callback=self._on_search_terms_result,
            )
        elif event.button.id == "teardown-btn":
            from beachhead.tui.views.teardown import TeardownScreen

            self.app.push_screen(
                TeardownScreen(
                    store_path=self._store_path,
                    config_path=self._config_path,
                ),
                callback=self._on_teardown_result,
            )

    def _on_search_terms_result(self, terms: list[str] | None) -> None:
        if terms is None:
            return
        self.run_worker(self._save_search_terms(terms))

    async def _save_search_terms(self, terms: list[str]) -> None:
        from beachhead.core.config import resolve_config_path

        status = self.query_one("#export-result", Static)
        resolved = resolve_config_path(self._config_path)
        try:
            raw = yaml.safe_load(resolved.read_text()) or {}
            raw["custom_search_terms"] = terms
            header = ""
            text = resolved.read_text()
            for line in text.splitlines(keepends=True):
                if line.startswith("#"):
                    header += line
                else:
                    break
            resolved.write_text(
                header + yaml.dump(raw, default_flow_style=False, sort_keys=False)
            )
            self._custom_terms = tuple(terms)
            btn = self.query_one("#search-terms-btn", Button)
            btn.label = f"Search Terms ({len(terms)})" if terms else "Search Terms"
            count = len(terms)
            if count:
                status.update(f"[green]Saved {count} custom search term(s).[/]")
            else:
                status.update("[green]Custom search terms cleared.[/]")
        except Exception as exc:  # noqa: BLE001
            _log.debug("failed to save search terms", exc_info=True)
            status.update(f"[red]Failed to save search terms: {exc}[/]")

    def _on_teardown_result(self, executed: bool | None) -> None:
        if executed:
            self.app.exit()

    def _on_export_result(self, result: dict[str, Any] | None) -> None:
        if result is None:
            return
        self.run_worker(self._do_export(result))

    async def _do_export(self, opts: dict[str, Any]) -> None:
        from beachhead.core.export import (
            build_report,
            export_json,
            export_markdown,
        )
        from beachhead.core.secret_store import open_secret_store, secret_store_path

        status = self.query_one("#export-result", Static)
        filename: str = opts["filename"]
        include_secrets: bool = opts["include_secrets"]
        store = self._surface.store

        secret_store = None
        if include_secrets:
            passphrase = getattr(self.app, "_passphrase", None)
            if passphrase:
                try:
                    sec_path = secret_store_path(self._store_path)
                    if Path(sec_path).exists():  # noqa: ASYNC240
                        secret_store = open_secret_store(sec_path, passphrase)
                except Exception:  # noqa: BLE001
                    _log.debug("failed to open secret store for export", exc_info=True)

        try:
            report = build_report(
                store,
                secret_store=secret_store,
                include_secrets=include_secrets,
            )
            path = Path(filename)
            if filename.endswith(".md"):
                export_markdown(report, path)
            else:
                export_json(report, path)
            status.update(f"[green]Exported to {path.resolve()}[/]")  # noqa: ASYNC240
        except Exception as exc:  # noqa: BLE001
            _log.debug("export failed", exc_info=True)
            status.update(f"[red]Export failed: {exc}[/]")
        finally:
            if secret_store is not None:
                try:
                    secret_store.close()
                except Exception:  # noqa: BLE001, S110
                    pass
