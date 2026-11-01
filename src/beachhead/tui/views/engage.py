"""Engagement setup modal for the TUI.

Mirrors the CLI interactive bootstrap (core/config.py _bootstrap_interactive)
but as a Textual ModalScreen. Collects engagement name, authorization ref,
ADO organization, PAT (with live validation), and testing window. On save,
writes the config YAML and stores the PAT in the token cache.

When a PAT is entered the primary action button shows "Test" and validates
the PAT against the ADO API. Once validated it becomes "Save". With no PAT
the button shows "Save" directly.
"""

from __future__ import annotations

import logging

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Static

_log = logging.getLogger(__name__)


class EngagementSetupScreen(ModalScreen[bool]):
    """Modal for creating a new engagement config.

    Dismisses with ``True`` if the config was saved (caller should reload),
    ``False`` if cancelled.
    """

    CSS = """
    EngagementSetupScreen {
        align: center middle;
    }
    #engage-dialog {
        width: 76;
        height: auto;
        max-height: 44;
        border: thick $accent;
        padding: 1 2;
    }
    #engage-dialog Static {
        height: auto;
    }
    #engage-dialog Input {
        margin-bottom: 1;
    }
    #pat-status {
        height: auto;
        margin-bottom: 1;
    }
    #engage-buttons {
        height: 3;
        margin-top: 1;
    }
    #engage-buttons Button {
        margin-right: 1;
    }
    #engage-status {
        height: auto;
        margin-top: 1;
    }
    """

    def __init__(self, config_path: str | None = None) -> None:
        super().__init__()
        self._config_path = config_path
        self._pat_validated = False

    def compose(self) -> ComposeResult:
        with Vertical(id="engage-dialog"):
            yield Static("[bold]New Engagement[/]")

            yield Static("Engagement name")
            yield Input(placeholder="e.g. ACME-2026-Q2", id="engage-name")

            yield Static("Authorization ref [dim](optional)[/]")
            yield Input(placeholder="SOW/RoE number", id="engage-auth-ref")

            yield Static("ADO organization name")
            yield Input(placeholder="e.g. acme-eng", id="engage-ado-org")

            yield Static("Testing window [dim](days)[/]")
            yield Input(placeholder="90", id="engage-window-days")

            yield Static("Custom search terms [dim](optional, comma-separated)[/]")
            yield Input(
                placeholder="e.g. [known-secret-value], sqladmin, api-key, prod-key",
                id="engage-search-terms",
            )

            yield Static("ADO PAT")
            yield Input(placeholder="paste PAT", password=True, id="engage-pat")
            yield Static("", id="pat-status")

            with Horizontal(id="engage-buttons"):
                yield Button(
                    "Validate",
                    id="engage-action",
                    variant="warning",
                    disabled=True,
                )
                yield Button("Cancel", id="engage-cancel")
            yield Static("", id="engage-status")

    @property
    def _fields_valid(self) -> bool:
        name = self.query_one("#engage-name", Input).value.strip()
        org = self.query_one("#engage-ado-org", Input).value.strip()
        pat = self.query_one("#engage-pat", Input).value.strip()
        return bool(name and org and pat)

    def _sync_action(self) -> None:
        btn = self.query_one("#engage-action", Button)
        if not self._pat_validated:
            btn.label = "Validate"
            btn.variant = "warning"
            btn.disabled = not self._fields_valid
        else:
            btn.label = "Save"
            btn.variant = "primary"
            btn.disabled = False

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "engage-pat":
            self._pat_validated = False
            self.query_one("#pat-status", Static).update("")
        self._sync_action()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "engage-cancel":
            self.dismiss(False)
        elif event.button.id == "engage-action":
            if not self._pat_validated:
                self.run_worker(self._validate_pat())
            else:
                self.run_worker(self._save())

    async def _validate_pat(self) -> None:
        from beachhead.core.config import _validate_ado_pat

        pat = self.query_one("#engage-pat", Input).value.strip()
        org = self.query_one("#engage-ado-org", Input).value.strip()
        status = self.query_one("#pat-status", Static)

        if not org:
            status.update("[red]Enter an ADO organization first.[/]")
            return

        btn = self.query_one("#engage-action", Button)
        btn.disabled = True
        status.update("[dim]Validating PAT…[/]")

        ok, detail = _validate_ado_pat(pat, org)
        if ok:
            self._pat_validated = True
            status.update(f"[green]PAT valid — authenticated to {org}[/]")
        else:
            self._pat_validated = False
            status.update(f"[red]Validation failed: {detail}[/]")

        self._sync_action()

    async def _save(self) -> None:
        from beachhead.core.config import _BootstrapData, _render_config, resolve_config_path

        status = self.query_one("#engage-status", Static)
        name = self.query_one("#engage-name", Input).value.strip()
        auth_ref = self.query_one("#engage-auth-ref", Input).value.strip()
        org = self.query_one("#engage-ado-org", Input).value.strip()
        pat = self.query_one("#engage-pat", Input).value.strip()

        window_raw = self.query_one("#engage-window-days", Input).value.strip()
        try:
            window_days = int(window_raw) if window_raw else 90
            if window_days < 1:
                raise ValueError
        except ValueError:
            status.update("[red]Window days must be a positive number.[/]")
            return

        terms_raw = self.query_one("#engage-search-terms", Input).value.strip()
        search_terms = [t.strip() for t in terms_raw.split(",") if t.strip()] or None

        data = _BootstrapData(
            engagement=name,
            authorization_ref=auth_ref,
            ado_organizations=[org],
            custom_search_terms=search_terms,
            window_days=window_days,
        )

        resolved = resolve_config_path(self._config_path)
        try:
            resolved.write_text(_render_config(data))
        except Exception as exc:  # noqa: BLE001
            _log.debug("failed to write config", exc_info=True)
            status.update(f"[red]Failed to write config: {exc}[/]")
            return

        if pat:
            try:
                from beachhead.core.auth.ado_pat import _store_pat_sync

                _store_pat_sync(pat)
            except Exception:  # noqa: BLE001
                _log.debug("failed to store PAT", exc_info=True)
                status.update(
                    "[green]Config saved.[/] [yellow]PAT storage failed — "
                    "set later with 'bh auth ado-pat'.[/]"
                )
                self.dismiss(True)
                return

        self.dismiss(True)
