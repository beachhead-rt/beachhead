"""Teardown modal: destroy all local engagement data.

Two-step confirmation: the operator must press Confirm, which enables the
Execute button. Execute deletes the store, secret store, engagement config,
token cache, and their WAL/SHM sidecars — the same set as ``bh engage teardown``.
"""

from __future__ import annotations

from pathlib import Path

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Static


class TeardownScreen(ModalScreen[bool]):
    """Modal engagement teardown with two-step confirmation gate.

    Dismisses with ``True`` if teardown executed (caller should exit the app),
    ``False`` if cancelled.
    """

    CSS = """
    TeardownScreen {
        align: center middle;
    }
    #td-dialog {
        width: 72;
        height: auto;
        max-height: 28;
        border: thick $error;
        padding: 1 2;
    }
    #td-dialog Static {
        height: auto;
    }
    #td-file-list {
        margin: 1 0;
        height: auto;
        max-height: 12;
    }
    #td-buttons {
        height: 3;
        margin-top: 1;
    }
    #td-buttons Button {
        margin-right: 1;
    }
    #td-status {
        margin-top: 1;
        height: auto;
    }
    """

    def __init__(
        self,
        *,
        store_path: str,
        config_path: str | None = None,
    ) -> None:
        super().__init__()
        self._store_path = store_path
        self._config_path = config_path
        self._confirmed = False

    def compose(self) -> ComposeResult:
        with Vertical(id="td-dialog"):
            yield Static("[bold]Teardown[/]")
            yield Static(
                "[yellow]This will permanently delete all local engagement data.[/]\n"
                "Files targeted for removal:"
            )
            yield Static("", id="td-file-list")
            with Horizontal(id="td-buttons"):
                yield Button("Confirm", id="td-confirm", variant="warning")
                yield Button(
                    "Execute",
                    id="td-execute",
                    variant="error",
                    disabled=True,
                )
                yield Button("Cancel", id="td-cancel")
            yield Static("", id="td-status")

    def on_mount(self) -> None:
        self._refresh_file_list()

    def _targets(self) -> list[tuple[Path, str]]:
        from beachhead.core.auth.token_cache import default_cache_path
        from beachhead.core.config import resolve_config_path
        from beachhead.core.secret_store import secret_store_path

        store = Path(self._store_path)
        secrets = Path(secret_store_path(str(store)))
        tokens = default_cache_path()
        config = Path(resolve_config_path(self._config_path))

        targets: list[tuple[Path, str]] = [
            (store, "store"),
            (secrets, "secret store"),
            (config, "engagement config"),
            (tokens, "token cache"),
        ]
        for suffix in ("-wal", "-shm"):
            for base, label in [(store, "store"), (secrets, "secret store")]:
                sidecar = base.with_name(base.name + suffix)
                targets.append((sidecar, f"{label} {suffix}"))
        return targets

    def _refresh_file_list(self) -> None:
        existing = [(p, label) for p, label in self._targets() if p.exists()]
        file_list = self.query_one("#td-file-list", Static)
        if not existing:
            file_list.update("[dim]No engagement files found.[/]")
            self.query_one("#td-confirm", Button).disabled = True
            self.query_one("#td-execute", Button).disabled = True
            return

        lines = []
        for p, label in existing:
            lines.append(f"  [red]•[/] {label}: [dim]{p}[/]")
        file_list.update("\n".join(lines))

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "td-cancel":
            self.dismiss(False)
        elif event.button.id == "td-confirm":
            self._confirmed = True
            event.button.disabled = True
            self.query_one("#td-execute", Button).disabled = False
            self.query_one("#td-status", Static).update(
                "[yellow]Teardown armed. Press Execute to delete files.[/]"
            )
        elif event.button.id == "td-execute" and self._confirmed:
            self._run_teardown()

    def _run_teardown(self) -> None:
        status = self.query_one("#td-status", Static)
        existing = [(p, label) for p, label in self._targets() if p.exists()]

        if not existing:
            status.update("[dim]Nothing to tear down.[/]")
            return

        if hasattr(self.app, "surface") and self.app.surface is not None:
            try:
                self.app.surface.store.close()
            except Exception:  # noqa: BLE001, S110
                pass

        removed: list[str] = []
        errors: list[str] = []
        for p, label in existing:
            try:
                p.unlink()
                removed.append(label)
            except Exception as exc:  # noqa: BLE001
                errors.append(f"{label}: {exc}")

        parts: list[str] = []
        if removed:
            parts.append(f"[green]Removed:[/] {', '.join(removed)}")
        if errors:
            parts.append("[red]Errors:[/]\n" + "\n".join(f"  {e}" for e in errors))
        status.update("\n".join(parts))

        self.dismiss(True)
