"""Runs view: a master DataTable of runs over a detail panel + that run's audit entries."""

from __future__ import annotations

from typing import Any

from textual.app import ComposeResult
from textual.containers import Vertical
from textual.widgets import DataTable, Static

from beachhead.core.store import Store
from beachhead.surface import format_duration


class RunsView(Vertical):
    def __init__(self, store: Store, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._store: Store = store

    def compose(self) -> ComposeResult:
        yield Static("Runs", classes="view-title")
        yield DataTable(id="runs-table")
        yield Static("Select a run", id="run-detail")
        yield DataTable(id="run-audit")

    def on_mount(self) -> None:
        runs_table = self.query_one("#runs-table", DataTable)
        runs_table.cursor_type = "row"
        runs_table.add_columns(
            "module", "phase", "operator", "started", "finished", "status"
        )
        self.query_one("#run-audit", DataTable).add_columns(
            "ts", "action", "target", "result"
        )
        self._columns_ready = True

    def on_show(self) -> None:
        if getattr(self, "_columns_ready", False):
            self.reload()
        self.refresh(layout=True)

    def reload(self) -> None:
        table = self.query_one("#runs-table", DataTable)
        table.clear()
        runs = self._store.runs()
        for run in runs:
            table.add_row(
                run.module,
                run.phase,
                run.operator,
                run.started_at,
                run.finished_at or "—",
                run.status,
                key=run.id,
            )

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.data_table.id != "runs-table":
            return
        run_id = event.row_key.value
        if run_id is None:
            return
        run = self._store.get_run(run_id)
        if run is None:
            return
        self.query_one("#run-detail", Static).update(
            f"{run.module}  id={run.id}  status={run.status}  duration={format_duration(run)}"
        )
        audit = self.query_one("#run-audit", DataTable)
        audit.clear()
        for entry in self._store.audit_entries(run_id=run_id):
            audit.add_row(entry.ts, entry.action, entry.target, entry.result)
