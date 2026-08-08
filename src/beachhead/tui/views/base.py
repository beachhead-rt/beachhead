"""TableView: a titled DataTable backed by a store-read callback.

Supports per-column formatting via ``_format_cell`` and automatic ID
truncation for columns listed in ``_id_columns``.
"""

from __future__ import annotations

from typing import Any, ClassVar

from rich.text import Text
from textual.app import ComposeResult
from textual.containers import Vertical
from textual.widgets import DataTable, Static

from beachhead.core.store import Store

_ID_TRUNC = 8


def _fmt(value: Any) -> str:
    return "" if value is None else str(value)


def _short_id(value: Any) -> str | Text:
    """Truncate long IDs (GUIDs, ARM paths) for table display."""
    s = _fmt(value)
    if not s:
        return s
    if s.startswith("/"):
        parts = s.rstrip("/").rsplit("/", 1)
        name = parts[-1] if len(parts) > 1 else s
        if len(name) > 20:
            return Text(name[:17] + "...", style="dim")
        return name
    if len(s) > 12:
        return Text(s[:_ID_TRUNC] + "...", style="dim")
    return s


_MAX_CELL_WIDTH = 50


class TableView(Vertical):
    title: str = ""
    empty_text: str = "No rows."
    columns: ClassVar[list[tuple[str, str]]] = []
    cursor_mode: str = "row"
    _id_columns: ClassVar[frozenset[str]] = frozenset()

    def __init__(self, store: Store, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._store: Store = store

    def compose(self) -> ComposeResult:
        yield Static(self.title, classes="view-title")
        yield DataTable(id="table", cursor_type=self.cursor_mode)
        yield Static("", id="empty")

    def on_mount(self) -> None:
        self.query_one("#table", DataTable).add_columns(*[h for h, _ in self.columns])
        self._columns_ready = True

    def on_show(self) -> None:
        if getattr(self, "_columns_ready", False):
            self.reload()
        self.refresh(layout=True)

    def fetch(self) -> list[Any]:
        raise NotImplementedError

    def _format_cell(self, key: str, value: Any) -> str | Text:
        if key in self._id_columns:
            return _short_id(value)
        s = _fmt(value)
        if len(s) > _MAX_CELL_WIDTH:
            return Text(s[: _MAX_CELL_WIDTH - 3] + "...", style="dim")
        return s

    def reload(self) -> None:
        table = self.query_one("#table", DataTable)
        table.clear()
        rows = self.fetch()
        empty = self.query_one("#empty", Static)
        if not rows:
            empty.update(self.empty_text)
            return
        empty.update("")
        for item in rows:
            table.add_row(
                *[self._format_cell(key, getattr(item, key)) for _, key in self.columns]
            )
