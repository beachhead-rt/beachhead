"""Table-backed views with drill-down, ID truncation, and severity coloring.

Each view uses cursor_type="row" (inherited from TableView) and wires
DataTable.RowSelected events for drill-down navigation via app.drill_to_*().
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import BindingType
from textual.containers import Vertical
from textual.widgets import DataTable, Input, Select, Static

from beachhead.tui.views.base import TableView, _fmt

if TYPE_CHECKING:
    from beachhead.core.store import Store


def _get_surface_org(widget: Static) -> str:
    """Extract org from the TUI's surface context."""
    try:
        surface = widget.app.surface  # type: ignore[attr-defined]
        if surface:
            orgs = surface.config.ado_organizations
            return next(iter(orgs)) if orgs else ""
    except Exception:  # noqa: BLE001, S110
        pass
    return ""


def _open_in_spyglass(url: str, status_widget: Static, project: str = "") -> None:
    """Ensure SpyGlass is running with auth, then open a deep-link URL."""
    from beachhead.tui.urls import open_in_spyglass

    org = _get_surface_org(status_widget)
    ok, msg = open_in_spyglass(url, org=org, project=project)
    if ok:
        status_widget.update(f"[green]Opened:[/] {msg}")
    else:
        status_widget.update(f"[yellow]{msg}[/]")

# ---------------------------------------------------------------------------
# Severity / score coloring helpers
# ---------------------------------------------------------------------------

_SEVERITY_STYLES: dict[str, str] = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "dim",
    "info": "dim",
}


def _severity_text(value: Any) -> Text:
    s = _fmt(value).lower()
    style = _SEVERITY_STYLES.get(s, "")
    return Text(_fmt(value), style=style)


def _score_text(value: Any) -> Text:
    s = _fmt(value)
    try:
        score = float(s)
    except (ValueError, TypeError):
        return Text(s)
    if score >= 7.0:
        return Text(s, style="bold red")
    if score >= 4.0:
        return Text(s, style="yellow")
    return Text(s, style="dim")


# ---------------------------------------------------------------------------
# Views
# ---------------------------------------------------------------------------


class AttackPathsView(TableView):
    title = "Attack paths"
    empty_text = (
        "[dim]No attack paths derived.[/]\n"
        "1. Run [bold]enumerate[/] modules to collect ADO resources\n"
        "2. Run [bold]analyze.ado_attack_paths[/] to derive paths from the collected data"
    )
    columns: ClassVar[list[tuple[str, str]]] = [
        ("score", "score"),
        ("source", "source_id"),
        ("target", "target_id"),
        ("techniques", "technique_str"),
        ("description", "description"),
    ]
    _id_columns: ClassVar[frozenset[str]] = frozenset({"source_id", "target_id"})

    BINDINGS: ClassVar[list[BindingType]] = [
        ("o", "open_url", "Open in SpyGlass"),
    ]

    min_score_filter: float = 0.0
    _path_rows: list[_PathRow]

    def compose(self) -> ComposeResult:
        yield Static(self.title, classes="view-title")
        yield Input(placeholder="filter source/target/technique/description...", id="path-filter")
        yield DataTable(id="table", cursor_type="row")
        yield Static("", id="status-bar")
        yield Static("", id="empty")

    def _format_cell(self, key: str, value: Any) -> str | Text:
        if key == "score":
            return _score_text(value)
        if key == "description":
            return _fmt(value)
        return super()._format_cell(key, value)

    def fetch(self) -> list[Any]:
        paths = self._store.attack_paths()
        if self.min_score_filter > 0:
            paths = [p for p in paths if p.score >= self.min_score_filter]
        needle = self.query_one("#path-filter", Input).value.strip().lower()
        if needle:
            paths = [
                p for p in paths
                if needle in p.source_id.lower()
                or needle in p.target_id.lower()
                or needle in p.description.lower()
                or any(needle in t.lower() for t in p.technique_ids)
            ]
        self._path_rows = [_PathRow(p) for p in paths]
        return self._path_rows

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "path-filter":
            self.reload()

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if not hasattr(self, "_path_rows") or not self._path_rows:
            return
        row = event.cursor_row
        if 0 <= row < len(self._path_rows):
            self.app.drill_to_attack_path(self._path_rows[row].path_id)  # type: ignore[attr-defined]

    def _resource_name(self, resource_id: str) -> str:
        for r in self._store.resources():
            if r.resource_id == resource_id:
                return r.name or ""
        return ""

    def action_open_url(self) -> None:
        from beachhead.tui.urls import extract_project, spyglass_resource_url

        status = self.query_one("#status-bar", Static)
        if not hasattr(self, "_path_rows") or not self._path_rows:
            status.update("[yellow]No attack paths to open.[/]")
            return
        table = self.query_one("#table", DataTable)
        cursor = table.cursor_row
        if cursor < 0 or cursor >= len(self._path_rows):
            return
        row = self._path_rows[cursor]
        rid = row.source_id
        url = spyglass_resource_url(
            rid, name=self._resource_name(rid),
        )
        if not url:
            rid = row.target_id
            url = spyglass_resource_url(
                rid, name=self._resource_name(rid),
            )
        if not url:
            status.update("[yellow]No SpyGlass URL available for this path.[/]")
            return
        _open_in_spyglass(url, status, project=extract_project(rid))


class _PathRow:
    """Adapter that formats attack path fields for the table view."""

    def __init__(self, path: Any) -> None:
        self.path_id = path.id
        self.score = f"{path.score:.1f}"
        self.source_id = path.source_id
        self.target_id = path.target_id
        self.technique_str = ", ".join(path.technique_ids)
        self.description = path.description


_RES_SKIP_PROPS = frozenset({"org", "flags", "install_state", "last_updated"})
_RES_NAME_PROPS = frozenset({"name", "resource_id", "extension_name", "extension_id"})


def _resource_props_keys(resources: list[Any]) -> list[str]:
    """Pick properties_summary keys common to the visible resource set."""
    if not resources:
        return []
    counts: dict[str, int] = {}
    for r in resources:
        for key in r.properties_summary or {}:
            if key not in _RES_SKIP_PROPS and key not in _RES_NAME_PROPS:
                counts[key] = counts.get(key, 0) + 1
    threshold = len(resources) * 0.5
    return [k for k, c in sorted(counts.items(), key=lambda x: -x[1]) if c >= threshold][:5]


_ALL_TYPES = "__all__"


class ResourcesView(TableView):
    title = "Resources"
    empty_text = "[dim]No resources recorded.[/]\nRun an [bold]enumerate[/] module to populate."
    columns: ClassVar[list[tuple[str, str]]] = []

    BINDINGS: ClassVar[list[BindingType]] = [
        ("o", "open_url", "Open in SpyGlass"),
    ]

    _resources: list[Any]

    def __init__(self, store: Store, **kwargs: Any) -> None:
        super().__init__(store, **kwargs)
        self._known_types: frozenset[str] = frozenset()
        self._resources = []

    def compose(self) -> ComposeResult:
        yield Static(self.title, classes="view-title")
        yield Select[str](
            [("All types", _ALL_TYPES)],
            value=_ALL_TYPES,
            allow_blank=False,
            id="res-type-select",
        )
        yield Input(placeholder="filter by name...", id="res-filter")
        yield DataTable(id="table", cursor_type="row")
        yield Static("", id="status-bar")
        yield Static("", id="empty")

    def on_mount(self) -> None:
        self._refresh_type_options()
        self.reload()

    def _refresh_type_options(self) -> None:
        all_resources = self._store.resources()
        types = frozenset(r.type for r in all_resources if r.type)
        if types == self._known_types:
            return
        self._known_types = types
        select = self.query_one("#res-type-select", Select)
        current = select.value
        options: list[tuple[str, str]] = [("All types", _ALL_TYPES)]
        for t in sorted(types):
            options.append((t, t))
        select.set_options(options)
        if current in types or current == _ALL_TYPES:
            select.value = current
        else:
            select.value = _ALL_TYPES

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "res-type-select":
            self.reload()

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "res-filter":
            self.reload()

    def fetch(self) -> list[Any]:
        resources = self._store.resources()
        selected_type = self.query_one("#res-type-select", Select).value
        if selected_type != _ALL_TYPES and selected_type != Select.BLANK:
            resources = [r for r in resources if r.type == selected_type]
        needle = self.query_one("#res-filter", Input).value.strip().lower()
        if needle:
            resources = [r for r in resources if needle in (r.name or "").lower()]
        return resources

    def reload(self) -> None:
        self._refresh_type_options()
        table = self.query_one("#table", DataTable)
        table.clear(columns=True)

        resources = self.fetch()
        self._resources = resources
        empty = self.query_one("#empty", Static)
        if not resources:
            empty.update(self.empty_text)
            return
        empty.update("")

        types = {r.type for r in resources}
        show_type = len(types) > 1
        prop_keys = _resource_props_keys(resources)

        if show_type:
            table.add_column("type")
        table.add_column("name")
        for k in prop_keys:
            table.add_column(k)

        for r in resources:
            cells: list[str | Text] = []
            if show_type:
                cells.append(_fmt(r.type))
            cells.append(_fmt(r.name))
            props = r.properties_summary or {}
            for key in prop_keys:
                val = props.get(key, "")
                if isinstance(val, list):
                    val = ", ".join(str(v) for v in val)
                s = str(val) if val else ""
                if len(s) > 50:
                    cells.append(Text(s[:47] + "...", style="dim"))
                else:
                    cells.append(s)
            table.add_row(*cells)

    def action_open_url(self) -> None:
        from beachhead.tui.urls import extract_project, spyglass_resource_url

        table = self.query_one("#table", DataTable)
        status = self.query_one("#status-bar", Static)
        if not self._resources:
            status.update("[yellow]No resources to open.[/]")
            return
        cursor = table.cursor_row
        if cursor < 0 or cursor >= len(self._resources):
            return
        r = self._resources[cursor]
        url = spyglass_resource_url(r.resource_id, name=r.name or "")
        if not url:
            status.update("[yellow]No SpyGlass URL available for this resource.[/]")
            return
        _open_in_spyglass(url, status, project=extract_project(r.resource_id))


class FindingsView(TableView):
    title = "Findings"
    empty_text = (
        "[dim]No findings recorded.[/]\nRun a [bold]collect[/] or [bold]enumerate[/] module first."
    )
    columns: ClassVar[list[tuple[str, str]]] = [
        ("kind", "kind"),
        ("reference", "reference"),
        ("source", "source_label"),
        ("file", "file_label"),
    ]

    BINDINGS: ClassVar[list[BindingType]] = [
        ("o", "open_url", "Open in SpyGlass"),
    ]

    _finding_rows: list[_FindingRow]

    def compose(self) -> ComposeResult:
        yield Static(self.title, classes="view-title")
        yield Input(placeholder="filter kind/reference...", id="filter")
        yield DataTable(id="table", cursor_type="row")
        yield Static("", id="status-bar")
        yield Static("", id="empty")

    def fetch(self) -> list[Any]:
        rows = self._store.findings()
        needle = self.query_one("#filter", Input).value.strip().lower()
        if needle:
            rows = [f for f in rows if needle in f.kind.lower() or needle in f.reference.lower()]
        self._finding_rows = [_FindingRow(f) for f in rows]
        return self._finding_rows

    def on_input_changed(self, event: Input.Changed) -> None:
        self.reload()

    def action_open_url(self) -> None:
        from beachhead.tui.urls import extract_project

        table = self.query_one("#table", DataTable)
        status = self.query_one("#status-bar", Static)
        if not hasattr(self, "_finding_rows") or not self._finding_rows:
            status.update("[yellow]No findings to open.[/]")
            return
        cursor = table.cursor_row
        if cursor < 0 or cursor >= len(self._finding_rows):
            return
        row = self._finding_rows[cursor]
        url = row.spyglass_url
        if not url:
            status.update("[yellow]No SpyGlass URL available for this finding.[/]")
            return
        project = row._details.get("project", "") or extract_project(row.resource_id)
        _open_in_spyglass(url, status, project=project)

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if not hasattr(self, "_finding_rows") or not self._finding_rows:
            return
        row = event.cursor_row
        if row < 0 or row >= len(self._finding_rows):
            return
        fr = self._finding_rows[row]
        self.app.drill_to_finding(
            {  # type: ignore[attr-defined]
                "kind": fr.kind,
                "reference": fr.reference,
                "resource_id": getattr(fr, "resource_id", ""),
                "details": fr._details,
                "spyglass_url": fr.spyglass_url,
            }
        )


_SOURCE_NAME_KEYS = (
    "repo_name",
    "group_name",
    "pipeline_name",
    "endpoint_name",
    "pool_name",
    "feed_name",
    "extension_name",
    "app_name",
    "wiki_name",
    "build_number",
    "work_item_label",
)


class _FindingRow:
    """Adapter that enriches a Finding with source label."""

    def __init__(self, finding: Any) -> None:
        from beachhead.tui.urls import spyglass_finding_url

        self.kind = finding.kind
        self.reference = finding.reference
        self.resource_id = getattr(finding, "resource_id", "")

        details = finding.details or {}
        self._details = details
        self.spyglass_url = spyglass_finding_url(details, self.resource_id)

        org = details.get("org", "")
        project = details.get("project", "")
        name = ""
        for key in _SOURCE_NAME_KEYS:
            name = details.get(key, "")
            if name:
                break
        if org and project and name:
            self.source_label = f"{org}/{project}/{name}"
        elif org and name:
            self.source_label = f"{org}/{name}"
        elif project and name:
            self.source_label = f"{project}/{name}"
        elif name:
            self.source_label = name
        else:
            self.source_label = ""

        self.file_label = details.get("file_path", "") or details.get("variable_name", "")


_CRED_SOURCE_KEYS = (
    "repo_name", "pipeline_name", "group_name", "wiki_name",
)


def _cred_source_label(details: dict[str, Any]) -> str:
    """Build a human-readable source label from credential details."""
    org = details.get("org", "")
    project = details.get("project", "")
    name = ""
    for key in _CRED_SOURCE_KEYS:
        name = str(details.get(key, ""))
        if name:
            break
    if not name:
        pid = details.get("pipeline_id", "")
        if pid:
            name = f"pipeline/{pid}"
    parts = [p for p in (org, project, name) if p]
    return "/".join(parts)


class CredentialsView(Vertical):
    """Discovered credentials from the secure credential store."""

    title = "Credentials"

    BINDINGS: ClassVar[list[BindingType]] = [
        ("o", "open_url", "Open in SpyGlass"),
    ]

    _creds: list[Any]

    def __init__(self, store_path: str, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._store_path = store_path
        self._creds = []
        self._all_creds: list[Any] | None = None

    def _open_secrets(self) -> Any:
        from pathlib import Path

        from beachhead.core.secret_store import open_secret_store, secret_store_path

        sec_path = secret_store_path(self._store_path)
        if not Path(sec_path).exists():
            return None
        passphrase = getattr(self.app, "_passphrase", None)
        if not passphrase:
            return None
        try:
            return open_secret_store(sec_path, passphrase)
        except Exception:  # noqa: BLE001
            return None

    def compose(self) -> ComposeResult:
        yield Static(self.title, classes="view-title")
        yield Input(placeholder="filter kind/reference...", id="cred-filter")
        yield DataTable(id="cred-table", cursor_type="row")
        yield Static("", id="cred-status")
        yield Static("", id="empty")

    def on_mount(self) -> None:
        table = self.query_one("#cred-table", DataTable)
        table.add_columns("Kind", "Type", "Value", "Reference", "Source")
        self.reload()

    def on_show(self) -> None:
        self.invalidate_cache()
        self.reload()
        self.refresh(layout=True)

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "cred-filter":
            self.reload()

    def _load_creds(self) -> list[Any] | None:
        if self._all_creds is not None:
            return self._all_creds
        secrets = self._open_secrets()
        if secrets is None:
            return None
        try:
            self._all_creds = secrets.list_credentials()
        finally:
            secrets.close()
        return self._all_creds

    def invalidate_cache(self) -> None:
        self._all_creds = None

    def reload(self) -> None:
        table = self.query_one("#cred-table", DataTable)
        table.clear()
        empty = self.query_one("#empty", Static)

        creds = self._load_creds()
        if creds is None:
            self._creds = []
            empty.update(
                "[dim]No credential store found.[/]\n"
                "Run a [bold]harvest[/] or [bold]exploit[/] module to populate."
            )
            return

        needle = self.query_one("#cred-filter", Input).value.strip().lower()
        if needle:
            creds = [
                c for c in creds
                if needle in c.kind.lower()
                or needle in c.reference.lower()
            ]

        if not creds:
            self._creds = []
            empty.update(
                "[dim]No credentials discovered yet.[/]\n"
                "Run a [bold]harvest[/] or [bold]exploit[/] module to populate."
            )
            return
        empty.update("")
        self._creds = creds

        for cred in creds:
            details = cred.details or {}
            cred_type = str(details.get("credential_type", ""))
            source = _cred_source_label(details)
            val = cred.value
            if len(val) > 50:
                val = val[:47] + "..."
            table.add_row(cred.kind, cred_type, val, cred.reference, source)

    def action_open_url(self) -> None:
        from beachhead.tui.urls import spyglass_credential_url

        status = self.query_one("#cred-status", Static)
        if not self._creds:
            status.update("[yellow]No credentials to open.[/]")
            return
        table = self.query_one("#cred-table", DataTable)
        cursor = table.cursor_row
        if cursor < 0 or cursor >= len(self._creds):
            return
        cred = self._creds[cursor]
        details = cred.details or {}
        url = spyglass_credential_url(details)
        if not url:
            status.update("[yellow]No SpyGlass URL available for this credential.[/]")
            return
        _open_in_spyglass(url, status, project=details.get("project", ""))


class AuditView(TableView):
    title = "Audit log"
    empty_text = "[dim]No audit entries. Entries are created when modules run.[/]"
    columns: ClassVar[list[tuple[str, str]]] = [
        ("ts", "ts"),
        ("operator", "operator"),
        ("action", "action"),
        ("target", "target"),
        ("result", "result"),
    ]

    def fetch(self) -> list[Any]:
        return self._store.audit_entries()
