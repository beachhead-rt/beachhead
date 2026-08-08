"""Detail screens pushed on drill-down from table views."""

from __future__ import annotations

from typing import Any

from textual.app import ComposeResult
from textual.binding import BindingType
from textual.containers import VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import DataTable, Static

from beachhead.core.store import Store


class AttackPathDetailScreen(ModalScreen[None]):
    """Shows attack path edge details, related entities, and next steps."""

    DEFAULT_CSS = """
    AttackPathDetailScreen {
        align: center middle;
    }
    #path-detail-container {
        width: 90%;
        height: 85%;
        background: $surface;
        border: thick $primary;
        padding: 1 2;
    }
    .detail-heading {
        text-style: bold;
        margin-top: 1;
        color: $accent;
    }
    .next-step {
        margin: 0 0 0 2;
    }
    """

    BINDINGS: list[BindingType] = [
        ("escape", "dismiss", "Close"),
        ("o", "open_url", "Open in SpyGlass"),
    ]

    def __init__(self, store: Store, path_id: str, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._store = store
        self._path_id = path_id
        self._source_id = ""
        self._target_id = ""

    def compose(self) -> ComposeResult:
        with VerticalScroll(id="path-detail-container"):
            yield Static("", id="path-header")
            yield Static("Edges", classes="detail-heading")
            yield DataTable(id="path-edges", cursor_type="row")
            yield Static("Next Steps", classes="detail-heading")
            yield Static("", id="path-next-steps")
            yield Static("", id="path-status")

    def _get_org(self) -> str:
        try:
            surface = self.app.surface  # type: ignore[attr-defined]
            if surface:
                orgs = surface.config.ado_organizations
                return next(iter(orgs)) if orgs else ""
        except Exception:  # noqa: BLE001, S110
            pass
        return ""

    def _resource_name(self, resource_id: str) -> str:
        for r in self._store.resources():
            if r.resource_id == resource_id:
                return r.name or ""
        return ""

    def action_open_url(self) -> None:
        from beachhead.tui.urls import extract_project, open_in_spyglass, spyglass_resource_url

        status = self.query_one("#path-status", Static)
        rid = self._source_id
        url = spyglass_resource_url(rid, name=self._resource_name(rid))
        if not url:
            rid = self._target_id
            url = spyglass_resource_url(rid, name=self._resource_name(rid))
        if not url:
            status.update("[yellow]No SpyGlass URL available for this path.[/]")
            return
        ok, msg = open_in_spyglass(url, org=self._get_org(), project=extract_project(rid))
        if ok:
            status.update(f"[green]Opened:[/] {msg}")
        else:
            status.update(f"[yellow]{msg}[/]")

    def on_mount(self) -> None:
        paths = self._store.attack_paths()
        header = self.query_one("#path-header", Static)
        path = next((p for p in paths if p.id == self._path_id), None)
        if path is None:
            header.update("[bold]Attack path not found[/]")
            return
        self._source_id = path.source_id
        self._target_id = path.target_id
        header.update(
            f"[bold]Attack Path — score {path.score:.1f}[/]\n"
            f"  source: {path.source_id}\n"
            f"  target: {path.target_id}\n"
            f"  techniques: {', '.join(path.technique_ids)}\n"
            f"  {path.description}"
        )
        edges_table = self.query_one("#path-edges", DataTable)
        edges_table.add_columns("from", "to", "relationship", "technique")
        for edge in path.edges:
            edges_table.add_row(
                edge.get("from", ""),
                edge.get("to", ""),
                edge.get("relationship", ""),
                edge.get("technique", ""),
            )

        steps = _generate_next_steps(path)
        steps_widget = self.query_one("#path-next-steps", Static)
        if steps:
            lines: list[str] = []
            for i, (desc, cmd, conf) in enumerate(steps, 1):
                conf_style = "green" if conf == "high" else "yellow"
                lines.append(f"  {i}. {desc}")
                lines.append(
                    f"     [bold]$ {cmd}[/]  "
                    f"[{conf_style}]{conf} confidence[/{conf_style}]"
                )
                lines.append("")
            steps_widget.update("\n".join(lines))
        else:
            steps_widget.update(
                "[dim]No automated next steps available for this path type.[/]"
            )


# ---------------------------------------------------------------------------
# Attack path → next steps mapping
# ---------------------------------------------------------------------------

# Maps edge "via" values to next steps. Each attack path is derived from
# findings already in the store, so next steps must point FORWARD in the
# kill chain — never back to the module that produced the source finding.
#
# Data flow: enumerate → harvest → analyze/exploit
#   enumerate-sourced edges → recommend harvest or exploit
#   harvest-sourced edges  → recommend analyze or exploit (harvest already ran)

_NEXT_STEPS: dict[str, list[tuple[str, str, str]]] = {
    # -- Enumerate-sourced paths (recommend harvest / exploit) ---------------
    "service_connection": [
        (
            "Extract service connection credentials",
            "bh exploit run ado_service_connection_extract",
            "_svc_conn",
        ),
    ],
    "azure_rm_scope": [
        (
            "Extract service connection credentials",
            "bh exploit run ado_service_connection_extract",
            "_svc_conn",
        ),
    ],
    "variable_group_link": [
        (
            "Harvest plaintext secrets from this variable group",
            "bh harvest run ado_variable_scan",
            "high",
        ),
        (
            "Extract linked Key Vault secrets at pipeline runtime",
            "bh exploit run ado_pipeline_vardump",
            "high",
        ),
    ],
    "self_hosted_pool": [
        (
            "Scan pipeline logs from this pool for leaked secrets",
            "bh harvest run ado_pipeline_log_scan",
            "high",
        ),
        (
            "Extract runtime secrets from pipelines executing on this agent pool",
            "bh exploit run ado_pipeline_vardump",
            "high",
        ),
    ],
    "no_branch_policy": [
        (
            "Inject into a pipeline via direct push to unprotected branch",
            "bh exploit run ado_pipeline_vardump",
            "high",
        ),
        (
            "Scan pipeline logs for secrets already leaked through this repo",
            "bh harvest run ado_pipeline_log_scan",
            "medium",
        ),
    ],
    "pr_no_reviewer": [
        (
            "Submit self-approved PR to inject into triggered pipelines",
            "bh exploit run ado_pipeline_vardump",
            "high",
        ),
        (
            "Scan pipeline logs for secrets already leaked through this repo",
            "bh harvest run ado_pipeline_log_scan",
            "medium",
        ),
    ],
    "public_upstream": [
        (
            "Harvest credentials from repos that consume this feed",
            "bh harvest run ado_credential_scan",
            "medium",
        ),
    ],
    "external_webhook": [
        (
            "Harvest credentials from repos that configure these hooks",
            "bh harvest run ado_credential_scan",
            "medium",
        ),
    ],
    "insecure_webhook": [
        (
            "Harvest credentials from repos that configure these hooks",
            "bh harvest run ado_credential_scan",
            "medium",
        ),
    ],
    "high_privilege_extension": [
        (
            "Harvest credentials from repos and pipelines this extension can access",
            "bh harvest run ado_credential_scan",
            "medium",
        ),
    ],
    # -- Harvest-sourced paths (harvest already ran — recommend analyze / exploit) --
    "ado_credential_exposure": [
        (
            "Review and validate discovered credentials",
            "bh analyze run discovered_credentials",
            "high",
        ),
        (
            "Use discovered credentials to extract pipeline runtime secrets",
            "bh exploit run ado_pipeline_vardump",
            "high",
        ),
    ],
    "ado_pipeline_plaintext_variable": [
        (
            "Review and validate discovered credentials",
            "bh analyze run discovered_credentials",
            "high",
        ),
        (
            "Extract full runtime variable values via pipeline injection",
            "bh exploit run ado_pipeline_vardump",
            "high",
        ),
    ],
    "ado_variable_group_plaintext_secret": [
        (
            "Review and validate discovered credentials",
            "bh analyze run discovered_credentials",
            "high",
        ),
        (
            "Extract full runtime variable values via pipeline injection",
            "bh exploit run ado_pipeline_vardump",
            "high",
        ),
    ],
    "ado_pipeline_log_secret": [
        (
            "Review and validate discovered credentials",
            "bh analyze run discovered_credentials",
            "high",
        ),
        (
            "Extract additional secrets at pipeline runtime",
            "bh exploit run ado_pipeline_vardump",
            "high",
        ),
    ],
    "ado_wiki_credential": [
        (
            "Review and validate discovered credentials",
            "bh analyze run discovered_credentials",
            "high",
        ),
        (
            "Extract pipeline runtime secrets using discovered credentials",
            "bh exploit run ado_pipeline_vardump",
            "medium",
        ),
    ],
}

_PERMISSION_STEPS: list[tuple[str, str, str]] = [
    (
        "Extract runtime secrets via pipelines your permissions allow you to modify",
        "bh exploit run ado_pipeline_vardump",
        "high",
    ),
    (
        "Harvest credentials from repos accessible with these permissions",
        "bh harvest run ado_credential_scan",
        "high",
    ),
]


def _generate_next_steps(path: Any) -> list[tuple[str, str, str]]:
    """Generate actionable next steps from attack path edges."""
    seen: set[str] = set()
    steps: list[tuple[str, str, str]] = []
    has_admin = "PAT has Administrator" in (path.description or "")
    for edge in path.edges:
        via = str(edge.get("via", ""))
        if via in _NEXT_STEPS:
            for desc, cmd, conf in _NEXT_STEPS[via]:
                if cmd in seen:
                    continue
                seen.add(cmd)
                if conf == "_svc_conn":
                    conf = _svc_conn_confidence(has_admin)
                    desc = _svc_conn_description(has_admin)
                steps.append((desc, cmd, conf))
        elif via.startswith("permissions:"):
            for step in _PERMISSION_STEPS:
                if step[1] not in seen:
                    seen.add(step[1])
                    steps.append(step)
            ns = via.split(":", 1)[1] if ":" in via else ""
            _add_permission_specific_steps(
                ns, path.description, steps, seen,
            )
    return steps


def _svc_conn_confidence(has_admin: bool) -> str:
    return "high" if has_admin else "low"


def _svc_conn_description(has_admin: bool) -> str:
    if has_admin:
        return (
            "Extract service connection credentials"
            " (PAT has Administrator access)"
        )
    return (
        "Extract service connection credentials"
        " (PAT lacks Administrator — likely to fail)"
    )


def _add_permission_specific_steps(
    ns_name: str,
    description: str,
    steps: list[tuple[str, str, str]],
    seen: set[str],
) -> None:
    """Add permission-type-specific next steps based on namespace and actions."""
    desc_lower = description.lower()
    if "forcepush" in desc_lower or "bypass" in desc_lower or "exempt" in desc_lower:
        cmd = "bh harvest run ado_credential_scan"
        if cmd not in seen:
            seen.add(cmd)
            steps.append((
                "Harvest credentials from repos you can force-push to or bypass policies on",
                cmd,
                "high",
            ))
    if "editbuilddefinition" in desc_lower or "queuebuilds" in desc_lower:
        cmd = "bh exploit run ado_pipeline_vardump"
        if cmd not in seen:
            seen.add(cmd)
            steps.append((
                "Inject into pipelines you can modify or trigger to extract runtime secrets",
                cmd,
                "high",
            ))
    if "editreleasedefinition" in desc_lower or "managedeployments" in desc_lower:
        cmd = "bh harvest run ado_pipeline_log_scan"
        if cmd not in seen:
            seen.add(cmd)
            steps.append((
                "Scan release pipeline logs for secrets leaked during deployments",
                cmd,
                "high",
            ))
    if "managemembership" in desc_lower:
        cmd = "bh harvest run ado_variable_scan"
        if cmd not in seen:
            seen.add(cmd)
            steps.append((
                "Harvest variable group secrets accessible after escalating group membership",
                cmd,
                "high",
            ))


class FindingDetailScreen(ModalScreen[None]):
    """Shows finding details with full reference and metadata."""

    DEFAULT_CSS = """
    FindingDetailScreen {
        align: center middle;
    }
    #finding-detail-container {
        width: 90%;
        height: 60%;
        background: $surface;
        border: thick $primary;
        padding: 1 2;
        overflow-y: auto;
    }
    #finding-status { height: 1; }
    .clickable-resource { text-style: underline; }
    .clickable-resource:hover { color: $accent; }
    """

    BINDINGS: list[BindingType] = [
        ("escape", "dismiss", "Close"),
        ("o", "open_url", "Open in SpyGlass"),
    ]

    def __init__(self, finding_data: dict[str, Any], **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._data = finding_data
        self._url = finding_data.get("spyglass_url", "")

    def compose(self) -> ComposeResult:
        with VerticalScroll(id="finding-detail-container"):
            yield Static("", id="finding-header")
            yield Static("", id="finding-resource")
            yield Static("", id="finding-body")
            yield Static("", id="finding-status")

    def on_mount(self) -> None:
        header = self.query_one("#finding-header", Static)
        resource_widget = self.query_one("#finding-resource", Static)
        body = self.query_one("#finding-body", Static)

        header.update(f"[bold]{self._data.get('kind', '')}[/]")

        resource_id = self._data.get("resource_id", "")
        if self._url and resource_id:
            resource_widget.update(
                f"resource: [@click=screen.open_url]{resource_id}[/]"
                "  [dim]\\[o] open in SpyGlass[/]"
            )
        elif resource_id:
            resource_widget.update(f"resource: {resource_id}")

        lines = [f"[bold]Reference:[/] {self._data.get('reference', '')}"]
        details = self._data.get("details", {})
        if details:
            lines.append("")
            lines.append("[bold]Details:[/]")
            for k, v in sorted(details.items()):
                display_v = str(v)
                if k == "ado_url" and display_v.startswith("https://"):
                    display_v = display_v[8:]
                lines.append(f"  {k}: {display_v}")
        body.update("\n".join(lines))

    def action_open_url(self) -> None:
        from beachhead.tui.urls import extract_project, open_in_spyglass

        status = self.query_one("#finding-status", Static)
        if not self._url:
            status.update("[yellow]No SpyGlass URL available for this finding.[/]")
            return
        org = ""
        try:
            surface = self.app.surface  # type: ignore[attr-defined]
            if surface:
                orgs = surface.config.ado_organizations
                org = next(iter(orgs)) if orgs else ""
        except Exception:  # noqa: BLE001, S110
            pass
        details = self._data.get("details", {})
        resource_id = self._data.get("resource_id", "")
        project = details.get("project", "") or extract_project(resource_id)
        ok, msg = open_in_spyglass(self._url, org=org, project=project)
        if ok:
            status.update(f"[green]Opened:[/] {msg}")
        else:
            status.update(f"[yellow]{msg}[/]")
