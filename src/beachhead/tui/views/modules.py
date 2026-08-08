"""Modules view: catalog of discovered modules with run buttons and output log.

Discovers modules via the loader, groups them by phase, and lets the operator
trigger a module run. Output streams to a log panel; results land in the store
and appear in the existing Runs/Identities/Roles views on refresh.

The TUI opens the store read-only for its views; module runs need a writable
store. This view opens a separate write-capable store connection for module
execution, so the read-only contract of the other views is preserved.

On run completion, notifies the app to refresh the engagement bar counts.

For ado_pipeline_vardump the flow is Search → Select pipeline → name clone →
Confirm → Run. For ado_yaml_pipeline_vardump the flow is the same minus the
clone name step (YAML vardump uses a temp branch, not a cloned definition).
For ado_service_connection_extract the flow is Search → Select connection →
Select pipeline (injection vehicle) → name branch → Confirm → Run.
Search bootstraps a RunEnv to call the ADO APIs, then the operator picks
targets before the exploit runs.
"""

from __future__ import annotations

from typing import Any

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.reactive import reactive
from textual.widgets import Button, Checkbox, Input, RichLog, Select, Static
from textual.worker import Worker, WorkerState

from beachhead.core.loader import ModuleRegistry, load_modules
from beachhead.core.module import Module, Phase


class ModulesView(Vertical):
    """Module catalog + runner view with reactive run state."""

    DEFAULT_CSS = """
    ModulesView {
        height: 1fr;
    }
    #mod-left {
        width: 40;
        border-right: solid $primary;
    }
    #mod-search {
        margin: 0 0 1 0;
    }
    #mod-catalog {
        overflow-y: auto;
    }
    #mod-detail {
        width: 1fr;
        padding: 0 1;
    }
    .phase-header {
        text-style: bold;
        margin: 2 0 1 0;
    }
    .phase-header-first {
        text-style: bold;
        margin: 0 0 1 0;
    }
    .mod-btn {
        margin: 0 1 1 1;
        width: 1fr;
    }
    .mod-summary {
        margin: 0 1 2 1;
    }
    #mod-vardump-params {
        height: auto;
        max-height: 10;
        margin: 0 0 1 0;
    }
    #mod-vardump-params-label {
        height: 1;
        color: $text-muted;
    }
    #mod-output {
        height: 1fr;
        border: solid $primary;
    }
    #mod-status { height: 1; dock: bottom; padding: 0 1; }
    #mod-status.running { background: $warning; color: $text; }
    #mod-status.success { background: $success; color: $text; }
    #mod-status.error { background: $error; color: $text; }
    """

    run_state: reactive[str] = reactive("idle")
    run_module_name: reactive[str] = reactive("")

    def __init__(
        self,
        *,
        store_path: str | None = None,
        config_path: str | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self._registry: ModuleRegistry | None = None
        self._selected: Module | None = None
        self._run_active = False
        self._confirmed = False
        self._store_path = store_path
        self._config_path = config_path
        # vardump / svc-conn-extract interactive state
        self._pipelines: list[dict[str, Any]] = []
        self._all_pipelines: list[dict[str, Any]] = []
        self._selected_pipeline: dict[str, Any] | None = None
        self._connections: list[dict[str, Any]] = []
        self._selected_connection: dict[str, Any] | None = None
        self._searching = False
        self._preflight_passed: bool | None = None  # None = not run yet
        self._preflight_running = False

    def compose(self) -> ComposeResult:
        yield Static("Modules", classes="view-title")
        with Horizontal():
            with Vertical(id="mod-left"):
                yield Input(placeholder="search modules...", id="mod-search")
                yield VerticalScroll(id="mod-catalog")
            with Vertical(id="mod-detail"):
                yield Static("", id="mod-info")
                with Vertical(id="mod-vardump-params"):
                    yield Checkbox(
                        "Secrets only", value=True,
                        id="mod-secrets-only",
                    )
                    yield Select[str](
                        [], prompt="Select a connection…",
                        id="mod-connection-select",
                    )
                    yield Select[str](
                        [], prompt="Select a pipeline…",
                        id="mod-pipeline-select",
                    )
                    yield Static(
                        "Clone name",
                        id="mod-vardump-params-label",
                    )
                    yield Input(placeholder="clone name…", id="mod-clone-name")
                with Horizontal(id="mod-actions"):
                    yield Button(
                        "🔍 Search", id="btn-search", variant="primary",
                    )
                    yield Button(
                        "⚠ Confirm", id="btn-confirm", variant="error",
                    )
                    yield Button("▶ Run", id="btn-run", variant="warning", disabled=True)
                yield Static("", id="mod-status")
                yield RichLog(id="mod-output", highlight=True, markup=True)

    def on_mount(self) -> None:
        self._registry = load_modules()
        self._build_catalog()
        self._update_buttons()
        self._catalog_ready = True

    def _build_catalog(self) -> None:
        catalog = self.query_one("#mod-catalog", VerticalScroll)
        if self._registry is None or len(self._registry) == 0:
            catalog.mount(Static("[dim]No modules registered.[/]"))
            return

        search = ""
        try:
            search = self.query_one("#mod-search", Input).value.strip().lower()
        except Exception:  # noqa: BLE001, S110
            pass

        first_phase = True
        for phase in Phase:
            mods = self._registry.list_phase(phase)
            if search:
                mods = [
                    m
                    for m in mods
                    if search in m.meta.name.lower()
                    or search in m.meta.summary.lower()
                ]
            if not mods:
                continue
            header_cls = "phase-header-first" if first_phase else "phase-header"
            first_phase = False
            catalog.mount(Static(f"[bold]{phase.value.upper()}[/]", classes=header_cls))
            for mod in mods:
                gated = " ⚠" if mod.meta.gated else ""
                techs = ""
                if mod.meta.technique_ids:
                    techs = f"  {', '.join(mod.meta.technique_ids)}"
                short_name = mod.meta.name.split(".", 1)[-1]
                safe_id = mod.meta.name.replace(".", "-")
                btn = Button(
                    f"{short_name}{gated}",
                    id=f"mod-{safe_id}",
                    classes="mod-btn",
                )
                catalog.mount(btn)
                catalog.mount(
                    Static(
                        f"[dim]{mod.meta.summary}{techs}[/]",
                        classes="mod-summary",
                    )
                )

    _VARDUMP = "exploit.ado_pipeline_vardump"
    _YAML_VARDUMP = "exploit.ado_yaml_pipeline_vardump"
    _SVC_CONN_EXTRACT = "exploit.ado_service_connection_extract"
    _DISCOVERED_CREDS = "analyze.discovered_credentials"
    _COLLECTED_RESOURCES = "analyze.collected_resources"
    _ADO_ATTACK_PATHS = "analyze.ado_attack_paths"

    @property
    def _is_vardump(self) -> bool:
        return self._selected is not None and self._selected.meta.name == self._VARDUMP

    @property
    def _is_yaml_vardump(self) -> bool:
        return self._selected is not None and self._selected.meta.name == self._YAML_VARDUMP

    @property
    def _is_either_vardump(self) -> bool:
        return self._is_vardump or self._is_yaml_vardump

    @property
    def _is_svc_conn_extract(self) -> bool:
        return self._selected is not None and self._selected.meta.name == self._SVC_CONN_EXTRACT

    @property
    def _is_discovered_creds(self) -> bool:
        return self._selected is not None and self._selected.meta.name == self._DISCOVERED_CREDS

    @property
    def _is_collected_resources(self) -> bool:
        return self._selected is not None and self._selected.meta.name == self._COLLECTED_RESOURCES

    @property
    def _is_ado_attack_paths(self) -> bool:
        return self._selected is not None and self._selected.meta.name == self._ADO_ATTACK_PATHS

    @property
    def _no_secrets(self) -> bool:
        """Selected module needs the secret store but passphrase was skipped."""
        return (
            self._selected is not None
            and self._selected.meta.needs_secrets
            and not getattr(self.app, "_passphrase", None)
        )

    def _update_buttons(self) -> None:
        run_btn = self.query_one("#btn-run", Button)
        confirm_btn = self.query_one("#btn-confirm", Button)
        search_btn = self.query_one("#btn-search", Button)
        params = self.query_one("#mod-vardump-params")

        if self._selected is None:
            run_btn.disabled = True
            run_btn.display = False
            confirm_btn.display = False
            search_btn.display = False
            params.display = False
            return

        if self._is_discovered_creds or self._is_collected_resources:
            search_btn.display = False
            params.display = False
            confirm_btn.display = False
            run_btn.display = True
            run_btn.label = "👁  View"
            run_btn.disabled = self._no_secrets
            return

        if self._is_ado_attack_paths and not self._run_active:
            search_btn.display = False
            params.display = False
            confirm_btn.display = False
            ran_ok = (
                self.run_state == "success"
                and self.run_module_name == self._ADO_ATTACK_PATHS
            )
            run_btn.display = True
            if ran_ok:
                run_btn.label = "👁  View"
            else:
                run_btn.label = "▶ Run"
            run_btn.disabled = False
            return

        run_btn.label = "▶ Run"

        if self._is_either_vardump:
            secrets_cb = self.query_one("#mod-secrets-only", Checkbox)
            secrets_cb.display = True
            conn_select = self.query_one("#mod-connection-select", Select)
            conn_select.display = False
            params.display = True
            pipeline_select = self.query_one("#mod-pipeline-select", Select)
            pipeline_select.display = bool(self._pipelines)
            clone_label = self.query_one("#mod-vardump-params-label", Static)
            clone_input = self.query_one("#mod-clone-name", Input)
            clone_label.display = bool(self._pipelines)
            clone_input.display = bool(self._pipelines)
            if self._is_yaml_vardump:
                clone_label.update("Branch name")
                clone_input.placeholder = "branch name…"
            else:
                clone_label.update("Clone name")
                clone_input.placeholder = "clone name…"
            search_btn.display = True
            search_btn.disabled = (
                self._run_active or self._searching or self._no_secrets
            )

            if not self._pipelines or self._selected_pipeline is None:
                confirm_btn.display = False
                run_btn.display = False
            elif not self._confirmed:
                confirm_btn.display = True
                confirm_btn.disabled = (
                    self._run_active
                    or self._no_secrets
                    or self._preflight_running
                    or self._preflight_passed is not True
                )
                run_btn.display = False
            else:
                confirm_btn.display = False
                run_btn.display = True
                run_btn.disabled = self._run_active or self._no_secrets
        elif self._is_svc_conn_extract:
            secrets_cb = self.query_one("#mod-secrets-only", Checkbox)
            secrets_cb.display = False
            params.display = True
            conn_select = self.query_one("#mod-connection-select", Select)
            conn_select.display = bool(self._connections)
            pipeline_select = self.query_one("#mod-pipeline-select", Select)
            pipeline_select.display = bool(self._pipelines)
            clone_label = self.query_one("#mod-vardump-params-label", Static)
            clone_input = self.query_one("#mod-clone-name", Input)
            clone_label.update("Branch name")
            clone_input.placeholder = "branch name…"
            has_data = bool(self._connections) and bool(self._pipelines)
            clone_label.display = has_data
            clone_input.display = has_data
            search_btn.display = True
            search_btn.disabled = (
                self._run_active or self._searching or self._no_secrets
            )

            ready = (
                self._selected_connection is not None
                and self._selected_pipeline is not None
            )
            if not ready:
                confirm_btn.display = False
                run_btn.display = False
            elif not self._confirmed:
                confirm_btn.display = True
                confirm_btn.disabled = (
                    self._run_active
                    or self._no_secrets
                    or self._preflight_running
                    or self._preflight_passed is not True
                )
                run_btn.display = False
            else:
                confirm_btn.display = False
                run_btn.display = True
                run_btn.disabled = self._run_active or self._no_secrets
        else:
            search_btn.display = False
            params.display = False
            is_gated = self._selected.meta.gated
            if is_gated and not self._confirmed:
                confirm_btn.display = True
                confirm_btn.disabled = self._run_active or self._no_secrets
                run_btn.display = False
            else:
                confirm_btn.display = False
                run_btn.display = True
                run_btn.disabled = self._run_active or self._no_secrets

    def _update_info(self) -> None:
        info = self.query_one("#mod-info", Static)
        if self._selected is None:
            info.update("[dim]Select a module from the catalog.[/]")
            return
        m = self._selected.meta
        gated = "  [yellow]GATED (--confirm required)[/]" if m.gated else ""
        techs = f"  ATT&CK: {', '.join(m.technique_ids)}" if m.technique_ids else ""
        secrets_hint = ""
        if self._no_secrets:
            secrets_hint = (
                "\n[red]Secret store passphrase required"
                " — restart TUI and enter passphrase.[/]"
            )
        info.update(
            f"[bold]{m.name}[/]  {m.phase.value}/{m.access.value}"
            f"{gated}\n{m.summary}{techs}{secrets_hint}"
        )

    def _reset_vardump_state(self) -> None:
        self._pipelines = []
        self._all_pipelines = []
        self._selected_pipeline = None
        self._connections = []
        self._selected_connection = None
        self._confirmed = False
        self._searching = False
        self._preflight_passed = None
        self._preflight_running = False
        try:
            self.query_one("#mod-connection-select", Select).set_options([])
            self.query_one("#mod-pipeline-select", Select).set_options([])
            self.query_one("#mod-clone-name", Input).value = ""
        except Exception:  # noqa: BLE001, S110
            pass

    def _start_preflight(self) -> None:
        """Run pre-flight permission checks for the selected pipeline."""
        if self._selected_pipeline is None:
            return
        self._preflight_passed = None
        self._preflight_running = True
        log = self.query_one("#mod-output", RichLog)
        log.write("\n── Running pre-flight permission checks… ──")
        self.run_worker(
            self._run_preflight(),
            name="preflight",
            exclusive=True,
        )

    async def _run_preflight(self) -> str:
        import os

        from beachhead.core.clients.ado_search import AdoSearchClient

        pipeline = self._selected_pipeline
        if pipeline is None:
            return "[yellow]No pipeline selected[/]"

        log_console = self._make_log_console()

        pat = os.environ.get("BEACHHEAD_ADO_PAT")
        if not pat:
            try:
                from beachhead.core.auth.token_cache import load_tokens

                entry = load_tokens().get("ado")
                if entry is not None:
                    pat = entry.access_token
            except Exception:  # noqa: BLE001, S110
                pass
        if not pat:
            return "[yellow]Pre-flight skipped — no PAT available[/]"

        org = pipeline.get("org", "")
        project = pipeline.get("project", "")
        definition_id = pipeline.get("id", 0)

        from beachhead.core.boot import bootstrap_run_env

        try:
            env = await bootstrap_run_env(
                store_path=self._store_path or "",
                config_path=self._config_path,
                passphrase=getattr(self.app, "_passphrase", None),
                console=log_console,
            )
        except Exception as exc:  # noqa: BLE001
            return f"[red]Pre-flight bootstrap failed: {exc}[/]"

        from beachhead.core.audit import AuditLog

        run_id = env.store.start_run(
            module="preflight_permission_check", phase="exploit",
            operator=env.operator,
        )
        audit = AuditLog(env.store, operator=env.operator, run_id=run_id)
        client = AdoSearchClient(
            org=org, pat=pat, scope=env.scope,
            audit=audit, run_id=run_id,
        )

        try:
            if self._is_yaml_vardump or self._is_svc_conn_extract:
                from beachhead.modules.exploit._vardump_common import preflight_yaml

                definition = await client.get_build_definition(project, definition_id)
                if not definition:
                    return "[red]Could not fetch pipeline definition[/]"
                repo_info = definition.get("repository", {})
                repo_id = repo_info.get("id", "")
                default_branch = repo_info.get("defaultBranch", "refs/heads/main")
                pf = await preflight_yaml(
                    log_console, client, project, definition_id,
                    repo_id, default_branch,
                )
            else:
                from beachhead.modules.exploit._vardump_common import preflight_classic

                pf = await preflight_classic(
                    log_console, client, project, definition_id,
                )

            self._preflight_passed = pf.can_proceed
            if pf.can_proceed:
                return "[green]Pre-flight passed — ready to confirm[/]"
            return "[red]Pre-flight failed — see blockers above[/]"
        except Exception as exc:  # noqa: BLE001
            self._preflight_passed = None
            env.store.finish_run(run_id, status="error")
            return f"[yellow]Pre-flight error: {exc}[/]"
        finally:
            try:
                env.store.finish_run(run_id, status="ok")
            except Exception:  # noqa: BLE001, S110
                pass
            await client.close()
            env.store.close()

    async def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "mod-search" and getattr(self, "_catalog_ready", False):
            catalog = self.query_one("#mod-catalog", VerticalScroll)
            await catalog.remove_children()
            self._build_catalog()

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "mod-connection-select":
            val = event.value
            if not isinstance(val, str):
                self._selected_connection = None
                self._selected_pipeline = None
                self._confirmed = False
                self._update_buttons()
                return
            idx = int(val)
            if 0 <= idx < len(self._connections):
                self._selected_connection = self._connections[idx]
                self._selected_pipeline = None
                self._confirmed = False
                conn_project = self._selected_connection.get("project", "")
                self._pipelines = [
                    p for p in self._all_pipelines
                    if p.get("project") == conn_project
                ]
                select = self.query_one("#mod-pipeline-select", Select)
                options: list[tuple[str, str]] = []
                for i, p in enumerate(self._pipelines):
                    options.append((
                        f"[{p['id']}] {p['name']}",
                        str(i),
                    ))
                select.set_options(options)
                clone_input = self.query_one("#mod-clone-name", Input)
                conn_id = self._selected_connection.get("id", "")[:8]
                clone_input.value = f"bh-svcconn-{conn_id}"
                self._update_buttons()
            return

        if event.select.id != "mod-pipeline-select":
            return
        val = event.value
        if not isinstance(val, str):
            self._selected_pipeline = None
            self._confirmed = False
            self._preflight_passed = None
            self._update_buttons()
            return
        idx = int(val)
        if 0 <= idx < len(self._pipelines):
            self._selected_pipeline = self._pipelines[idx]
            self._confirmed = False
            self._preflight_passed = None
            clone_input = self.query_one("#mod-clone-name", Input)
            if self._is_yaml_vardump:
                clone_input.value = f"bh-vardump-{self._selected_pipeline['id']}"
            elif self._is_vardump:
                clone_input.value = self._selected_pipeline["name"] + "-vardump"
            self._update_buttons()
            if self._is_either_vardump or self._is_svc_conn_extract:
                self._start_preflight()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn_id = event.button.id or ""

        if btn_id.startswith("mod-"):
            module_name = btn_id[4:].replace("-", ".", 1)
            if self._registry is not None:
                self._selected = self._registry.get(module_name)
                self._confirmed = False
                self._reset_vardump_state()
                self._update_info()
                self._update_buttons()
            return

        if btn_id == "btn-search":
            self._start_search()
            return

        if btn_id == "btn-confirm":
            self._confirmed = True
            self._update_buttons()
            log = self.query_one("#mod-output", RichLog)
            log.write("[yellow]⚠ Confirmed — Run button enabled.[/]")
            return

        if btn_id == "btn-run" and self._selected is not None:
            if self._is_discovered_creds:
                self.app.action_show("credentials")  # type: ignore[attr-defined]
                return
            if self._is_collected_resources:
                self.app.action_show("resources")  # type: ignore[attr-defined]
                return
            if (
                self._is_ado_attack_paths
                and self.run_state == "success"
                and self.run_module_name == self._ADO_ATTACK_PATHS
            ):
                self.app.action_show("paths")  # type: ignore[attr-defined]
                return
            self._start_run()

    # ------------------------------------------------------------------ #
    # Search (vardump pipeline discovery)
    # ------------------------------------------------------------------ #

    def _start_search(self) -> None:
        if self._store_path is None:
            log = self.query_one("#mod-output", RichLog)
            log.write(
                "[yellow]Search requires a configured engagement "
                "environment (auth, scope, store).[/]"
            )
            return

        self._searching = True
        self._update_buttons()
        log = self.query_one("#mod-output", RichLog)

        if self._is_svc_conn_extract:
            log.write("\n── Searching for service connections & pipelines… ──")
            self.run_worker(
                self._search_svc_connections(),
                name="search-pipelines",
                exclusive=True,
            )
            return

        yaml_mode = self._is_yaml_vardump
        kind = "YAML" if yaml_mode else "classic"
        secrets_only = self.query_one("#mod-secrets-only", Checkbox).value
        qualifier = " (secrets only)" if secrets_only else ""
        log.write(f"\n── Searching for {kind} pipelines{qualifier}… ──")

        self.run_worker(
            self._search_pipelines(yaml_mode=yaml_mode, secrets_only=secrets_only),
            name="search-pipelines",
            exclusive=True,
        )

    async def _search_pipelines(
        self, *, yaml_mode: bool = False, secrets_only: bool = False,
    ) -> str:
        from beachhead.core.boot import bootstrap_run_env
        from beachhead.core.errors import ConfigMissingError
        from beachhead.core.module import Access, ModuleMeta, Phase, RunContext, RunResult
        from beachhead.core.runner import run_module

        try:
            env = await bootstrap_run_env(
                store_path=self._store_path or "",
                config_path=self._config_path,
                passphrase=getattr(self.app, "_passphrase", None),
            )
        except ConfigMissingError as exc:
            return (
                f"[yellow]No engagement config found at {exc.config_path}[/]\n"
                "Run [bold]bh[/] in the CLI to create one interactively."
            )
        except Exception as exc:  # noqa: BLE001
            return f"[red]Bootstrap failed: {exc}[/]"

        pipelines: list[dict[str, Any]] = []
        kind = "YAML" if yaml_mode else "classic"

        class _Discovery:
            meta = ModuleMeta(
                name="exploit.ado_pipeline_vardump",
                phase=Phase.EXPLOIT, access=Access.READ,
                requires_browser=False, technique_ids=(),
                summary=f"Search for {kind} pipelines.",
            )

            async def run(self_, ctx: RunContext) -> RunResult:  # noqa: N805
                nonlocal pipelines
                if yaml_mode:
                    from beachhead.modules.exploit.ado_yaml_pipeline_vardump import (
                        AdoYamlPipelineVardump,
                    )
                    pipelines = await AdoYamlPipelineVardump.discover(
                        ctx, secrets_only=secrets_only,
                    )
                else:
                    from beachhead.modules.exploit.ado_pipeline_vardump import (
                        AdoPipelineVardump,
                    )
                    pipelines = await AdoPipelineVardump.discover(
                        ctx, secrets_only=secrets_only,
                    )
                return RunResult(ok=True, written=0)

        try:
            await run_module(_Discovery(), env)
            self._pipelines = pipelines
            if not pipelines:
                return f"[yellow]No {kind} pipelines found.[/]"
            return f"[green]Found {len(pipelines)} {kind} pipeline(s).[/]"
        except Exception as exc:
            return f"[red]Search failed: {exc}[/]"
        finally:
            if env.secrets is not None:
                env.secrets.close()
            env.store.close()

    async def _search_svc_connections(self) -> str:
        from beachhead.core.boot import bootstrap_run_env
        from beachhead.core.errors import ConfigMissingError
        from beachhead.core.module import Access, ModuleMeta, Phase, RunContext, RunResult
        from beachhead.core.runner import run_module

        try:
            env = await bootstrap_run_env(
                store_path=self._store_path or "",
                config_path=self._config_path,
                passphrase=getattr(self.app, "_passphrase", None),
            )
        except ConfigMissingError as exc:
            return (
                f"[yellow]No engagement config found at {exc.config_path}[/]\n"
                "Run [bold]bh[/] in the CLI to create one interactively."
            )
        except Exception as exc:  # noqa: BLE001
            return f"[red]Bootstrap failed: {exc}[/]"

        result_data: dict[str, list[dict[str, Any]]] = {}

        class _Discovery:
            meta = ModuleMeta(
                name="exploit.ado_service_connection_extract",
                phase=Phase.EXPLOIT, access=Access.READ,
                requires_browser=False, technique_ids=(),
                summary="Search for service connections.",
            )

            async def run(self_, ctx: RunContext) -> RunResult:  # noqa: N805
                nonlocal result_data
                from beachhead.modules.exploit.ado_service_connection_extract import (
                    AdoServiceConnectionExtract,
                )
                result_data = await AdoServiceConnectionExtract.discover(ctx)
                return RunResult(ok=True, written=0)

        try:
            await run_module(_Discovery(), env)
            self._connections = result_data.get("connections", [])
            self._all_pipelines = result_data.get("pipelines", [])
            self._pipelines = []
            parts: list[str] = []
            if self._connections:
                parts.append(f"{len(self._connections)} connection(s)")
            if self._all_pipelines:
                parts.append(f"{len(self._all_pipelines)} pipeline(s)")
            if not parts:
                return "[yellow]No supported service connections or pipelines found.[/]"
            return f"[green]Found {', '.join(parts)}.[/]"
        except Exception as exc:
            return f"[red]Search failed: {exc}[/]"
        finally:
            if env.secrets is not None:
                env.secrets.close()
            env.store.close()

    # ------------------------------------------------------------------ #
    # Run
    # ------------------------------------------------------------------ #

    def _start_run(self) -> None:
        if self._selected is None or self._run_active:
            return

        if self._store_path is None:
            log = self.query_one("#mod-output", RichLog)
            log.write(
                "[yellow]Module execution requires a configured engagement "
                "environment (auth, scope, store).[/]"
            )
            log.write(
                "[yellow]Use the CLI (`bh enumerate run <module>`) for headless execution.[/]"
            )
            return

        self._run_active = True
        self.run_state = "running"
        self.run_module_name = self._selected.meta.name
        self._update_buttons()
        self._update_status_bar()

        log = self.query_one("#mod-output", RichLog)
        log.write(f"\n── Running {self._selected.meta.name} ──")

        self.app.active_runs += 1  # type: ignore[attr-defined]

        mod: Module
        if self._is_vardump and self._selected_pipeline is not None:
            from beachhead.modules.exploit.ado_pipeline_vardump import (
                AdoPipelineVardump,
            )

            target = {**self._selected_pipeline, "_preflight_done": True}
            mod = AdoPipelineVardump(target_pipeline=target)
        elif self._is_yaml_vardump and self._selected_pipeline is not None:
            from beachhead.modules.exploit.ado_yaml_pipeline_vardump import (
                AdoYamlPipelineVardump,
            )

            target = {**self._selected_pipeline, "_preflight_done": True}
            mod = AdoYamlPipelineVardump(target_pipeline=target)
        elif (
            self._is_svc_conn_extract
            and self._selected_connection is not None
            and self._selected_pipeline is not None
        ):
            from beachhead.modules.exploit.ado_service_connection_extract import (
                AdoServiceConnectionExtract,
            )

            target_conn = {**self._selected_connection, "_preflight_done": True}
            mod = AdoServiceConnectionExtract(
                target_connection=target_conn,
                target_pipeline_id=self._selected_pipeline["id"],
            )
        else:
            mod = self._selected

        self.run_worker(
            self._run_module(mod),
            name=f"run-{self._selected.meta.name}",
            exclusive=True,
        )

    def _make_log_console(self) -> Any:
        """Create a Rich Console that writes into the TUI RichLog."""
        from rich.console import Console
        from rich.text import Text

        log = self.query_one("#mod-output", RichLog)

        class _LogFile:
            """File-like that flushes each write to the RichLog widget."""

            def write(self_, text: str) -> int:  # noqa: N805
                for line in text.rstrip("\n").split("\n"):
                    if line:
                        log.write(Text.from_ansi(line))
                return len(text)

            def flush(self_: Any) -> None:  # noqa: N805
                pass

        return Console(file=_LogFile(), markup=True, highlight=False)  # type: ignore[arg-type]

    async def _run_module(self, mod: Module) -> str:
        from beachhead.core.boot import bootstrap_run_env
        from beachhead.core.errors import ConfigMissingError
        from beachhead.core.runner import run_module

        log_console = self._make_log_console()

        try:
            env = await bootstrap_run_env(
                store_path=self._store_path or "",
                config_path=self._config_path,
                passphrase=getattr(self.app, "_passphrase", None),
                console=log_console,
            )
        except ConfigMissingError as exc:
            return (
                f"[yellow]No engagement config found at {exc.config_path}[/]\n"
                "Run [bold]bh[/] in the CLI to create one interactively."
            )
        except Exception as exc:  # noqa: BLE001
            return f"[red]Bootstrap failed: {exc}[/]"
        confirm_gate = self._tui_confirm if mod.meta.gated else None
        try:
            result = await run_module(mod, env, confirm=confirm_gate, prompt=self._tui_prompt)
            if result.ok:
                if result.written == 0 and result.message:
                    return f"[yellow]{result.message}[/]"
                label = {
                    "enumerate": "resources",
                    "harvest": "findings",
                    "analyze": "attack paths",
                    "exploit": "findings",
                }.get(mod.meta.phase, "written")
                msg = f"[green]Done — {result.written} {label}[/]"
                if result.message:
                    msg += f"\n[dim]{result.message}[/]"
                return msg
            return f"[red]Failed: {result.message}[/]"
        except Exception as exc:
            return f"[red]Error: {exc}[/]"
        finally:
            if env.secrets is not None:
                env.secrets.close()
            env.store.close()

    async def _tui_confirm(self, prompt: str, *, dangerous: bool = False) -> bool:
        log = self.query_one("#mod-output", RichLog)
        suffix = " [red](DANGEROUS)[/]" if dangerous else ""
        log.write(f"[yellow]Confirm: {prompt}{suffix}[/] → approved")
        return True

    async def _tui_prompt(self, message: str, *, default: str = "") -> str:
        log = self.query_one("#mod-output", RichLog)
        if self.run_module_name in (
            self._VARDUMP, self._YAML_VARDUMP, self._SVC_CONN_EXTRACT,
        ):
            try:
                clone_name = self.query_one("#mod-clone-name", Input).value.strip()
                if clone_name:
                    log.write(f"[dim]{message}[/] → {clone_name!r}")
                    return clone_name
            except Exception:  # noqa: BLE001
                pass
        log.write(f"[dim]{message}[/] → {default!r}")
        return default

    # ------------------------------------------------------------------ #
    # Worker lifecycle
    # ------------------------------------------------------------------ #

    def on_worker_state_changed(self, event: Worker.StateChanged) -> None:
        worker_name = event.worker.name or ""

        if worker_name == "search-pipelines":
            self._on_search_complete(event)
            return

        if worker_name == "preflight":
            self._preflight_running = False
            if event.state in (WorkerState.SUCCESS, WorkerState.ERROR):
                log = self.query_one("#mod-output", RichLog)
                if event.state == WorkerState.SUCCESS:
                    log.write(str(event.worker.result))
                else:
                    log.write(f"[red]Pre-flight error: {event.worker.error}[/]")
                self._update_buttons()
            return

        if event.state == WorkerState.SUCCESS:
            log = self.query_one("#mod-output", RichLog)
            log.write(str(event.worker.result))
            log.write("── End ──\n")
            self._run_active = False
            self.run_state = "success"
            self._update_buttons()
            self._update_status_bar()
            self._notify_app_run_complete()
        elif event.state == WorkerState.ERROR:
            log = self.query_one("#mod-output", RichLog)
            log.write(f"[red]Worker error: {event.worker.error}[/]")
            log.write("── End ──\n")
            self._run_active = False
            self.run_state = "error"
            self._update_buttons()
            self._update_status_bar()
            self._notify_app_run_complete()

    def _on_search_complete(self, event: Worker.StateChanged) -> None:
        if event.state not in (WorkerState.SUCCESS, WorkerState.ERROR):
            return

        self._searching = False
        log = self.query_one("#mod-output", RichLog)

        if event.state == WorkerState.ERROR:
            log.write(f"[red]Search error: {event.worker.error}[/]")
            self._update_buttons()
            return

        log.write(str(event.worker.result))

        if self._connections:
            conn_select = self.query_one("#mod-connection-select", Select)
            conn_options: list[tuple[str, str]] = []
            for i, c in enumerate(self._connections):
                label = f"[{c['type']}] {c['name']}  ({c['project']})"
                if c.get("url"):
                    label += f"  {c['url']}"
                conn_options.append((label, str(i)))
            conn_select.set_options(conn_options)

        if not self._is_svc_conn_extract and self._pipelines:
            select = self.query_one("#mod-pipeline-select", Select)
            options: list[tuple[str, str]] = []
            for i, p in enumerate(self._pipelines):
                label = f"[{p['id']}] {p['name']}  ({p['project']})"
                n_s = p.get("secrets", 0)
                if n_s:
                    label += f"  ({n_s} secret(s))"
                options.append((label, str(i)))
            select.set_options(options)

        if self._is_svc_conn_extract:
            if self._connections and self._all_pipelines:
                log.write(
                    "[dim]Select a connection, then pick a pipeline "
                    "from that project, enter a branch name, then Confirm.[/]"
                )
        elif self._pipelines:
            if self._is_yaml_vardump:
                log.write("[dim]Select a pipeline, enter a branch name, then Confirm.[/]")
            else:
                log.write("[dim]Select a pipeline, enter a clone name, then Confirm.[/]")

        self._update_buttons()

    def _update_status_bar(self) -> None:
        status = self.query_one("#mod-status", Static)
        status.set_class(self.run_state == "running", "running")
        status.set_class(self.run_state == "success", "success")
        status.set_class(self.run_state == "error", "error")
        if self.run_state == "running":
            status.update(f"Running: {self.run_module_name}…")
        elif self.run_state == "success":
            status.update(f"Completed: {self.run_module_name}")
        elif self.run_state == "error":
            status.update(f"Failed: {self.run_module_name}")
        else:
            status.update("")

    def _notify_app_run_complete(self) -> None:
        try:
            self.app.active_runs = max(0, self.app.active_runs - 1)  # type: ignore[attr-defined]
            self.app._refresh_engagement_bar()  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001, S110
            pass
        try:
            dashboard = self.app.query_one("#dashboard")
            reload = getattr(dashboard, "reload", None)
            if callable(reload):
                reload()
        except Exception:  # noqa: BLE001, S110
            pass

    def on_show(self) -> None:
        self.refresh(layout=True)

    async def reload(self) -> None:
        """Refresh module catalog (called by the app's 'r' binding)."""
        self._registry = load_modules()
        self._selected = None
        self._confirmed = False
        self._reset_vardump_state()
        catalog = self.query_one("#mod-catalog", VerticalScroll)
        await catalog.remove_children()
        self._build_catalog()
        self._update_info()
        self._update_buttons()
