"""TUI tests via Textual's headless Pilot.

API adaptation note (Textual 8.2.7): Static.renderable does not exist in this version;
the equivalent attribute is Static.content (returns the original string/renderable passed
to the constructor or the last value passed to .update()).  All assertions that the spec
wrote as ``str(Static.renderable)`` are expressed here as ``str(Static.content)`` with
identical semantics.
"""

from __future__ import annotations

from textual.widgets import Button, ContentSwitcher, DataTable, Static

from beachhead.tui.app import BeachheadTUI


async def test_mounts_read_only(engagement_env):
    app = BeachheadTUI(store_path=engagement_env.store_path, config_path=engagement_env.config_path)
    async with app.run_test() as pilot:
        from beachhead.tui.widgets import EngagementBar

        app.query_one(EngagementBar)
        assert app.query_one("#main", ContentSwitcher).current == "dashboard"
        await pilot.press("3")
        assert app.query_one("#main", ContentSwitcher).current == "runs"


async def test_scope_mismatch_banner(engagement_env, write_config, tmp_path):
    from beachhead.tui.widgets import EngagementBar

    other = write_config(
        tmp_path / "other.yaml", subscriptions=["99999999-9999-9999-9999-999999999999"]
    )
    app = BeachheadTUI(store_path=engagement_env.store_path, config_path=other)
    async with app.run_test():
        assert app.query_one(EngagementBar).has_class("scope-mismatch")


async def test_no_config_shows_create_button(engagement_env, tmp_path):
    absent = str(tmp_path / "absent.yaml")
    app = BeachheadTUI(store_path=engagement_env.store_path, config_path=absent)
    async with app.run_test():
        assert app.query_one("#main", ContentSwitcher).current == "no-config"
        assert app.query_one("#create-engagement-btn", Button).disabled is False


async def test_missing_store_auto_created(engagement_env, tmp_path):
    """When the store doesn't exist, it's created so views render normally."""
    absent = str(tmp_path / "absent.sqlite")
    app = BeachheadTUI(store_path=absent, config_path=engagement_env.config_path)
    async with app.run_test():
        assert app.query_one("#main", ContentSwitcher).current == "dashboard"


async def test_dashboard_counts(engagement_env):
    app = BeachheadTUI(store_path=engagement_env.store_path, config_path=engagement_env.config_path)
    async with app.run_test():
        from rich.console import Console as RichConsole

        panel = app.query_one("#stats-panel", Static)
        console = RichConsole(file=__import__("io").StringIO(), width=120)
        console.print(panel.content)
        rendered = console.file.getvalue()
        assert "Runs" in rendered
        assert "Resources" in rendered
        assert app.query_one("#recent", DataTable).row_count == 3


async def test_runs_view_master_detail(engagement_env):
    app = BeachheadTUI(store_path=engagement_env.store_path, config_path=engagement_env.config_path)
    async with app.run_test() as pilot:
        await pilot.press("3")  # runs
        view = app.query_one("#runs", object)
        runs_table = view.query_one("#runs-table", DataTable)
        assert runs_table.row_count == 3
        # select the first data row -> detail + audit populate
        runs_table.focus()
        await pilot.pause()
        runs_table.move_cursor(row=0)
        await pilot.press("enter")
        await pilot.pause()
        detail = str(view.query_one("#run-detail", Static).content)
        assert "id=" in detail

        # drill into the run that has an audit entry (enumerate.ado_repos),
        # not the currently-running collect.ado_credential_scan row (row 0, newest-first).
        for i in range(runs_table.row_count):
            row = runs_table.get_row_at(i)
            if row[0] == "enumerate.ado_repos":
                runs_table.move_cursor(row=i)
                break
        await pilot.press("enter")
        await pilot.pause()
        assert view.query_one("#run-audit", DataTable).row_count == 1


async def test_modules_view_shows_catalog(engagement_env):
    app = BeachheadTUI(store_path=engagement_env.store_path, config_path=engagement_env.config_path)
    async with app.run_test() as pilot:
        await pilot.press("2")  # modules
        assert app.query_one("#main", ContentSwitcher).current == "modules"
        from textual.widgets import Button

        buttons = app.query_one("#modules").query(Button)
        mod_buttons = [b for b in buttons if b.id and b.id.startswith("mod-")]
        assert len(mod_buttons) >= 1
        names = [b.label.plain for b in mod_buttons]
        assert any("ado_pipelines" in n for n in names)


async def test_paths_view_empty(engagement_env):
    app = BeachheadTUI(store_path=engagement_env.store_path, config_path=engagement_env.config_path)
    async with app.run_test() as pilot:
        await pilot.press("5")  # paths
        assert app.query_one("#main", ContentSwitcher).current == "paths"


async def test_audit_view_via_keybinding(engagement_env):
    app = BeachheadTUI(store_path=engagement_env.store_path, config_path=engagement_env.config_path)
    async with app.run_test() as pilot:
        await pilot.press("8")  # audit
        assert app.query_one("#main", ContentSwitcher).current == "audit"


async def test_resources_view_via_nav(engagement_env):
    app = BeachheadTUI(store_path=engagement_env.store_path, config_path=engagement_env.config_path)
    async with app.run_test() as pilot:
        app.action_show("resources")
        await pilot.pause()
        assert app.query_one("#main", ContentSwitcher).current == "resources"


async def test_findings_view_via_nav(engagement_env):
    app = BeachheadTUI(store_path=engagement_env.store_path, config_path=engagement_env.config_path)
    async with app.run_test() as pilot:
        app.action_show("findings")
        await pilot.pause()
        assert app.query_one("#main", ContentSwitcher).current == "findings"


async def test_findings_view_ado_repo_columns(engagement_env):
    """Findings with ADO details show repo/file columns and support open action."""
    from conftest import FakeClock, FakeIds

    from beachhead.core.store.engine import open_store

    st = open_store(engagement_env.store_path, clock=FakeClock(), id_factory=FakeIds())
    run_id = st.start_run(
        module="collect.ado_credential_scan", phase="collect", operator="op"
    )
    st.insert_finding(
        kind="ado_credential_exposure",
        resource_id="ado://acme-eng/MyProject/my-repo",
        reference="AKIA***WXYZ",
        run_id=run_id,
        redacted=True,
        details={
            "pattern_id": "aws_access_key",
            "repo_name": "my-repo",
            "project": "MyProject",
            "org": "acme-eng",
            "file_path": "/src/config.py",
            "ado_url": "https://dev.azure.com/acme-eng/MyProject/_git/my-repo?path=/src/config.py&version=GBmain",
        },
    )
    st.finish_run(run_id, status="ok")
    st.close()

    app = BeachheadTUI(store_path=engagement_env.store_path, config_path=engagement_env.config_path)
    async with app.run_test() as pilot:
        app.action_show("findings")
        await pilot.pause()
        table = app.query_one("#findings DataTable", DataTable)
        assert table.row_count == 1
        row = table.get_row_at(0)
        assert "MyProject/my-repo" in str(row)
        assert "/src/config.py" in str(row)


def test_finding_row_ado_fields():
    """_FindingRow computes source_label and file_label from details."""
    from beachhead.core.store.rows import Finding
    from beachhead.tui.views.tables import _FindingRow

    f = Finding(
        id="fake-1",
        kind="ado_credential_exposure",
        resource_id=None,
        reference="AKIA***WXYZ",
        redacted=True,
        details={
            "repo_name": "infra-repo",
            "project": "Platform",
            "org": "acme-eng",
            "file_path": "/deploy/secrets.yaml",
            "ado_url": "https://dev.azure.com/acme-eng/Platform/_git/infra-repo?path=/deploy/secrets.yaml&version=GBmain",
        },
        run_id="run-1",
        collected_at="2026-01-01T00:00:00",
    )
    row = _FindingRow(f)
    assert row.source_label == "acme-eng/Platform/infra-repo"
    assert row.file_label == "/deploy/secrets.yaml"
    assert row.ado_url == f.details["ado_url"]

    f_no_ado = Finding(
        id="fake-2", kind="ado_credential_exposure", resource_id=None,
        reference="ref", redacted=False, details={},
        run_id="run-1", collected_at="2026-01-01T00:00:00",
    )
    row2 = _FindingRow(f_no_ado)
    assert row2.source_label == ""
    assert row2.file_label == ""
    assert row2.ado_url == ""

    f_vargroup = Finding(
        id="fake-3", kind="ado_credential_exposure", resource_id=None,
        reference="ref", redacted=False,
        details={
            "org": "acme-eng",
            "project": "Platform",
            "group_name": "shared-secrets",
        },
        run_id="run-1", collected_at="2026-01-01T00:00:00",
    )
    row3 = _FindingRow(f_vargroup)
    assert row3.source_label == "acme-eng/Platform/shared-secrets"

    f_pipeline = Finding(
        id="fake-4", kind="ado_credential_exposure", resource_id=None,
        reference="ref", redacted=False,
        details={
            "org": "acme-eng",
            "project": "Platform",
            "pipeline_name": "deploy-prod",
        },
        run_id="run-1", collected_at="2026-01-01T00:00:00",
    )
    row4 = _FindingRow(f_pipeline)
    assert row4.source_label == "acme-eng/Platform/deploy-prod"



