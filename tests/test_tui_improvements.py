"""Tests for TUI improvements: command palette, engagement bar, drill-down, reactive state."""

from __future__ import annotations

from textual.widgets import ContentSwitcher, DataTable, Static

from beachhead.tui.app import BeachheadTUI
from beachhead.tui.widgets import EngagementBar

# ---------------------------------------------------------------------------
# Engagement bar
# ---------------------------------------------------------------------------


async def test_engagement_bar_renders(engagement_env):
    """The engagement bar appears and shows engagement name + scope info."""
    app = BeachheadTUI(store_path=engagement_env.store_path, config_path=engagement_env.config_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        ebar = app.query_one(EngagementBar)
        assert ebar.engagement_name == "ACME-2026-Q2"
        bar_engagement = str(ebar.query_one("#bar-engagement", Static).content)
        assert "ACME-2026-Q2" in bar_engagement


async def test_engagement_bar_shows_scope_info(engagement_env):
    """Scope info includes ADO orgs."""
    app = BeachheadTUI(store_path=engagement_env.store_path, config_path=engagement_env.config_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        ebar = app.query_one(EngagementBar)
        assert "scope:" in str(ebar.query_one("#bar-scope", Static).content)


async def test_engagement_bar_shows_run_count(engagement_env):
    """Run count reflects the store's summary."""
    app = BeachheadTUI(store_path=engagement_env.store_path, config_path=engagement_env.config_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        ebar = app.query_one(EngagementBar)
        assert ebar.run_count == 3
        bar_runs = str(ebar.query_one("#bar-runs", Static).content)
        assert "runs: 3" in bar_runs



async def test_engagement_bar_scope_mismatch(engagement_env, write_config, tmp_path):
    """Scope mismatch sets the bar class and warning text."""
    other = write_config(
        tmp_path / "other.yaml", subscriptions=["99999999-9999-9999-9999-999999999999"]
    )
    app = BeachheadTUI(store_path=engagement_env.store_path, config_path=other)
    async with app.run_test() as pilot:
        await pilot.pause()
        ebar = app.query_one(EngagementBar)
        assert not ebar.scope_match
        assert ebar.has_class("scope-mismatch")


# ---------------------------------------------------------------------------
# Command palette
# ---------------------------------------------------------------------------


async def test_command_palette_provider_registered(engagement_env):
    """BeachheadCommandProvider is in the app's COMMANDS."""
    from beachhead.tui.commands import BeachheadCommandProvider

    assert BeachheadCommandProvider in BeachheadTUI.COMMANDS


def test_command_provider_view_commands():
    """The provider exposes commands for all views."""
    from beachhead.tui.commands import _VIEW_COMMANDS

    view_ids = [cmd[0] for cmd in _VIEW_COMMANDS]
    assert "dashboard" in view_ids
    assert "modules" in view_ids
    assert "findings" in view_ids
    assert "paths" in view_ids
    assert "teardown" in view_ids
    assert "cleanup" not in view_ids
    assert len(view_ids) == 9


def test_command_provider_filter_commands():
    """Filter commands exist for findings and attack paths."""
    from beachhead.tui.commands import _FILTER_COMMANDS

    assert "findings" in _FILTER_COMMANDS
    assert "paths" in _FILTER_COMMANDS


def test_fuzzy_score_exact_match():
    """Exact substring match scores 1.0."""
    from beachhead.tui.commands import _fuzzy_score

    assert _fuzzy_score("dashboard", "go to dashboard") == 1.0


def test_fuzzy_score_no_match():
    """Non-matching query scores 0.0."""
    from beachhead.tui.commands import _fuzzy_score

    assert _fuzzy_score("xyz", "dashboard") == 0.0


def test_fuzzy_score_partial_match():
    """Subsequence match scores between 0.5 and 1.0."""
    from beachhead.tui.commands import _fuzzy_score

    score = _fuzzy_score("dsh", "dashboard")
    assert 0.5 < score < 1.0


# ---------------------------------------------------------------------------
# Command action dispatch
# ---------------------------------------------------------------------------


async def test_handle_command_action_refresh(engagement_env):
    """Refresh action doesn't crash when surface is loaded."""
    app = BeachheadTUI(store_path=engagement_env.store_path, config_path=engagement_env.config_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        app.handle_command_action("refresh")


# ---------------------------------------------------------------------------
# Drill-down
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Table view defaults
# ---------------------------------------------------------------------------


async def test_table_views_use_row_cursor(engagement_env):
    """All table views default to cursor_type='row'."""
    app = BeachheadTUI(store_path=engagement_env.store_path, config_path=engagement_env.config_path)
    async with app.run_test() as pilot:
        for view_id in ("resources", "paths", "audit"):
            app.action_show(view_id)
            await pilot.pause()
            view = app.query_one(f"#{view_id}")
            table = view.query_one(DataTable)
            assert table.cursor_type == "row", f"{view_id} should use row cursor"


async def test_dashboard_recent_runs_uses_row_cursor(engagement_env):
    """Dashboard's recent runs table also uses row cursor."""
    app = BeachheadTUI(store_path=engagement_env.store_path, config_path=engagement_env.config_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        table = app.query_one("#recent", DataTable)
        assert table.cursor_type == "row"


# ---------------------------------------------------------------------------
# Reactive dashboard
# ---------------------------------------------------------------------------


async def test_dashboard_reactive_summary(engagement_env):
    """Dashboard stats panel shows counts."""
    app = BeachheadTUI(store_path=engagement_env.store_path, config_path=engagement_env.config_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        from rich.console import Console as RichConsole

        panel = app.query_one("#stats-panel", Static)
        console = RichConsole(file=__import__("io").StringIO(), width=120)
        console.print(panel.content)
        rendered = console.file.getvalue()
        assert "Runs" in rendered
        assert "Resources" in rendered


async def test_dashboard_stats_rendered(engagement_env):
    """Dashboard stats panel renders after mount."""
    app = BeachheadTUI(store_path=engagement_env.store_path, config_path=engagement_env.config_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        from rich.console import Console as RichConsole

        panel = app.query_one("#stats-panel", Static)
        console = RichConsole(file=__import__("io").StringIO(), width=120)
        console.print(panel.content)
        rendered = console.file.getvalue()
        assert "Runs" in rendered


# ---------------------------------------------------------------------------
# Modules view reactive status bar
# ---------------------------------------------------------------------------


async def test_modules_view_has_status_bar(engagement_env):
    """The modules view has a status bar for run state."""
    app = BeachheadTUI(store_path=engagement_env.store_path, config_path=engagement_env.config_path)
    async with app.run_test() as pilot:
        await pilot.press("2")  # modules
        await pilot.pause()
        modules_view = app.query_one("#modules")
        status = modules_view.query_one("#mod-status", Static)
        assert status is not None


async def test_modules_view_search_filter(engagement_env):
    """Module catalog can be filtered via the search input."""
    from textual.widgets import Button, Input

    app = BeachheadTUI(store_path=engagement_env.store_path, config_path=engagement_env.config_path)
    async with app.run_test() as pilot:
        await pilot.press("2")  # modules
        await pilot.pause()
        modules_view = app.query_one("#modules")
        all_buttons = [
            b for b in modules_view.query(Button) if b.id and b.id.startswith("mod-")
        ]
        all_count = len(all_buttons)
        assert all_count > 0

        search = modules_view.query_one("#mod-search", Input)
        search.value = "ado_credential"
        await pilot.pause()
        filtered_buttons = [
            b for b in modules_view.query(Button) if b.id and b.id.startswith("mod-")
        ]
        assert len(filtered_buttons) < all_count
        assert len(filtered_buttons) >= 1


# ---------------------------------------------------------------------------
# Attack path filtering
# ---------------------------------------------------------------------------


async def test_attack_path_score_filter(engagement_env):
    """Attack paths view supports min_score_filter."""
    from conftest import FakeClock, FakeIds

    from beachhead.core.store.engine import open_store

    st = open_store(engagement_env.store_path, clock=FakeClock(), id_factory=FakeIds())
    run_id = st.start_run(
        module="analyze.privesc_paths", phase="analyze", operator="op"
    )
    st.insert_attack_path(
        source_id="u-1",
        target_id="sp-1",
        edges=[{"from": "u-1", "to": "sp-1", "relationship": "owns"}],
        technique_ids=["T1098"],
        score=3.0,
        description="Low-score path",
        run_id=run_id,
    )
    st.insert_attack_path(
        source_id="u-1",
        target_id="sp-2",
        edges=[{"from": "u-1", "to": "sp-2", "relationship": "owns"}],
        technique_ids=["T1098"],
        score=8.5,
        description="High-score path",
        run_id=run_id,
    )
    st.finish_run(run_id, status="ok")
    st.close()

    app = BeachheadTUI(store_path=engagement_env.store_path, config_path=engagement_env.config_path)
    async with app.run_test() as pilot:
        app.action_show("paths")
        await pilot.pause()
        from beachhead.tui.views.tables import AttackPathsView

        paths_view = app.query_one(AttackPathsView)
        table = paths_view.query_one(DataTable)
        assert table.row_count == 2

        paths_view.min_score_filter = 7.0
        paths_view.reload()
        await pilot.pause()
        assert table.row_count == 1


# ---------------------------------------------------------------------------
# Attack path next steps
# ---------------------------------------------------------------------------


async def test_attack_path_detail_shows_next_steps(engagement_env):
    """Attack path detail screen shows next steps with commands."""
    from conftest import FakeClock, FakeIds

    from beachhead.core.store.engine import open_store

    st = open_store(engagement_env.store_path, clock=FakeClock(), id_factory=FakeIds())
    run_id = st.start_run(
        module="analyze.ado_attack_paths", phase="analyze", operator="op"
    )
    path_id = st.insert_attack_path(
        source_id="sc-1",
        target_id="keyvault-1",
        edges=[{"from": "sc-1", "to": "keyvault-1", "via": "service_connection"}],
        technique_ids=["T1552.001"],
        score=7.5,
        description="Service connection with access to Key Vault",
        run_id=run_id,
    )
    st.finish_run(run_id, status="ok")
    st.close()

    app = BeachheadTUI(store_path=engagement_env.store_path, config_path=engagement_env.config_path)
    async with app.run_test() as pilot:
        app.drill_to_attack_path(path_id)
        await pilot.pause()
        await pilot.pause()
        from beachhead.tui.views.detail import AttackPathDetailScreen

        screens = [s for s in app.screen_stack if isinstance(s, AttackPathDetailScreen)]
        assert len(screens) == 1
        steps = str(screens[0].query_one("#path-next-steps", Static).content)
        assert "bh harvest run ado_credential_scan" in steps
        assert "high confidence" in steps


def test_generate_next_steps_service_connection():
    """Next steps generator handles service_connection edge."""
    from beachhead.tui.views.detail import _generate_next_steps

    class FakePath:
        edges = [{"from": "sc-1", "to": "kv-1", "via": "service_connection"}]
        description = "service connection path"

    steps = _generate_next_steps(FakePath())
    commands = [s[1] for s in steps]
    assert "bh harvest run ado_credential_scan" in commands
    assert "bh exploit run ado_pipeline_vardump" in commands


def test_generate_next_steps_permissions():
    """Next steps generator handles permissions: prefix edges."""
    from beachhead.tui.views.detail import _generate_next_steps

    class FakePath:
        edges = [{"from": "identity-1", "to": "target", "via": "permissions:Build"}]
        description = "has [EditBuildDefinition, QueueBuilds] on Build"

    steps = _generate_next_steps(FakePath())
    commands = [s[1] for s in steps]
    assert "bh exploit run ado_pipeline_vardump" in commands
    assert "bh harvest run ado_credential_scan" in commands


def test_generate_next_steps_no_match():
    """Next steps generator returns empty for unknown edge types."""
    from beachhead.tui.views.detail import _generate_next_steps

    class FakePath:
        edges = [{"from": "a", "to": "b", "via": "unknown_type"}]
        description = "unknown"

    steps = _generate_next_steps(FakePath())
    assert steps == []


def test_generate_next_steps_deduplicates():
    """Next steps with duplicate commands are deduplicated."""
    from beachhead.tui.views.detail import _generate_next_steps

    class FakePath:
        edges = [
            {"from": "a", "to": "b", "via": "ado_credential_exposure"},
            {"from": "c", "to": "d", "via": "ado_pipeline_plaintext_variable"},
        ]
        description = "multiple credential findings"

    steps = _generate_next_steps(FakePath())
    commands = [s[1] for s in steps]
    assert len(commands) == len(set(commands))


# ---------------------------------------------------------------------------
# Finding drill-down
# ---------------------------------------------------------------------------


async def test_finding_detail_screen(engagement_env):
    """Finding drill-down opens a detail screen."""
    from conftest import FakeClock, FakeIds

    from beachhead.core.store.engine import open_store

    st = open_store(engagement_env.store_path, clock=FakeClock(), id_factory=FakeIds())
    run_id = st.start_run(
        module="collect.ado_credential_scan", phase="collect", operator="op"
    )
    st.insert_finding(
        kind="ado_credential_exposure",
        resource_id="ado://acme-eng/Proj/repo",
        reference="AKIA***WXYZ",
        run_id=run_id,
        redacted=True,
        details={
            "pattern_id": "aws_access_key",
            "repo_name": "my-repo",
            "project": "Proj",
            "org": "acme-eng",
            "file_path": "/src/config.py",
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
        table.focus()
        await pilot.pause()
        table.move_cursor(row=0)
        await pilot.press("enter")
        await pilot.pause()
        from beachhead.tui.views.detail import FindingDetailScreen

        assert any(isinstance(s, FindingDetailScreen) for s in app.screen_stack)


# ---------------------------------------------------------------------------
# Collapsible tab bar
# ---------------------------------------------------------------------------


async def test_toggle_tabs_hides_tab_bar(engagement_env):
    """Pressing 't' toggles the tab bar visibility."""
    from textual.widgets import Tabs

    app = BeachheadTUI(store_path=engagement_env.store_path, config_path=engagement_env.config_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        tabs = app.query_one("#tab-bar", Tabs)
        assert tabs.display is True
        await pilot.press("t")
        assert tabs.display is False
        await pilot.press("t")
        assert tabs.display is True


async def test_navigation_works_with_tabs_hidden(engagement_env):
    """Keyboard shortcuts still switch views when tabs are hidden."""
    from textual.widgets import Tabs

    app = BeachheadTUI(store_path=engagement_env.store_path, config_path=engagement_env.config_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        await pilot.press("t")
        assert app.query_one("#tab-bar", Tabs).display is False
        await pilot.press("3")
        assert app.query_one("#main", ContentSwitcher).current == "runs"


# ---------------------------------------------------------------------------
# Keyboard shortcuts
# ---------------------------------------------------------------------------


async def test_resources_via_keybinding(engagement_env):
    """Pressing '4' switches to the resources view."""
    app = BeachheadTUI(store_path=engagement_env.store_path, config_path=engagement_env.config_path)
    async with app.run_test() as pilot:
        await pilot.press("4")
        assert app.query_one("#main", ContentSwitcher).current == "resources"


async def test_findings_via_keybinding(engagement_env):
    """Pressing '6' switches to the findings view."""
    app = BeachheadTUI(store_path=engagement_env.store_path, config_path=engagement_env.config_path)
    async with app.run_test() as pilot:
        await pilot.press("6")
        assert app.query_one("#main", ContentSwitcher).current == "findings"


# ---------------------------------------------------------------------------
# Column auto-sizing
# ---------------------------------------------------------------------------


def test_format_cell_truncates_long_values():
    """Long cell values are truncated to _MAX_CELL_WIDTH."""
    from beachhead.tui.views.base import _MAX_CELL_WIDTH, TableView

    class FakeStore:
        pass

    view = TableView.__new__(TableView)
    view._store = FakeStore()

    long_val = "x" * 100
    result = view._format_cell("some_col", long_val)
    assert len(result.plain) == _MAX_CELL_WIDTH
    assert result.plain.endswith("...")

    short_val = "hello"
    result2 = view._format_cell("some_col", short_val)
    assert result2 == "hello"


# ---------------------------------------------------------------------------
# Live refresh (reload on switch)
# ---------------------------------------------------------------------------


async def test_switch_view_reloads_target(engagement_env):
    """Switching views reloads the target so data is always fresh."""
    app = BeachheadTUI(store_path=engagement_env.store_path, config_path=engagement_env.config_path)
    async with app.run_test() as pilot:
        await pilot.press("8")  # audit
        view = app.query_one("#audit")
        table = view.query_one(DataTable)
        assert table.row_count >= 1


# ---------------------------------------------------------------------------
# Teardown modal (launched from dashboard)
# ---------------------------------------------------------------------------


async def test_teardown_button_opens_modal(engagement_env):
    """Clicking the Start button on the dashboard opens the teardown modal."""
    from textual.widgets import Button

    from beachhead.tui.views.teardown import TeardownScreen

    app = BeachheadTUI(store_path=engagement_env.store_path, config_path=engagement_env.config_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        app.query_one("#teardown-btn", Button).press()
        await pilot.pause()
        assert isinstance(app.screen, TeardownScreen)


async def test_teardown_execute_disabled_until_confirm(engagement_env):
    """Execute button stays disabled until Confirm is pressed."""
    from textual.widgets import Button

    from beachhead.tui.views.teardown import TeardownScreen

    app = BeachheadTUI(store_path=engagement_env.store_path, config_path=engagement_env.config_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        app.query_one("#teardown-btn", Button).press()
        await pilot.pause()
        screen = app.screen
        assert isinstance(screen, TeardownScreen)

        confirm_btn = screen.query_one("#td-confirm", Button)
        execute_btn = screen.query_one("#td-execute", Button)

        assert execute_btn.disabled is True
        assert confirm_btn.disabled is False

        confirm_btn.press()
        await pilot.pause()

        assert confirm_btn.disabled is True
        assert execute_btn.disabled is False


async def test_teardown_execute_removes_files_and_exits(engagement_env):
    """Execute teardown deletes engagement files and exits the app."""
    from pathlib import Path

    from textual.widgets import Button

    from beachhead.tui.views.teardown import TeardownScreen

    store_path = Path(engagement_env.store_path)
    assert store_path.exists()

    app = BeachheadTUI(store_path=engagement_env.store_path, config_path=engagement_env.config_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        app.query_one("#teardown-btn", Button).press()
        await pilot.pause()
        screen = app.screen
        assert isinstance(screen, TeardownScreen)

        screen.query_one("#td-confirm", Button).press()
        await pilot.pause()
        screen.query_one("#td-execute", Button).press()
        await pilot.pause()

    assert not store_path.exists()
