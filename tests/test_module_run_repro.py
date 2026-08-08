"""Regression: _running name collision with Textual Widget._running.

Textual sets Widget._running = True when a widget is mounted in a running app.
ModulesView used the same attribute name for its own run-in-progress flag, so
the run button was permanently disabled. Renamed to _run_active.
"""
from __future__ import annotations

from textual.widgets import Button, ContentSwitcher

from beachhead.tui.app import BeachheadTUI
from beachhead.tui.views.modules import ModulesView


async def test_module_select_enables_run_button(engagement_env):
    """Selecting a module in the catalog must enable the Run button."""
    app = BeachheadTUI(
        store_path=engagement_env.store_path,
        config_path=engagement_env.config_path,
    )
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.press("2")
        await pilot.pause()
        assert app.query_one("#main", ContentSwitcher).current == "modules"

        mv = app.query_one("#modules", ModulesView)
        btn_run = mv.query_one("#btn-run", Button)
        assert btn_run.disabled is True
        assert mv._run_active is False

        mod_buttons = [b for b in mv.query(Button) if b.id and b.id.startswith("mod-")]
        assert mod_buttons
        mod_buttons[0].press()
        await pilot.pause()

        assert mv._selected is not None
        assert btn_run.disabled is False
