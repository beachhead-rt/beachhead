"""Beachhead headless CLI — entry point ``bh`` (see pyproject ``[project.scripts]``).

Top-level read commands over the local store (status/runs/audit),
plus ``bh tui``. Phase groups (enumerate/analyze/collect/persist) remain placeholders until
the module-dispatch slice.
"""

from __future__ import annotations

import typer

from beachhead import __version__
from beachhead.cli import _read, _triage
from beachhead.cli._auth import auth_app
from beachhead.cli._banner import print_banner
from beachhead.cli._completion import ensure_completion
from beachhead.cli._dispatch import make_phase_app, modules_command
from beachhead.cli._engage import engage_app
from beachhead.cli.common import CliOptions, console

_DEFAULT_STORE = "./beachhead.sqlite"

app = typer.Typer(
    name="bh",
    help="Authorized Azure DevOps post-exploitation framework.",
    invoke_without_command=True,
    add_completion=True,
)

# Phase groups — each discovers registered modules via entry points.
for _phase in ("enumerate", "analyze", "harvest", "exploit"):
    app.add_typer(make_phase_app(_phase), name=_phase)

# Auth commands.
app.add_typer(auth_app, name="auth")

# Engagement lifecycle.
app.add_typer(engage_app, name="engage")


def _version(value: bool) -> None:
    if value:
        console.print(f"beachhead {__version__}")
        raise typer.Exit


@app.callback()
def main(
    ctx: typer.Context,
    _version_flag: bool = typer.Option(
        False, "--version", callback=_version, is_eager=True, help="Show version and exit."
    ),
    store: str | None = typer.Option(
        None, "--store", "-s", envvar="BEACHHEAD_STORE", help="Path to the SQLite store."
    ),
    config: str | None = typer.Option(
        None, "--config", "-c", help="Path to the engagement config (else env/default)."
    ),
) -> None:
    """Beachhead CLI. Operates only within a signed engagement and its scope config."""
    ensure_completion()
    print_banner(console)
    ctx.obj = CliOptions(store_path=store or _DEFAULT_STORE, config_path=config)
    if ctx.invoked_subcommand is None:
        console.print(ctx.get_help())
        raise typer.Exit


# Read commands (read-only; defined in _read).
app.command("status")(_read.status)
app.command("paths")(_read.paths)
app.command("findings")(_read.findings)
app.command("audit")(_read.audit)
app.command("tui")(_read.tui)
app.command("modules")(modules_command)

# Triage commands.
app.command("dismiss")(_triage.dismiss)
app.command("restore")(_triage.restore)


if __name__ == "__main__":  # pragma: no cover
    app()
