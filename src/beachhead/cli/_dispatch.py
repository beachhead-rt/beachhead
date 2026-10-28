"""CLI phase dispatch — ``bh <phase> <module>`` execution.

Discovers registered modules via entry points, lists them, and runs
selected modules through the runner.  Called from the phase typer groups
in ``cli/__init__.py``.
"""

from __future__ import annotations

import asyncio
from collections.abc import Sequence

import typer

from beachhead.cli.common import console, emit_error
from beachhead.core.loader import ModuleRegistry, load_modules
from beachhead.core.module import Phase
from beachhead.core.timefilter import SINCE_HELP, parse_since

__all__ = ["make_phase_app", "modules_command"]

_registry: ModuleRegistry | None = None


def _get_registry() -> ModuleRegistry:
    global _registry  # noqa: PLW0603
    if _registry is None:
        _registry = load_modules()
    return _registry


def modules_command(
    filter_: str = typer.Argument(
        None, metavar="FILTER", help="Filter by name, summary, or ATT&CK ID."
    ),
    phase_: str = typer.Option(
        None, "--phase", "-p", help="Show only one phase (enumerate/analyze/collect/persist)."
    ),
) -> None:
    """List all registered modules. (bh modules, bh modules ado -p enumerate)"""
    reg = _get_registry()
    if phase_:
        mods = reg.list_phase(phase_)
    else:
        mods = reg.list_all()
    if filter_:
        needle = filter_.lower()
        mods = [
            m
            for m in mods
            if needle in m.meta.name.lower()
            or needle in m.meta.summary.lower()
            or any(needle in t.lower() for t in m.meta.technique_ids)
        ]
    if not mods:
        label = f" matching '{filter_}'" if filter_ else ""
        console.print(f"[dim]No modules{label}.[/]")
        return
    current_phase = ""
    for m in mods:
        if m.meta.phase.value != current_phase:
            current_phase = m.meta.phase.value
            console.print(f"\n[bold underline]{current_phase}[/]")
        gated = " [yellow][gated][/]" if m.meta.gated else ""
        techs = ", ".join(m.meta.technique_ids) if m.meta.technique_ids else ""
        console.print(
            f"  [bold]{m.meta.name}[/]{gated}  {m.meta.summary}"
            + (f"  [dim]({techs})[/]" if techs else "")
        )
    console.print(f"\n[dim]{len(mods)} module(s)[/]")


def make_phase_app(phase: str) -> typer.Typer:
    """Build a Typer sub-app for one phase with list + run commands."""
    app = typer.Typer(
        name=phase,
        no_args_is_help=True,
        help=f"{phase.capitalize()} modules. (bh {phase} list, bh {phase} run <module>)",
    )

    @app.command("list")
    def list_modules(
        filter_: str = typer.Argument(
            None, metavar="FILTER", help="Filter modules by name, summary, or ATT&CK ID."
        ),
    ) -> None:
        """List available modules in this phase."""
        reg = _get_registry()
        mods = reg.list_phase(phase)
        if filter_:
            needle = filter_.lower()
            mods = [
                m
                for m in mods
                if needle in m.meta.name.lower()
                or needle in m.meta.summary.lower()
                or any(needle in t.lower() for t in m.meta.technique_ids)
            ]
        if not mods:
            label = f" matching '{filter_}'" if filter_ else ""
            console.print(f"[dim]No {phase} modules{label}.[/]")
            return
        for m in mods:
            gated = " [yellow][gated][/]" if m.meta.gated else ""
            techs = ", ".join(m.meta.technique_ids) if m.meta.technique_ids else ""
            console.print(
                f"  [bold]{m.meta.name}[/]{gated}  {m.meta.summary}"
                + (f"  [dim]({techs})[/]" if techs else "")
            )

    def _complete_module(incomplete: str) -> list[tuple[str, str]]:
        reg = _get_registry()
        results: list[tuple[str, str]] = []
        for m in reg.list_phase(phase):
            short = m.meta.name.removeprefix(f"{phase}.")
            if short.startswith(incomplete) or m.meta.name.startswith(incomplete):
                results.append((short, m.meta.summary))
        return results

    @app.command("run")
    def run_module_cmd(
        ctx: typer.Context,
        module_name: str = typer.Argument(
            help="Module name to run.", autocompletion=_complete_module
        ),
        confirm: bool = typer.Option(
            False, "--confirm", help="Confirm execution of gated (write/manual) operations."
        ),
        since: str | None = typer.Option(
            None, "--since", help=SINCE_HELP,
        ),
    ) -> None:
        """Run a module."""
        reg = _get_registry()
        mod = reg.get(module_name) or reg.get(f"{phase}.{module_name}")
        if mod is None:
            avail = [m.meta.name.removeprefix(f"{phase}.") for m in reg.list_phase(phase)]
            emit_error(
                f"unknown module {module_name!r}; available: {avail}",
                kind="module",
                json_=False,
            )
            raise typer.Exit(1)
        if mod.meta.phase != Phase(phase):
            emit_error(
                f"module {module_name!r} is phase={mod.meta.phase.value}, not {phase}",
                kind="module",
                json_=False,
            )
            raise typer.Exit(1)

        if mod.meta.gated and not confirm:
            console.print(
                f"[red]Error:[/] {module_name!r} is a gated exploit module.\n"
                f"Pass [bold]--confirm[/] to authorize execution."
            )
            raise typer.Exit(1)

        opts = ctx.obj
        console.print(f"[bold]Running {module_name}[/]")

        asyncio.run(_execute(mod, opts, confirmed=confirm, since=parse_since(since) if since else None))

    @app.command("run-all")
    def run_all_cmd(
        ctx: typer.Context,
        confirm: bool = typer.Option(
            False, "--confirm", help="Confirm execution of gated (write/manual) operations."
        ),
        since: str | None = typer.Option(
            None, "--since", help=SINCE_HELP,
        ),
    ) -> None:
        """Run all modules in this phase sequentially."""
        reg = _get_registry()
        mods = reg.list_phase(phase)
        if not mods:
            console.print(f"[dim]No {phase} modules registered.[/]")
            return

        opts = ctx.obj
        console.print(f"[bold]Running all {len(mods)} {phase} module(s)[/]")
        asyncio.run(_execute_all(mods, opts, confirmed=confirm, since=parse_since(since) if since else None))

    return app


async def _cli_confirm(prompt: str, *, dangerous: bool = False) -> bool:
    """Interactive confirmation gate for gated operations."""
    suffix = " [red](DANGEROUS)[/red]" if dangerous else ""
    console.print(f"\n[yellow]{prompt}{suffix}[/yellow]")
    try:
        answer = console.input("[bold]Proceed? [y/N]: [/bold]").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    return answer in ("y", "yes")


def _cli_passphrase() -> str | None:
    """Resolve the secret store passphrase for CLI usage (env var or getpass)."""
    from beachhead.core.secret_store import resolve_passphrase

    try:
        return resolve_passphrase()
    except Exception:  # noqa: BLE001
        return None


async def _execute(mod: object, opts: object, *, confirmed: bool, since: object = None) -> None:
    from beachhead.cli.common import CliOptions
    from beachhead.core.boot import bootstrap_run_env
    from beachhead.core.errors import (
        BeachheadError,
        ConfigMissingError,
    )
    from beachhead.core.runner import run_module

    cli_opts: CliOptions = opts  # type: ignore[assignment]
    needs_secrets = getattr(getattr(mod, "meta", None), "needs_secrets", False)
    pp = _cli_passphrase() if needs_secrets else None
    if needs_secrets and pp is None:
        console.print(
            "[red]Error:[/] This module requires the secret store passphrase.\n"
            "Set [bold]BH_SECRETS_KEY[/] or provide it when prompted."
        )
        raise typer.Exit(1)
    try:
        env = await bootstrap_run_env(
            store_path=cli_opts.store_path,
            config_path=cli_opts.config_path,
            passphrase=pp,
        )
    except ConfigMissingError as exc:
        env = await _bootstrap_and_retry(cli_opts, exc, passphrase=pp)
    except BeachheadError as exc:
        console.print(f"[red]Error:[/] {exc}")
        raise typer.Exit(1) from exc
    env.since = since  # type: ignore[assignment]
    confirm_gate = _cli_confirm if confirmed else None
    try:
        result = await run_module(mod, env, confirm=confirm_gate)  # type: ignore[arg-type]
        if result.ok:
            console.print(
                f"[green]Done[/] — {result.written} written"
                + (f": {result.message}" if result.message else "")
            )
        else:
            console.print(f"[red]Failed[/]: {result.message}")
            raise typer.Exit(1)
    except BeachheadError as exc:
        console.print(f"[red]Error:[/] {exc}")
        raise typer.Exit(1) from exc
    finally:
        if env.secrets is not None:
            env.secrets.close()
        env.store.close()


async def _execute_all(
    mods: Sequence[object], opts: object, *, confirmed: bool, since: object = None
) -> None:
    from beachhead.cli.common import CliOptions
    from beachhead.core.boot import bootstrap_run_env
    from beachhead.core.errors import BeachheadError, ConfigMissingError
    from beachhead.core.runner import run_module

    cli_opts: CliOptions = opts  # type: ignore[assignment]
    any_needs = any(
        getattr(getattr(m, "meta", None), "needs_secrets", False) for m in mods
    )
    pp = _cli_passphrase() if any_needs else None
    try:
        env = await bootstrap_run_env(
            store_path=cli_opts.store_path,
            config_path=cli_opts.config_path,
            passphrase=pp,
        )
    except ConfigMissingError as exc:
        env = await _bootstrap_and_retry(cli_opts, exc, passphrase=pp)
    except BeachheadError as exc:
        console.print(f"[red]Error:[/] {exc}")
        raise typer.Exit(1) from exc
    env.since = since  # type: ignore[assignment]
    confirm_gate = _cli_confirm if confirmed else None
    passed = 0
    failed = 0
    skipped = 0
    try:
        for mod in mods:
            name = mod.meta.name  # type: ignore[attr-defined]
            if getattr(mod.meta, "needs_secrets", False) and pp is None:  # type: ignore[attr-defined]
                console.print(f"\n[bold]▸ {name}[/]")
                console.print(
                    "  [yellow]⊘[/] skipped (secret store passphrase required)"
                )
                skipped += 1
                continue
            console.print(f"\n[bold]▸ {name}[/]")
            if mod.meta.gated and not confirmed:  # type: ignore[attr-defined]
                console.print(
                    "  [yellow]⊘[/] skipped (pass --confirm to run gated exploit modules)"
                )
                skipped += 1
                continue
            try:
                result = await run_module(mod, env, confirm=confirm_gate)  # type: ignore[arg-type]
                if result.ok:
                    console.print(f"  [green]✓[/] {result.written} written")
                    passed += 1
                else:
                    console.print(f"  [red]✗[/] {result.message}")
                    failed += 1
            except Exception as exc:  # noqa: BLE001
                console.print(f"  [red]✗[/] {exc}")
                failed += 1
    finally:
        if env.secrets is not None:
            env.secrets.close()
        env.store.close()

    skip_msg = f", {skipped} skipped" if skipped else ""
    console.print(f"\n[bold]Done:[/] {passed} passed, {failed} failed{skip_msg}")
    if failed:
        raise typer.Exit(1)


async def _bootstrap_and_retry(
    opts: object,
    exc: object,
    *,
    passphrase: str | None = None,
) -> object:
    """Handle missing config during module execution: offer creation, then retry."""
    from beachhead.cli.common import CliOptions
    from beachhead.core.boot import bootstrap_run_env
    from beachhead.core.config import bootstrap_config
    from beachhead.core.errors import ConfigError

    missing = exc
    cli_opts: CliOptions = opts  # type: ignore[assignment]
    console.print(f"[yellow]No engagement config found at {missing.config_path}[/]")
    console.print("Let's create one.\n")
    try:
        written = bootstrap_config(cli_opts.config_path)
    except ConfigError as create_exc:
        emit_error(f"config: {create_exc}", kind="config", json_=False)
        raise typer.Exit(2) from create_exc
    console.print(f"\n[green]Config written to {written}[/]\n")
    try:
        return await bootstrap_run_env(
            store_path=cli_opts.store_path,
            config_path=cli_opts.config_path,
            passphrase=passphrase,
        )
    except (ConfigError, Exception) as retry_exc:
        emit_error(str(retry_exc), kind="config", json_=False)
        raise typer.Exit(2) from retry_exc
