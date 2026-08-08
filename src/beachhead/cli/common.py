"""Shared CLI plumbing: option bag, surface loader, and Rich/JSON emitters."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import typer
from rich.console import Console
from rich.table import Table

from beachhead.core.errors import ConfigError, ConfigMissingError, StoreError
from beachhead.surface import SurfaceContext, open_surface

console = Console()


@dataclass(frozen=True, slots=True)
class CliOptions:
    store_path: str
    config_path: str | None


def emit_error(message: str, *, kind: str, json_: bool) -> None:
    if json_:
        typer.echo(json.dumps({"error": message, "kind": kind}), err=True)
    else:
        console.print(f"[red]{message}[/]")


def load_surface(opts: CliOptions, *, json_: bool) -> SurfaceContext:
    """Bootstrap, mapping refuse conditions to exit code 2.

    On missing config (no file), offers interactive creation unless --json mode.
    """
    try:
        return open_surface(opts.store_path, opts.config_path)
    except ConfigMissingError as exc:
        if json_:
            emit_error(f"config: {exc}", kind="config", json_=True)
            raise typer.Exit(2) from exc
        return _offer_config_creation(opts, exc)
    except ConfigError as exc:
        emit_error(f"config: {exc}", kind="config", json_=json_)
        raise typer.Exit(2) from exc
    except StoreError as exc:
        emit_error(f"store: {exc}", kind="store", json_=json_)
        raise typer.Exit(1) from exc


def _offer_config_creation(opts: CliOptions, exc: ConfigMissingError) -> SurfaceContext:
    """Full onboarding: config creation, ADO PAT, optional fresh store."""
    from beachhead.core.config import bootstrap_config

    console.print(f"[yellow]No engagement config found at {exc.config_path}[/]")
    console.print("Let's set up a new engagement.\n")
    try:
        written = bootstrap_config(opts.config_path)
    except ConfigError as create_exc:
        emit_error(f"config: {create_exc}", kind="config", json_=False)
        raise typer.Exit(2) from create_exc
    console.print(f"\n[green]Config written to {written}[/]")

    _offer_fresh_store(opts)
    _ensure_store(opts)

    try:
        sc = open_surface(opts.store_path, opts.config_path)
    except ConfigError as retry_exc:
        emit_error(str(retry_exc), kind="config", json_=False)
        raise typer.Exit(2) from retry_exc
    if not sc.scope_match:
        console.print(
            "[yellow]Scope-hash mismatch — the store was created under a "
            "different scope config. Consider starting fresh with "
            "'bh engage teardown --confirm'.[/]"
        )
    return sc


def _offer_fresh_store(opts: CliOptions) -> None:
    """If a store exists from a prior engagement, offer to start fresh."""
    from pathlib import Path

    store = Path(opts.store_path)
    if not store.exists():
        return

    from beachhead.core.config import load_config
    from beachhead.core.store.engine import open_store_readonly

    config = load_config(opts.config_path)
    ro = open_store_readonly(opts.store_path)
    try:
        eng = ro.get_engagement()
        if eng is None:
            return
        old_name = eng.name
    except Exception:  # noqa: BLE001
        return
    finally:
        ro.close()

    if old_name == config.engagement:
        return

    console.print("\n[bold underline]Existing Data[/]")
    console.print(
        f"  [dim]Store has data from engagement"
        f" [bold]{old_name}[/].[/]"
    )
    console.print(
        "  [bold]Start fresh?[/] [dim](y/n, default no)[/]: ",
        end="",
    )
    try:
        answer = input("").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return

    if answer not in ("y", "yes"):
        return

    backup = store.with_suffix(".sqlite.bak")
    store.rename(backup)
    console.print(
        f"  [green]Old store backed up[/] → {backup}"
    )


def _ensure_store(opts: CliOptions) -> None:
    """Create the store and seed the engagement row if it doesn't exist yet."""
    from pathlib import Path

    if Path(opts.store_path).exists():
        return

    from beachhead.core.config import load_config
    from beachhead.core.store.engine import open_store

    config = load_config(opts.config_path)
    st = open_store(opts.store_path)
    st.ensure_engagement(name=config.engagement, scope_hash=config.scope_hash)
    st.close()


def fetch[T](json_: bool, fn: Callable[[], T]) -> T:
    """Run a store read, mapping StoreError to exit code 1."""
    try:
        return fn()
    except StoreError as exc:
        emit_error(f"store: {exc}", kind="store", json_=json_)
        raise typer.Exit(1) from exc


def emit_json(command: str, rows: list[dict[str, Any]]) -> None:
    typer.echo(json.dumps({"command": command, "rows": rows}))


def emit_table(*, title: str, columns: list[tuple[str, str]], rows: list[dict[str, Any]]) -> None:
    table = Table(title=title)
    for header, _ in columns:
        table.add_column(header)
    for row in rows:
        table.add_row(*[_fmt(row.get(key)) for _, key in columns])
    console.print(table)


def _fmt(value: Any) -> str:
    return "" if value is None else str(value)
