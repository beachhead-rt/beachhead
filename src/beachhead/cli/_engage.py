"""Engagement lifecycle commands — ``bh engage status/export/teardown``."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import typer
from rich.table import Table

from beachhead.cli.common import CliOptions, console, emit_json, fetch, load_surface

engage_app = typer.Typer(
    name="engage",
    help="Engagement lifecycle. (bh engage status, bh engage export, bh engage teardown)",
    no_args_is_help=True,
)


@engage_app.command("status")
def status(ctx: typer.Context, json_: bool = typer.Option(False, "--json")) -> None:
    """Detailed engagement status: scope, runs, findings."""
    sc = load_surface(ctx.obj, json_=json_)
    try:
        cfg = sc.config
        summ = fetch(json_, sc.store.summary)
        now = datetime.now(UTC)
        window_ok = cfg.window_start <= now <= cfg.window_end
        runs = fetch(json_, sc.store.runs)

        ok_runs = sum(1 for r in runs if r.status == "ok")
        err_runs = sum(1 for r in runs if r.status == "error")

        fields = {
            "engagement": cfg.engagement,
            "authorization_ref": cfg.authorization_ref,
            "window": f"{cfg.window_start:%Y-%m-%d} to {cfg.window_end:%Y-%m-%d}",
            "window_state": "active" if window_ok else "OUTSIDE",
            "scope_match": sc.scope_match,
            "scope_hash": cfg.scope_hash[:16] + "...",
            "ado_organizations": len(cfg.ado_organizations),
            "total_runs": summ.runs,
            "ok_runs": ok_runs,
            "error_runs": err_runs,
            "findings": summ.findings,
            "attack_paths": summ.attack_paths,
        }

        if json_:
            emit_json("engage_status", [fields])
            return

        if not sc.scope_match:
            console.print("[red]scope-hash MISMATCH — config differs from the store[/]")

        table = Table(title=f"Engagement: {cfg.engagement}")
        table.add_column("field")
        table.add_column("value")
        for key, value in fields.items():
            style = ""
            if key == "window_state" and not window_ok:
                style = "red"
            table.add_row(key, str(value), style=style)
        console.print(table)
    finally:
        sc.store.close()


@engage_app.command("export")
def export(
    ctx: typer.Context,
    output: str = typer.Option(..., "--output", "-o", help="Output file path (.json or .md)."),
    format_: str = typer.Option(
        None,
        "--format",
        "-f",
        help="Export format: 'json' or 'markdown'. Auto-detected from extension if omitted.",
    ),
    include_secrets: bool = typer.Option(
        False,
        "--include-secrets",
        help="Include plaintext credentials in the report. Requires --confirm.",
    ),
    confirm: bool = typer.Option(
        False,
        "--confirm",
        help="Required when --include-secrets is used.",
    ),
) -> None:
    """Export engagement report (findings, attack paths, audit, and optionally credentials)."""
    opts: CliOptions = ctx.obj
    sc = load_surface(opts, json_=False)
    try:
        out_path = Path(output)

        if include_secrets and not confirm:
            console.print(
                "[red]--include-secrets exports plaintext credentials; "
                "pass --confirm to acknowledge.[/]"
            )
            raise typer.Exit(1)

        fmt = format_
        if fmt is None:
            if out_path.suffix in (".json",):
                fmt = "json"
            elif out_path.suffix in (".md", ".markdown"):
                fmt = "markdown"
            else:
                console.print(
                    "[red]Cannot detect format from extension; use --format json|markdown[/]"
                )
                raise typer.Exit(1)

        if fmt not in ("json", "markdown"):
            console.print(f"[red]Unknown format {fmt!r}; use json or markdown[/]")
            raise typer.Exit(1)

        from beachhead.core.export import build_report, export_json, export_markdown
        from beachhead.core.secret_store import (
            open_secret_store,
            resolve_passphrase,
            secret_store_path,
        )

        secret_store = None
        if include_secrets:
            sec_path = secret_store_path(opts.store_path)
            if not Path(sec_path).exists():
                console.print(
                    "[yellow]No secret store found — report will have no credentials.[/]"
                )
            else:
                try:
                    secret_store = open_secret_store(sec_path, resolve_passphrase())
                except Exception as exc:  # noqa: BLE001
                    console.print(f"[red]Error opening secret store:[/] {exc}")
                    raise typer.Exit(1) from exc

        try:
            report = build_report(
                sc.store,
                metadata={
                    "exported_at": datetime.now(UTC).isoformat(),
                    "engagement": sc.config.engagement,
                    "authorization_ref": sc.config.authorization_ref,
                },
                secret_store=secret_store,
                include_secrets=include_secrets,
            )

            if fmt == "json":
                export_json(report, out_path)
            else:
                export_markdown(report, out_path)

            cred_count = len(report.credentials)
            parts = [
                f"{report.summary.findings} findings",
                f"{report.summary.attack_paths} attack paths",
                f"{report.summary.runs} runs",
            ]
            if cred_count:
                parts.append(f"{cred_count} credentials")
            console.print(f"[green]Report exported[/] to {out_path}  ({', '.join(parts)})")
        except typer.Exit:
            raise
        except Exception as exc:  # noqa: BLE001
            console.print(f"[red]Export failed:[/] {exc}")
            raise typer.Exit(1) from exc
        finally:
            if secret_store is not None:
                secret_store.close()
    finally:
        sc.store.close()


@engage_app.command("teardown")
def teardown(
    ctx: typer.Context,
    confirm: bool = typer.Option(False, "--confirm", help="Required to execute teardown."),
) -> None:
    """Destroy all local engagement data: store, secrets, config, and cached tokens."""
    opts: CliOptions = ctx.obj
    store_path = Path(opts.store_path)
    removed: list[str] = []

    from beachhead.core.auth.token_cache import default_cache_path
    from beachhead.core.config import resolve_config_path
    from beachhead.core.secret_store import secret_store_path

    secrets_path = Path(secret_store_path(str(store_path)))
    token_path = default_cache_path()
    config_path = Path(resolve_config_path(opts.config_path))

    targets: list[tuple[Path, str]] = [
        (store_path, "store"),
        (secrets_path, "secret store"),
        (config_path, "engagement config"),
        (token_path, "token cache"),
    ]
    # WAL/SHM sidecars
    for suffix in ("-wal", "-shm"):
        for base, label in [(store_path, "store"), (secrets_path, "secret store")]:
            sidecar = base.with_name(base.name + suffix)
            targets.append((sidecar, f"{label} {suffix}"))

    existing = [(p, label) for p, label in targets if p.exists()]

    if not existing:
        console.print("[dim]Nothing to tear down — no engagement files found.[/]")
        return

    console.print("[bold red]Teardown will permanently delete:[/]")
    for p, label in existing:
        console.print(f"  {label}: {p}")

    if not confirm:
        console.print("\n[yellow]Pass --confirm to execute.[/]")
        raise typer.Exit(1)

    for p, label in existing:
        try:
            p.unlink()
            removed.append(label)
        except OSError as exc:
            console.print(f"  [red]Failed to remove {label}: {exc}[/]")

    console.print(f"\n[green]Teardown complete.[/] Removed: {', '.join(removed)}.")
