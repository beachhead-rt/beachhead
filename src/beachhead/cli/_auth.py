"""Token acquisition commands — ``bh auth ado-pat / status / clear``."""

from __future__ import annotations

import asyncio

import typer

from beachhead.cli.common import console
from beachhead.core.auth.token_entry import TokenEntry

_VALID_AUDIENCES = ("ado",)

auth_app = typer.Typer(
    name="auth",
    help="Token acquisition and management. (bh auth status, bh auth ado-pat)",
    no_args_is_help=True,
)


def _mask(token: str) -> str:
    return f"…{token[-4:]}" if len(token) >= 4 else "…"


def _save_entry(entry: TokenEntry) -> None:
    """Merge the new entry into the token cache on disk."""
    from beachhead.core.auth.token_cache import load_tokens, save_tokens

    existing = load_tokens()
    existing[entry.audience] = entry
    path = save_tokens(existing)
    console.print(f"[dim]Token cached → {path}[/]")


@auth_app.command("ado-pat")
def ado_pat() -> None:
    """Store an ADO Personal Access Token (read from stdin, never the command line)."""
    import sys

    from beachhead.core.auth.ado_pat import _resolve_pat_identity, read_pat

    if sys.stdin.isatty():
        console.print("[dim]Paste your ADO PAT and press Enter (input is masked):[/]")
        raw = read_pat("  ADO PAT: ")
    else:
        raw = sys.stdin.readline().strip()

    if not raw:
        console.print("[red]Empty input — no PAT stored.[/]")
        raise typer.Exit(1)

    console.print("  [dim]Validating PAT…[/]", end="")
    identity = _resolve_pat_identity(raw)
    if identity:
        console.print(f"\r  [green]PAT valid — {identity}[/]")
    else:
        console.print("\r  [red]PAT invalid — could not authenticate[/]")
        raise typer.Exit(1)

    from beachhead.core.auth.ado_pat import acquire_token_ado_pat

    try:
        entry = asyncio.run(acquire_token_ado_pat(raw))
    except Exception as exc:
        console.print(f"[red]ADO PAT acquisition failed:[/] {exc}")
        raise typer.Exit(1) from exc

    _save_entry(entry)
    console.print(f"[green]ADO PAT stored[/]  identity={identity}  token={_mask(entry.access_token)}")


@auth_app.command("status")
def status() -> None:
    """Show cached tokens."""
    from beachhead.core.auth.token_cache import default_cache_path, load_tokens

    try:
        entries = load_tokens()
    except Exception as exc:
        console.print(f"[red]Failed to read token cache:[/] {exc}")
        raise typer.Exit(1) from exc

    if not entries:
        path = default_cache_path()
        console.print(
            f"[dim]No tokens cached ({path}). "
            "Use 'bh auth ado-pat' to store a PAT.[/]"
        )
        return

    from beachhead.core.auth.ado_pat import _resolve_pat_identity

    for aud, entry in entries.items():
        if aud == "ado":
            identity = _resolve_pat_identity(entry.access_token)
            if identity:
                console.print(
                    f"  [bold]{aud}[/]  [green]valid[/]  identity={identity}  "
                    f"token={_mask(entry.access_token)}"
                )
            else:
                console.print(
                    f"  [bold]{aud}[/]  [red]invalid[/]  "
                    f"token={_mask(entry.access_token)}"
                )
        else:
            console.print(
                f"  [bold]{aud}[/]  token={_mask(entry.access_token)}"
            )


@auth_app.command("clear")
def clear(
    audience: str = typer.Argument(
        None, help="Audience to clear ('ado'). Omit to clear all."
    ),
) -> None:
    """Remove cached tokens."""
    from beachhead.core.auth.token_cache import default_cache_path, load_tokens, save_tokens

    path = default_cache_path()
    if audience is not None:
        if audience not in _VALID_AUDIENCES:
            console.print(f"[red]Invalid audience {audience!r}; use: ado[/]")
            raise typer.Exit(1)
        try:
            existing = load_tokens()
        except Exception as exc:  # noqa: BLE001
            console.print(f"[red]Error reading token cache: {exc}[/]")
            raise typer.Exit(1) from exc
        if audience not in existing:
            console.print(f"[dim]No cached token for {audience!r}.[/]")
            return
        del existing[audience]
        try:
            save_tokens(existing, path)
        except OSError as exc:
            console.print(f"[red]Error writing token cache: {exc}[/]")
            raise typer.Exit(1) from exc
        console.print(f"[green]Cleared {audience} token from cache.[/]")
    else:
        if path.is_file():
            path.unlink()
            console.print(f"[green]Token cache removed ({path}).[/]")
        else:
            console.print("[dim]No token cache file to remove.[/]")
