"""Dismiss / restore findings, credentials, and attack paths as false positives."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import typer

from beachhead.cli.common import CliOptions, console, emit_json
from beachhead.core.store.engine import open_store


def dismiss(
    ctx: typer.Context,
    ids: list[str] = typer.Argument(..., help="One or more finding, credential, or path IDs."),
    json_: bool = typer.Option(False, "--json"),
) -> None:
    """Mark findings, credentials, or attack paths as false positives."""
    opts: CliOptions = ctx.obj
    store = open_store(opts.store_path)
    results: list[dict[str, object]] = []
    try:
        for item_id in ids:
            ok, kind = _set_fp(store, opts, item_id, fp=True)
            results.append({"id": item_id, "kind": kind, "dismissed": ok})
            if not json_:
                if ok:
                    console.print(f"[green]Dismissed[/] {kind} {item_id[:12]}")
                else:
                    console.print(f"[red]Not found:[/] {item_id[:12]}")
    finally:
        store.close()
    if json_:
        emit_json("dismiss", results)


def restore(
    ctx: typer.Context,
    ids: list[str] = typer.Argument(..., help="One or more finding, credential, or path IDs."),
    json_: bool = typer.Option(False, "--json"),
) -> None:
    """Restore false-positive findings, credentials, or attack paths."""
    opts: CliOptions = ctx.obj
    store = open_store(opts.store_path)
    results: list[dict[str, object]] = []
    try:
        for item_id in ids:
            ok, kind = _set_fp(store, opts, item_id, fp=False)
            results.append({"id": item_id, "kind": kind, "restored": ok})
            if not json_:
                if ok:
                    console.print(f"[green]Restored[/] {kind} {item_id[:12]}")
                else:
                    console.print(f"[red]Not found:[/] {item_id[:12]}")
    finally:
        store.close()
    if json_:
        emit_json("restore", results)


def _set_fp(
    store: Any,
    opts: CliOptions,
    item_id: str,
    *,
    fp: bool,
) -> tuple[bool, str]:
    """Try findings, then attack_paths, then credentials. Returns (success, kind)."""
    rows = store._query("SELECT 1 FROM findings WHERE id = ?", (item_id,))
    if rows:
        if fp:
            store.dismiss_finding(item_id)
        else:
            store.restore_finding(item_id)
        return True, "finding"

    rows = store._query("SELECT 1 FROM attack_paths WHERE id = ?", (item_id,))
    if rows:
        if fp:
            store.dismiss_attack_path(item_id)
        else:
            store.restore_attack_path(item_id)
        return True, "attack_path"

    ok = _try_credential(opts, item_id, fp=fp)
    if ok:
        return True, "credential"

    return False, "unknown"


def _try_credential(opts: CliOptions, cred_id: str, *, fp: bool) -> bool:
    from beachhead.core.secret_store import open_secret_store, resolve_passphrase, secret_store_path

    sec_path = secret_store_path(opts.store_path)
    if not Path(sec_path).exists():
        return False
    try:
        passphrase = resolve_passphrase()
    except Exception:  # noqa: BLE001
        return False
    ss = open_secret_store(sec_path, passphrase)
    try:
        if fp:
            ok = ss.dismiss_credential(cred_id)
        else:
            ok = ss.restore_credential(cred_id)
    finally:
        ss.close()
    return ok
