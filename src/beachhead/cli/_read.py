"""Read commands over the local store. Rendered as Rich tables or a --json envelope."""

from __future__ import annotations

from dataclasses import asdict
from datetime import UTC, datetime

import typer

from beachhead.cli.common import (
    console,
    emit_error,
    emit_json,
    emit_table,
    fetch,
    load_surface,
)
from beachhead.core.store.rows import Run
from beachhead.core.timefilter import SINCE_HELP, filter_by_time, parse_since
from beachhead.surface import format_duration


def _run_dict(run: Run) -> dict[str, object]:
    duration = format_duration(run)
    return {**asdict(run), "duration": duration}


_RUN_COLUMNS = [
    ("module", "module"),
    ("phase", "phase"),
    ("operator", "operator"),
    ("started", "started_at"),
    ("finished", "finished_at"),
    ("status", "status"),
]


def status(ctx: typer.Context, json_: bool = typer.Option(False, "--json")) -> None:
    """Engagement summary. (bh status, bh status --json)"""
    sc = load_surface(ctx.obj, json_=json_)
    try:
        cfg = sc.config
        now = datetime.now(UTC)
        window_ok = cfg.window_start <= now <= cfg.window_end
        summ = fetch(json_, sc.store.summary)
        fields = {
            "engagement": cfg.engagement,
            "authorization_ref": cfg.authorization_ref,
            "ado_organizations": ", ".join(sorted(cfg.ado_organizations)) or "—",
            "window": f"{cfg.window_start:%Y-%m-%d} to {cfg.window_end:%Y-%m-%d}",
            "window_state": "OK" if window_ok else "OUTSIDE",
            "allow_write": cfg.allow_write,
            "scope_hash": "match" if sc.scope_match else "MISMATCH",
            "runs": summ.runs,
            "resources": summ.resources,
            "findings": summ.findings,
            "attack_paths": summ.attack_paths,
        }
        if json_:
            emit_json("status", [fields])
            return
        if not sc.scope_match:
            console.print("[red]scope-hash MISMATCH — config differs from the store[/]")

        from rich.rule import Rule

        console.print()
        console.print(Rule(f"[bold]{cfg.engagement}[/]", style="cyan"))
        console.print()
        console.print(f"  [bold]ADO orgs[/]       {fields['ado_organizations']}")
        if cfg.authorization_ref:
            console.print(f"  [bold]Authorization[/]  {cfg.authorization_ref}")
        window_state = fields["window_state"]
        window_end = f"[red]{window_state}[/]" if not window_ok else window_state
        console.print(f"  [bold]Window[/]         {fields['window']}  ({window_end})")
        console.print()

        console.print(f"  Runs: {summ.runs}    Resources: {summ.resources}    "
                       f"Findings: {summ.findings}    Attack paths: {summ.attack_paths}")
        console.print()
    finally:
        sc.store.close()


def runs(
    ctx: typer.Context,
    run: str | None = typer.Option(None, "--run", help="Show one run + its audit."),
    since: str | None = typer.Option(None, "--since", help=SINCE_HELP),
    json_: bool = typer.Option(False, "--json"),
) -> None:
    """Run history. (bh runs, bh runs --run ID)"""
    sc = load_surface(ctx.obj, json_=json_)
    try:
        if run is not None:
            found = fetch(json_, lambda: sc.store.get_run(run))
            if found is None:
                emit_error(f"no run with id {run!r}", kind="store", json_=json_)
                raise typer.Exit(1)
            entries = fetch(json_, lambda: sc.store.audit_entries(run_id=run))
            detail = _run_dict(found)
            audit_rows = [asdict(a) for a in entries]
            if json_:
                emit_json("run", [{"run": detail, "audit": audit_rows}])
                return
            console.print(
                f"[bold]{found.module}[/]  id={found.id}  status={found.status}  "
                f"duration={detail['duration']}"
            )
            emit_table(
                title="Audit entries",
                columns=[
                    ("ts", "ts"),
                    ("action", "action"),
                    ("target", "target"),
                    ("result", "result"),
                ],
                rows=audit_rows,
            )
            return
        rows = fetch(json_, sc.store.runs)
        cutoff = parse_since(since) if since else None
        rows = filter_by_time(rows, cutoff, "started_at")
        dicts = [_run_dict(r) for r in rows]
        if json_:
            emit_json("runs", dicts)
            return
        if not rows:
            console.print("No runs recorded.")
            return
        emit_table(title="Runs", columns=_RUN_COLUMNS, rows=dicts)
    finally:
        sc.store.close()


def resources(
    ctx: typer.Context,
    type_: str | None = typer.Option(None, "--type", help="Filter by resource type."),
    search: str | None = typer.Option(None, "--search", help="Substring on name or resource_id."),
    since: str | None = typer.Option(None, "--since", help=SINCE_HELP),
    json_: bool = typer.Option(False, "--json"),
) -> None:
    """Collected resources. (bh resources, bh resources --type ado_extension)"""
    sc = load_surface(ctx.obj, json_=json_)
    try:
        rows = fetch(json_, sc.store.resources)
        cutoff = parse_since(since) if since else None
        rows = filter_by_time(rows, cutoff, "collected_at")
        if type_ is not None:
            needle = type_.lower()
            rows = [r for r in rows if needle in r.type.lower()]
        if search is not None:
            needle = search.lower()
            rows = [
                r
                for r in rows
                if (r.name and needle in r.name.lower())
                or needle in r.resource_id.lower()
            ]
        dicts = [asdict(r) for r in rows]
        if json_:
            emit_json("resources", dicts)
            return
        if not rows:
            console.print("No resources recorded.")
            return

        by_type: dict[str, int] = {}
        for r in rows:
            by_type[r.type] = by_type.get(r.type, 0) + 1

        emit_table(
            title="Resources",
            columns=[
                ("type", "type"),
                ("name", "name"),
                ("resource_id", "resource_id"),
            ],
            rows=dicts,
        )

        summary_parts = [f"{count} {t}" for t, count in sorted(by_type.items())]
        console.print(f"\n[bold]Total: {len(rows)}[/] ({', '.join(summary_parts)})")
    finally:
        sc.store.close()


def paths(
    ctx: typer.Context,
    since: str | None = typer.Option(None, "--since", help=SINCE_HELP),
    all_: bool = typer.Option(False, "--all", help="Include false positives."),
    json_: bool = typer.Option(False, "--json"),
) -> None:
    """Attack paths. (bh paths, bh paths --json)"""
    sc = load_surface(ctx.obj, json_=json_)
    try:
        rows = fetch(json_, lambda: sc.store.attack_paths(include_fp=all_))
        cutoff = parse_since(since) if since else None
        rows = filter_by_time(rows, cutoff, "collected_at")
        dicts = [asdict(p) for p in rows]
        if json_:
            emit_json("attack_paths", dicts)
            return
        if not rows:
            console.print("No attack paths derived.")
            return
        emit_table(
            title="Attack paths",
            columns=[
                ("source", "source_id"),
                ("target", "target_id"),
                ("score", "score"),
                ("techniques", "technique_ids"),
                ("description", "description"),
            ],
            rows=dicts,
        )
    finally:
        sc.store.close()


def findings(
    ctx: typer.Context,
    kind: str | None = typer.Option(None, "--kind", help="Filter by finding kind."),
    since: str | None = typer.Option(None, "--since", help=SINCE_HELP),
    all_: bool = typer.Option(False, "--all", help="Include false positives."),
    json_: bool = typer.Option(False, "--json"),
) -> None:
    """Collected findings. (bh findings, bh findings --kind ado_credential)"""
    sc = load_surface(ctx.obj, json_=json_)
    try:
        rows = fetch(json_, lambda: sc.store.findings(kind=kind, include_fp=all_))
        cutoff = parse_since(since) if since else None
        rows = filter_by_time(rows, cutoff, "collected_at")
        dicts = [asdict(f) for f in rows]
        for d in dicts:
            details = d.get("details") or {}
            resource_id = d.get("resource_id", "")
            from beachhead.core.urls import resolve_finding_url

            ado_url = resolve_finding_url(details, resource_id)
            d["ado_url"] = ado_url

            org = details.get("org", "")
            project = details.get("project", "")
            file_path = details.get("file_path", "")
            source_name = (
                details.get("repo_name", "")
                or details.get("group_name", "")
                or details.get("pipeline_name", "")
                or details.get("endpoint_name", "")
                or details.get("pool_name", "")
                or details.get("feed_name", "")
                or details.get("extension_name", "")
                or details.get("app_name", "")
                or details.get("wiki_name", "")
                or details.get("build_number", "")
                or details.get("work_item_label", "")
            )
            if org and project and source_name:
                label = f"{org}/{project}/{source_name}"
            elif org and source_name:
                label = f"{org}/{source_name}"
            elif project and source_name:
                label = f"{project}/{source_name}"
            else:
                label = source_name
            if ado_url and label:
                d["source_link"] = f"[link={ado_url}]{label}[/link]"
            else:
                d["source_link"] = label
            file_or_var = file_path or details.get("variable_name", "")
            if ado_url and file_or_var:
                d["file_link"] = f"[link={ado_url}]{file_or_var}[/link]"
            else:
                d["file_link"] = file_or_var
        if json_:
            emit_json("findings", dicts)
            return
        if not rows:
            console.print("No findings recorded.")
            return
        emit_table(
            title="Findings",
            columns=[
                ("kind", "kind"),
                ("reference", "reference"),
                ("source", "source_link"),
                ("file", "file_link"),
            ],
            rows=dicts,
        )
    finally:
        sc.store.close()


def audit(
    ctx: typer.Context,
    run: str | None = typer.Option(None, "--run", help="Filter by run id."),
    since: str | None = typer.Option(None, "--since", help=SINCE_HELP),
    json_: bool = typer.Option(False, "--json"),
) -> None:
    """Append-only audit log. (bh audit, bh audit --run ID)"""
    sc = load_surface(ctx.obj, json_=json_)
    try:
        rows = fetch(json_, lambda: sc.store.audit_entries(run_id=run))
        cutoff = parse_since(since) if since else None
        rows = filter_by_time(rows, cutoff, "ts")
        dicts = [asdict(a) for a in rows]
        if json_:
            emit_json("audit", dicts)
            return
        if not rows:
            console.print("No audit entries recorded.")
            return
        emit_table(
            title="Audit log",
            columns=[
                ("ts", "ts"),
                ("operator", "operator"),
                ("action", "action"),
                ("target", "target"),
                ("result", "result"),
            ],
            rows=dicts,
        )
    finally:
        sc.store.close()


def tui(ctx: typer.Context) -> None:
    """Launch the Textual operator interface."""
    from beachhead.tui.app import BeachheadTUI

    opts = ctx.obj
    BeachheadTUI(store_path=opts.store_path, config_path=opts.config_path).run()
