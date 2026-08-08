"""analyze.discovered_credentials — display harvested credentials offline.

Reads from the engagement's secure credential store (the separate
``*.secrets.sqlite`` database populated by harvest and exploit modules)
and displays discovered credentials in a formatted table. Makes no API
calls — works entirely offline against locally stored data.

MITRE ATT&CK: T1552.001 (Unsecured Credentials: Credentials In Files)
"""

from __future__ import annotations

from beachhead.core.module import Access, ModuleMeta, Phase, RunContext, RunResult


class DiscoveredCredentials:
    meta = ModuleMeta(
        name="analyze.discovered_credentials",
        phase=Phase.ANALYZE,
        access=Access.READ,
        requires_browser=False,
        technique_ids=("T1552.001",),
        needs_secrets=True,
        summary="Display discovered credentials from the secure credential store (offline).",
    )

    async def run(self, ctx: RunContext) -> RunResult:
        if ctx.secrets is None:
            ctx.console.print("[yellow]No credential store available.[/]")
            return RunResult(ok=True, written=0, message="No credential store")

        creds = ctx.secrets.list_credentials()
        if not creds:
            ctx.console.print(
                "[dim]No credentials discovered yet. "
                "Run harvest or exploit modules first.[/]"
            )
            return RunResult(ok=True, written=0, message="No credentials found")

        from rich.table import Table

        table = Table(
            title=f"Discovered Credentials ({len(creds)})",
            show_lines=True,
            expand=True,
        )
        table.add_column("Kind", ratio=2, no_wrap=False)
        table.add_column("Type", ratio=2, no_wrap=False)
        table.add_column("Value", ratio=4, no_wrap=False, overflow="fold")
        table.add_column("Reference", ratio=3, no_wrap=False)
        table.add_column("Source", ratio=2, no_wrap=False)

        for cred in creds:
            details = cred.details or {}
            cred_type = details.get("credential_type", "")
            source = details.get("source_module", "")
            org = details.get("org", "")
            project = details.get("project", "")
            if org and project:
                source = f"{org}/{project}"
            table.add_row(
                cred.kind,
                str(cred_type),
                cred.value,
                cred.reference,
                source,
            )

        ctx.console.print(table)

        by_kind: dict[str, int] = {}
        for cred in creds:
            by_kind[cred.kind] = by_kind.get(cred.kind, 0) + 1

        summary_parts = [f"{count} {kind}" for kind, count in sorted(by_kind.items())]
        ctx.console.print(f"\n[bold]Total: {len(creds)}[/] ({', '.join(summary_parts)})")

        return RunResult(
            ok=True,
            written=0,
            message=f"{len(creds)} credential(s) displayed",
            details={"total": len(creds), "by_kind": by_kind},
        )
