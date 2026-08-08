"""analyze.collected_resources — display collected resources offline.

Reads from the engagement store and displays all collected resources
(ADO extensions, service connections, repos, pipelines, feeds, etc.)
in a formatted table grouped by type. Makes no API calls.

MITRE ATT&CK: T1580 (Cloud Infrastructure Discovery)
"""

from __future__ import annotations

from beachhead.core.module import Access, ModuleMeta, Phase, RunContext, RunResult


class CollectedResources:
    meta = ModuleMeta(
        name="analyze.collected_resources",
        phase=Phase.ANALYZE,
        access=Access.READ,
        requires_browser=False,
        technique_ids=("T1580",),
        summary="Display collected resources from the store (offline).",
    )

    async def run(self, ctx: RunContext) -> RunResult:
        resources = ctx.store.resources()
        if not resources:
            ctx.console.print(
                "[dim]No resources collected yet. "
                "Run enumerate modules first.[/]"
            )
            return RunResult(ok=True, written=0, message="No resources found")

        from rich.table import Table

        by_type: dict[str, list] = {}
        for r in resources:
            by_type.setdefault(r.type, []).append(r)

        for rtype, items in sorted(by_type.items()):
            table = Table(
                title=f"{rtype} ({len(items)})",
                show_lines=True,
                expand=True,
            )
            table.add_column("Name", no_wrap=False)
            table.add_column("Resource ID", no_wrap=False)

            props_keys = _common_props_keys(items)
            for key in props_keys:
                table.add_column(key, no_wrap=False)

            for r in items:
                props = r.properties_summary or {}
                row = [r.name or "", r.resource_id]
                for key in props_keys:
                    val = props.get(key, "")
                    if isinstance(val, list):
                        val = ", ".join(str(v) for v in val)
                    row.append(str(val) if val else "")
                table.add_row(*row)

            ctx.console.print(table)
            ctx.console.print()

        summary_parts = [f"{len(items)} {t}" for t, items in sorted(by_type.items())]
        ctx.console.print(
            f"[bold]Total: {len(resources)}[/] ({', '.join(summary_parts)})"
        )

        return RunResult(
            ok=True,
            written=0,
            message=f"{len(resources)} resource(s) displayed",
            details={"total": len(resources), "by_type": {k: len(v) for k, v in by_type.items()}},
        )


_SKIP_PROPS = frozenset({"org", "flags", "install_state", "last_updated"})


def _common_props_keys(items: list) -> list[str]:
    """Pick the most useful properties_summary keys to show as columns."""
    counts: dict[str, int] = {}
    for r in items:
        props = r.properties_summary or {}
        for key in props:
            if key not in _SKIP_PROPS:
                counts[key] = counts.get(key, 0) + 1

    threshold = len(items) * 0.5
    keys = [k for k, c in counts.items() if c >= threshold]
    name_keys = {"name", "resource_id", "extension_name", "extension_id"}
    keys = [k for k in keys if k not in name_keys]
    return keys[:5]
